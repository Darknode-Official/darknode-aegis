#!/usr/bin/env python3
"""AEGIS Real Vulnerability Scanner
Wraps nuclei, nikto, testssl.sh, wpscan, and NVD API for real vulnerability
scanning with authorization gates and rich TUI output.
"""
import subprocess
import shutil
import json
import os
import sys
import re
import tempfile
import hashlib
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.parse import quote_plus
from urllib.error import URLError, HTTPError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from core.db import MissionDB

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.text import Text
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

LEGAL_DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════════════╗
║                    AEGIS VULNERABILITY SCANNER                         ║
║                        LEGAL DISCLAIMER                                ║
╠══════════════════════════════════════════════════════════════════════════╣
║  This tool performs ACTIVE vulnerability scanning against target        ║
║  systems. Unauthorized scanning is ILLEGAL and may violate:             ║
║                                                                        ║
║    • Computer Fraud and Abuse Act (CFAA)                                ║
║    • Computer Misuse Act (UK)                                           ║
║    • Applicable local, state, and international laws                    ║
║                                                                        ║
║  You MUST have EXPLICIT WRITTEN AUTHORIZATION from the system owner     ║
║  before running any scans. The operator assumes ALL legal liability.    ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "bright_red",
    "MEDIUM":   "yellow",
    "LOW":      "blue",
    "INFO":     "dim",
}

DB_PATH = os.path.expanduser("~/.aegis/missions.db")


def _run(cmd, timeout=300):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 1
    except Exception as e:
        return "", str(e), 1


def _has(tool):
    return shutil.which(tool) is not None


def _confirm_auth(target, console=None):
    c = console or (Console() if HAS_RICH else None)
    if c and HAS_RICH:
        c.print(LEGAL_DISCLAIMER, style="bold yellow")
        c.print(f"\n[bold]Target:[/bold] {target}")
        c.print("[bold red]Do you have written authorization to scan this target?[/bold red]")
    else:
        print(LEGAL_DISCLAIMER)
        print(f"\nTarget: {target}")
        print("Do you have written authorization to scan this target?")
    resp = input("\nType 'YES I AM AUTHORIZED' to proceed: ").strip()
    return resp == "YES I AM AUTHORIZED"


class AegisVulnScan:
    name = "AEGIS Vulnerability Scanner"
    description = "Real vulnerability scanning with nuclei, nikto, testssl.sh, wpscan, and NVD"
    category = "vuln"
    mitre = ["T1595.002", "T1190", "T1210"]

    def __init__(self, mission_id=None, db_path=None):
        self.console = Console() if HAS_RICH else None
        self.findings = []
        self.mission_id = mission_id or f"vuln-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
        self.db = MissionDB(db_path or DB_PATH)
        self.authorized = False

    def _sev_style(self, severity):
        return SEVERITY_COLORS.get(severity.upper(), "white")

    def _add_finding(self, severity, title, detail="", host="", port=0,
                     service="", cve="", cvss=0.0, remediation=""):
        finding = {
            "severity": severity.upper(),
            "title": title,
            "detail": detail,
            "host": host,
            "port": port,
            "service": service,
            "cve": cve,
            "cvss": cvss,
            "remediation": remediation,
            "module": self.name,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self.findings.append(finding)
        self.db.add_finding(
            mission_id=self.mission_id, severity=severity.upper(),
            title=title, detail=detail, module=self.name,
            host=host, port=port, service=service,
            cve=cve, cvss=cvss, remediation=remediation,
        )
        if self.console and HAS_RICH:
            self.console.print(
                f"  [{self._sev_style(severity)}][{severity.upper()}][/{self._sev_style(severity)}] {title}"
            )

    def _log_action(self, command, output="", result=""):
        self.db.add_action(
            mission_id=self.mission_id, command=command,
            output=output[:4000], result=result, module=self.name,
        )

    def authorize(self, target):
        if not _confirm_auth(target, self.console):
            if self.console and HAS_RICH:
                self.console.print("[bold red]Authorization denied. Aborting.[/bold red]")
            else:
                print("Authorization denied. Aborting.")
            return False
        self.authorized = True
        existing = self.db.get_mission(self.mission_id)
        if not existing:
            self.db.create_mission(self.mission_id, "Vulnerability Scan", target)
        return True

    # ── nuclei scan ──────────────────────────────────────────────────────
    def nuclei_scan(self, target):
        if not self.authorized:
            return []
        if not _has("nuclei"):
            if self.console:
                self.console.print("[yellow]nuclei not found — skipping nuclei scan[/yellow]")
            return []

        if self.console and HAS_RICH:
            self.console.print(Panel("[bold cyan]Running Nuclei Scan[/bold cyan]", box=box.ROUNDED))

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tf:
            out_path = tf.name

        cmd = f"nuclei -u {target} -jsonl -o {out_path} -silent -nc -timeout 10 -retries 1 2>/dev/null"
        self._log_action(cmd)

        if self.console and HAS_RICH:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                          TimeElapsedColumn(), console=self.console) as progress:
                task = progress.add_task("Nuclei scanning...", total=None)
                stdout, stderr, rc = _run(cmd, timeout=600)
                progress.update(task, completed=True)
        else:
            stdout, stderr, rc = _run(cmd, timeout=600)

        results = []
        if os.path.exists(out_path):
            with open(out_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        results.append(entry)
                    except json.JSONDecodeError:
                        continue
            os.unlink(out_path)

        for r in results:
            info = r.get("info", {})
            sev = info.get("severity", "info").upper()
            name = info.get("name", r.get("template-id", "Unknown"))
            matched = r.get("matched-at", target)
            desc = info.get("description", "")
            ref = ", ".join(info.get("reference", [])[:3]) if info.get("reference") else ""
            cve_ids = [c for c in info.get("classification", {}).get("cve-id", []) if c] if isinstance(info.get("classification"), dict) else []
            cve_str = ", ".join(cve_ids[:3])
            cvss_score = info.get("classification", {}).get("cvss-score", 0.0) if isinstance(info.get("classification"), dict) else 0.0
            detail = f"Matched: {matched}"
            if desc:
                detail += f"\nDescription: {desc}"
            if ref:
                detail += f"\nReferences: {ref}"
            self._add_finding(
                severity=sev, title=f"Nuclei: {name}", detail=detail,
                host=target, cve=cve_str,
                cvss=float(cvss_score) if cvss_score else 0.0,
                remediation=info.get("remediation", ""),
            )

        self._log_action(cmd, output=f"{len(results)} findings", result="OK" if rc == 0 else "ERROR")
        return results

    # ── nikto scan ───────────────────────────────────────────────────────
    def nikto_scan(self, url):
        if not self.authorized:
            return []
        if not _has("nikto"):
            if self.console:
                self.console.print("[yellow]nikto not found — skipping nikto scan[/yellow]")
            return []

        if self.console and HAS_RICH:
            self.console.print(Panel("[bold cyan]Running Nikto Scan[/bold cyan]", box=box.ROUNDED))

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tf:
            out_path = tf.name

        cmd = f"nikto -h {url} -Format json -output {out_path} -Tuning 1234567890abc -maxtime 300s 2>/dev/null"
        self._log_action(cmd)

        if self.console and HAS_RICH:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                          TimeElapsedColumn(), console=self.console) as progress:
                task = progress.add_task("Nikto scanning...", total=None)
                stdout, stderr, rc = _run(cmd, timeout=360)
                progress.update(task, completed=True)
        else:
            stdout, stderr, rc = _run(cmd, timeout=360)

        results = []
        if os.path.exists(out_path):
            try:
                with open(out_path, "r") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    vulns = data.get("vulnerabilities", [])
                    if not vulns:
                        for host_data in data.get("host", [data]):
                            vulns.extend(host_data.get("vulnerabilities", []))
                    results = vulns
                elif isinstance(data, list):
                    results = data
            except (json.JSONDecodeError, KeyError):
                with open(out_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("+ "):
                            results.append({"msg": line[2:], "id": "", "OSVDB": ""})
            os.unlink(out_path)

        for vuln in results:
            msg = vuln.get("msg", vuln.get("message", str(vuln)))
            osvdb = vuln.get("OSVDB", vuln.get("id", ""))
            sev = "MEDIUM"
            msg_lower = msg.lower()
            if any(w in msg_lower for w in ["rce", "injection", "remote code", "backdoor"]):
                sev = "CRITICAL"
            elif any(w in msg_lower for w in ["xss", "traversal", "directory listing", "default credentials"]):
                sev = "HIGH"
            elif any(w in msg_lower for w in ["information disclosure", "header", "cookie"]):
                sev = "LOW"
            self._add_finding(
                severity=sev, title=f"Nikto: {msg[:120]}",
                detail=f"OSVDB: {osvdb}\n{msg}" if osvdb else msg,
                host=url,
            )

        self._log_action(cmd, output=f"{len(results)} findings", result="OK" if rc == 0 else "ERROR")
        return results

    # ── SSL/TLS audit ────────────────────────────────────────────────────
    def ssl_audit(self, host):
        if not self.authorized:
            return []
        if not _has("testssl.sh") and not _has("testssl"):
            if self.console:
                self.console.print("[yellow]testssl.sh not found — skipping SSL audit[/yellow]")
            return []

        if self.console and HAS_RICH:
            self.console.print(Panel("[bold cyan]Running SSL/TLS Audit[/bold cyan]", box=box.ROUNDED))

        testssl_bin = "testssl.sh" if _has("testssl.sh") else "testssl"
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tf:
            out_path = tf.name

        target = host if ":" in host else f"{host}:443"
        cmd = f"{testssl_bin} --jsonfile {out_path} --quiet --color 0 --fast {target} 2>/dev/null"
        self._log_action(cmd)

        if self.console and HAS_RICH:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                          TimeElapsedColumn(), console=self.console) as progress:
                task = progress.add_task("testssl.sh auditing...", total=None)
                stdout, stderr, rc = _run(cmd, timeout=300)
                progress.update(task, completed=True)
        else:
            stdout, stderr, rc = _run(cmd, timeout=300)

        results = []
        if os.path.exists(out_path):
            try:
                with open(out_path, "r") as f:
                    data = json.load(f)
                results = data if isinstance(data, list) else data.get("scanResult", [data])
            except (json.JSONDecodeError, KeyError):
                pass
            os.unlink(out_path)

        sev_map = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
                    "LOW": "LOW", "WARN": "MEDIUM", "INFO": "INFO", "OK": "INFO"}

        for entry in results:
            if isinstance(entry, dict):
                entry_sev = entry.get("severity", "INFO").upper()
                finding_text = entry.get("finding", "")
                test_id = entry.get("id", "")
                if entry_sev in ("OK", "INFO") and "not vulnerable" in finding_text.lower():
                    continue
                mapped_sev = sev_map.get(entry_sev, "INFO")
                if mapped_sev == "INFO" and not any(k in test_id.lower() for k in
                        ["vuln", "weak", "deprecated", "expired", "selfsigned"]):
                    continue
                self._add_finding(
                    severity=mapped_sev,
                    title=f"SSL: {test_id} — {finding_text[:100]}",
                    detail=finding_text, host=host,
                    remediation="Update TLS configuration per Mozilla SSL guidelines",
                )

        self._log_action(cmd, output=f"{len(self.findings)} ssl findings", result="OK" if rc == 0 else "ERROR")
        return results

    # ── Security header audit ────────────────────────────────────────────
    def header_audit(self, url):
        if not self.authorized:
            return {}

        if self.console and HAS_RICH:
            self.console.print(Panel("[bold cyan]Checking Security Headers[/bold cyan]", box=box.ROUNDED))

        expected_headers = {
            "Strict-Transport-Security":  ("HIGH",   "Add HSTS header with max-age >= 31536000"),
            "Content-Security-Policy":    ("HIGH",   "Implement a strict Content-Security-Policy"),
            "X-Frame-Options":            ("MEDIUM", "Set X-Frame-Options to DENY or SAMEORIGIN"),
            "X-Content-Type-Options":     ("MEDIUM", "Set X-Content-Type-Options: nosniff"),
            "Referrer-Policy":            ("LOW",    "Set Referrer-Policy to strict-origin-when-cross-origin"),
            "Permissions-Policy":         ("LOW",    "Configure Permissions-Policy to restrict browser features"),
            "X-XSS-Protection":           ("LOW",    "Set X-XSS-Protection: 1; mode=block (legacy fallback)"),
            "Cross-Origin-Opener-Policy":  ("LOW",   "Set Cross-Origin-Opener-Policy: same-origin"),
            "Cross-Origin-Resource-Policy":("LOW",   "Set Cross-Origin-Resource-Policy: same-origin"),
        }

        dangerous_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]

        results = {"present": [], "missing": [], "dangerous": []}

        try:
            req = Request(url, method="HEAD")
            req.add_header("User-Agent", "AEGIS-VulnScanner/1.0")
            resp = urlopen(req, timeout=15)
            headers = {k.lower(): v for k, v in resp.getheaders()}
            resp_headers_raw = dict(resp.getheaders())
        except Exception as e:
            try:
                req = Request(url, method="GET")
                req.add_header("User-Agent", "AEGIS-VulnScanner/1.0")
                resp = urlopen(req, timeout=15)
                headers = {k.lower(): v for k, v in resp.getheaders()}
                resp_headers_raw = dict(resp.getheaders())
            except Exception as e2:
                self._add_finding("MEDIUM", f"Header audit failed: {e2}", host=url)
                return results

        self._log_action(f"HEAD {url}", output=json.dumps(resp_headers_raw, indent=2)[:2000])

        for hdr, (sev, fix) in expected_headers.items():
            if hdr.lower() in headers:
                results["present"].append(hdr)
                val = headers[hdr.lower()]
                if hdr == "Strict-Transport-Security":
                    match = re.search(r"max-age=(\d+)", val)
                    if match and int(match.group(1)) < 31536000:
                        self._add_finding("MEDIUM", f"Weak HSTS: max-age={match.group(1)} (< 1 year)",
                                          detail=f"Header value: {val}", host=url,
                                          remediation="Set max-age to at least 31536000")
            else:
                results["missing"].append(hdr)
                self._add_finding(sev, f"Missing header: {hdr}",
                                  detail=f"The {hdr} header is not set on {url}",
                                  host=url, remediation=fix)

        for hdr in dangerous_headers:
            if hdr.lower() in headers:
                val = headers[hdr.lower()]
                results["dangerous"].append(f"{hdr}: {val}")
                self._add_finding("LOW", f"Information disclosure: {hdr}",
                                  detail=f"{hdr}: {val}", host=url,
                                  remediation=f"Remove or suppress the {hdr} header")

        if self.console and HAS_RICH:
            tbl = Table(title="Security Headers", box=box.SIMPLE_HEAVY)
            tbl.add_column("Header", style="cyan")
            tbl.add_column("Status")
            for hdr in expected_headers:
                if hdr in results["present"]:
                    tbl.add_row(hdr, "[green]PRESENT[/green]")
                else:
                    sev = expected_headers[hdr][0]
                    tbl.add_row(hdr, f"[{self._sev_style(sev)}]MISSING[/{self._sev_style(sev)}]")
            self.console.print(tbl)

        return results

    # ── WordPress scan ───────────────────────────────────────────────────
    def wordpress_scan(self, url):
        if not self.authorized:
            return []
        if not _has("wpscan"):
            if self.console:
                self.console.print("[yellow]wpscan not found — skipping WordPress scan[/yellow]")
            return []

        if self.console and HAS_RICH:
            self.console.print(Panel("[bold cyan]Running WPScan[/bold cyan]", box=box.ROUNDED))

        api_token = os.environ.get("WPSCAN_API_TOKEN", "")
        token_flag = f"--api-token {api_token}" if api_token else ""

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tf:
            out_path = tf.name

        cmd = f"wpscan --url {url} {token_flag} --format json --output {out_path} --random-user-agent --no-banner 2>/dev/null"
        self._log_action(cmd.replace(api_token, "REDACTED") if api_token else cmd)

        if self.console and HAS_RICH:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                          TimeElapsedColumn(), console=self.console) as progress:
                task = progress.add_task("WPScan running...", total=None)
                stdout, stderr, rc = _run(cmd, timeout=300)
                progress.update(task, completed=True)
        else:
            stdout, stderr, rc = _run(cmd, timeout=300)

        results = []
        if os.path.exists(out_path):
            try:
                with open(out_path, "r") as f:
                    data = json.load(f)

                ver_info = data.get("version", {})
                if ver_info:
                    status = ver_info.get("status", "")
                    number = ver_info.get("number", "unknown")
                    if status == "insecure":
                        self._add_finding("HIGH", f"WordPress {number} is outdated/insecure",
                                          host=url, service="wordpress",
                                          remediation="Update WordPress to latest version")
                    for vuln in ver_info.get("vulnerabilities", []):
                        results.append(vuln)
                        refs = ", ".join(vuln.get("references", {}).get("url", [])[:2])
                        self._add_finding("HIGH",
                            f"WP Core: {vuln.get('title', 'Unknown vulnerability')}",
                            detail=refs, host=url, service="wordpress",
                            cve=", ".join(vuln.get("references", {}).get("cve", [])[:2]),
                            remediation=vuln.get("fixed_in", "Update WordPress"),
                        )

                for pname, pdata in data.get("plugins", {}).items():
                    for vuln in pdata.get("vulnerabilities", []):
                        results.append(vuln)
                        self._add_finding("HIGH",
                            f"WP Plugin [{pname}]: {vuln.get('title', 'Vulnerable')}",
                            host=url, service="wordpress",
                            cve=", ".join(vuln.get("references", {}).get("cve", [])[:2]),
                            remediation=vuln.get("fixed_in", f"Update {pname}"),
                        )

                for tname, tdata in data.get("themes", {}).items():
                    for vuln in tdata.get("vulnerabilities", []):
                        results.append(vuln)
                        self._add_finding("MEDIUM",
                            f"WP Theme [{tname}]: {vuln.get('title', 'Vulnerable')}",
                            host=url, service="wordpress",
                            remediation=vuln.get("fixed_in", f"Update {tname}"),
                        )

            except (json.JSONDecodeError, KeyError):
                pass
            os.unlink(out_path)

        self._log_action(cmd, output=f"{len(results)} wp vulns", result="OK" if rc == 0 else "ERROR")
        return results

    # ── CVE lookup via NVD ───────────────────────────────────────────────
    def cve_lookup(self, service, version):
        if self.console and HAS_RICH:
            self.console.print(Panel(f"[bold cyan]CVE Lookup: {service} {version}[/bold cyan]", box=box.ROUNDED))

        keyword = quote_plus(f"{service} {version}")
        api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=20"
        self._log_action(f"NVD API query: {service} {version}")

        results = []
        try:
            req = Request(api_url)
            req.add_header("User-Agent", "AEGIS-VulnScanner/1.0")
            resp = urlopen(req, timeout=30)
            data = json.loads(resp.read().decode("utf-8"))

            for item in data.get("vulnerabilities", []):
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "")
                descriptions = cve_data.get("descriptions", [])
                desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
                metrics = cve_data.get("metrics", {})
                cvss_score = 0.0
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    metric_list = metrics.get(key, [])
                    if metric_list:
                        cvss_score = metric_list[0].get("cvssData", {}).get("baseScore", 0.0)
                        break

                sev = "INFO"
                if cvss_score >= 9.0:
                    sev = "CRITICAL"
                elif cvss_score >= 7.0:
                    sev = "HIGH"
                elif cvss_score >= 4.0:
                    sev = "MEDIUM"
                elif cvss_score > 0:
                    sev = "LOW"

                results.append({"cve": cve_id, "cvss": cvss_score, "severity": sev, "description": desc})
                self._add_finding(
                    severity=sev, title=f"CVE: {cve_id} (CVSS {cvss_score})",
                    detail=desc[:500], host=f"{service}/{version}",
                    cve=cve_id, cvss=cvss_score, service=service,
                    remediation=f"Update {service} past version {version}",
                )

        except (URLError, HTTPError, json.JSONDecodeError) as e:
            if self.console:
                self.console.print(f"[yellow]NVD API error: {e}[/yellow]")
            self._log_action(f"NVD API query: {service} {version}", output=str(e), result="ERROR")

        if self.console and HAS_RICH and results:
            tbl = Table(title=f"CVEs for {service} {version}", box=box.SIMPLE_HEAVY)
            tbl.add_column("CVE", style="cyan", width=18)
            tbl.add_column("CVSS", justify="right", width=6)
            tbl.add_column("Severity", width=10)
            tbl.add_column("Description", max_width=60)
            for r in results[:15]:
                tbl.add_row(r["cve"], f"{r['cvss']:.1f}",
                            Text(r["severity"], style=self._sev_style(r["severity"])),
                            r["description"][:60])
            self.console.print(tbl)

        return results

    # ── Run all scans ────────────────────────────────────────────────────
    def run_all(self, target):
        if not self.authorize(target):
            return []

        self.findings = []
        url = target if target.startswith("http") else f"https://{target}"
        host = target.replace("https://", "").replace("http://", "").split("/")[0]

        if self.console and HAS_RICH:
            self.console.print(Panel(
                f"[bold green]Starting Full Vulnerability Scan[/bold green]\nTarget: {target}",
                title="AEGIS VulnScan", box=box.DOUBLE_EDGE,
            ))

        self.header_audit(url)
        self.ssl_audit(host)
        self.nuclei_scan(target)
        self.nikto_scan(url)
        self.wordpress_scan(url)

        self._print_summary()
        return self.findings

    def _print_summary(self):
        if not self.console or not HAS_RICH:
            print(f"\nTotal findings: {len(self.findings)}")
            return

        counts = {}
        for f in self.findings:
            s = f["severity"]
            counts[s] = counts.get(s, 0) + 1

        tbl = Table(title="Scan Summary", box=box.HEAVY_EDGE)
        tbl.add_column("Severity", style="bold")
        tbl.add_column("Count", justify="right")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in counts:
                tbl.add_row(Text(sev, style=self._sev_style(sev)), str(counts[sev]))
        tbl.add_row(Text("TOTAL", style="bold white"), str(len(self.findings)))
        self.console.print(tbl)

    def close(self):
        self.db.close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="AEGIS Real Vulnerability Scanner")
    parser.add_argument("target", help="Target URL or hostname")
    parser.add_argument("--mission", default=None, help="Mission ID")
    parser.add_argument("--nuclei", action="store_true", help="Run nuclei scan only")
    parser.add_argument("--nikto", action="store_true", help="Run nikto scan only")
    parser.add_argument("--ssl", action="store_true", help="Run SSL audit only")
    parser.add_argument("--headers", action="store_true", help="Run header audit only")
    parser.add_argument("--wpscan", action="store_true", help="Run WordPress scan only")
    parser.add_argument("--cve", nargs=2, metavar=("SERVICE", "VERSION"), help="CVE lookup")
    args = parser.parse_args()

    scanner = AegisVulnScan(mission_id=args.mission)

    try:
        if args.cve:
            scanner.authorized = True
            scanner.cve_lookup(args.cve[0], args.cve[1])
        elif any([args.nuclei, args.nikto, args.ssl, args.headers, args.wpscan]):
            if not scanner.authorize(args.target):
                sys.exit(1)
            if args.nuclei:
                scanner.nuclei_scan(args.target)
            if args.nikto:
                scanner.nikto_scan(args.target)
            if args.ssl:
                scanner.ssl_audit(args.target)
            if args.headers:
                url = args.target if args.target.startswith("http") else f"https://{args.target}"
                scanner.header_audit(url)
            if args.wpscan:
                scanner.wordpress_scan(args.target)
            scanner._print_summary()
        else:
            scanner.run_all(args.target)
    finally:
        scanner.close()
