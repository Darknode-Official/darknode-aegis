#!/usr/bin/env python3
"""AEGIS Real Reconnaissance Module
Wraps real reconnaissance tools (nmap, gobuster, ffuf, subfinder, amass,
enum4linux, smbclient, snmpwalk, dig) to perform live scanning against
authorized targets. Every action requires explicit user confirmation.

LEGAL: For authorized penetration testing and security assessments only.
"""
import subprocess
import shutil
import json
import os
import sys
import re
import socket
import tempfile
from datetime import datetime

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
╔══════════════════════════════════════════════════════════════════╗
║                    LEGAL DISCLAIMER                            ║
║                                                                ║
║  This tool performs ACTIVE reconnaissance against live systems. ║
║  Unauthorized scanning is illegal under the CFAA (18 U.S.C.    ║
║  § 1030) and equivalent laws worldwide.                        ║
║                                                                ║
║  You MUST have explicit written authorization from the system   ║
║  owner before running any scan. The operator assumes full       ║
║  legal responsibility for all actions performed.                ║
║                                                                ║
║  AEGIS and its developers are not liable for misuse.            ║
╚══════════════════════════════════════════════════════════════════╝
"""

DB_PATH = os.path.expanduser("~/.aegis/missions.db")

COMMON_WORDLISTS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/wordlists/dirb/big.txt",
]

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "PTR", "CAA"]

SCAN_PROFILES = {
    "quick":    {"flags": "-T4 --top-ports 100",         "desc": "Top 100 ports, fast timing"},
    "standard": {"flags": "-T3 -p-",                     "desc": "All TCP ports, normal timing"},
    "full":     {"flags": "-T4 -p- -A",                  "desc": "All ports + OS/version/script detection"},
    "stealth":  {"flags": "-sS -T2 --top-ports 1000",    "desc": "SYN stealth scan, slow timing"},
    "udp":      {"flags": "-sU --top-ports 50",           "desc": "Top 50 UDP ports"},
}


def _run(cmd, timeout=300):
    """Execute a shell command and return (stdout, stderr, returncode)."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", 1
    except Exception as e:
        return "", str(e), 1


def _has(tool):
    """Check if a tool is available on PATH."""
    return shutil.which(tool) is not None


def _find_wordlist():
    """Find the first available wordlist on the system."""
    for wl in COMMON_WORDLISTS:
        if os.path.isfile(wl):
            return wl
    return None


class AegisRecon:
    """Real reconnaissance engine wrapping live scanning tools."""

    name = "AEGIS Real Recon"
    description = "Live reconnaissance using nmap, gobuster, subfinder, amass, enum4linux, and more"
    category = "recon"
    mitre = ["T1046", "T1018", "T1595.001", "T1595.002", "T1590"]

    def __init__(self, mission_id=None):
        self.console = Console() if HAS_RICH else None
        self.mission_id = mission_id or f"recon-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
        self.findings = []
        self.actions = []
        self.db = MissionDB(DB_PATH)
        existing = self.db.get_mission(self.mission_id)
        if not existing:
            self.db.create_mission(self.mission_id, "Real Recon", "pending", operator="aegis-recon")
        self.tools = {
            "nmap": _has("nmap"),
            "masscan": _has("masscan"),
            "gobuster": _has("gobuster"),
            "ffuf": _has("ffuf"),
            "subfinder": _has("subfinder"),
            "amass": _has("amass"),
            "dig": _has("dig"),
            "enum4linux": _has("enum4linux"),
            "smbclient": _has("smbclient"),
            "snmpwalk": _has("snmpwalk"),
        }

    def _print(self, msg, style=""):
        if self.console:
            self.console.print(msg, style=style)
        else:
            print(msg)

    def _print_disclaimer(self):
        if self.console:
            self.console.print(Panel(LEGAL_DISCLAIMER.strip(), title="⚠ LEGAL WARNING",
                                     border_style="bold red"))
        else:
            print(LEGAL_DISCLAIMER)

    def _confirm(self, action_desc):
        """Require explicit user confirmation before any scan."""
        self._print_disclaimer()
        self._print(f"\n[bold yellow]Action:[/bold yellow] {action_desc}" if self.console
                    else f"\nAction: {action_desc}")
        response = input("\n[?] Do you have WRITTEN AUTHORIZATION to perform this action? (yes/no): ").strip().lower()
        if response not in ("yes", "y"):
            self._print("[bold red]Aborted. Authorization not confirmed.[/bold red]" if self.console
                        else "Aborted. Authorization not confirmed.")
            return False
        self.actions.append({"action": action_desc, "authorized": True,
                             "timestamp": datetime.utcnow().isoformat()})
        return True

    def _add_finding(self, severity, title, detail, host="", port=0, service="", mitre=""):
        finding = {
            "severity": severity, "title": title, "detail": detail,
            "host": host, "port": port, "service": service,
            "mitre": mitre, "module": self.name,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self.findings.append(finding)
        self.db.add_finding(self.mission_id, severity, title, detail=detail,
                            module=self.name, host=host, port=port,
                            service=service, mitre=mitre)
        return finding

    def _log_action(self, command, output="", result=""):
        self.db.add_action(self.mission_id, command, output=output[:2000],
                           result=result, module=self.name)

    def _require_tool(self, tool):
        if not self.tools.get(tool):
            self._print(f"[bold red]✗ {tool} is not installed or not on PATH[/bold red]"
                        if self.console else f"✗ {tool} is not installed or not on PATH")
            return False
        return True

    def _show_results_table(self, title, columns, rows):
        if not self.console:
            print(f"\n--- {title} ---")
            for row in rows:
                print("  ".join(str(v) for v in row))
            return
        table = Table(title=title, box=box.ROUNDED, show_lines=True)
        for col_name, col_style in columns:
            table.add_column(col_name, style=col_style)
        for row in rows:
            table.add_row(*[str(v) for v in row])
        self.console.print(table)

    # ─────────────────────────── Port Scan ───────────────────────────

    def port_scan(self, target, profile="quick"):
        """Run nmap port scan with selectable profile."""
        if not self._require_tool("nmap"):
            return []
        if profile not in SCAN_PROFILES:
            self._print(f"[red]Unknown profile '{profile}'. Use: {', '.join(SCAN_PROFILES)}[/red]"
                        if self.console else f"Unknown profile. Use: {', '.join(SCAN_PROFILES)}")
            return []

        prof = SCAN_PROFILES[profile]
        action = f"Port scan ({profile}: {prof['desc']}) against {target}"
        if not self._confirm(action):
            return []

        xml_out = tempfile.mktemp(suffix=".xml")
        cmd = f"nmap {prof['flags']} -oX {xml_out} {target}"
        self._print(f"[cyan]Running:[/cyan] {cmd}" if self.console else f"Running: {cmd}")

        results = []
        timeout = 600 if profile in ("standard", "full") else 300
        with self._progress("Scanning ports") as progress:
            task = progress.add_task("nmap", total=None)
            stdout, stderr, rc = _run(cmd, timeout=timeout)
            progress.update(task, completed=100)

        self._log_action(cmd, output=stdout, result="success" if rc == 0 else "failed")

        if rc != 0:
            self._print(f"[red]nmap failed: {stderr}[/red]" if self.console else f"nmap failed: {stderr}")
            return []

        results = self._parse_nmap_xml(xml_out)
        try:
            os.unlink(xml_out)
        except OSError:
            pass

        rows = []
        for r in results:
            sev = "INFO"
            if r.get("state") == "open":
                sev = "LOW"
                if r.get("port", 0) in (21, 23, 445, 3389, 1433, 3306, 5432):
                    sev = "MEDIUM"
            self._add_finding(sev, f"Open port {r['port']}/{r['protocol']}",
                              f"Service: {r.get('service', 'unknown')} "
                              f"Version: {r.get('version', 'unknown')}",
                              host=target, port=r.get("port", 0),
                              service=r.get("service", ""), mitre="T1046")
            rows.append((str(r["port"]), r["protocol"], r.get("state", ""),
                         r.get("service", ""), r.get("version", "")))

        self._show_results_table(f"Port Scan Results — {target}",
                                 [("Port", "cyan"), ("Proto", ""), ("State", "green"),
                                  ("Service", "yellow"), ("Version", "")], rows)
        return results

    def _parse_nmap_xml(self, xml_path):
        """Parse nmap XML output for open ports and services."""
        results = []
        if not os.path.isfile(xml_path):
            return results
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(xml_path)
            root = tree.getroot()
            for host in root.findall(".//host"):
                for port_el in host.findall(".//port"):
                    state_el = port_el.find("state")
                    service_el = port_el.find("service")
                    entry = {
                        "port": int(port_el.get("portid", 0)),
                        "protocol": port_el.get("protocol", "tcp"),
                        "state": state_el.get("state", "unknown") if state_el is not None else "unknown",
                        "service": service_el.get("name", "unknown") if service_el is not None else "unknown",
                        "version": "",
                    }
                    if service_el is not None:
                        ver_parts = [service_el.get("product", ""),
                                     service_el.get("version", ""),
                                     service_el.get("extrainfo", "")]
                        entry["version"] = " ".join(p for p in ver_parts if p).strip()
                    if entry["state"] == "open":
                        results.append(entry)
        except Exception as e:
            self._print(f"[red]XML parse error: {e}[/red]" if self.console else f"XML parse error: {e}")
        return results

    # ────────────────────── Service Enumeration ──────────────────────

    def service_enum(self, target):
        """Run nmap service version detection and banner grabbing."""
        if not self._require_tool("nmap"):
            return []
        if not self._confirm(f"Service enumeration (-sV --script=banner) against {target}"):
            return []

        xml_out = tempfile.mktemp(suffix=".xml")
        cmd = f"nmap -sV --version-intensity 5 --script=banner -T4 --top-ports 1000 -oX {xml_out} {target}"
        self._print(f"[cyan]Running:[/cyan] {cmd}" if self.console else f"Running: {cmd}")

        with self._progress("Enumerating services") as progress:
            task = progress.add_task("nmap -sV", total=None)
            stdout, stderr, rc = _run(cmd, timeout=600)
            progress.update(task, completed=100)

        self._log_action(cmd, output=stdout, result="success" if rc == 0 else "failed")
        results = self._parse_nmap_xml(xml_out)
        try:
            os.unlink(xml_out)
        except OSError:
            pass

        rows = []
        for r in results:
            self._add_finding("INFO", f"Service: {r['service']} on port {r['port']}",
                              f"Version: {r.get('version', 'unknown')}",
                              host=target, port=r["port"], service=r["service"],
                              mitre="T1046")
            rows.append((str(r["port"]), r["service"], r.get("version", "unknown")))

        self._show_results_table(f"Service Enumeration — {target}",
                                 [("Port", "cyan"), ("Service", "yellow"), ("Version", "")], rows)
        return results

    # ──────────────────── Web Directory Enumeration ──────────────────

    def web_enum(self, url, wordlist=None, extensions="php,html,txt,bak,asp,aspx,jsp"):
        """Run gobuster or ffuf for directory brute-forcing."""
        has_gobuster = self.tools.get("gobuster")
        has_ffuf = self.tools.get("ffuf")
        if not has_gobuster and not has_ffuf:
            self._print("[red]✗ Neither gobuster nor ffuf is installed[/red]"
                        if self.console else "✗ Neither gobuster nor ffuf is installed")
            return []

        wl = wordlist or _find_wordlist()
        if not wl:
            self._print("[red]✗ No wordlist found. Install seclists or dirb.[/red]"
                        if self.console else "✗ No wordlist found.")
            return []

        if not self._confirm(f"Web directory enumeration against {url}"):
            return []

        results = []
        if has_gobuster:
            cmd = (f"gobuster dir -u {url} -w {wl} -x {extensions} "
                   f"-t 20 --no-error -q --timeout 10s")
            self._print(f"[cyan]Running:[/cyan] {cmd}" if self.console else f"Running: {cmd}")

            with self._progress("Brute-forcing directories") as progress:
                task = progress.add_task("gobuster", total=None)
                stdout, stderr, rc = _run(cmd, timeout=600)
                progress.update(task, completed=100)

            self._log_action(cmd, output=stdout, result="success" if rc == 0 else "partial")

            for line in stdout.splitlines():
                match = re.match(r"(/\S+)\s+\(Status:\s*(\d+)\)", line)
                if match:
                    path, status = match.group(1), match.group(2)
                    results.append({"path": path, "status": int(status)})
        elif has_ffuf:
            cmd = (f"ffuf -u {url}/FUZZ -w {wl} -mc 200,201,301,302,403 "
                   f"-e .{extensions.replace(',', ',.')} -t 20 -s")
            self._print(f"[cyan]Running:[/cyan] {cmd}" if self.console else f"Running: {cmd}")

            with self._progress("Fuzzing directories") as progress:
                task = progress.add_task("ffuf", total=None)
                stdout, stderr, rc = _run(cmd, timeout=600)
                progress.update(task, completed=100)

            self._log_action(cmd, output=stdout, result="success" if rc == 0 else "partial")

            for line in stdout.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    results.append({"path": "/" + line, "status": 200})

        rows = []
        for r in results:
            sev = "INFO"
            if r["status"] == 200:
                sev = "LOW"
            if any(s in r["path"].lower() for s in ("admin", "backup", "config", ".env", ".git")):
                sev = "MEDIUM"
            self._add_finding(sev, f"Discovered path: {r['path']}",
                              f"HTTP {r['status']}", host=url, mitre="T1595.002")
            rows.append((r["path"], str(r["status"])))

        self._show_results_table(f"Web Enumeration — {url}",
                                 [("Path", "cyan"), ("Status", "green")], rows)
        return results

    # ────────────────────── Subdomain Enumeration ────────────────────

    def subdomain_enum(self, domain):
        """Run subfinder and amass for passive subdomain discovery."""
        has_subfinder = self.tools.get("subfinder")
        has_amass = self.tools.get("amass")
        if not has_subfinder and not has_amass:
            self._print("[red]✗ Neither subfinder nor amass is installed[/red]"
                        if self.console else "✗ Neither subfinder nor amass is installed")
            return []

        if not self._confirm(f"Subdomain enumeration against {domain}"):
            return []

        subdomains = set()

        if has_subfinder:
            cmd = f"subfinder -d {domain} -silent"
            self._print(f"[cyan]Running:[/cyan] {cmd}" if self.console else f"Running: {cmd}")
            with self._progress("Subfinder scanning") as progress:
                task = progress.add_task("subfinder", total=None)
                stdout, stderr, rc = _run(cmd, timeout=300)
                progress.update(task, completed=100)
            self._log_action(cmd, output=stdout, result="success" if rc == 0 else "failed")
            for line in stdout.splitlines():
                sub = line.strip()
                if sub and "." in sub:
                    subdomains.add(sub)

        if has_amass:
            cmd = f"amass enum -passive -d {domain} -timeout 5"
            self._print(f"[cyan]Running:[/cyan] {cmd}" if self.console else f"Running: {cmd}")
            with self._progress("Amass enumeration") as progress:
                task = progress.add_task("amass", total=None)
                stdout, stderr, rc = _run(cmd, timeout=600)
                progress.update(task, completed=100)
            self._log_action(cmd, output=stdout, result="success" if rc == 0 else "failed")
            for line in stdout.splitlines():
                sub = line.strip()
                if sub and "." in sub:
                    subdomains.add(sub)

        sorted_subs = sorted(subdomains)
        rows = []
        for sub in sorted_subs:
            try:
                ip = socket.gethostbyname(sub)
            except socket.gaierror:
                ip = "unresolved"
            self._add_finding("INFO", f"Subdomain: {sub}", f"Resolves to: {ip}",
                              host=sub, mitre="T1590.002")
            self.db.add_ioc(self.mission_id, "domain", sub,
                            context=f"Subdomain of {domain}", source="subfinder/amass")
            rows.append((sub, ip))

        self._show_results_table(f"Subdomains — {domain}",
                                 [("Subdomain", "cyan"), ("IP", "green")], rows)
        self._print(f"\n[bold green]Total subdomains found: {len(sorted_subs)}[/bold green]"
                    if self.console else f"\nTotal subdomains found: {len(sorted_subs)}")
        return sorted_subs

    # ──────────────────────── DNS Enumeration ────────────────────────

    def dns_enum(self, domain):
        """Full DNS enumeration: all record types + zone transfer attempt."""
        if not self._require_tool("dig"):
            return {}
        if not self._confirm(f"DNS enumeration against {domain}"):
            return {}

        results = {}
        rows = []

        with self._progress("Querying DNS records") as progress:
            task = progress.add_task("DNS enum", total=len(DNS_RECORD_TYPES) + 1)

            for rtype in DNS_RECORD_TYPES:
                cmd = f"dig +short {domain} {rtype}"
                stdout, stderr, rc = _run(cmd, timeout=30)
                progress.advance(task)
                records = [l.strip() for l in stdout.splitlines() if l.strip()]
                if records:
                    results[rtype] = records
                    for rec in records:
                        rows.append((rtype, rec))
                        self._add_finding("INFO", f"DNS {rtype} record for {domain}",
                                          rec, host=domain, mitre="T1590.002")
                self._log_action(cmd, output=stdout)

            # Zone transfer attempt
            ns_servers = results.get("NS", [])
            for ns in ns_servers:
                ns_clean = ns.rstrip(".")
                cmd = f"dig @{ns_clean} {domain} AXFR +short"
                stdout, stderr, rc = _run(cmd, timeout=30)
                progress.advance(task)
                if rc == 0 and stdout and "Transfer failed" not in stdout and "XFR size" not in stderr:
                    results["AXFR"] = stdout.splitlines()
                    self._add_finding("CRITICAL",
                                      f"DNS zone transfer allowed on {ns_clean}",
                                      f"Full zone data exposed:\n{stdout[:500]}",
                                      host=domain, mitre="T1590.002")
                    rows.append(("AXFR", f"ALLOWED on {ns_clean} — {len(stdout.splitlines())} records"))
                self._log_action(cmd, output=stdout)

        self._show_results_table(f"DNS Records — {domain}",
                                 [("Type", "cyan"), ("Value", "")], rows)
        return results

    # ──────────────────────── SMB Enumeration ────────────────────────

    def smb_enum(self, target):
        """Run enum4linux and smbclient for SMB share enumeration."""
        has_e4l = self.tools.get("enum4linux")
        has_smb = self.tools.get("smbclient")
        if not has_e4l and not has_smb:
            self._print("[red]✗ Neither enum4linux nor smbclient is installed[/red]"
                        if self.console else "✗ Neither enum4linux nor smbclient is installed")
            return {}
        if not self._confirm(f"SMB enumeration against {target}"):
            return {}

        results = {"shares": [], "users": [], "groups": [], "raw": ""}

        if has_e4l:
            cmd = f"enum4linux -a {target}"
            self._print(f"[cyan]Running:[/cyan] {cmd}" if self.console else f"Running: {cmd}")
            with self._progress("enum4linux scanning") as progress:
                task = progress.add_task("enum4linux", total=None)
                stdout, stderr, rc = _run(cmd, timeout=300)
                progress.update(task, completed=100)
            self._log_action(cmd, output=stdout[:2000], result="success" if rc == 0 else "partial")
            results["raw"] = stdout

            for line in stdout.splitlines():
                share_match = re.search(r"//\S+/(\S+)\s+Mapping:\s+(\S+)", line)
                if share_match:
                    results["shares"].append({
                        "name": share_match.group(1),
                        "access": share_match.group(2),
                    })
                user_match = re.search(r"user:\[([^\]]+)\]", line)
                if user_match:
                    uname = user_match.group(1)
                    if uname not in results["users"]:
                        results["users"].append(uname)

        if has_smb:
            cmd = f"smbclient -L //{target} -N 2>/dev/null"
            self._print(f"[cyan]Running:[/cyan] {cmd}" if self.console else f"Running: {cmd}")
            stdout, stderr, rc = _run(cmd, timeout=60)
            self._log_action(cmd, output=stdout, result="success" if rc == 0 else "partial")

            for line in stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 2 and parts[1] == "Disk":
                    share_name = parts[0]
                    if not any(s["name"] == share_name for s in results["shares"]):
                        results["shares"].append({"name": share_name, "access": "unknown"})

        rows = []
        for share in results["shares"]:
            sev = "LOW"
            if share["name"].upper() in ("C$", "ADMIN$", "IPC$"):
                sev = "MEDIUM"
            self._add_finding(sev, f"SMB share: {share['name']}", f"Access: {share['access']}",
                              host=target, port=445, service="smb", mitre="T1135")
            rows.append((share["name"], share.get("access", "unknown")))
        for user in results["users"]:
            self._add_finding("LOW", f"SMB user: {user}", "Enumerated via null session",
                              host=target, port=445, service="smb", mitre="T1087")
            rows.append((f"User: {user}", "enumerated"))

        self._show_results_table(f"SMB Enumeration — {target}",
                                 [("Item", "cyan"), ("Details", "")], rows)
        return results

    # ──────────────────────── SNMP Enumeration ───────────────────────

    def snmp_enum(self, target, community="public"):
        """Run snmpwalk if SNMP is open."""
        if not self._require_tool("snmpwalk"):
            return {}
        if not self._confirm(f"SNMP enumeration against {target} with community '{community}'"):
            return {}

        results = {"system": [], "interfaces": [], "processes": [], "raw": ""}
        oids = {
            "system":     "1.3.6.1.2.1.1",
            "interfaces": "1.3.6.1.2.1.2.2.1.2",
            "routes":     "1.3.6.1.2.1.4.21.1",
            "software":   "1.3.6.1.2.1.25.6.3.1.2",
            "processes":  "1.3.6.1.2.1.25.4.2.1.2",
        }
        rows = []

        with self._progress("SNMP walking") as progress:
            task = progress.add_task("snmpwalk", total=len(oids))
            for label, oid in oids.items():
                cmd = f"snmpwalk -v2c -c {community} {target} {oid}"
                stdout, stderr, rc = _run(cmd, timeout=60)
                progress.advance(task)
                self._log_action(cmd, output=stdout[:1000])

                if rc == 0 and stdout:
                    entries = [l.strip() for l in stdout.splitlines() if l.strip()]
                    results[label] = entries
                    for entry in entries[:20]:
                        rows.append((label, entry[:120]))

                    if label == "system":
                        self._add_finding("MEDIUM", f"SNMP system info exposed on {target}",
                                          "\n".join(entries[:5]),
                                          host=target, port=161, service="snmp",
                                          mitre="T1046")

        if rows:
            self._add_finding("MEDIUM", f"SNMP community '{community}' accepted on {target}",
                              f"Retrieved {sum(len(v) for v in results.values() if isinstance(v, list))} entries",
                              host=target, port=161, service="snmp", mitre="T1046")

        self._show_results_table(f"SNMP Enumeration — {target}",
                                 [("Category", "cyan"), ("Data", "")], rows[:40])
        return results

    # ───────────────────────── Helpers ────────────────────────────────

    def _progress(self, description):
        if HAS_RICH:
            return Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=self.console,
            )

        class _DummyProgress:
            def __enter__(self):
                print(f"  [{description}] Running...")
                return self
            def __exit__(self, *a):
                pass
            def add_task(self, desc, total=None):
                return 0
            def advance(self, task_id):
                pass
            def update(self, task_id, completed=None):
                pass
        return _DummyProgress()

    def tool_status(self):
        """Print availability of all required tools."""
        if self.console:
            table = Table(title="Tool Availability", box=box.SIMPLE)
            table.add_column("Tool", style="cyan")
            table.add_column("Status")
            for tool, available in self.tools.items():
                status = "[green]✓ installed[/green]" if available else "[red]✗ missing[/red]"
                table.add_row(tool, status)
            self.console.print(table)
        else:
            print("\n--- Tool Availability ---")
            for tool, available in self.tools.items():
                print(f"  {tool}: {'✓' if available else '✗'}")

    def summary(self):
        """Print summary of all findings."""
        stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            stats[f["severity"]] = stats.get(f["severity"], 0) + 1
        if self.console:
            table = Table(title="Recon Summary", box=box.DOUBLE_EDGE)
            table.add_column("Severity", style="bold")
            table.add_column("Count", justify="right")
            colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
                       "LOW": "cyan", "INFO": "dim"}
            for sev, count in stats.items():
                table.add_row(Text(sev, style=colors.get(sev, "")), str(count))
            table.add_row(Text("TOTAL", style="bold"), str(len(self.findings)))
            self.console.print(table)
        else:
            print("\n--- Recon Summary ---")
            for sev, count in stats.items():
                print(f"  {sev}: {count}")
            print(f"  TOTAL: {len(self.findings)}")

    def close(self):
        """Close DB connection."""
        self.db.close()


# ═══════════════════════════════════════════════════════════════════
#  CLI Entry Point
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AEGIS Real Reconnaissance Module")
    parser.add_argument("target", help="Target IP, hostname, URL, or domain")
    parser.add_argument("--mission", default=None, help="Mission ID")
    parser.add_argument("--scan", choices=["port", "service", "web", "subdomain", "dns", "smb", "snmp", "all"],
                        default="port", help="Scan type")
    parser.add_argument("--profile", choices=list(SCAN_PROFILES.keys()), default="quick",
                        help="Port scan profile")
    parser.add_argument("--wordlist", default=None, help="Wordlist for web enumeration")
    parser.add_argument("--community", default="public", help="SNMP community string")
    parser.add_argument("--tools", action="store_true", help="Show tool availability")
    args = parser.parse_args()

    recon = AegisRecon(mission_id=args.mission)

    if args.tools:
        recon.tool_status()
        sys.exit(0)

    try:
        if args.scan == "port":
            recon.port_scan(args.target, profile=args.profile)
        elif args.scan == "service":
            recon.service_enum(args.target)
        elif args.scan == "web":
            recon.web_enum(args.target, wordlist=args.wordlist)
        elif args.scan == "subdomain":
            recon.subdomain_enum(args.target)
        elif args.scan == "dns":
            recon.dns_enum(args.target)
        elif args.scan == "smb":
            recon.smb_enum(args.target)
        elif args.scan == "snmp":
            recon.snmp_enum(args.target, community=args.community)
        elif args.scan == "all":
            recon.port_scan(args.target, profile=args.profile)
            recon.service_enum(args.target)
            recon.dns_enum(args.target)
            recon.subdomain_enum(args.target)
            recon.smb_enum(args.target)
            recon.snmp_enum(args.target, community=args.community)
            if args.target.startswith("http"):
                recon.web_enum(args.target, wordlist=args.wordlist)

        recon.summary()
    finally:
        recon.close()
