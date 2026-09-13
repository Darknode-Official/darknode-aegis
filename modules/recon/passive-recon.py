#!/usr/bin/env python3
"""AEGIS Passive Reconnaissance Module
Gathers intelligence about a target without directly touching in-scope systems.
Uses WHOIS, DNS, Certificate Transparency, and public records.
"""
import subprocess, json, os, sys, re, socket, hashlib
from datetime import datetime

def _run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", 1
    except Exception as e:
        return "", str(e), 1

def _has(tool):
    return subprocess.run(["which", tool], capture_output=True).returncode == 0

class PassiveRecon:
    name = "Passive Reconnaissance"
    description = "Gather intelligence via WHOIS, DNS, CT logs, and public records without touching the target"
    category = "recon"
    mitre = ["T1590", "T1591", "T1592", "T1593", "T1594", "T1596"]

    def __init__(self, target, options=None):
        self.target = target
        self.options = options or {}
        self.findings = []
        self.actions = []
        self.subdomains = set()

    def _add(self, severity, title, detail, evidence="", mitre=""):
        self.findings.append({
            "severity": severity, "title": title, "detail": detail,
            "evidence": evidence, "mitre": mitre,
            "timestamp": datetime.utcnow().isoformat(), "module": self.name
        })

    def _confirm(self, action, confirm_fn):
        self.actions.append(action)
        if confirm_fn:
            return confirm_fn(action)
        return True

    def whois_lookup(self, confirm_fn=None):
        if not _has("whois"):
            self._add("info", "WHOIS tool not installed", "Install with: sudo apt install whois")
            return
        cmd = f"whois {self.target}"
        if not self._confirm(f"Run WHOIS lookup: {cmd}", confirm_fn):
            return
        out, err, rc = _run(cmd, timeout=15)
        if rc != 0 or not out:
            self._add("info", "WHOIS lookup failed", err or "No output")
            return
        info = {}
        for line in out.splitlines():
            line = line.strip()
            llow = line.lower()
            if "registrar:" in llow:
                info["registrar"] = line.split(":", 1)[1].strip()
            elif "creation date:" in llow or "created:" in llow:
                info["created"] = line.split(":", 1)[1].strip()
            elif "expir" in llow and "date" in llow:
                info["expires"] = line.split(":", 1)[1].strip()
            elif "name server:" in llow or "nserver:" in llow:
                ns = line.split(":", 1)[1].strip().lower()
                info.setdefault("nameservers", []).append(ns)
            elif "registrant org" in llow:
                info["org"] = line.split(":", 1)[1].strip()
            elif "registrant country" in llow:
                info["country"] = line.split(":", 1)[1].strip()
        self._add("info", f"WHOIS data for {self.target}", json.dumps(info, indent=2), out[:2000], "T1596.002")

    def dns_enumeration(self, confirm_fn=None):
        if not _has("dig"):
            self._add("info", "dig not installed", "Install with: sudo apt install dnsutils")
            return
        record_types = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "SRV"]
        results = {}
        for rtype in record_types:
            cmd = f"dig +short {self.target} {rtype}"
            if not self._confirm(f"DNS lookup: {cmd}", confirm_fn):
                continue
            out, _, rc = _run(cmd, timeout=10)
            if out:
                records = [line.strip() for line in out.splitlines() if line.strip()]
                results[rtype] = records
                if rtype == "A":
                    for ip in records:
                        self._add("info", f"A record: {self.target} -> {ip}", f"IPv4 address resolved", ip, "T1590.002")
                elif rtype == "MX":
                    for mx in records:
                        self._add("info", f"MX record: {mx}", "Mail server discovered", mx, "T1590.002")
                elif rtype == "NS":
                    for ns in records:
                        self._add("info", f"Nameserver: {ns}", "Authoritative DNS server", ns, "T1590.002")
                elif rtype == "TXT":
                    for txt in records:
                        if "v=spf1" in txt:
                            self._analyze_spf(txt)
                        elif "v=DMARC1" in txt:
                            self._analyze_dmarc(txt)
                        elif "v=DKIM1" in txt:
                            self._add("info", "DKIM record found", txt, txt, "T1590.002")
                        else:
                            self._add("info", f"TXT record", txt, txt, "T1590.002")
        self._add("info", f"DNS enumeration complete for {self.target}", json.dumps(results, indent=2))

    def _analyze_spf(self, record):
        issues = []
        if "+all" in record:
            issues.append("SPF uses +all (allows ANY server to send email) -- CRITICAL misconfiguration")
        elif "~all" in record:
            issues.append("SPF uses ~all (softfail) instead of -all (hardfail) -- emails from unauthorized servers may still be delivered")
        elif "?all" in record:
            issues.append("SPF uses ?all (neutral) -- provides no protection")
        if not issues and "-all" not in record:
            issues.append("SPF record does not end with -all")
        includes = re.findall(r'include:(\S+)', record)
        if len(includes) > 8:
            issues.append(f"SPF has {len(includes)} includes (max 10 DNS lookups allowed)")
        severity = "high" if any("CRITICAL" in i for i in issues) else "medium" if issues else "info"
        self._add(severity, "SPF record analysis", "\n".join(issues) if issues else "SPF properly configured with -all", record, "T1590.002")

    def _analyze_dmarc(self, record):
        issues = []
        if "p=none" in record:
            issues.append("DMARC policy is 'none' -- no enforcement, only monitoring")
        elif "p=quarantine" in record:
            issues.append("DMARC policy is 'quarantine' -- good but 'reject' is stronger")
        if "pct=" in record:
            pct = re.search(r'pct=(\d+)', record)
            if pct and int(pct.group(1)) < 100:
                issues.append(f"DMARC only applies to {pct.group(1)}% of messages")
        if "rua=" not in record:
            issues.append("No DMARC aggregate report address (rua=) configured")
        severity = "medium" if issues else "info"
        self._add(severity, "DMARC record analysis", "\n".join(issues) if issues else "DMARC properly configured", record, "T1590.002")

    def dns_zone_transfer(self, confirm_fn=None):
        if not _has("dig"):
            return
        ns_out, _, _ = _run(f"dig +short {self.target} NS", timeout=10)
        if not ns_out:
            return
        for ns in ns_out.splitlines():
            ns = ns.strip().rstrip(".")
            if not ns:
                continue
            cmd = f"dig @{ns} {self.target} AXFR"
            if not self._confirm(f"Attempt zone transfer: {cmd}", confirm_fn):
                continue
            out, _, rc = _run(cmd, timeout=15)
            if "Transfer failed" in out or "REFUSED" in out or not out:
                self._add("info", f"Zone transfer denied by {ns}", "AXFR refused -- this is correct behavior")
            else:
                records = [l for l in out.splitlines() if l.strip() and not l.startswith(";")]
                if len(records) > 3:
                    self._add("critical", f"Zone transfer SUCCESSFUL from {ns}", f"Entire DNS zone exposed -- {len(records)} records leaked", out[:3000], "T1590.002")
                    for line in records:
                        parts = line.split()
                        if len(parts) >= 1 and self.target in parts[0]:
                            sub = parts[0].rstrip(".")
                            self.subdomains.add(sub)

    def ct_lookup(self, confirm_fn=None):
        cmd = f'curl -s "https://crt.sh/?q=%25.{self.target}&output=json" --max-time 15'
        if not self._confirm(f"Query Certificate Transparency logs: {cmd}", confirm_fn):
            return
        out, err, rc = _run(cmd, timeout=20)
        if rc != 0 or not out:
            self._add("info", "CT log lookup failed or offline", "crt.sh may be unavailable -- try again later")
            return
        try:
            certs = json.loads(out)
        except json.JSONDecodeError:
            self._add("info", "CT log response invalid", out[:500])
            return
        names = set()
        for cert in certs:
            cn = cert.get("common_name", "")
            if cn and "*" not in cn:
                names.add(cn.lower())
            san = cert.get("name_value", "")
            for n in san.split("\n"):
                n = n.strip().lower()
                if n and "*" not in n and self.target in n:
                    names.add(n)
        self.subdomains.update(names)
        self._add("info", f"CT logs: {len(names)} unique names found", "\n".join(sorted(names)[:100]), f"Source: crt.sh, total certs: {len(certs)}", "T1596.002")

    def reverse_dns(self, confirm_fn=None):
        out, _, _ = _run(f"dig +short {self.target} A", timeout=10)
        if not out:
            return
        for ip in out.splitlines():
            ip = ip.strip()
            if not re.match(r'\d+\.\d+\.\d+\.\d+', ip):
                continue
            cmd = f"dig +short -x {ip}"
            if not self._confirm(f"Reverse DNS lookup: {cmd}", confirm_fn):
                continue
            rev, _, _ = _run(cmd, timeout=10)
            if rev:
                self._add("info", f"Reverse DNS: {ip} -> {rev.strip()}", "PTR record found", rev.strip(), "T1590.002")

    def asn_lookup(self, confirm_fn=None):
        out, _, _ = _run(f"dig +short {self.target} A", timeout=10)
        if not out:
            return
        ip = out.splitlines()[0].strip()
        if not re.match(r'\d+\.\d+\.\d+\.\d+', ip):
            return
        cmd = f'curl -s "https://ipinfo.io/{ip}/json" --max-time 10'
        if not self._confirm(f"ASN lookup: {cmd}", confirm_fn):
            return
        out, _, rc = _run(cmd, timeout=15)
        if rc == 0 and out:
            try:
                data = json.loads(out)
                org = data.get("org", "unknown")
                asn = org.split()[0] if org else "unknown"
                self._add("info", f"ASN: {org}", f"IP: {ip}, City: {data.get('city', '?')}, Region: {data.get('region', '?')}, Country: {data.get('country', '?')}", out, "T1590.001")
            except json.JSONDecodeError:
                pass

    def generate_dorks(self):
        dorks = [
            f'site:{self.target}',
            f'site:{self.target} filetype:pdf',
            f'site:{self.target} filetype:doc OR filetype:docx OR filetype:xls',
            f'site:{self.target} filetype:sql OR filetype:bak OR filetype:log',
            f'site:{self.target} filetype:env OR filetype:yml OR filetype:yaml OR filetype:json',
            f'site:{self.target} inurl:admin OR inurl:login OR inurl:dashboard',
            f'site:{self.target} inurl:api OR inurl:swagger OR inurl:graphql',
            f'site:{self.target} intitle:"index of"',
            f'site:{self.target} intext:"password" OR intext:"secret" OR intext:"api_key"',
            f'site:{self.target} ext:php inurl:config',
            f'site:{self.target} inurl:wp-content OR inurl:wp-includes',
            f'site:{self.target} inurl:.git',
            f'"{self.target}" filetype:pdf',
            f'"{self.target}" site:github.com',
            f'"{self.target}" site:pastebin.com',
            f'"{self.target}" site:trello.com',
            f'"{self.target}" intext:password',
            f'intitle:"index of" "{self.target}"',
            f'inurl:"{self.target}" filetype:log',
            f'"{self.target}" ext:sql | ext:dbf | ext:mdb',
        ]
        self._add("info", f"Google dorks generated for {self.target}", "\n".join(dorks), f"{len(dorks)} dorks ready for manual search", "T1593.002")

    def email_format_detection(self):
        formats = [
            {"pattern": "first.last", "example": f"john.doe@{self.target}"},
            {"pattern": "flast", "example": f"jdoe@{self.target}"},
            {"pattern": "firstl", "example": f"johnd@{self.target}"},
            {"pattern": "first", "example": f"john@{self.target}"},
            {"pattern": "last.first", "example": f"doe.john@{self.target}"},
            {"pattern": "first_last", "example": f"john_doe@{self.target}"},
            {"pattern": "first-last", "example": f"john-doe@{self.target}"},
            {"pattern": "flastname", "example": f"jdoe@{self.target}"},
        ]
        detail = "Possible email formats (verify with OSINT):\n"
        for f in formats:
            detail += f"  {f['pattern']:20s} {f['example']}\n"
        self._add("info", f"Email format candidates for {self.target}", detail, "", "T1589.002")

    def run(self, confirm_fn=None):
        print(f"\n[AEGIS] Passive Reconnaissance: {self.target}")
        print("=" * 60)
        self.whois_lookup(confirm_fn)
        self.dns_enumeration(confirm_fn)
        self.dns_zone_transfer(confirm_fn)
        self.ct_lookup(confirm_fn)
        self.reverse_dns(confirm_fn)
        self.asn_lookup(confirm_fn)
        self.generate_dorks()
        self.email_format_detection()
        if self.subdomains:
            self._add("info", f"Total subdomains discovered: {len(self.subdomains)}", "\n".join(sorted(self.subdomains)[:200]))
        print(f"\n[AEGIS] Passive recon complete: {len(self.findings)} findings")
        return self.findings

    def get_findings(self):
        return self.findings

    def get_subdomains(self):
        return sorted(self.subdomains)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 passive-recon.py <domain>")
        sys.exit(1)
    target = sys.argv[1]
    def confirm(action):
        resp = input(f"\n[?] {action}\n    Execute? [y/n]: ").strip().lower()
        return resp in ("y", "yes")
    mod = PassiveRecon(target)
    findings = mod.run(confirm_fn=confirm)
    print(f"\n{'='*60}")
    print(f"FINDINGS SUMMARY: {len(findings)}")
    print(f"{'='*60}")
    for f in findings:
        sev = f["severity"].upper()
        color = {"critical": "\033[91m", "high": "\033[91m", "medium": "\033[93m", "low": "\033[94m", "info": "\033[90m"}.get(f["severity"], "")
        print(f"  {color}[{sev:8s}]\033[0m {f['title']}")
