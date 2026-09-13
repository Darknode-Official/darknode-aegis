#!/usr/bin/env python3
"""DNS attack and defense operations — enumeration, tunneling detection, DGA analysis, DNSSEC audit"""
import subprocess
import os
import sys
import re
import math
import json
from datetime import datetime
from collections import Counter

class DNSWarfare:
    name = "DNS Warfare"
    description = "DNS attack and defense operations — enumeration, tunneling detection, DGA analysis, sinkholing, RPZ rules"
    category = "network"
    mitre = ["T1071.004", "T1568.002", "T1583.001", "T1048.003"]

    # Suspicious TLDs commonly used in attacks
    SUSPICIOUS_TLDS = [
        ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".club", ".online", ".site",
        ".wang", ".win", ".bid", ".stream", ".trade", ".date", ".faith", ".review",
        ".science", ".party", ".cricket", ".racing", ".accountant", ".download",
        ".loan", ".men", ".work", ".click", ".link", ".space", ".host", ".press",
        ".pw", ".buzz", ".surf", ".monster", ".quest", ".rest", ".cyou", ".icu",
        ".cam", ".fit", ".beauty", ".hair", ".skin", ".makeup", ".boats", ".sbs",
        ".bond", ".cfd", ".mom", ".yachts", ".zip", ".mov", ".dad", ".phd",
        ".prof", ".foo", ".nexus", ".lol", ".rip", ".wtf", ".fail", ".gripe",
        ".country", ".kim", ".xxx", ".adult", ".porn", ".sex", ".sexy", ".webcam",
        ".su", ".to", ".cc", ".ws", ".bz", ".nu", ".in", ".cm", ".co.cc",
        ".onion", ".bit", ".emc", ".coin", ".bazar", ".lib",
        ".duckdns.org", ".no-ip.org", ".ddns.net", ".hopto.org", ".zapto.org",
        ".sytes.net", ".serveblog.net", ".redirectme.net", ".bounceme.net",
        ".myftp.biz", ".myftp.org", ".serveftp.com", ".portmap.io",
        ".ngrok.io", ".pagekite.me", ".localtunnel.me", ".serveo.net",
        ".trycloudflare.com",
    ]

    # Known DGA patterns from real malware families
    DGA_PATTERNS = [
        {"family": "Conficker", "description": "Time-based DGA generating 250 domains/day across 5 TLDs", "pattern": "8-11 char lowercase alpha, rotating .com/.net/.org/.info/.biz", "entropy_range": [3.5, 4.2], "example": "aklserbjf.com"},
        {"family": "CryptoLocker", "description": "1000 domains/day, 12-15 chars", "pattern": "12-15 char lowercase alpha, 7 TLDs", "entropy_range": [3.8, 4.5], "example": "qlcmekjhrtbnv.org"},
        {"family": "Necurs", "description": "2048 domains per cycle, mixed alpha", "pattern": "7-18 char lowercase alpha, .com/.net/.org/.pw/.top/.biz", "entropy_range": [3.6, 4.3], "example": "pxhkwvmt.pw"},
        {"family": "Emotet", "description": "Wordlist-based DGA combining dictionary words", "pattern": "word+word+number, .com/.net", "entropy_range": [2.8, 3.5], "example": "greentable42.com"},
        {"family": "Ramnit", "description": "Seed-based DGA using current date", "pattern": "8-19 char alphanumeric, .com/.eu/.bid", "entropy_range": [3.4, 4.1], "example": "tjm3k8nqp2.eu"},
        {"family": "Murofet/Zeus", "description": "1000 domains per day based on date seed", "pattern": "15-25 char lowercase alpha, .com/.net/.org/.info/.biz", "entropy_range": [3.7, 4.4], "example": "qwertasgdfzxcvbnm.biz"},
        {"family": "Bamital", "description": "Rotating DGA with short domain names", "pattern": "6-10 char lowercase alpha, .com/.net", "entropy_range": [3.3, 4.0], "example": "bkmrxh.com"},
        {"family": "Tinba", "description": "Short DGA domains with numeric components", "pattern": "6-12 char alphanumeric, .com", "entropy_range": [3.2, 3.9], "example": "k4m8v2.com"},
        {"family": "Pushdo", "description": "Date-seeded pseudo-random domains", "pattern": "7-11 char lowercase alpha, random TLD from set of 10", "entropy_range": [3.5, 4.2], "example": "hqwmntkb.info"},
        {"family": "QakBot", "description": "Pseudo-random domains with consonant-heavy patterns", "pattern": "8-25 char lowercase alpha, .com/.net/.org", "entropy_range": [3.6, 4.3], "example": "xghjkmnpqrstvw.net"},
    ]

    DNS_RECORD_TYPES = [
        ("A", "IPv4 address"),
        ("AAAA", "IPv6 address"),
        ("CNAME", "Canonical name / alias"),
        ("MX", "Mail exchange server"),
        ("NS", "Authoritative nameserver"),
        ("TXT", "Text records (SPF, DKIM, DMARC, verification)"),
        ("SOA", "Start of authority"),
        ("SRV", "Service locator"),
        ("PTR", "Reverse DNS pointer"),
        ("CAA", "Certificate Authority Authorization"),
        ("DNSKEY", "DNSSEC public key"),
        ("DS", "DNSSEC Delegation Signer"),
        ("RRSIG", "DNSSEC signature"),
        ("NSEC", "DNSSEC next secure record"),
        ("NSEC3", "DNSSEC hashed denial of existence"),
        ("TLSA", "TLS certificate association (DANE)"),
        ("NAPTR", "Naming Authority Pointer"),
        ("HINFO", "Host information"),
        ("LOC", "Geographic location"),
        ("SSHFP", "SSH fingerprint"),
    ]

    def __init__(self, target, options=None):
        self.target = target
        self.options = options or {}
        self.findings = []
        self.actions = []
        self.has_dig = self._check_tool("dig")
        self.has_nslookup = self._check_tool("nslookup")
        self.has_host = self._check_tool("host")

    def _check_tool(self, name):
        try:
            subprocess.run(["which", name], capture_output=True, timeout=5)
            return True
        except Exception:
            return False

    def _run_cmd(self, cmd, timeout=30):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.stdout.strip(), r.returncode
        except subprocess.TimeoutExpired:
            return "[TIMEOUT]", 1
        except Exception as e:
            return str(e), 1

    def _add_finding(self, severity, title, detail, mitre=""):
        self.findings.append({
            "severity": severity,
            "title": title,
            "detail": detail,
            "mitre": mitre,
            "module": self.name,
            "timestamp": datetime.now().isoformat(),
        })

    def _confirm(self, action, confirm_fn):
        if confirm_fn:
            return confirm_fn(action)
        return True

    def run(self, confirm_fn=None):
        print(f"\n[DNS-WARFARE] Target: {self.target}")
        print("=" * 60)
        mode = self.options.get("mode", "full")
        if mode in ("enum", "full"):
            self.enumerate_dns(confirm_fn)
        if mode in ("zone", "full"):
            self.test_zone_transfer(confirm_fn)
        if mode in ("security", "full"):
            self.audit_email_security()
            self.audit_dnssec()
        if mode in ("tunnel", "full"):
            self.detect_dns_tunneling()
        if mode in ("dga", "full"):
            self.detect_dga()
        return self.findings

    def enumerate_dns(self, confirm_fn=None):
        if not self.has_dig:
            print("[!] dig not available. Install with: sudo apt install dnsutils")
            return
        if not self._confirm(f"Enumerate DNS records for {self.target} using dig", confirm_fn):
            return
        print(f"\n[*] Enumerating DNS records for {self.target}...")
        for rtype, desc in self.DNS_RECORD_TYPES[:12]:
            out, rc = self._run_cmd(["dig", "+short", self.target, rtype])
            if out and rc == 0:
                print(f"  [{rtype:6s}] {out}")
                self.actions.append({"cmd": f"dig +short {self.target} {rtype}", "output": out})
                if rtype == "TXT":
                    self._analyze_txt_records(out)
                elif rtype == "MX":
                    self._analyze_mx_records(out)
                elif rtype == "NS":
                    for ns in out.split("\n"):
                        ns = ns.strip().rstrip(".")
                        if ns:
                            ns_ip, _ = self._run_cmd(["dig", "+short", ns, "A"])
                            if ns_ip:
                                print(f"         -> {ns} ({ns_ip.split(chr(10))[0]})")

    def _analyze_txt_records(self, txt_output):
        lines = txt_output.split("\n")
        has_spf = any("v=spf1" in l for l in lines)
        has_dmarc = any("v=DMARC1" in l for l in lines)
        has_dkim = any("v=DKIM1" in l for l in lines)
        if not has_spf:
            self._add_finding("HIGH", "Missing SPF record", f"No SPF record found for {self.target}. Email spoofing is possible.", "T1566.001")
        else:
            for l in lines:
                if "v=spf1" in l:
                    if "+all" in l:
                        self._add_finding("CRITICAL", "SPF set to +all (pass everything)", f"SPF: {l} — anyone can send email as {self.target}", "T1566.001")
                    elif "~all" in l:
                        self._add_finding("MEDIUM", "SPF uses soft fail (~all)", f"SPF: {l} — soft fail allows spoofed emails to be delivered", "T1566.001")
                    elif "-all" in l:
                        print(f"  [OK] SPF configured with hard fail (-all)")
        if not has_dmarc:
            dmarc_out, _ = self._run_cmd(["dig", "+short", f"_dmarc.{self.target}", "TXT"])
            if not dmarc_out or "v=DMARC1" not in dmarc_out:
                self._add_finding("HIGH", "Missing DMARC record", f"No DMARC record for {self.target}. No policy for handling spoofed emails.", "T1566.001")
            else:
                self._analyze_dmarc(dmarc_out)
        else:
            for l in lines:
                if "v=DMARC1" in l:
                    self._analyze_dmarc(l)

    def _analyze_dmarc(self, dmarc):
        if "p=none" in dmarc:
            self._add_finding("MEDIUM", "DMARC policy is 'none' (monitor only)", f"DMARC: {dmarc} — spoofed emails are delivered normally", "T1566.001")
        elif "p=quarantine" in dmarc:
            print(f"  [OK] DMARC quarantine policy in place")
        elif "p=reject" in dmarc:
            print(f"  [OK] DMARC reject policy in place (strongest)")

    def _analyze_mx_records(self, mx_output):
        lines = mx_output.strip().split("\n")
        for line in lines:
            parts = line.strip().split()
            if len(parts) >= 2:
                mx_host = parts[-1].rstrip(".")
                if any(provider in mx_host.lower() for provider in ["google", "outlook", "protonmail", "zoho", "mimecast", "barracuda"]):
                    print(f"  [INFO] Mail provider detected: {mx_host}")

    def test_zone_transfer(self, confirm_fn=None):
        if not self.has_dig:
            return
        if not self._confirm(f"Attempt DNS zone transfer (AXFR) against {self.target} nameservers", confirm_fn):
            return
        print(f"\n[*] Testing zone transfer for {self.target}...")
        ns_out, _ = self._run_cmd(["dig", "+short", self.target, "NS"])
        if not ns_out:
            print("  [!] No nameservers found")
            return
        for ns in ns_out.strip().split("\n"):
            ns = ns.strip().rstrip(".")
            if not ns:
                continue
            print(f"  [*] Trying AXFR against {ns}...")
            axfr_out, rc = self._run_cmd(["dig", f"@{ns}", self.target, "AXFR", "+noall", "+answer"], timeout=15)
            if axfr_out and "XFR size" in axfr_out:
                record_count = len(axfr_out.strip().split("\n"))
                self._add_finding("CRITICAL", f"Zone transfer allowed on {ns}", f"Full zone transfer succeeded — {record_count} records exposed.\nThis reveals the entire DNS zone including internal hostnames.\n\nOutput (first 20 lines):\n{chr(10).join(axfr_out.split(chr(10))[:20])}", "T1590.002")
            else:
                print(f"    [-] Transfer refused (good)")

    def audit_dnssec(self):
        if not self.has_dig:
            return
        print(f"\n[*] Auditing DNSSEC for {self.target}...")
        dnskey_out, _ = self._run_cmd(["dig", "+short", self.target, "DNSKEY"])
        ds_out, _ = self._run_cmd(["dig", "+short", self.target, "DS"])
        rrsig_out, _ = self._run_cmd(["dig", "+short", self.target, "RRSIG"])
        if not dnskey_out and not ds_out:
            self._add_finding("MEDIUM", "DNSSEC not enabled", f"No DNSKEY or DS records found for {self.target}. DNS responses can be spoofed via cache poisoning.", "T1557.004")
        else:
            print(f"  [OK] DNSSEC appears to be enabled")
            if dnskey_out:
                keys = dnskey_out.strip().split("\n")
                print(f"  [INFO] {len(keys)} DNSKEY record(s) found")
            if rrsig_out:
                print(f"  [OK] RRSIG records present (responses are signed)")

    def audit_email_security(self):
        print(f"\n[*] Auditing email security for {self.target}...")
        if self.has_dig:
            dkim_out, _ = self._run_cmd(["dig", "+short", f"default._domainkey.{self.target}", "TXT"])
            if not dkim_out:
                selectors = ["default", "google", "selector1", "selector2", "dkim", "mail", "k1", "s1", "s2"]
                found = False
                for sel in selectors:
                    out, _ = self._run_cmd(["dig", "+short", f"{sel}._domainkey.{self.target}", "TXT"])
                    if out and "v=DKIM1" in out:
                        print(f"  [OK] DKIM found with selector: {sel}")
                        found = True
                        break
                if not found:
                    self._add_finding("MEDIUM", "No DKIM record found", f"Checked {len(selectors)} common selectors for {self.target}. DKIM signing may not be configured.", "T1566.001")

    def detect_dns_tunneling(self):
        """Analyze DNS query data for tunneling indicators"""
        print(f"\n[*] DNS tunneling detection reference")
        print("  Indicators of DNS tunneling:")
        print("    - Query names with high entropy (>3.5 bits/char)")
        print("    - Unusually long subdomain labels (>30 chars)")
        print("    - High volume of TXT/NULL/CNAME queries to single domain")
        print("    - Regular query intervals (beaconing)")
        print("    - Base64/hex-encoded subdomain labels")
        print("    - New or low-reputation authoritative nameservers")
        print("")
        print("  Detection queries:")
        print("    Splunk: index=dns | eval len=len(query) | where len>50 | stats count by query src_ip")
        print("    ELK:    dns.question.name.length > 50 AND dns.question.type: (TXT OR NULL)")
        print("")
        print("  Tools: iodine, dnscat2, dns2tcp, DNSExfiltrator")
        print("  Defense: DNS firewall (RPZ), query length limits, NXDOMAIN rate limiting")

    @staticmethod
    def calculate_entropy(s):
        if not s:
            return 0.0
        freq = Counter(s)
        length = len(s)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    def detect_dga(self):
        """DGA detection reference and analyzer"""
        print(f"\n[*] Domain Generation Algorithm (DGA) detection")
        print("  Known DGA families and patterns:")
        for i, dga in enumerate(self.DGA_PATTERNS, 1):
            print(f"\n  [{i}] {dga['family']}")
            print(f"      {dga['description']}")
            print(f"      Pattern: {dga['pattern']}")
            print(f"      Entropy range: {dga['entropy_range'][0]:.1f} - {dga['entropy_range'][1]:.1f} bits/char")
            print(f"      Example: {dga['example']}")
        print("\n  Detection methodology:")
        print("    1. Extract domain names from DNS query logs")
        print("    2. Calculate Shannon entropy of each domain label")
        print("    3. Flag domains with entropy > 3.5 bits/char")
        print("    4. Check against known DGA patterns (length, charset, TLD)")
        print("    5. Cluster similar domains — DGA produces many similar-looking names")
        print("    6. Check domain age — DGA domains are typically < 30 days old")
        print("    7. Check registration patterns — bulk registrations from same registrar")

    def analyze_domain(self, domain):
        """Analyze a single domain for DGA characteristics"""
        label = domain.split(".")[0] if "." in domain else domain
        entropy = self.calculate_entropy(label)
        length = len(label)
        consonant_ratio = sum(1 for c in label.lower() if c in "bcdfghjklmnpqrstvwxyz") / max(len(label), 1)
        digit_ratio = sum(1 for c in label if c.isdigit()) / max(len(label), 1)
        tld = "." + domain.split(".")[-1] if "." in domain else ""
        suspicious_tld = tld.lower() in [t.lower() for t in self.SUSPICIOUS_TLDS]
        score = 0
        reasons = []
        if entropy > 3.5:
            score += 30
            reasons.append(f"High entropy: {entropy:.2f}")
        if length > 15:
            score += 15
            reasons.append(f"Long label: {length} chars")
        if consonant_ratio > 0.7:
            score += 20
            reasons.append(f"High consonant ratio: {consonant_ratio:.2f}")
        if suspicious_tld:
            score += 20
            reasons.append(f"Suspicious TLD: {tld}")
        if digit_ratio > 0.3 and digit_ratio < 1.0:
            score += 10
            reasons.append(f"Mixed alphanumeric: {digit_ratio:.2f} digits")
        for dga in self.DGA_PATTERNS:
            if dga["entropy_range"][0] <= entropy <= dga["entropy_range"][1]:
                if dga["entropy_range"][0] <= entropy <= dga["entropy_range"][1]:
                    score += 5
                    reasons.append(f"Matches {dga['family']} entropy range")
                    break
        return {
            "domain": domain,
            "entropy": entropy,
            "length": length,
            "consonant_ratio": consonant_ratio,
            "suspicious_tld": suspicious_tld,
            "dga_score": min(score, 100),
            "verdict": "LIKELY DGA" if score >= 50 else "SUSPICIOUS" if score >= 30 else "PROBABLY LEGIT",
            "reasons": reasons,
        }

    def generate_rpz_rules(self, domains):
        """Generate DNS Response Policy Zone rules for blocking domains"""
        rules = []
        rules.append("; DNS RPZ zone file for blocking malicious domains")
        rules.append(f"; Generated by AEGIS DNS Warfare module on {datetime.now().isoformat()}")
        rules.append(f"; {len(domains)} domain(s)")
        rules.append("")
        rules.append("$TTL 300")
        rules.append(f"@ IN SOA localhost. admin.localhost. ({datetime.now().strftime('%Y%m%d')}01 3600 600 86400 300)")
        rules.append("  IN NS  localhost.")
        rules.append("")
        for domain in domains:
            d = domain.rstrip(".")
            rules.append(f"{d} CNAME .  ; Block domain")
            rules.append(f"*.{d} CNAME .  ; Block all subdomains")
        return "\n".join(rules)

    def generate_sinkhole_config(self, domains):
        """Generate DNS sinkhole configurations"""
        configs = {}
        bind_zones = []
        for d in domains:
            d = d.rstrip(".")
            bind_zones.append(f'zone "{d}" {{ type master; file "/etc/bind/db.sinkhole"; }};')
        configs["bind9"] = "\n".join(bind_zones)
        unbound_local = []
        for d in domains:
            d = d.rstrip(".")
            unbound_local.append(f'local-zone: "{d}" redirect')
            unbound_local.append(f'local-data: "{d} A 127.0.0.1"')
        configs["unbound"] = "\n".join(unbound_local)
        dnsmasq_conf = []
        for d in domains:
            d = d.rstrip(".")
            dnsmasq_conf.append(f"address=/{d}/127.0.0.1")
        configs["dnsmasq"] = "\n".join(dnsmasq_conf)
        hosts_entries = []
        for d in domains:
            d = d.rstrip(".")
            hosts_entries.append(f"127.0.0.1 {d}")
            hosts_entries.append(f"127.0.0.1 www.{d}")
        configs["hosts_file"] = "\n".join(hosts_entries)
        return configs

    def get_findings(self):
        return self.findings

    def get_actions(self):
        return self.actions


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    mode = sys.argv[2] if len(sys.argv) > 2 else "full"
    dns = DNSWarfare(target, {"mode": mode})
    confirm = lambda action: input(f"\n[?] {action}? [y/N] ").strip().lower() == "y"
    findings = dns.run(confirm_fn=confirm)
    if findings:
        print(f"\n{'='*60}")
        print(f"[DNS-WARFARE] {len(findings)} finding(s):")
        for f in findings:
            print(f"  [{f['severity']:8s}] {f['title']}")
    else:
        print("\n[DNS-WARFARE] No findings.")

    if len(sys.argv) > 3 and sys.argv[3] == "--analyze":
        domains = sys.argv[4:]
        print(f"\n[*] Analyzing {len(domains)} domain(s) for DGA:")
        for d in domains:
            result = dns.analyze_domain(d)
            print(f"\n  {result['domain']}: {result['verdict']} (score: {result['dga_score']})")
            print(f"    Entropy: {result['entropy']:.2f}, Length: {result['length']}, Consonants: {result['consonant_ratio']:.2f}")
            for r in result["reasons"]:
                print(f"    - {r}")
