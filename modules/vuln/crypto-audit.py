#!/usr/bin/env python3
"""AEGIS Cryptographic Audit Module
TLS version testing, cipher suite grading, certificate validation,
known TLS vulnerabilities, SSH crypto audit.
"""
import subprocess, json, os, sys, re, ssl, socket
from datetime import datetime

def _run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except:
        return "", "", 1

def _has(tool):
    return subprocess.run(["which", tool], capture_output=True).returncode == 0

CIPHER_GRADES = {
    "A": {"patterns": ["ECDHE.*AES.*GCM.*SHA384", "ECDHE.*AES.*GCM.*SHA256", "ECDHE.*CHACHA20.*POLY1305", "DHE.*AES.*GCM.*SHA384", "DHE.*AES.*GCM.*SHA256"], "desc": "Strong: AEAD with forward secrecy"},
    "B": {"patterns": ["ECDHE.*AES.*CBC.*SHA256", "ECDHE.*AES.*CBC.*SHA384", "DHE.*AES.*CBC.*SHA256"], "desc": "Good: Forward secrecy but CBC mode"},
    "C": {"patterns": ["AES.*GCM.*SHA384", "AES.*GCM.*SHA256", "AES256.*SHA256"], "desc": "Acceptable: Strong cipher but no forward secrecy"},
    "D": {"patterns": ["AES.*CBC.*SHA$", "AES128.*SHA$", "3DES", "CAMELLIA"], "desc": "Weak: Legacy ciphers, no forward secrecy"},
    "F": {"patterns": ["RC4", "DES(?!3)", "NULL", "EXPORT", "anon", "MD5"], "desc": "Insecure: Must be disabled immediately"},
}

TLS_VULNS = [
    {"name": "POODLE", "cve": "CVE-2014-3566", "affects": "SSLv3", "check": "SSLv3 support", "severity": "high", "fix": "Disable SSLv3"},
    {"name": "BEAST", "cve": "CVE-2011-3389", "affects": "TLS 1.0 with CBC", "check": "TLSv1.0 with CBC ciphers", "severity": "medium", "fix": "Disable TLS 1.0 or use only GCM/stream ciphers"},
    {"name": "SWEET32", "cve": "CVE-2016-2183", "affects": "3DES/Blowfish", "check": "64-bit block ciphers", "severity": "medium", "fix": "Disable 3DES and Blowfish ciphers"},
    {"name": "DROWN", "cve": "CVE-2016-0800", "affects": "SSLv2", "check": "SSLv2 support or shared key with SSLv2 server", "severity": "critical", "fix": "Disable SSLv2, ensure no key sharing"},
    {"name": "Heartbleed", "cve": "CVE-2014-0160", "affects": "OpenSSL 1.0.1-1.0.1f", "check": "OpenSSL version in Server header", "severity": "critical", "fix": "Upgrade OpenSSL to 1.0.1g+, reissue certificates"},
    {"name": "ROBOT", "cve": "CVE-2017-13099", "affects": "RSA key exchange", "check": "RSA key exchange ciphers", "severity": "high", "fix": "Disable RSA key exchange, use only ECDHE/DHE"},
    {"name": "CRIME", "cve": "CVE-2012-4929", "affects": "TLS compression", "check": "TLS compression enabled", "severity": "medium", "fix": "Disable TLS compression"},
    {"name": "LOGJAM", "cve": "CVE-2015-4000", "affects": "DHE with <=1024-bit", "check": "DH parameters < 2048 bits", "severity": "medium", "fix": "Use 2048+ bit DH parameters or ECDHE"},
    {"name": "FREAK", "cve": "CVE-2015-0204", "affects": "EXPORT ciphers", "check": "Export-grade ciphers", "severity": "high", "fix": "Disable all EXPORT ciphers"},
    {"name": "Lucky13", "cve": "CVE-2013-0169", "affects": "CBC ciphers", "check": "CBC mode ciphers", "severity": "low", "fix": "Prefer GCM/ChaCha20 over CBC"},
    {"name": "Raccoon", "cve": "CVE-2020-1968", "affects": "DH key exchange", "check": "DH key exchange without precomputation defense", "severity": "medium", "fix": "Prefer ECDHE, upgrade OpenSSL"},
    {"name": "Ticketbleed", "cve": "CVE-2016-9244", "affects": "F5 BIG-IP", "check": "F5 BIG-IP with session tickets", "severity": "high", "fix": "Apply F5 patch"},
]

class CryptoAudit:
    name = "Cryptographic Audit"
    description = "TLS version, cipher suite grading, certificate validation, known TLS vulnerabilities, SSH crypto"
    category = "vuln"
    mitre = ["T1557", "T1040", "T1556"]

    def __init__(self, target, options=None):
        self.target = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        self.options = options or {}
        self.findings = []
        self.port = int(options.get("port", 443)) if options else 443

    def _add(self, severity, title, detail, evidence="", mitre=""):
        self.findings.append({
            "severity": severity, "title": title, "detail": detail,
            "evidence": evidence, "mitre": mitre,
            "timestamp": datetime.utcnow().isoformat(), "module": self.name
        })

    def _confirm(self, action, confirm_fn):
        if confirm_fn:
            return confirm_fn(action)
        return True

    def _grade_cipher(self, cipher_name):
        for grade, info in CIPHER_GRADES.items():
            for pattern in info["patterns"]:
                if re.search(pattern, cipher_name, re.IGNORECASE):
                    return grade, info["desc"]
        return "C", "Unknown classification"

    def tls_version_check(self, confirm_fn=None):
        action = f"Test TLS protocol versions on {self.target}:{self.port}"
        if not self._confirm(action, confirm_fn):
            return
        versions = {
            "TLSv1.3": {"supported": False, "grade": "A"},
            "TLSv1.2": {"supported": False, "grade": "A"},
            "TLSv1.1": {"supported": False, "grade": "F", "deprecated": True},
            "TLSv1.0": {"supported": False, "grade": "F", "deprecated": True},
        }
        for ver_name in versions:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                if ver_name == "TLSv1.3":
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
                elif ver_name == "TLSv1.2":
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
                elif ver_name == "TLSv1.1":
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_1
                    ctx.maximum_version = ssl.TLSVersion.TLSv1_1
                elif ver_name == "TLSv1.0":
                    ctx.minimum_version = ssl.TLSVersion.TLSv1
                    ctx.maximum_version = ssl.TLSVersion.TLSv1
                with ctx.wrap_socket(socket.socket(), server_hostname=self.target) as s:
                    s.settimeout(5)
                    s.connect((self.target, self.port))
                    versions[ver_name]["supported"] = True
            except:
                pass

        detail = "Protocol version support:\n"
        issues = []
        for ver, info in versions.items():
            status = "SUPPORTED" if info["supported"] else "not supported"
            detail += f"  {ver:10s} {status}\n"
            if info["supported"] and info.get("deprecated"):
                issues.append(f"{ver} is deprecated and MUST be disabled (RFC 8996)")
        if versions["TLSv1.3"]["supported"]:
            detail += "\nTLS 1.3 support: excellent"
        elif versions["TLSv1.2"]["supported"]:
            detail += "\nTLS 1.2 is the minimum acceptable version"
        severity = "high" if issues else "info"
        self._add(severity, f"TLS protocol versions on {self.target}", detail + ("\n\nIssues:\n" + "\n".join(issues) if issues else ""), "", "T1557")

    def cipher_suite_audit(self, confirm_fn=None):
        if not _has("nmap"):
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(socket.socket(), server_hostname=self.target) as s:
                    s.settimeout(5)
                    s.connect((self.target, self.port))
                    cipher = s.cipher()
                    if cipher:
                        grade, desc = self._grade_cipher(cipher[0])
                        self._add("info" if grade in "AB" else "medium", f"Negotiated cipher: {cipher[0]} (Grade {grade})", f"Protocol: {cipher[1]}\nBits: {cipher[2]}\nClassification: {desc}", "", "T1557")
            except:
                pass
            return

        cmd = f"nmap --script ssl-enum-ciphers -p {self.port} {self.target}"
        if not self._confirm(f"Enumerate cipher suites: {cmd}", confirm_fn):
            return
        out, _, rc = _run(cmd, timeout=30)
        if rc != 0:
            return
        ciphers = re.findall(r'(TLS_\S+|SSL_\S+)', out)
        grades = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
        details = []
        for c in ciphers:
            grade, desc = self._grade_cipher(c)
            grades[grade] += 1
            details.append(f"  [{grade}] {c}")
        overall = "A" if grades["F"] == 0 and grades["D"] == 0 else "F" if grades["F"] > 0 else "D"
        severity = "critical" if overall == "F" else "high" if overall == "D" else "info"
        self._add(severity, f"Cipher suite grade: {overall} ({len(ciphers)} ciphers)", f"Grade distribution: A={grades['A']} B={grades['B']} C={grades['C']} D={grades['D']} F={grades['F']}\n\n" + "\n".join(details[:30]), "", "T1557")

    def certificate_check(self, confirm_fn=None):
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.target) as s:
                s.settimeout(10)
                s.connect((self.target, self.port))
                cert = s.getpeercert()
        except ssl.SSLCertVerificationError as e:
            self._add("high", f"Certificate verification failed", str(e), "", "T1557")
            return
        except Exception as e:
            self._add("info", f"Cannot connect to {self.target}:{self.port}", str(e))
            return

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")
        san = [e[1] for e in cert.get("subjectAltName", [])]
        serial = cert.get("serialNumber", "")

        issues = []
        try:
            from datetime import datetime as dt
            expiry = dt.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - dt.utcnow()).days
            if days_left < 0:
                issues.append(f"CRITICAL: Certificate EXPIRED {abs(days_left)} days ago")
            elif days_left < 30:
                issues.append(f"WARNING: Certificate expires in {days_left} days")
            elif days_left < 90:
                issues.append(f"Notice: Certificate expires in {days_left} days")
        except:
            pass

        cn = subject.get("commonName", "")
        if cn != self.target and f"*.{'.'.join(self.target.split('.')[1:])}" != cn:
            if self.target not in san:
                issues.append(f"Certificate CN ({cn}) does not match target ({self.target})")

        issuer_org = issuer.get("organizationName", "")
        if issuer_org == subject.get("organizationName", ""):
            issues.append("Self-signed certificate detected")

        detail = f"Subject: {subject.get('commonName', '?')}\n"
        detail += f"Issuer: {issuer_org}\n"
        detail += f"Valid: {not_before} to {not_after}\n"
        detail += f"SANs: {', '.join(san[:10])}\n"
        detail += f"Serial: {serial}\n"
        if issues:
            detail += "\nIssues:\n" + "\n".join(f"  - {i}" for i in issues)
        severity = "critical" if any("EXPIRED" in i for i in issues) else "high" if any("Self-signed" in i for i in issues) else "info"
        self._add(severity, f"Certificate: {cn}", detail, "", "T1557")

    def known_tls_vulns(self, confirm_fn=None):
        if _has("sslscan"):
            cmd = f"sslscan --no-colour {self.target}:{self.port}"
            if self._confirm(f"Run sslscan: {cmd}", confirm_fn):
                out, _, rc = _run(cmd, timeout=30)
                if rc == 0 and out:
                    for vuln in TLS_VULNS:
                        if vuln["name"].lower() in out.lower() or vuln["affects"].lower() in out.lower():
                            self._add(vuln["severity"], f"TLS vulnerability: {vuln['name']} ({vuln['cve']})", f"Affects: {vuln['affects']}\nFix: {vuln['fix']}", "", "T1557")

    def ssh_crypto_audit(self, confirm_fn=None):
        if not _has("ssh-keyscan"):
            return
        cmd = f"ssh-keyscan -t rsa,ecdsa,ed25519 {self.target} 2>/dev/null"
        if not self._confirm(f"SSH key scan: {cmd}", confirm_fn):
            return
        out, _, rc = _run(cmd, timeout=10)
        if not out:
            return
        issues = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                key_type = parts[1]
                if "ssh-rsa" in key_type:
                    issues.append("RSA host key (check key size >= 2048 bits)")
                elif "ssh-dss" in key_type:
                    issues.append("DSA host key (WEAK - should use Ed25519 or ECDSA)")
                elif "ecdsa" in key_type:
                    pass
                elif "ed25519" in key_type:
                    pass
        severity = "medium" if any("WEAK" in i for i in issues) else "info"
        self._add(severity, f"SSH host keys on {self.target}", "\n".join(out.splitlines()[:5]) + ("\n\nIssues:\n" + "\n".join(issues) if issues else ""), "", "T1557")

    def hsts_check(self, confirm_fn=None):
        cmd = f'curl -sS -D- -o /dev/null --max-time 5 -k "https://{self.target}"'
        out, _, rc = _run(cmd, timeout=8)
        if rc != 0:
            return
        hsts = ""
        for line in out.splitlines():
            if "strict-transport-security" in line.lower():
                hsts = line.split(":", 1)[1].strip()
                break
        if not hsts:
            self._add("medium", "HSTS not configured", f"https://{self.target} does not send Strict-Transport-Security header\nUsers can be downgraded to HTTP via MITM", "", "T1557")
        else:
            max_age = re.search(r'max-age=(\d+)', hsts)
            if max_age and int(max_age.group(1)) < 31536000:
                self._add("low", f"HSTS max-age too short ({max_age.group(1)}s)", "Recommend max-age=31536000 (1 year) with includeSubDomains", hsts, "T1557")
            elif "includesubdomains" not in hsts.lower():
                self._add("low", "HSTS missing includeSubDomains", f"Current: {hsts}", hsts, "T1557")

    def run(self, confirm_fn=None):
        print(f"\n[AEGIS] Cryptographic Audit: {self.target}:{self.port}")
        print("=" * 60)
        self.tls_version_check(confirm_fn)
        self.cipher_suite_audit(confirm_fn)
        self.certificate_check(confirm_fn)
        self.known_tls_vulns(confirm_fn)
        self.hsts_check(confirm_fn)
        if self.options.get("ssh", True):
            self.ssh_crypto_audit(confirm_fn)
        print(f"\n[AEGIS] Crypto audit complete: {len(self.findings)} findings")
        return self.findings

    def get_findings(self):
        return self.findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 crypto-audit.py <hostname> [port]")
        sys.exit(1)
    target = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    def confirm(action):
        resp = input(f"\n[?] {action}\n    Execute? [y/n]: ").strip().lower()
        return resp in ("y", "yes")
    mod = CryptoAudit(target, {"port": port})
    mod.run(confirm_fn=confirm)
    for f in mod.get_findings():
        sev = f["severity"].upper()
        color = {"critical": "\033[91m", "high": "\033[91m", "medium": "\033[93m", "low": "\033[94m", "info": "\033[90m"}.get(f["severity"], "")
        print(f"  {color}[{sev:8s}]\033[0m {f['title']}")
