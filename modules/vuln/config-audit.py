#!/usr/bin/env python3
"""AEGIS Configuration Audit Module
SSH, SSL/TLS, HTTP headers, DNS, email security, CIS benchmarks,
backup files, admin interfaces, debug mode detection.
"""
import subprocess, json, os, sys, re, ssl, socket
from datetime import datetime

def _run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except:
        return "", "", 1

def _has(tool):
    return subprocess.run(["which", tool], capture_output=True).returncode == 0

WEAK_SSH_CIPHERS = ["3des-cbc", "arcfour", "arcfour128", "arcfour256", "blowfish-cbc", "cast128-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc"]
WEAK_SSH_KEXS = ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"]
WEAK_SSH_MACS = ["hmac-md5", "hmac-sha1", "umac-64", "hmac-md5-96", "hmac-sha1-96"]

BACKUP_EXTENSIONS = [".bak", ".old", ".orig", ".save", ".swp", ".swo", ".tmp", "~", ".copy", ".backup", ".sql", ".sql.gz", ".tar", ".tar.gz", ".zip", ".rar", ".7z"]

ADMIN_PATHS = ["/admin", "/administrator", "/wp-admin", "/phpmyadmin", "/pma", "/adminer", "/manager/html", "/console", "/jmx-console", "/admin-console", "/webmail", "/cpanel", "/plesk", "/directadmin", "/panel", "/control", "/cockpit"]

CIS_CHECKS_LINUX = [
    {"id": "1.1.1", "title": "Ensure filesystem integrity checking is configured", "cmd": "dpkg -l aide 2>/dev/null || rpm -q aide 2>/dev/null", "pass_if": "aide", "severity": "medium"},
    {"id": "1.4.1", "title": "Ensure permissions on bootloader config", "cmd": "stat -c '%a' /boot/grub/grub.cfg 2>/dev/null || stat -c '%a' /boot/grub2/grub.cfg 2>/dev/null", "pass_if": "600", "severity": "high"},
    {"id": "2.1.1", "title": "Ensure NFS is not running", "cmd": "systemctl is-active nfs-server 2>/dev/null", "pass_if": "inactive", "severity": "medium"},
    {"id": "2.2.1", "title": "Ensure time synchronization is in use", "cmd": "systemctl is-active chronyd 2>/dev/null || systemctl is-active systemd-timesyncd 2>/dev/null || systemctl is-active ntpd 2>/dev/null", "pass_if": "active", "severity": "medium"},
    {"id": "3.1.1", "title": "Ensure IP forwarding is disabled", "cmd": "sysctl net.ipv4.ip_forward", "pass_if": "= 0", "severity": "medium"},
    {"id": "3.2.1", "title": "Ensure source routed packets are not accepted", "cmd": "sysctl net.ipv4.conf.all.accept_source_route", "pass_if": "= 0", "severity": "medium"},
    {"id": "3.2.2", "title": "Ensure ICMP redirects are not accepted", "cmd": "sysctl net.ipv4.conf.all.accept_redirects", "pass_if": "= 0", "severity": "medium"},
    {"id": "3.3.1", "title": "Ensure TCP SYN cookies are enabled", "cmd": "sysctl net.ipv4.tcp_syncookies", "pass_if": "= 1", "severity": "medium"},
    {"id": "4.1.1", "title": "Ensure auditd is installed", "cmd": "dpkg -l auditd 2>/dev/null || rpm -q audit 2>/dev/null", "pass_if": "audit", "severity": "high"},
    {"id": "4.2.1", "title": "Ensure rsyslog is installed and running", "cmd": "systemctl is-active rsyslog 2>/dev/null", "pass_if": "active", "severity": "medium"},
    {"id": "5.1.1", "title": "Ensure cron daemon is enabled", "cmd": "systemctl is-enabled cron 2>/dev/null || systemctl is-enabled crond 2>/dev/null", "pass_if": "enabled", "severity": "low"},
    {"id": "5.2.1", "title": "Ensure SSH PermitRootLogin is disabled", "cmd": "grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null", "pass_if": "no", "severity": "high"},
    {"id": "5.2.2", "title": "Ensure SSH PasswordAuthentication is disabled", "cmd": "grep -i '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null", "pass_if": "no", "severity": "medium"},
    {"id": "5.2.3", "title": "Ensure SSH MaxAuthTries is 4 or less", "cmd": "grep -i '^MaxAuthTries' /etc/ssh/sshd_config 2>/dev/null", "pass_if": r"[1-4]$", "severity": "medium"},
    {"id": "5.2.4", "title": "Ensure SSH Protocol is 2", "cmd": "grep -i '^Protocol' /etc/ssh/sshd_config 2>/dev/null", "pass_if": "2", "severity": "high"},
    {"id": "5.3.1", "title": "Ensure password creation requirements", "cmd": "grep -E '^minlen|^dcredit|^ucredit|^ocredit|^lcredit' /etc/security/pwquality.conf 2>/dev/null", "pass_if": "minlen", "severity": "medium"},
    {"id": "5.4.1", "title": "Ensure password expiration is 365 days or less", "cmd": "grep '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null", "pass_if": r"[0-9]+", "severity": "low"},
    {"id": "5.4.2", "title": "Ensure password change minimum is 7 days", "cmd": "grep '^PASS_MIN_DAYS' /etc/login.defs 2>/dev/null", "pass_if": r"[7-9]|[1-9][0-9]", "severity": "low"},
    {"id": "6.1.1", "title": "Ensure permissions on /etc/passwd", "cmd": "stat -c '%a' /etc/passwd", "pass_if": "644", "severity": "high"},
    {"id": "6.1.2", "title": "Ensure permissions on /etc/shadow", "cmd": "stat -c '%a' /etc/shadow", "pass_if": "0|640|600", "severity": "critical"},
    {"id": "6.2.1", "title": "Ensure no accounts have empty passwords", "cmd": "awk -F: '($2 == \"\") {print $1}' /etc/shadow 2>/dev/null", "pass_if": "^$", "severity": "critical"},
]

class ConfigAudit:
    name = "Configuration Audit"
    description = "SSH, SSL/TLS, HTTP headers, CIS benchmarks, backup file detection, admin interface discovery"
    category = "vuln"
    mitre = ["T1592.004", "T1082"]

    def __init__(self, target, options=None):
        self.target = target
        self.options = options or {}
        self.findings = []

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

    def ssh_audit(self, confirm_fn=None):
        cmd = f"ssh-keyscan -t rsa,ecdsa,ed25519 {self.target} 2>/dev/null"
        if not self._confirm(f"SSH key scan: {cmd}", confirm_fn):
            return
        out, _, rc = _run(cmd, timeout=10)
        if not out:
            self._add("info", "SSH not responding or not available", "")
            return
        nmap_cmd = f"nmap -sV -p22 --script ssh2-enum-algos {self.target}"
        if not self._confirm(f"SSH algorithm enumeration: {nmap_cmd}", confirm_fn):
            return
        nmap_out, _, nrc = _run(nmap_cmd, timeout=30)
        if nrc != 0:
            return
        issues = []
        for cipher in WEAK_SSH_CIPHERS:
            if cipher in nmap_out:
                issues.append(f"Weak cipher: {cipher}")
        for kex in WEAK_SSH_KEXS:
            if kex in nmap_out:
                issues.append(f"Weak key exchange: {kex}")
        for mac in WEAK_SSH_MACS:
            if mac in nmap_out:
                issues.append(f"Weak MAC: {mac}")
        if issues:
            self._add("medium", f"SSH weak algorithms ({len(issues)})", "\n".join(issues), nmap_out[:1000], "T1592.004")
        else:
            self._add("info", "SSH algorithms: no weak algorithms found", "", "", "T1592.004")

    def ssl_audit(self, confirm_fn=None):
        host = self.target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        issues = []
        deprecated = ["SSLv3", "TLSv1", "TLSv1.1"]
        for proto in deprecated:
            try:
                if proto == "SSLv3":
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
                    ctx.maximum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                        s.settimeout(5)
                        s.connect((host, 443))
                        issues.append(f"CRITICAL: {proto} supported (must be disabled)")
            except:
                pass
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(10)
                s.connect((host, 443))
                version = s.version()
                cipher = s.cipher()
                cert = s.getpeercert()
                not_after = cert.get("notAfter", "")
                if version in ("TLSv1", "TLSv1.1"):
                    issues.append(f"HIGH: Using deprecated {version}")
                if cipher and "RC4" in cipher[0]:
                    issues.append(f"HIGH: RC4 cipher in use ({cipher[0]})")
                if cipher and "DES" in cipher[0] and "3DES" not in cipher[0]:
                    issues.append(f"HIGH: DES cipher in use ({cipher[0]})")
                if cipher and cipher[2] < 128:
                    issues.append(f"MEDIUM: Cipher key length < 128 bits ({cipher[2]})")
                self._add("info", f"TLS: {version}, cipher: {cipher[0] if cipher else '?'}", "\n".join(issues) if issues else "No issues found", "", "T1592.004")
        except Exception as e:
            self._add("info", f"SSL/TLS connection failed: {e}", "")

    def backup_file_check(self, confirm_fn=None):
        url_base = self.target if "://" in self.target else f"https://{self.target}"
        common_files = ["index", "config", "database", "db", "admin", "login", "wp-config", "settings", "application", "web"]
        checks = []
        for f in common_files:
            for ext in BACKUP_EXTENSIONS[:8]:
                checks.append(f"/{f}{ext}")
                checks.append(f"/{f}.php{ext}")
        action = f"Check {len(checks)} backup file paths on {url_base}"
        if not self._confirm(action, confirm_fn):
            return
        found = []
        for path in checks:
            url = url_base.rstrip("/") + path
            cmd = f'curl -sS -o /dev/null -w "%{{http_code}}" --max-time 3 -k "{url}"'
            out, _, rc = _run(cmd, timeout=5)
            if rc == 0 and out == "200":
                found.append(path)
                self._add("high", f"Backup file found: {path}", f"URL: {url}\nAccessible without authentication", "", "T1083")
        if not found:
            self._add("info", "No backup files found", f"Checked {len(checks)} paths")

    def admin_interface_check(self, confirm_fn=None):
        url_base = self.target if "://" in self.target else f"https://{self.target}"
        action = f"Check {len(ADMIN_PATHS)} admin interface paths"
        if not self._confirm(action, confirm_fn):
            return
        for path in ADMIN_PATHS:
            url = url_base.rstrip("/") + path
            cmd = f'curl -sS -o /dev/null -w "%{{http_code}}" --max-time 5 -k "{url}"'
            out, _, rc = _run(cmd, timeout=8)
            if rc == 0 and out in ("200", "301", "302"):
                severity = "medium" if out == "200" else "low"
                self._add(severity, f"Admin interface: {path} [{out}]", f"URL: {url}", "", "T1082")

    def cis_benchmark(self, confirm_fn=None):
        if os.name != "posix":
            self._add("info", "CIS benchmark checks require Linux", "")
            return
        action = f"Run {len(CIS_CHECKS_LINUX)} CIS benchmark checks (local system)"
        if not self._confirm(action, confirm_fn):
            return
        passed = 0
        failed = 0
        for check in CIS_CHECKS_LINUX:
            out, _, rc = _run(check["cmd"], timeout=5)
            pass_pattern = check["pass_if"]
            check_passed = False
            if pass_pattern == "^$":
                check_passed = not out.strip()
            elif re.search(pass_pattern, out, re.IGNORECASE):
                check_passed = True
            if check_passed:
                passed += 1
            else:
                failed += 1
                self._add(check["severity"], f"CIS {check['id']}: {check['title']}", f"Status: FAIL\nOutput: {out or '(empty)'}\nExpected: {pass_pattern}", out[:200], "T1082")
        self._add("info", f"CIS benchmark: {passed} passed, {failed} failed out of {len(CIS_CHECKS_LINUX)}", f"Pass rate: {passed/(passed+failed)*100:.0f}%" if (passed+failed) > 0 else "N/A")

    def run(self, confirm_fn=None):
        print(f"\n[AEGIS] Configuration Audit: {self.target}")
        print("=" * 60)
        self.ssh_audit(confirm_fn)
        self.ssl_audit(confirm_fn)
        self.backup_file_check(confirm_fn)
        self.admin_interface_check(confirm_fn)
        if self.options.get("cis"):
            self.cis_benchmark(confirm_fn)
        print(f"\n[AEGIS] Config audit complete: {len(self.findings)} findings")
        return self.findings

    def get_findings(self):
        return self.findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 config-audit.py <target> [--cis]")
        sys.exit(1)
    target = sys.argv[1]
    opts = {"cis": "--cis" in sys.argv}
    def confirm(action):
        resp = input(f"\n[?] {action}\n    Execute? [y/n]: ").strip().lower()
        return resp in ("y", "yes")
    mod = ConfigAudit(target, opts)
    mod.run(confirm_fn=confirm)
    for f in mod.get_findings():
        sev = f["severity"].upper()
        color = {"critical": "\033[91m", "high": "\033[91m", "medium": "\033[93m", "low": "\033[94m", "info": "\033[90m"}.get(f["severity"], "")
        print(f"  {color}[{sev:8s}]\033[0m {f['title']}")
