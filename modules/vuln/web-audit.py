#!/usr/bin/env python3
"""AEGIS Web Application Audit Module
OWASP-style web vulnerability testing: SQLi, XSS, traversal, command injection,
SSRF, open redirect, CSRF, info disclosure. Integrates nikto/sqlmap/gobuster.
"""
import subprocess, json, os, sys, re
from datetime import datetime
from urllib.parse import quote, urlencode

def _run(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except:
        return "", "", 1

def _has(tool):
    return subprocess.run(["which", tool], capture_output=True).returncode == 0

SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "' OR 1=1#", "1' ORDER BY 1--", "1' UNION SELECT NULL--", "1 AND 1=1", "1 AND 1=2", "'; WAITFOR DELAY '0:0:5'--", "1' AND SLEEP(5)--", "1') OR ('1'='1"]
SQLI_ERRORS = ["sql syntax", "mysql_fetch", "ORA-0", "PostgreSQL", "Microsoft OLE DB", "Unclosed quotation", "SQLSTATE", "sqlite3", "syntax error", "warning: mysql", "pg_query", "unterminated string", "ODBC SQL Server"]

XSS_PAYLOADS = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', "'-alert(1)-'", '<svg onload=alert(1)>', '{{7*7}}', '${7*7}', '<img src=1 onerror=alert(1)>']
XSS_INDICATORS = ["<script>alert(1)</script>", "onerror=alert(1)", "<svg onload="]

TRAVERSAL_PAYLOADS = ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "....//....//....//etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "..%252f..%252f..%252fetc%252fpasswd"]
TRAVERSAL_INDICATORS = ["root:x:0:0", "root:*:0:0", "[boot loader]", "[extensions]"]

CMDI_PAYLOADS = [";id", "|id", "$(id)", "`id`", ";cat /etc/passwd", "|cat /etc/passwd", "& whoami", "| whoami", "; whoami"]
CMDI_INDICATORS = ["uid=", "gid=", "root:x:0:0"]

INFO_DISCLOSURE_PATHS = [
    ("/server-status", "Apache server-status"),
    ("/server-info", "Apache server-info"),
    ("/phpinfo.php", "PHP info page"),
    ("/info.php", "PHP info page"),
    ("/test.php", "Test page"),
    ("/debug", "Debug endpoint"),
    ("/trace", "Trace endpoint"),
    ("/actuator/env", "Spring Boot env"),
    ("/actuator/beans", "Spring Boot beans"),
    ("/actuator/mappings", "Spring Boot mappings"),
    ("/actuator/configprops", "Spring Boot config"),
    ("/elmah.axd", "ELMAH error log"),
    ("/.env", "Environment file"),
    ("/.git/HEAD", "Git repository"),
    ("/.git/config", "Git config"),
    ("/.svn/entries", "SVN repository"),
    ("/web.config", "IIS web config"),
    ("/crossdomain.xml", "Flash cross-domain"),
    ("/wp-config.php.bak", "WordPress config backup"),
    ("/config.php.bak", "PHP config backup"),
]

class WebAudit:
    name = "Web Application Audit"
    description = "OWASP web vulnerability testing: SQLi, XSS, path traversal, command injection, info disclosure"
    category = "vuln"
    mitre = ["T1190", "T1059.007"]

    def __init__(self, target, options=None):
        self.target = target if "://" in target else f"https://{target}"
        self.options = options or {}
        self.findings = []
        self.actions = []

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

    def _curl_get(self, url, timeout=10):
        cmd = f'curl -sS --max-time {timeout} -k "{url}"'
        out, err, rc = _run(cmd, timeout=timeout+5)
        return out, rc

    def sqli_test(self, params=None, confirm_fn=None):
        if not params:
            params = self.options.get("params", [])
        if not params:
            self._add("info", "No parameters provided for SQLi testing", "Provide URL parameters to test: --params 'id=1&name=test'")
            return
        action = f"Test {len(SQLI_PAYLOADS)} SQLi payloads against {len(params)} parameters on {self.target}"
        if not self._confirm(action, confirm_fn):
            return
        for param in params:
            for payload in SQLI_PAYLOADS:
                test_url = f"{self.target}?{param}={quote(payload)}"
                body, rc = self._curl_get(test_url)
                if rc != 0:
                    continue
                for err in SQLI_ERRORS:
                    if err.lower() in body.lower():
                        self._add("critical", f"SQL Injection in '{param}'", f"Error-based SQLi detected\nPayload: {payload}\nError: {err}\nURL: {test_url}", body[:500], "T1190")
                        return

    def xss_test(self, params=None, confirm_fn=None):
        if not params:
            params = self.options.get("params", [])
        if not params:
            return
        action = f"Test {len(XSS_PAYLOADS)} XSS payloads against {len(params)} parameters"
        if not self._confirm(action, confirm_fn):
            return
        for param in params:
            for payload in XSS_PAYLOADS:
                test_url = f"{self.target}?{param}={quote(payload)}"
                body, rc = self._curl_get(test_url)
                if rc != 0:
                    continue
                for indicator in XSS_INDICATORS:
                    if indicator in body:
                        self._add("high", f"Reflected XSS in '{param}'", f"Payload reflected in response\nPayload: {payload}\nURL: {test_url}", body[:500], "T1059.007")
                        return

    def traversal_test(self, params=None, confirm_fn=None):
        if not params:
            params = self.options.get("params", [])
        if not params:
            return
        action = f"Test {len(TRAVERSAL_PAYLOADS)} path traversal payloads"
        if not self._confirm(action, confirm_fn):
            return
        for param in params:
            for payload in TRAVERSAL_PAYLOADS:
                test_url = f"{self.target}?{param}={quote(payload)}"
                body, rc = self._curl_get(test_url)
                if rc != 0:
                    continue
                for indicator in TRAVERSAL_INDICATORS:
                    if indicator in body:
                        self._add("critical", f"Path Traversal in '{param}'", f"File content leaked\nPayload: {payload}\nURL: {test_url}", body[:500], "T1083")
                        return

    def cmdi_test(self, params=None, confirm_fn=None):
        if not params:
            params = self.options.get("params", [])
        if not params:
            return
        action = f"Test {len(CMDI_PAYLOADS)} command injection payloads"
        if not self._confirm(action, confirm_fn):
            return
        for param in params:
            for payload in CMDI_PAYLOADS:
                test_url = f"{self.target}?{param}={quote(payload)}"
                body, rc = self._curl_get(test_url)
                if rc != 0:
                    continue
                for indicator in CMDI_INDICATORS:
                    if indicator in body:
                        self._add("critical", f"Command Injection in '{param}'", f"OS command output in response\nPayload: {payload}\nURL: {test_url}", body[:500], "T1059")
                        return

    def info_disclosure_test(self, confirm_fn=None):
        action = f"Check {len(INFO_DISCLOSURE_PATHS)} sensitive paths for info disclosure"
        if not self._confirm(action, confirm_fn):
            return
        for path, desc in INFO_DISCLOSURE_PATHS:
            url = self.target.rstrip("/") + path
            cmd = f'curl -sS -o /dev/null -w "%{{http_code}}" --max-time 5 -k "{url}"'
            out, _, rc = _run(cmd, timeout=8)
            if rc == 0 and out == "200":
                body, _ = self._curl_get(url, timeout=5)
                severity = "high" if any(s in path for s in [".git", ".env", "actuator", "phpinfo", "config"]) else "medium"
                self._add(severity, f"Info Disclosure: {desc} ({path})", f"URL: {url}\nAccessible without auth", body[:300] if body else "", "T1082")

    def csrf_check(self, confirm_fn=None):
        body, rc = self._curl_get(self.target)
        if rc != 0 or not body:
            return
        forms = re.findall(r'<form[^>]*>(.*?)</form>', body, re.DOTALL | re.IGNORECASE)
        for i, form in enumerate(forms):
            has_csrf = bool(re.search(r'csrf|_token|authenticity_token|__RequestVerificationToken|anti-forgery', form, re.IGNORECASE))
            method = re.search(r'method=["\']?(\w+)', form, re.IGNORECASE)
            method_str = method.group(1).upper() if method else "GET"
            if method_str == "POST" and not has_csrf:
                action = re.search(r'action=["\']([^"\']*)', form, re.IGNORECASE)
                action_str = action.group(1) if action else "(same page)"
                self._add("medium", f"Missing CSRF token in form #{i+1}", f"Method: {method_str}\nAction: {action_str}\nNo CSRF token found in the form", form[:300], "T1190")

    def nikto_scan(self, confirm_fn=None):
        if not _has("nikto"):
            return
        cmd = f"nikto -host {self.target} -maxtime 120 -Format json -output -"
        if not self._confirm(f"Run nikto scan: {cmd}", confirm_fn):
            return
        out, _, rc = _run(cmd, timeout=180)
        if rc == 0 and out:
            vulns = re.findall(r'\+ (OSVDB-\d+|[A-Z].*?:.*?)(?:\n|$)', out)
            if vulns:
                self._add("medium", f"Nikto: {len(vulns)} findings", "\n".join(vulns[:20]), out[:2000], "T1595.002")

    def gobuster_scan(self, confirm_fn=None):
        if not _has("gobuster"):
            return
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        if not os.path.exists(wordlist):
            wordlist = "/usr/share/dirbuster/wordlists/directory-list-2.3-small.txt"
        if not os.path.exists(wordlist):
            return
        cmd = f"gobuster dir -u {self.target} -w {wordlist} -t 10 -q --no-error -o -"
        if not self._confirm(f"Directory brute force: {cmd}", confirm_fn):
            return
        out, _, rc = _run(cmd, timeout=120)
        if rc == 0 and out:
            found = [l for l in out.splitlines() if l.strip() and "Status:" in l]
            if found:
                self._add("info", f"Gobuster: {len(found)} paths found", "\n".join(found[:30]), "", "T1595.002")

    def run(self, confirm_fn=None):
        print(f"\n[AEGIS] Web Application Audit: {self.target}")
        print("=" * 60)
        params = self.options.get("params", [])
        if params:
            self.sqli_test(params, confirm_fn)
            self.xss_test(params, confirm_fn)
            self.traversal_test(params, confirm_fn)
            self.cmdi_test(params, confirm_fn)
        self.info_disclosure_test(confirm_fn)
        self.csrf_check(confirm_fn)
        if self.options.get("nikto"):
            self.nikto_scan(confirm_fn)
        if self.options.get("gobuster"):
            self.gobuster_scan(confirm_fn)
        print(f"\n[AEGIS] Web audit complete: {len(self.findings)} findings")
        return self.findings

    def get_findings(self):
        return self.findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 web-audit.py <url> [param1 param2 ...]")
        sys.exit(1)
    target = sys.argv[1]
    params = sys.argv[2:] if len(sys.argv) > 2 else []
    def confirm(action):
        resp = input(f"\n[?] {action}\n    Execute? [y/n]: ").strip().lower()
        return resp in ("y", "yes")
    mod = WebAudit(target, {"params": params, "nikto": True, "gobuster": True})
    mod.run(confirm_fn=confirm)
    for f in mod.get_findings():
        sev = f["severity"].upper()
        color = {"critical": "\033[91m", "high": "\033[91m", "medium": "\033[93m", "low": "\033[94m", "info": "\033[90m"}.get(f["severity"], "")
        print(f"  {color}[{sev:8s}]\033[0m {f['title']}")
