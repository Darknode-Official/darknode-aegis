#!/usr/bin/env python3
"""AEGIS Web Application Reconnaissance Module
Fingerprints web technologies, analyzes security headers, discovers paths,
and checks SSL/TLS configuration.
"""
import subprocess, json, os, sys, re, socket, ssl
from datetime import datetime
from urllib.parse import urlparse

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

SECURITY_HEADERS = {
    "strict-transport-security": {"required": True, "desc": "HSTS - forces HTTPS", "good": "max-age=31536000; includeSubDomains", "weight": 10},
    "content-security-policy": {"required": True, "desc": "CSP - prevents XSS and injection", "good": "default-src 'self'", "weight": 15},
    "x-content-type-options": {"required": True, "desc": "Prevents MIME sniffing", "good": "nosniff", "weight": 5},
    "x-frame-options": {"required": True, "desc": "Prevents clickjacking", "good": "DENY or SAMEORIGIN", "weight": 8},
    "x-xss-protection": {"required": False, "desc": "Legacy XSS filter (CSP is better)", "good": "0 (disabled, rely on CSP)", "weight": 2},
    "referrer-policy": {"required": True, "desc": "Controls referrer leakage", "good": "strict-origin-when-cross-origin", "weight": 5},
    "permissions-policy": {"required": True, "desc": "Controls browser features", "good": "camera=(), microphone=(), geolocation=()", "weight": 5},
    "cross-origin-opener-policy": {"required": False, "desc": "Isolates browsing context", "good": "same-origin", "weight": 3},
    "cross-origin-resource-policy": {"required": False, "desc": "Prevents cross-origin reads", "good": "same-origin", "weight": 3},
    "cross-origin-embedder-policy": {"required": False, "desc": "Controls embedding", "good": "require-corp", "weight": 3},
    "cache-control": {"required": False, "desc": "Controls caching behavior", "good": "no-store for sensitive pages", "weight": 3},
    "x-permitted-cross-domain-policies": {"required": False, "desc": "Controls Flash/PDF cross-domain", "good": "none", "weight": 2},
    "expect-ct": {"required": False, "desc": "Certificate Transparency enforcement", "good": "enforce, max-age=86400", "weight": 3},
    "access-control-allow-origin": {"required": False, "desc": "CORS origin policy", "good": "specific origin, not *", "weight": 5},
    "server": {"required": False, "desc": "Server software disclosure", "good": "should be removed or generic", "weight": 3, "check": "disclosure"},
}

COMMON_PATHS = [
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/favicon.ico",
    "/admin", "/administrator", "/login", "/signin", "/auth", "/dashboard",
    "/api", "/api/v1", "/api/v2", "/api/docs", "/swagger", "/swagger-ui.html",
    "/swagger.json", "/openapi.json", "/graphql", "/graphiql",
    "/.git", "/.git/HEAD", "/.git/config", "/.env", "/.env.local", "/.env.production",
    "/wp-admin", "/wp-login.php", "/wp-content", "/wp-includes",
    "/phpmyadmin", "/pma", "/adminer", "/adminer.php",
    "/server-status", "/server-info", "/.htaccess", "/.htpasswd",
    "/web.config", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/xmlrpc.php", "/readme.html", "/license.txt",
    "/console", "/debug", "/trace", "/actuator", "/actuator/health",
    "/actuator/env", "/actuator/beans", "/actuator/mappings",
    "/metrics", "/health", "/status", "/info", "/env",
    "/elmah.axd", "/error_log", "/errors.log",
    "/backup", "/backup.sql", "/dump.sql", "/database.sql",
    "/config.php", "/config.yml", "/config.json", "/settings.json",
    "/composer.json", "/package.json", "/Gemfile", "/requirements.txt",
    "/Dockerfile", "/docker-compose.yml", "/.dockerignore",
    "/Makefile", "/Rakefile", "/Gruntfile.js", "/gulpfile.js",
    "/.DS_Store", "/thumbs.db", "/desktop.ini",
    "/cgi-bin/", "/cgi-bin/test.cgi", "/cgi-bin/printenv",
    "/test", "/test.php", "/phpinfo.php", "/info.php",
    "/tmp", "/temp", "/upload", "/uploads", "/files",
    "/old", "/bak", "/backup", "/archive",
    "/.svn", "/.svn/entries", "/.hg", "/.bzr",
    "/WEB-INF/web.xml", "/META-INF/MANIFEST.MF",
    "/manager/html", "/jmx-console", "/invoker/JMXInvokerServlet",
    "/solr", "/jenkins", "/hudson", "/nagios",
    "/zabbix", "/grafana", "/kibana", "/prometheus",
    "/.well-known/openid-configuration", "/oauth/authorize",
    "/saml/metadata", "/.well-known/jwks.json",
]

WAF_SIGNATURES = {
    "cloudflare": {"headers": ["cf-ray", "cf-cache-status", "__cfduid"], "server": ["cloudflare"]},
    "aws-waf": {"headers": ["x-amzn-requestid", "x-amz-cf-id"], "server": ["awselb", "amazons3"]},
    "akamai": {"headers": ["x-akamai-transformed"], "server": ["akamaighost"]},
    "imperva": {"headers": ["x-cdn", "x-iinfo"], "server": ["imperva", "incapsula"]},
    "f5-big-ip": {"headers": ["x-wa-info"], "server": ["big-ip", "bigip"]},
    "sucuri": {"headers": ["x-sucuri-id"], "server": ["sucuri"]},
    "barracuda": {"headers": ["barra_counter_session"], "server": ["barracuda"]},
    "fortiweb": {"headers": ["fortiwafsid"], "server": ["fortiweb"]},
    "modsecurity": {"headers": [], "server": ["mod_security"]},
    "nginx-waf": {"headers": ["x-naxsi-sig"], "server": []},
}

CMS_SIGNATURES = {
    "wordpress": {"paths": ["/wp-login.php", "/wp-admin", "/wp-content"], "meta": ["wp-", "wordpress"], "headers": ["x-powered-by: wordpress"]},
    "drupal": {"paths": ["/misc/drupal.js", "/sites/default"], "meta": ["drupal", "Drupal.settings"], "headers": ["x-drupal-"]},
    "joomla": {"paths": ["/administrator", "/media/jui"], "meta": ["joomla", "/media/system/js"], "headers": ["x-content-encoded-by: joomla"]},
    "magento": {"paths": ["/skin/frontend", "/js/mage"], "meta": ["magento", "mage/"], "headers": ["x-magento-"]},
    "shopify": {"paths": [], "meta": ["shopify", "cdn.shopify.com"], "headers": ["x-shopify-"]},
    "ghost": {"paths": ["/ghost"], "meta": ["ghost"], "headers": ["x-ghost-"]},
    "hugo": {"paths": [], "meta": ["hugo", "gohugo"], "headers": []},
    "next.js": {"paths": ["/_next"], "meta": ["__next", "__NEXT_DATA__"], "headers": ["x-nextjs-", "x-powered-by: next.js"]},
}

class WebRecon:
    name = "Web Application Reconnaissance"
    description = "HTTP probing, security headers, tech fingerprinting, path discovery, SSL/TLS analysis"
    category = "recon"
    mitre = ["T1595.002", "T1592.004", "T1590.002"]

    def __init__(self, target, options=None):
        self.target = target
        self.options = options or {}
        self.findings = []
        self.actions = []
        self.headers = {}
        self.body = ""
        self.status_code = 0
        self.technologies = []
        self.base_url = ""

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

    def _curl(self, url, follow=True, timeout=10):
        flags = "-sS -D- --max-time " + str(timeout)
        if follow:
            flags += " -L --max-redirs 5"
        cmd = f'curl {flags} "{url}"'
        out, err, rc = _run(cmd, timeout=timeout + 5)
        return out, rc

    def http_probe(self, confirm_fn=None):
        urls = []
        if "://" in self.target:
            urls = [self.target]
        else:
            urls = [f"https://{self.target}", f"http://{self.target}"]

        for url in urls:
            action = f"HTTP probe: curl -sS -D- {url}"
            if not self._confirm(action, confirm_fn):
                continue
            out, rc = self._curl(url)
            if rc != 0 or not out:
                continue

            parts = out.split("\r\n\r\n", 1)
            header_block = parts[0] if parts else ""
            self.body = parts[1] if len(parts) > 1 else ""

            status_m = re.search(r'HTTP/[\d.]+\s+(\d+)', header_block)
            if status_m:
                self.status_code = int(status_m.group(1))

            for line in header_block.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    self.headers[k.strip().lower()] = v.strip()

            self.base_url = url
            self._add("info", f"HTTP probe: {url} -> {self.status_code}", f"Server: {self.headers.get('server', 'not disclosed')}", header_block[:1000], "T1595.002")
            break

    def security_headers_check(self):
        if not self.headers:
            return
        score = 0
        max_score = sum(h["weight"] for h in SECURITY_HEADERS.values())
        issues = []
        for header, info in SECURITY_HEADERS.items():
            val = self.headers.get(header, "")
            check_type = info.get("check", "")
            if check_type == "disclosure":
                if val:
                    issues.append(f"[LOW] {header}: '{val}' -- server version disclosed")
                else:
                    score += info["weight"]
            elif val:
                score += info["weight"]
                if header == "strict-transport-security":
                    m = re.search(r'max-age=(\d+)', val)
                    if m and int(m.group(1)) < 31536000:
                        issues.append(f"[MEDIUM] HSTS max-age too short ({m.group(1)}s, recommend 31536000)")
                        score -= info["weight"] // 2
                if header == "content-security-policy":
                    if "'unsafe-inline'" in val:
                        issues.append("[MEDIUM] CSP allows 'unsafe-inline' -- weakens XSS protection")
                    if "'unsafe-eval'" in val:
                        issues.append("[MEDIUM] CSP allows 'unsafe-eval' -- weakens XSS protection")
                    if "default-src *" in val or "script-src *" in val:
                        issues.append("[HIGH] CSP is overly permissive (allows *)")
                        score -= info["weight"]
                if header == "access-control-allow-origin" and val == "*":
                    issues.append("[MEDIUM] CORS allows any origin (*)")
                    score -= info["weight"]
            elif info["required"]:
                issues.append(f"[MEDIUM] Missing header: {header} -- {info['desc']}")

        grade_pct = (score / max_score) * 100 if max_score else 0
        grade = "A" if grade_pct >= 90 else "B" if grade_pct >= 75 else "C" if grade_pct >= 60 else "D" if grade_pct >= 40 else "F"
        severity = "info" if grade in "AB" else "medium" if grade == "C" else "high"
        self._add(severity, f"Security Headers Grade: {grade} ({grade_pct:.0f}%)", "\n".join(issues) if issues else "All critical headers present", f"Score: {score}/{max_score}", "T1592.004")

    def tech_fingerprint(self):
        if not self.headers and not self.body:
            return
        techs = []
        server = self.headers.get("server", "")
        if server:
            techs.append(f"Server: {server}")
        powered = self.headers.get("x-powered-by", "")
        if powered:
            techs.append(f"X-Powered-By: {powered}")
        asp = self.headers.get("x-aspnet-version", "")
        if asp:
            techs.append(f"ASP.NET: {asp}")

        for cms, sigs in CMS_SIGNATURES.items():
            for meta in sigs.get("meta", []):
                if meta.lower() in self.body.lower():
                    techs.append(f"CMS: {cms}")
                    break
            for hdr in sigs.get("headers", []):
                k = hdr.split(":")[0].strip().lower()
                if k in self.headers:
                    techs.append(f"CMS: {cms}")
                    break

        js_libs = {
            "jquery": r'jquery[.-](\d[\d.]*)', "react": r'react[.-](\d[\d.]*)',
            "angular": r'angular[.-](\d[\d.]*)', "vue": r'vue[.-](\d[\d.]*)',
            "bootstrap": r'bootstrap[.-](\d[\d.]*)', "lodash": r'lodash[.-](\d[\d.]*)',
        }
        for lib, pattern in js_libs.items():
            m = re.search(pattern, self.body, re.IGNORECASE)
            if m:
                techs.append(f"JS: {lib} {m.group(1)}")
            elif lib in self.body.lower():
                techs.append(f"JS: {lib}")

        self.technologies = list(set(techs))
        if techs:
            self._add("info", f"Technologies detected ({len(techs)})", "\n".join(sorted(set(techs))), "", "T1592.004")

    def waf_detection(self):
        if not self.headers:
            return
        for waf, sigs in WAF_SIGNATURES.items():
            for h in sigs.get("headers", []):
                if h.lower() in self.headers:
                    self._add("info", f"WAF detected: {waf}", f"Identified via header: {h}", self.headers.get(h.lower(), ""), "T1595.002")
                    return
            server = self.headers.get("server", "").lower()
            for s in sigs.get("server", []):
                if s in server:
                    self._add("info", f"WAF detected: {waf}", f"Identified via Server header: {server}", "", "T1595.002")
                    return

    def path_discovery(self, confirm_fn=None):
        if not self.base_url:
            return
        action = f"Check {len(COMMON_PATHS)} common paths on {self.base_url}"
        if not self._confirm(action, confirm_fn):
            return
        found = []
        for path in COMMON_PATHS:
            url = self.base_url.rstrip("/") + path
            cmd = f'curl -sS -o /dev/null -w "%{{http_code}}" --max-time 5 "{url}"'
            out, _, rc = _run(cmd, timeout=8)
            if rc == 0 and out in ("200", "301", "302", "401", "403"):
                found.append({"path": path, "status": out})
                severity = "info"
                if any(s in path for s in [".git", ".env", "backup", ".sql", "phpinfo", "debug", "actuator/env"]):
                    severity = "high"
                elif any(s in path for s in ["admin", "phpmyadmin", "manager", "console", "swagger"]):
                    severity = "medium"
                elif out == "401":
                    severity = "low"
                self._add(severity, f"Path found: {path} [{out}]", f"URL: {url}", "", "T1595.002")
        self._add("info", f"Path discovery: {len(found)}/{len(COMMON_PATHS)} found", "\n".join(f"  [{f['status']}] {f['path']}" for f in found), "", "T1595.002")

    def ssl_analysis(self, confirm_fn=None):
        host = self.target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(10)
                s.connect((host, 443))
                cert = s.getpeercert()
                cipher = s.cipher()
                version = s.version()
        except Exception as e:
            self._add("info", f"SSL/TLS connection failed: {host}", str(e))
            return

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        not_after = cert.get("notAfter", "")
        san = [entry[1] for entry in cert.get("subjectAltName", [])]

        info = f"Subject: {subject.get('commonName', '?')}\n"
        info += f"Issuer: {issuer.get('organizationName', '?')}\n"
        info += f"Expires: {not_after}\n"
        info += f"SANs: {', '.join(san[:20])}\n"
        info += f"Protocol: {version}\n"
        info += f"Cipher: {cipher[0] if cipher else '?'}"

        severity = "info"
        if version in ("SSLv3", "TLSv1", "TLSv1.1"):
            severity = "high"
            info += f"\nWARNING: {version} is deprecated and insecure"
        self._add(severity, f"SSL/TLS: {version}, {cipher[0] if cipher else '?'}", info, "", "T1590.002")

    def cookie_analysis(self):
        cookies = self.headers.get("set-cookie", "")
        if not cookies:
            return
        issues = []
        for cookie_str in cookies.split(","):
            cookie_str = cookie_str.strip()
            name = cookie_str.split("=")[0].strip() if "=" in cookie_str else cookie_str
            flags = cookie_str.lower()
            if "secure" not in flags:
                issues.append(f"[MEDIUM] Cookie '{name}' missing Secure flag")
            if "httponly" not in flags:
                issues.append(f"[LOW] Cookie '{name}' missing HttpOnly flag")
            if "samesite" not in flags:
                issues.append(f"[LOW] Cookie '{name}' missing SameSite attribute")
        if issues:
            self._add("medium", f"Cookie security issues ({len(issues)})", "\n".join(issues), cookies[:500], "T1592.004")

    def cors_check(self):
        origin = self.headers.get("access-control-allow-origin", "")
        if origin == "*":
            self._add("medium", "CORS: wildcard origin (*)", "Any website can make authenticated requests to this API if credentials are allowed", origin, "T1592.004")
        elif origin:
            creds = self.headers.get("access-control-allow-credentials", "")
            if creds.lower() == "true":
                self._add("info", f"CORS: allows origin {origin} with credentials", "Check if this origin is trusted", f"Origin: {origin}, Credentials: {creds}", "T1592.004")

    def run(self, confirm_fn=None):
        print(f"\n[AEGIS] Web Reconnaissance: {self.target}")
        print("=" * 60)
        self.http_probe(confirm_fn)
        self.security_headers_check()
        self.tech_fingerprint()
        self.waf_detection()
        self.cookie_analysis()
        self.cors_check()
        self.ssl_analysis(confirm_fn)
        if self.options.get("paths", True):
            self.path_discovery(confirm_fn)
        print(f"\n[AEGIS] Web recon complete: {len(self.findings)} findings")
        return self.findings

    def get_findings(self):
        return self.findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 web-recon.py <url-or-domain>")
        sys.exit(1)
    target = sys.argv[1]
    def confirm(action):
        resp = input(f"\n[?] {action}\n    Execute? [y/n]: ").strip().lower()
        return resp in ("y", "yes")
    mod = WebRecon(target, {"paths": True})
    findings = mod.run(confirm_fn=confirm)
    print(f"\n{'='*60}")
    print(f"FINDINGS: {len(findings)}")
    print(f"{'='*60}")
    for f in findings:
        sev = f["severity"].upper()
        color = {"critical": "\033[91m", "high": "\033[91m", "medium": "\033[93m", "low": "\033[94m", "info": "\033[90m"}.get(f["severity"], "")
        print(f"  {color}[{sev:8s}]\033[0m {f['title']}")
