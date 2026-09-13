#!/usr/bin/env python3
"""AEGIS Vulnerability Scanner Module
Matches discovered services against a CVE database, checks for known exploits,
CISA KEV status, and provides remediation guidance.
"""
import subprocess, json, os, sys, re
from datetime import datetime

def _run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except:
        return "", "", 1

def _has(tool):
    return subprocess.run(["which", tool], capture_output=True).returncode == 0

CVE_DB = [
    # Apache HTTP Server
    {"service": "apache", "regex": r"2\.4\.(49|50)", "cve": "CVE-2021-41773", "name": "Path Traversal RCE", "cvss": 9.8, "kev": True, "exploit": True, "fix": "Upgrade to Apache 2.4.51+"},
    {"service": "apache", "regex": r"2\.4\.([0-9]|[1-3][0-9]|4[0-8])$", "cve": "CVE-2019-0211", "name": "Local Privilege Escalation", "cvss": 7.8, "kev": False, "exploit": True, "fix": "Upgrade to Apache 2.4.39+"},
    {"service": "apache", "regex": r"2\.4\.(1[0-9]|2[0-9])", "cve": "CVE-2017-9798", "name": "Optionsbleed", "cvss": 7.5, "kev": False, "exploit": True, "fix": "Upgrade to Apache 2.4.28+"},
    # Nginx
    {"service": "nginx", "regex": r"1\.(1[0-7])\.", "cve": "CVE-2019-20372", "name": "HTTP Request Smuggling", "cvss": 5.3, "kev": False, "exploit": False, "fix": "Upgrade to nginx 1.17.7+"},
    {"service": "nginx", "regex": r"1\.\d\.\d", "cve": "CVE-2021-23017", "name": "DNS Resolver Off-by-One", "cvss": 7.7, "kev": False, "exploit": True, "fix": "Upgrade to nginx 1.20.1+"},
    # OpenSSH
    {"service": "openssh", "regex": r"[78]\.[0-9]", "cve": "CVE-2024-6387", "name": "regreSSHion", "cvss": 8.1, "kev": True, "exploit": True, "fix": "Upgrade to OpenSSH 9.8+"},
    {"service": "openssh", "regex": r"[67]\.", "cve": "CVE-2020-15778", "name": "Command Injection via scp", "cvss": 7.8, "kev": False, "exploit": True, "fix": "Upgrade to OpenSSH 8.8+ or use sftp"},
    {"service": "openssh", "regex": r"[2-7]\.", "cve": "CVE-2018-15473", "name": "Username Enumeration", "cvss": 5.3, "kev": False, "exploit": True, "fix": "Upgrade to OpenSSH 7.8+"},
    # MySQL
    {"service": "mysql", "regex": r"5\.[0-6]\.", "cve": "CVE-2012-2122", "name": "Auth Bypass", "cvss": 7.5, "kev": False, "exploit": True, "fix": "Upgrade to MySQL 5.7+"},
    {"service": "mysql", "regex": r"5\.7\.", "cve": "CVE-2016-6662", "name": "Remote Root Code Execution", "cvss": 9.8, "kev": False, "exploit": True, "fix": "Upgrade to MySQL 5.7.15+"},
    {"service": "mysql", "regex": r"8\.0\.[0-2][0-9]", "cve": "CVE-2023-21912", "name": "Server DoS", "cvss": 7.5, "kev": False, "exploit": False, "fix": "Upgrade to MySQL 8.0.33+"},
    # PostgreSQL
    {"service": "postgresql", "regex": r"(9\.[0-5]|10\.[0-9]$|11\.[0-9]$)", "cve": "CVE-2019-9193", "name": "COPY TO/FROM PROGRAM RCE", "cvss": 9.8, "kev": False, "exploit": True, "fix": "Restrict superuser access, upgrade"},
    {"service": "postgresql", "regex": r"1[0-4]\.", "cve": "CVE-2023-5868", "name": "Memory Disclosure", "cvss": 4.3, "kev": False, "exploit": False, "fix": "Upgrade to latest minor version"},
    # Microsoft SQL Server
    {"service": "mssql", "regex": r"2016|2017|2019", "cve": "CVE-2020-0618", "name": "SSRS RCE", "cvss": 8.8, "kev": True, "exploit": True, "fix": "Apply Microsoft security update"},
    # Tomcat
    {"service": "tomcat", "regex": r"[89]\.", "cve": "CVE-2020-1938", "name": "Ghostcat AJP", "cvss": 9.8, "kev": True, "exploit": True, "fix": "Disable AJP or upgrade to Tomcat 9.0.31+"},
    {"service": "tomcat", "regex": r"[7-9]\.", "cve": "CVE-2017-12615", "name": "PUT RCE", "cvss": 8.1, "kev": False, "exploit": True, "fix": "Disable PUT method, upgrade"},
    # WordPress
    {"service": "wordpress", "regex": r"[1-4]\.", "cve": "CVE-2021-29447", "name": "XXE via Media Library", "cvss": 7.1, "kev": False, "exploit": True, "fix": "Upgrade to WordPress 5.7.1+"},
    {"service": "wordpress", "regex": r"5\.[0-7]", "cve": "CVE-2022-21661", "name": "SQL Injection in WP_Query", "cvss": 8.0, "kev": False, "exploit": True, "fix": "Upgrade to WordPress 5.8.3+"},
    # Exchange
    {"service": "exchange", "regex": r"201[3-9]", "cve": "CVE-2021-26855", "name": "ProxyLogon SSRF->RCE", "cvss": 9.8, "kev": True, "exploit": True, "fix": "Apply Microsoft patch KB5000871"},
    {"service": "exchange", "regex": r"201[3-9]", "cve": "CVE-2021-34473", "name": "ProxyShell", "cvss": 9.8, "kev": True, "exploit": True, "fix": "Apply April/May 2021 updates"},
    {"service": "exchange", "regex": r"201[3-9]", "cve": "CVE-2022-41040", "name": "ProxyNotShell SSRF", "cvss": 8.8, "kev": True, "exploit": True, "fix": "Apply November 2022 updates"},
    # Log4j
    {"service": "java", "regex": r"log4j|2\.(0|[1-9]|1[0-4])\.", "cve": "CVE-2021-44228", "name": "Log4Shell JNDI RCE", "cvss": 10.0, "kev": True, "exploit": True, "fix": "Upgrade to Log4j 2.17.1+"},
    # Spring
    {"service": "spring", "regex": r"5\.3\.(0|[1-9]|1[0-7])$", "cve": "CVE-2022-22965", "name": "Spring4Shell RCE", "cvss": 9.8, "kev": True, "exploit": True, "fix": "Upgrade to Spring 5.3.18+"},
    {"service": "spring", "regex": r"cloud|gateway", "cve": "CVE-2022-22947", "name": "Spring Cloud Gateway RCE", "cvss": 10.0, "kev": True, "exploit": True, "fix": "Upgrade to Spring Cloud Gateway 3.1.1+"},
    # Redis
    {"service": "redis", "regex": r"[3-6]\.", "cve": "MISCONFIG", "name": "Unauthenticated Access", "cvss": 8.0, "kev": False, "exploit": True, "fix": "Enable requirepass, bind to localhost"},
    # MongoDB
    {"service": "mongodb", "regex": r"[3-5]\.", "cve": "MISCONFIG", "name": "Unauthenticated Access", "cvss": 7.5, "kev": False, "exploit": True, "fix": "Enable authentication, bind to localhost"},
    # Elasticsearch
    {"service": "elasticsearch", "regex": r"[1-7]\.", "cve": "MISCONFIG", "name": "Unauthenticated Access", "cvss": 7.5, "kev": False, "exploit": True, "fix": "Enable X-Pack security, bind to localhost"},
    {"service": "elasticsearch", "regex": r"1\.[0-4]", "cve": "CVE-2015-1427", "name": "Groovy Scripting RCE", "cvss": 9.8, "kev": False, "exploit": True, "fix": "Upgrade to Elasticsearch 1.4.3+"},
    # Jenkins
    {"service": "jenkins", "regex": r"2\.", "cve": "CVE-2024-23897", "name": "File Read via CLI", "cvss": 9.8, "kev": True, "exploit": True, "fix": "Upgrade to Jenkins 2.442+"},
    {"service": "jenkins", "regex": r"", "cve": "MISCONFIG", "name": "Script Console Exposed", "cvss": 9.8, "kev": False, "exploit": True, "fix": "Require authentication for Script Console"},
    # Docker
    {"service": "docker", "regex": r"", "cve": "MISCONFIG", "name": "Docker API Exposed", "cvss": 9.8, "kev": False, "exploit": True, "fix": "Enable TLS on Docker API, bind to localhost"},
    # Kubernetes
    {"service": "kubernetes", "regex": r"1\.", "cve": "CVE-2018-1002105", "name": "K8s Privilege Escalation", "cvss": 9.8, "kev": True, "exploit": True, "fix": "Upgrade Kubernetes"},
    # RDP
    {"service": "rdp", "regex": r"", "cve": "CVE-2019-0708", "name": "BlueKeep RCE", "cvss": 9.8, "kev": True, "exploit": True, "fix": "Patch Windows, disable RDP if not needed, enable NLA"},
    # SMB
    {"service": "smb", "regex": r"1\.0|v1", "cve": "CVE-2017-0144", "name": "EternalBlue", "cvss": 9.8, "kev": True, "exploit": True, "fix": "Disable SMBv1, apply MS17-010"},
    {"service": "smb", "regex": r"3\.0", "cve": "CVE-2020-0796", "name": "SMBGhost", "cvss": 10.0, "kev": True, "exploit": True, "fix": "Apply KB4551762"},
    # Fortinet
    {"service": "fortigate", "regex": r"7\.", "cve": "CVE-2024-21762", "name": "FortiOS SSL VPN RCE", "cvss": 9.8, "kev": True, "exploit": True, "fix": "Upgrade FortiOS"},
    {"service": "fortigate", "regex": r"[5-7]\.", "cve": "CVE-2022-42475", "name": "FortiOS Heap Overflow", "cvss": 9.8, "kev": True, "exploit": True, "fix": "Upgrade FortiOS"},
    # Palo Alto
    {"service": "panos", "regex": r"1[0-1]\.", "cve": "CVE-2024-3400", "name": "PAN-OS GlobalProtect RCE", "cvss": 10.0, "kev": True, "exploit": True, "fix": "Apply PAN-OS hotfix"},
    # Cisco
    {"service": "cisco", "regex": r"ios", "cve": "CVE-2023-20198", "name": "IOS XE Web UI Implant", "cvss": 10.0, "kev": True, "exploit": True, "fix": "Disable HTTP server, upgrade IOS XE"},
    # Ivanti
    {"service": "ivanti", "regex": r"", "cve": "CVE-2024-21887", "name": "Ivanti Connect Secure RCE", "cvss": 9.1, "kev": True, "exploit": True, "fix": "Apply Ivanti patches"},
    # Confluence
    {"service": "confluence", "regex": r"[7-8]\.", "cve": "CVE-2023-22515", "name": "Privilege Escalation to Admin", "cvss": 10.0, "kev": True, "exploit": True, "fix": "Upgrade Confluence"},
    {"service": "confluence", "regex": r"[6-7]\.", "cve": "CVE-2022-26134", "name": "OGNL Injection RCE", "cvss": 9.8, "kev": True, "exploit": True, "fix": "Upgrade Confluence"},
    # GitLab
    {"service": "gitlab", "regex": r"1[1-6]\.", "cve": "CVE-2023-7028", "name": "Account Takeover", "cvss": 10.0, "kev": True, "exploit": True, "fix": "Upgrade GitLab"},
    # vCenter
    {"service": "vcenter", "regex": r"[6-7]\.", "cve": "CVE-2021-21985", "name": "vSAN RCE", "cvss": 9.8, "kev": True, "exploit": True, "fix": "Upgrade vCenter"},
    # Citrix
    {"service": "citrix", "regex": r"", "cve": "CVE-2023-4966", "name": "Citrix Bleed", "cvss": 9.4, "kev": True, "exploit": True, "fix": "Upgrade NetScaler"},
    # MOVEit
    {"service": "moveit", "regex": r"", "cve": "CVE-2023-34362", "name": "MOVEit Transfer SQLi RCE", "cvss": 9.8, "kev": True, "exploit": True, "fix": "Upgrade MOVEit Transfer"},
    # F5
    {"service": "f5", "regex": r"", "cve": "CVE-2022-1388", "name": "BIG-IP iControl REST RCE", "cvss": 9.8, "kev": True, "exploit": True, "fix": "Upgrade BIG-IP"},
    # Struts
    {"service": "struts", "regex": r"2\.", "cve": "CVE-2017-5638", "name": "Jakarta Multipart RCE", "cvss": 10.0, "kev": True, "exploit": True, "fix": "Upgrade to Struts 2.5.10.1+"},
    # WebLogic
    {"service": "weblogic", "regex": r"1[0-4]\.", "cve": "CVE-2019-2725", "name": "Deserialization RCE", "cvss": 9.8, "kev": True, "exploit": True, "fix": "Apply Oracle patch"},
    # ActiveMQ
    {"service": "activemq", "regex": r"5\.", "cve": "CVE-2023-46604", "name": "ClassInfo RCE", "cvss": 10.0, "kev": True, "exploit": True, "fix": "Upgrade to ActiveMQ 5.18.3+"},
    # Grafana
    {"service": "grafana", "regex": r"[7-8]\.", "cve": "CVE-2021-43798", "name": "Path Traversal", "cvss": 7.5, "kev": True, "exploit": True, "fix": "Upgrade to Grafana 8.3.1+"},
    # Telerik
    {"service": "telerik", "regex": r"", "cve": "CVE-2019-18935", "name": "Deserialization RCE", "cvss": 9.8, "kev": True, "exploit": True, "fix": "Upgrade Telerik UI"},
    # PHP
    {"service": "php", "regex": r"[5-7]\.", "cve": "CVE-2024-4577", "name": "PHP-CGI Argument Injection", "cvss": 9.8, "kev": True, "exploit": True, "fix": "Upgrade PHP, disable CGI mode"},
    # Solr
    {"service": "solr", "regex": r"[5-8]\.", "cve": "CVE-2019-17558", "name": "Velocity Template RCE", "cvss": 9.8, "kev": False, "exploit": True, "fix": "Upgrade Apache Solr"},
    # Hadoop
    {"service": "hadoop", "regex": r"", "cve": "MISCONFIG", "name": "YARN Unauthenticated RCE", "cvss": 9.8, "kev": False, "exploit": True, "fix": "Enable Kerberos authentication"},
    # Consul
    {"service": "consul", "regex": r"1\.", "cve": "MISCONFIG", "name": "Consul API Unauthenticated", "cvss": 8.0, "kev": False, "exploit": True, "fix": "Enable ACLs"},
    # etcd
    {"service": "etcd", "regex": r"3\.", "cve": "MISCONFIG", "name": "etcd Unauthenticated", "cvss": 9.0, "kev": False, "exploit": True, "fix": "Enable client cert auth"},
    # Prometheus
    {"service": "prometheus", "regex": r"2\.", "cve": "MISCONFIG", "name": "Prometheus Unauthenticated", "cvss": 5.3, "kev": False, "exploit": False, "fix": "Put behind reverse proxy with auth"},
    # RabbitMQ
    {"service": "rabbitmq", "regex": r"3\.", "cve": "MISCONFIG", "name": "Default Credentials (guest/guest)", "cvss": 7.5, "kev": False, "exploit": True, "fix": "Change default password, restrict guest to localhost"},
    # Zabbix
    {"service": "zabbix", "regex": r"[4-6]\.", "cve": "CVE-2022-23131", "name": "SAML SSO Auth Bypass", "cvss": 9.8, "kev": True, "exploit": True, "fix": "Upgrade Zabbix"},
]

class VulnScanner:
    name = "Vulnerability Scanner"
    description = "Match discovered services against CVE database, check exploits, CISA KEV, and provide remediation"
    category = "vuln"
    mitre = ["T1595.002", "T1190"]

    def __init__(self, target, options=None):
        self.target = target
        self.options = options or {}
        self.findings = []
        self.services = options.get("services", []) if options else []

    def _add(self, severity, title, detail, evidence="", mitre=""):
        self.findings.append({
            "severity": severity, "title": title, "detail": detail,
            "evidence": evidence, "mitre": mitre,
            "timestamp": datetime.utcnow().isoformat(), "module": self.name
        })

    def _match_version(self, service_name, version):
        matches = []
        svc_lower = service_name.lower()
        for entry in CVE_DB:
            if entry["service"] not in svc_lower and svc_lower not in entry["service"]:
                continue
            if entry["regex"]:
                if not re.search(entry["regex"], version, re.IGNORECASE):
                    continue
            matches.append(entry)
        return matches

    def scan_services(self, services=None):
        if services:
            self.services = services
        if not self.services:
            self._add("info", "No services to scan", "Run active recon first to discover services")
            return
        total_vulns = 0
        for svc in self.services:
            svc_name = svc.get("service", svc.get("product", ""))
            version = svc.get("version", svc.get("product", ""))
            port = svc.get("port", "?")
            banner = f"{svc.get('product', '')} {version}".strip()
            full_str = f"{svc_name} {banner}"
            matches = self._match_version(full_str, full_str)
            for m in matches:
                severity = "critical" if m["cvss"] >= 9.0 else "high" if m["cvss"] >= 7.0 else "medium" if m["cvss"] >= 4.0 else "low"
                kev_str = " [CISA KEV]" if m["kev"] else ""
                exploit_str = " [Exploit Available]" if m["exploit"] else ""
                detail = f"CVE: {m['cve']}\nCVSS: {m['cvss']}\nName: {m['name']}\nService: {svc_name} on port {port}\nVersion: {version or 'unknown'}{kev_str}{exploit_str}\n\nRemediation: {m['fix']}"
                self._add(severity, f"{m['cve']}: {m['name']} (CVSS {m['cvss']})", detail, banner, "T1190")
                total_vulns += 1
        self._add("info", f"Vulnerability scan complete: {total_vulns} CVEs matched across {len(self.services)} services", f"Target: {self.target}", "", "T1595.002")

    def searchsploit_check(self, confirm_fn=None):
        if not _has("searchsploit"):
            return
        for svc in self.services:
            product = svc.get("product", svc.get("service", ""))
            version = svc.get("version", "")
            if not product:
                continue
            query = f"{product} {version}".strip()
            cmd = f'searchsploit --json "{query}"'
            if confirm_fn and not confirm_fn(f"Search exploits: {cmd}"):
                continue
            out, _, rc = _run(cmd, timeout=15)
            if rc == 0 and out:
                try:
                    data = json.loads(out)
                    exploits = data.get("RESULTS_EXPLOIT", [])
                    if exploits:
                        detail = f"Found {len(exploits)} exploits for {query}:\n"
                        for e in exploits[:10]:
                            detail += f"  - {e.get('Title', '?')} [{e.get('Path', '?')}]\n"
                        self._add("high", f"Exploits found: {query} ({len(exploits)})", detail, "", "T1190")
                except json.JSONDecodeError:
                    pass

    def nuclei_scan(self, confirm_fn=None):
        if not _has("nuclei"):
            return
        cmd = f"nuclei -u {self.target} -severity critical,high -silent -json"
        if confirm_fn and not confirm_fn(f"Run nuclei scan: {cmd}"):
            return
        out, _, rc = _run(cmd, timeout=300)
        if rc == 0 and out:
            for line in out.splitlines():
                try:
                    result = json.loads(line)
                    name = result.get("info", {}).get("name", "unknown")
                    severity = result.get("info", {}).get("severity", "medium")
                    matched = result.get("matched-at", "")
                    self._add(severity, f"Nuclei: {name}", f"Matched: {matched}", line[:500], "T1190")
                except json.JSONDecodeError:
                    continue

    def run(self, confirm_fn=None):
        print(f"\n[AEGIS] Vulnerability Scanner: {self.target}")
        print("=" * 60)
        self.scan_services()
        self.searchsploit_check(confirm_fn)
        if self.options.get("nuclei"):
            self.nuclei_scan(confirm_fn)
        crit = len([f for f in self.findings if f["severity"] == "critical"])
        high = len([f for f in self.findings if f["severity"] == "high"])
        print(f"\n[AEGIS] Vuln scan complete: {len(self.findings)} findings ({crit} critical, {high} high)")
        return self.findings

    def get_findings(self):
        return self.findings


if __name__ == "__main__":
    print("Usage: Import and pass service list from active-recon results")
    print("Example services: [{'service': 'apache', 'version': '2.4.49', 'port': 80}]")
    example_services = [
        {"service": "apache", "product": "Apache httpd", "version": "2.4.49", "port": 80},
        {"service": "openssh", "product": "OpenSSH", "version": "8.5p1", "port": 22},
        {"service": "mysql", "product": "MySQL", "version": "5.7.34", "port": 3306},
    ]
    mod = VulnScanner("example.com", {"services": example_services})
    findings = mod.run()
    for f in findings:
        sev = f["severity"].upper()
        color = {"critical": "\033[91m", "high": "\033[91m", "medium": "\033[93m", "low": "\033[94m", "info": "\033[90m"}.get(f["severity"], "")
        print(f"  {color}[{sev:8s}]\033[0m {f['title']}")
