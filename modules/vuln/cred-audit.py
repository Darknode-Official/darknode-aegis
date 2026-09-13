#!/usr/bin/env python3
"""AEGIS Credential Audit Module
Default credential testing, anonymous access checks, SNMP community strings.
Integrates with hydra for brute force (with user confirmation).
"""
import subprocess, json, os, sys, re, socket
from datetime import datetime

def _run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except:
        return "", "", 1

def _has(tool):
    return subprocess.run(["which", tool], capture_output=True).returncode == 0

DEFAULT_CREDS = {
    "ssh": [("root", "root"), ("root", "toor"), ("root", "password"), ("root", "123456"), ("admin", "admin"), ("admin", "password"), ("admin", "admin123"), ("user", "user"), ("guest", "guest"), ("pi", "raspberry"), ("ubuntu", "ubuntu"), ("vagrant", "vagrant"), ("deploy", "deploy"), ("test", "test")],
    "ftp": [("anonymous", ""), ("anonymous", "anonymous"), ("ftp", "ftp"), ("admin", "admin"), ("user", "user"), ("guest", "guest")],
    "telnet": [("admin", "admin"), ("root", "root"), ("admin", "password"), ("admin", "1234"), ("cisco", "cisco"), ("enable", "enable")],
    "mysql": [("root", ""), ("root", "root"), ("root", "mysql"), ("root", "password"), ("root", "toor"), ("admin", "admin"), ("dbadmin", "dbadmin"), ("test", "test")],
    "mssql": [("sa", ""), ("sa", "sa"), ("sa", "password"), ("sa", "P@ssw0rd"), ("sa", "sa123456")],
    "postgresql": [("postgres", "postgres"), ("postgres", "password"), ("postgres", ""), ("admin", "admin")],
    "mongodb": [("admin", "admin"), ("admin", "password"), ("root", "root"), ("", "")],
    "redis": [("", ""), ("", "redis"), ("", "password")],
    "snmp": [("public", ""), ("private", ""), ("community", ""), ("manager", ""), ("default", ""), ("monitor", ""), ("cisco", ""), ("admin", ""), ("snmpd", ""), ("system", "")],
    "tomcat": [("tomcat", "tomcat"), ("admin", "admin"), ("manager", "manager"), ("admin", "password"), ("tomcat", "s3cret"), ("role1", "role1"), ("both", "tomcat")],
    "jenkins": [("admin", "admin"), ("admin", "password"), ("admin", "jenkins"), ("jenkins", "jenkins")],
    "wordpress": [("admin", "admin"), ("admin", "password"), ("admin", "wordpress"), ("admin", "admin123"), ("editor", "editor")],
    "phpmyadmin": [("root", ""), ("root", "root"), ("pma", ""), ("admin", "admin")],
    "grafana": [("admin", "admin"), ("admin", "grafana"), ("admin", "password")],
    "kibana": [("elastic", "changeme"), ("elastic", "elastic"), ("admin", "admin")],
    "rabbitmq": [("guest", "guest"), ("admin", "admin"), ("rabbitmq", "rabbitmq")],
    "vnc": [("", "password"), ("", "vnc"), ("", "1234"), ("", "admin")],
}

class CredAudit:
    name = "Credential Audit"
    description = "Default credential testing, anonymous access checks, SNMP community strings"
    category = "vuln"
    mitre = ["T1110", "T1078.001"]

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

    def _confirm(self, action, confirm_fn):
        if confirm_fn:
            return confirm_fn(action)
        return True

    def _tcp_connect(self, host, port, timeout=3):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            s.close()
            return result == 0
        except:
            return False

    def _try_ssh(self, host, user, password, port=22):
        if _has("sshpass"):
            cmd = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p {port} {user}@{host} 'echo SUCCESS' 2>/dev/null"
            out, _, rc = _run(cmd, timeout=10)
            return "SUCCESS" in out
        return None

    def _try_mysql(self, host, user, password, port=3306):
        if _has("mysql"):
            cmd = f"mysql -h {host} -P {port} -u {user} --password='{password}' -e 'SELECT 1' 2>/dev/null"
            out, _, rc = _run(cmd, timeout=10)
            return rc == 0
        return None

    def _try_ftp(self, host, user, password, port=21):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, port))
            banner = s.recv(1024).decode("utf-8", errors="replace")
            s.send(f"USER {user}\r\n".encode())
            resp = s.recv(1024).decode("utf-8", errors="replace")
            s.send(f"PASS {password}\r\n".encode())
            resp = s.recv(1024).decode("utf-8", errors="replace")
            s.send(b"QUIT\r\n")
            s.close()
            return "230" in resp
        except:
            return False

    def _try_redis(self, host, password="", port=6379):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, port))
            if password:
                s.send(f"AUTH {password}\r\n".encode())
                resp = s.recv(1024).decode("utf-8", errors="replace")
                if "+OK" not in resp:
                    s.close()
                    return False
            s.send(b"INFO server\r\n")
            resp = s.recv(4096).decode("utf-8", errors="replace")
            s.close()
            return "redis_version" in resp
        except:
            return False

    def _try_snmp(self, host, community, port=161):
        if _has("snmpwalk"):
            cmd = f"snmpwalk -v2c -c {community} {host} system.sysDescr.0 2>/dev/null"
            out, _, rc = _run(cmd, timeout=10)
            return rc == 0 and out and "Timeout" not in out
        return None

    def anonymous_ftp(self, confirm_fn=None):
        if not self._tcp_connect(self.target, 21):
            return
        action = f"Test anonymous FTP access on {self.target}:21"
        if not self._confirm(action, confirm_fn):
            return
        if self._try_ftp(self.target, "anonymous", ""):
            self._add("high", "Anonymous FTP access", f"FTP on {self.target}:21 allows anonymous login\nAttacker can list and potentially download files", "", "T1078.001")
        else:
            self._add("info", "Anonymous FTP denied", "FTP requires authentication")

    def anonymous_smb(self, confirm_fn=None):
        if not self._tcp_connect(self.target, 445):
            return
        if not _has("smbclient"):
            return
        action = f"Test anonymous SMB access on {self.target}"
        if not self._confirm(action, confirm_fn):
            return
        cmd = f"smbclient -L //{self.target} -N 2>/dev/null"
        out, _, rc = _run(cmd, timeout=10)
        if rc == 0 and "Sharename" in out:
            shares = re.findall(r'^\s+(\S+)\s+Disk', out, re.MULTILINE)
            self._add("high", f"Anonymous SMB: {len(shares)} shares listed", f"Shares: {', '.join(shares)}\n\n{out[:1000]}", "", "T1078.001")
        else:
            self._add("info", "Anonymous SMB denied", "SMB requires authentication")

    def redis_unauth(self, confirm_fn=None):
        if not self._tcp_connect(self.target, 6379):
            return
        action = f"Test unauthenticated Redis access on {self.target}:6379"
        if not self._confirm(action, confirm_fn):
            return
        if self._try_redis(self.target):
            self._add("critical", "Redis unauthenticated access", f"Redis on {self.target}:6379 allows unauthenticated access\nAttacker can read/write data, potentially achieve RCE via SSH key injection or module loading", "", "T1078.001")

    def mongodb_unauth(self, confirm_fn=None):
        if not self._tcp_connect(self.target, 27017):
            return
        if not _has("mongosh") and not _has("mongo"):
            return
        action = f"Test unauthenticated MongoDB access on {self.target}:27017"
        if not self._confirm(action, confirm_fn):
            return
        tool = "mongosh" if _has("mongosh") else "mongo"
        cmd = f'{tool} --host {self.target} --eval "db.adminCommand({{listDatabases:1}})" --quiet 2>/dev/null'
        out, _, rc = _run(cmd, timeout=10)
        if rc == 0 and "databases" in out:
            self._add("critical", "MongoDB unauthenticated access", f"MongoDB on {self.target}:27017 allows unauthenticated access\n{out[:500]}", "", "T1078.001")

    def snmp_community(self, confirm_fn=None):
        if not self._tcp_connect(self.target, 161):
            if not _has("snmpwalk"):
                return
        action = f"Test {len(DEFAULT_CREDS['snmp'])} SNMP community strings on {self.target}"
        if not self._confirm(action, confirm_fn):
            return
        for community, _ in DEFAULT_CREDS["snmp"]:
            result = self._try_snmp(self.target, community)
            if result:
                self._add("high", f"SNMP community string accepted: '{community}'", f"SNMP on {self.target}:161 accepts community string '{community}'\nAttacker can enumerate network configuration, routing tables, ARP tables", "", "T1078.001")

    def default_cred_test(self, service, port, confirm_fn=None):
        creds = DEFAULT_CREDS.get(service, [])
        if not creds:
            return
        action = f"Test {len(creds)} default credentials for {service} on {self.target}:{port}"
        if not self._confirm(action, confirm_fn):
            return
        for user, password in creds:
            result = None
            if service == "ssh":
                result = self._try_ssh(self.target, user, password, port)
            elif service == "mysql":
                result = self._try_mysql(self.target, user, password, port)
            elif service == "ftp":
                result = self._try_ftp(self.target, user, password, port)
            elif service == "redis":
                result = self._try_redis(self.target, password, port)
            if result is True:
                pw_display = password if password else "(empty)"
                self._add("critical", f"Default credentials: {service} {user}:{pw_display}", f"Service: {service} on {self.target}:{port}\nUsername: {user}\nPassword: {pw_display}\nIMPACT: Full access to {service}", "", "T1078.001")
                return
            elif result is None:
                break

    def hydra_brute(self, service, port, confirm_fn=None):
        if not _has("hydra"):
            return
        wordlist = "/usr/share/wordlists/rockyou.txt"
        if not os.path.exists(wordlist):
            wordlist = "/usr/share/seclists/Passwords/Common-Credentials/top-1000.txt"
        if not os.path.exists(wordlist):
            return
        action = f"Run hydra brute force against {service} on {self.target}:{port} (using top passwords)"
        if not self._confirm(action, confirm_fn):
            return
        cmd = f"hydra -l admin -P {wordlist} -t 4 -f -vV {self.target} {service} -s {port} 2>/dev/null"
        out, _, rc = _run(cmd, timeout=120)
        if "successfully completed" in out.lower() or "1 valid password found" in out.lower():
            match = re.search(r'login:\s*(\S+)\s+password:\s*(\S+)', out)
            if match:
                self._add("critical", f"Brute force success: {service} {match.group(1)}:{match.group(2)}", f"Hydra found valid credentials\n{out[:500]}", "", "T1110")

    def run(self, confirm_fn=None):
        print(f"\n[AEGIS] Credential Audit: {self.target}")
        print("=" * 60)
        self.anonymous_ftp(confirm_fn)
        self.anonymous_smb(confirm_fn)
        self.redis_unauth(confirm_fn)
        self.mongodb_unauth(confirm_fn)
        self.snmp_community(confirm_fn)
        svc_port_map = {"ssh": 22, "ftp": 21, "mysql": 3306, "mssql": 1433, "postgresql": 5432, "tomcat": 8080, "jenkins": 8080, "redis": 6379}
        for svc in self.services:
            svc_name = svc.get("service", "").lower()
            port = svc.get("port", svc_port_map.get(svc_name, 0))
            if svc_name in DEFAULT_CREDS:
                self.default_cred_test(svc_name, port, confirm_fn)
        print(f"\n[AEGIS] Credential audit complete: {len(self.findings)} findings")
        return self.findings

    def get_findings(self):
        return self.findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 cred-audit.py <target>")
        sys.exit(1)
    def confirm(action):
        resp = input(f"\n[?] {action}\n    Execute? [y/n]: ").strip().lower()
        return resp in ("y", "yes")
    mod = CredAudit(sys.argv[1])
    mod.run(confirm_fn=confirm)
    for f in mod.get_findings():
        sev = f["severity"].upper()
        color = {"critical": "\033[91m", "high": "\033[91m", "medium": "\033[93m", "low": "\033[94m", "info": "\033[90m"}.get(f["severity"], "")
        print(f"  {color}[{sev:8s}]\033[0m {f['title']}")
