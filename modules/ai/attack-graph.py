#!/usr/bin/env python3
"""Attack graph generator and analyzer — maps all possible attack paths through a network"""
import json, os, sys, hashlib, copy
from datetime import datetime
from collections import defaultdict, deque

# =============================================================================
# VULNERABILITY-TO-TECHNIQUE MAPPING
# =============================================================================
VULN_TECHNIQUES = [
    {"service": "smb", "version": "1.0", "technique": "EternalBlue", "mitre": "T1210", "probability": 0.95, "prereq": "network_access", "result": "system_shell", "cvss": 9.8},
    {"service": "smb", "version": "2.0", "technique": "SMBGhost", "mitre": "T1210", "probability": 0.7, "prereq": "network_access", "result": "system_shell", "cvss": 10.0},
    {"service": "smb", "version": "*", "technique": "Anonymous Share Access", "mitre": "T1135", "probability": 0.6, "prereq": "network_access", "result": "info_disclosure", "cvss": 5.3},
    {"service": "exchange", "version": "2013-2019", "technique": "ProxyLogon", "mitre": "T1190", "probability": 0.9, "prereq": "network_access", "result": "system_shell", "cvss": 9.8},
    {"service": "exchange", "version": "2013-2019", "technique": "ProxyShell", "mitre": "T1190", "probability": 0.85, "prereq": "network_access", "result": "system_shell", "cvss": 9.8},
    {"service": "apache", "version": "2.4.49", "technique": "Path Traversal RCE", "mitre": "T1190", "probability": 0.95, "prereq": "network_access", "result": "user_shell", "cvss": 9.8},
    {"service": "java", "version": "log4j", "technique": "Log4Shell", "mitre": "T1190", "probability": 0.85, "prereq": "network_access", "result": "user_shell", "cvss": 10.0},
    {"service": "spring", "version": "5.3.x", "technique": "Spring4Shell", "mitre": "T1190", "probability": 0.7, "prereq": "network_access", "result": "user_shell", "cvss": 9.8},
    {"service": "ssh", "version": "*", "technique": "SSH Brute Force", "mitre": "T1110", "probability": 0.3, "prereq": "network_access", "result": "user_shell", "cvss": 7.5},
    {"service": "ssh", "version": "*", "technique": "SSH Key Reuse", "mitre": "T1021.004", "probability": 0.7, "prereq": "ssh_key", "result": "user_shell", "cvss": 8.0},
    {"service": "rdp", "version": "7.x", "technique": "BlueKeep", "mitre": "T1210", "probability": 0.5, "prereq": "network_access", "result": "system_shell", "cvss": 9.8},
    {"service": "rdp", "version": "*", "technique": "RDP Brute Force", "mitre": "T1110", "probability": 0.25, "prereq": "network_access", "result": "user_shell", "cvss": 7.5},
    {"service": "rdp", "version": "*", "technique": "RDP Pass-the-Hash", "mitre": "T1550.002", "probability": 0.8, "prereq": "ntlm_hash", "result": "user_shell", "cvss": 8.5},
    {"service": "mysql", "version": "*", "technique": "MySQL Default Creds", "mitre": "T1078", "probability": 0.4, "prereq": "network_access", "result": "db_access", "cvss": 7.5},
    {"service": "mssql", "version": "*", "technique": "MSSQL xp_cmdshell", "mitre": "T1059", "probability": 0.5, "prereq": "db_access", "result": "system_shell", "cvss": 8.0},
    {"service": "ftp", "version": "*", "technique": "Anonymous FTP", "mitre": "T1078", "probability": 0.5, "prereq": "network_access", "result": "info_disclosure", "cvss": 5.3},
    {"service": "redis", "version": "*", "technique": "Redis Unauthenticated", "mitre": "T1190", "probability": 0.8, "prereq": "network_access", "result": "system_shell", "cvss": 8.0},
    {"service": "docker", "version": "*", "technique": "Docker API Exposed", "mitre": "T1610", "probability": 0.9, "prereq": "network_access", "result": "system_shell", "cvss": 9.8},
    {"service": "jenkins", "version": "*", "technique": "Jenkins Script Console", "mitre": "T1059", "probability": 0.7, "prereq": "network_access", "result": "user_shell", "cvss": 9.8},
    {"service": "kubernetes", "version": "*", "technique": "K8s API Unauth", "mitre": "T1610", "probability": 0.6, "prereq": "network_access", "result": "system_shell", "cvss": 9.8},
    {"service": "tomcat", "version": "*", "technique": "Tomcat Manager Default Creds", "mitre": "T1078", "probability": 0.5, "prereq": "network_access", "result": "user_shell", "cvss": 7.5},
    {"service": "elasticsearch", "version": "*", "technique": "Elasticsearch Open", "mitre": "T1190", "probability": 0.9, "prereq": "network_access", "result": "info_disclosure", "cvss": 7.5},
    {"service": "ldap", "version": "*", "technique": "LDAP Anonymous Bind", "mitre": "T1087", "probability": 0.5, "prereq": "network_access", "result": "info_disclosure", "cvss": 5.3},
    {"service": "kerberos", "version": "*", "technique": "Kerberoasting", "mitre": "T1558.003", "probability": 0.8, "prereq": "domain_user", "result": "credential_access", "cvss": 7.5},
    {"service": "kerberos", "version": "*", "technique": "AS-REP Roasting", "mitre": "T1558.004", "probability": 0.7, "prereq": "network_access", "result": "credential_access", "cvss": 7.5},
    {"service": "netlogon", "version": "*", "technique": "ZeroLogon", "mitre": "T1068", "probability": 0.9, "prereq": "network_access", "result": "domain_admin", "cvss": 10.0},
    {"service": "http", "version": "*", "technique": "SQL Injection", "mitre": "T1190", "probability": 0.5, "prereq": "network_access", "result": "db_access", "cvss": 8.6},
    {"service": "http", "version": "*", "technique": "Command Injection", "mitre": "T1059", "probability": 0.4, "prereq": "network_access", "result": "user_shell", "cvss": 9.8},
    {"service": "http", "version": "*", "technique": "SSRF", "mitre": "T1190", "probability": 0.4, "prereq": "network_access", "result": "internal_access", "cvss": 7.5},
    {"service": "nfs", "version": "*", "technique": "NFS no_root_squash", "mitre": "T1078", "probability": 0.7, "prereq": "network_access", "result": "system_shell", "cvss": 7.5},
    {"service": "snmp", "version": "*", "technique": "SNMP Default Community", "mitre": "T1078", "probability": 0.6, "prereq": "network_access", "result": "info_disclosure", "cvss": 7.5},
    {"service": "modbus", "version": "*", "technique": "Modbus Unauthenticated", "mitre": "T0831", "probability": 0.9, "prereq": "network_access", "result": "ics_control", "cvss": 9.1},
    {"service": "dnp3", "version": "*", "technique": "DNP3 No Auth", "mitre": "T0831", "probability": 0.85, "prereq": "network_access", "result": "ics_control", "cvss": 9.1},
    {"service": "s7comm", "version": "*", "technique": "S7comm Unauthenticated", "mitre": "T0831", "probability": 0.9, "prereq": "network_access", "result": "ics_control", "cvss": 9.1},
    {"service": "imds", "version": "v1", "technique": "IMDS Credential Theft", "mitre": "T1552", "probability": 0.9, "prereq": "ssrf", "result": "cloud_creds", "cvss": 7.5},
    {"service": "s3", "version": "*", "technique": "S3 Bucket Public", "mitre": "T1530", "probability": 0.8, "prereq": "network_access", "result": "info_disclosure", "cvss": 7.5},
]

LATERAL_TECHNIQUES = [
    {"name": "Pass-the-Hash", "mitre": "T1550.002", "prereq": "ntlm_hash", "probability": 0.8, "target_os": "windows"},
    {"name": "Pass-the-Ticket", "mitre": "T1550.003", "prereq": "krb_ticket", "probability": 0.7, "target_os": "windows"},
    {"name": "PsExec", "mitre": "T1569.002", "prereq": "admin_creds", "probability": 0.9, "target_os": "windows"},
    {"name": "WMI Exec", "mitre": "T1047", "prereq": "admin_creds", "probability": 0.85, "target_os": "windows"},
    {"name": "WinRM", "mitre": "T1021.006", "prereq": "admin_creds", "probability": 0.85, "target_os": "windows"},
    {"name": "SSH Key Pivot", "mitre": "T1021.004", "prereq": "ssh_key", "probability": 0.9, "target_os": "linux"},
    {"name": "SSH Password", "mitre": "T1021.004", "prereq": "password", "probability": 0.8, "target_os": "linux"},
    {"name": "RDP Lateral", "mitre": "T1021.001", "prereq": "admin_creds", "probability": 0.8, "target_os": "windows"},
    {"name": "DCOM", "mitre": "T1021.003", "prereq": "admin_creds", "probability": 0.7, "target_os": "windows"},
    {"name": "Golden Ticket", "mitre": "T1558.001", "prereq": "krbtgt_hash", "probability": 0.95, "target_os": "windows"},
    {"name": "DCSync", "mitre": "T1003.006", "prereq": "domain_admin", "probability": 0.95, "target_os": "windows"},
]

PRIVESC_TECHNIQUES = [
    {"name": "Kernel Exploit", "mitre": "T1068", "probability": 0.4, "os": "any", "prereq": "user_shell", "result": "system_shell"},
    {"name": "SUID Binary", "mitre": "T1548.001", "probability": 0.5, "os": "linux", "prereq": "user_shell", "result": "system_shell"},
    {"name": "Sudo Misconfiguration", "mitre": "T1548.003", "probability": 0.4, "os": "linux", "prereq": "user_shell", "result": "system_shell"},
    {"name": "Token Impersonation", "mitre": "T1134", "probability": 0.6, "os": "windows", "prereq": "user_shell", "result": "system_shell"},
    {"name": "Unquoted Service Path", "mitre": "T1574.009", "probability": 0.3, "os": "windows", "prereq": "user_shell", "result": "system_shell"},
    {"name": "DLL Hijacking", "mitre": "T1574.001", "probability": 0.4, "os": "windows", "prereq": "user_shell", "result": "system_shell"},
    {"name": "UAC Bypass", "mitre": "T1548.002", "probability": 0.6, "os": "windows", "prereq": "user_shell", "result": "admin_shell"},
    {"name": "Docker Group", "mitre": "T1611", "probability": 0.9, "os": "linux", "prereq": "user_shell", "result": "system_shell"},
    {"name": "Cron Job Abuse", "mitre": "T1053.003", "probability": 0.3, "os": "linux", "prereq": "user_shell", "result": "system_shell"},
]

CRED_HARVEST_TECHNIQUES = [
    {"name": "Mimikatz logonpasswords", "mitre": "T1003.001", "prereq": "system_shell", "result": ["ntlm_hash", "password", "krb_ticket"], "os": "windows"},
    {"name": "SAM Dump", "mitre": "T1003.002", "prereq": "system_shell", "result": ["ntlm_hash"], "os": "windows"},
    {"name": "DCSync", "mitre": "T1003.006", "prereq": "domain_admin", "result": ["ntlm_hash", "krbtgt_hash"], "os": "windows"},
    {"name": "/etc/shadow", "mitre": "T1003.008", "prereq": "system_shell", "result": ["password_hash"], "os": "linux"},
    {"name": "SSH Key Theft", "mitre": "T1552.004", "prereq": "user_shell", "result": ["ssh_key"], "os": "linux"},
    {"name": "Browser Credentials", "mitre": "T1555.003", "prereq": "user_shell", "result": ["password"], "os": "any"},
    {"name": "Kerberoasting", "mitre": "T1558.003", "prereq": "domain_user", "result": ["password"], "os": "windows"},
    {"name": "DPAPI Secrets", "mitre": "T1555.004", "prereq": "system_shell", "result": ["password"], "os": "windows"},
    {"name": "Cloud Metadata", "mitre": "T1552.005", "prereq": "ssrf", "result": ["cloud_creds"], "os": "any"},
]

# =============================================================================
# NETWORK TOPOLOGY TEMPLATES
# =============================================================================
TEMPLATES = {
    "corporate": {
        "name": "Corporate Network",
        "hosts": [
            {"id": "fw", "name": "Firewall", "os": "linux", "role": "perimeter", "value": 9, "services": [], "segment": "perimeter"},
            {"id": "dc01", "name": "DC-01", "os": "windows", "role": "domain_controller", "value": 10, "services": ["ldap", "kerberos", "smb", "dns", "netlogon"], "segment": "servers"},
            {"id": "web01", "name": "WEB-01", "os": "linux", "role": "web_server", "value": 6, "services": ["http", "ssh", "apache"], "segment": "dmz"},
            {"id": "app01", "name": "APP-01", "os": "linux", "role": "app_server", "value": 7, "services": ["java", "ssh", "tomcat"], "segment": "servers"},
            {"id": "db01", "name": "DB-01", "os": "linux", "role": "database", "value": 9, "services": ["mysql", "ssh"], "segment": "data"},
            {"id": "mail01", "name": "MAIL-01", "os": "windows", "role": "mail_server", "value": 8, "services": ["exchange", "smb"], "segment": "dmz"},
            {"id": "ws01", "name": "WS-01", "os": "windows", "role": "workstation", "value": 5, "services": ["smb", "rdp"], "segment": "workstations"},
            {"id": "ws02", "name": "WS-02", "os": "windows", "role": "workstation", "value": 4, "services": ["smb", "rdp"], "segment": "workstations"},
            {"id": "jenkins", "name": "CI-01", "os": "linux", "role": "cicd", "value": 7, "services": ["jenkins", "ssh"], "segment": "servers"},
            {"id": "backup", "name": "BKP-01", "os": "linux", "role": "backup", "value": 8, "services": ["ssh", "nfs", "ftp"], "segment": "servers"},
        ],
        "connections": [
            ("fw", "web01"), ("fw", "mail01"), ("web01", "app01"), ("app01", "db01"),
            ("dc01", "ws01"), ("dc01", "ws02"), ("dc01", "mail01"), ("dc01", "app01"),
            ("dc01", "jenkins"), ("dc01", "backup"), ("ws01", "jenkins"), ("ws01", "db01"),
            ("backup", "db01"), ("backup", "dc01"),
        ],
        "entry_points": ["web01", "mail01"],
        "objectives": ["dc01", "db01"],
    },
    "cloud": {
        "name": "AWS Cloud",
        "hosts": [
            {"id": "alb", "name": "ALB", "os": "aws", "role": "load_balancer", "value": 5, "services": ["http"], "segment": "public"},
            {"id": "ec2web", "name": "EC2-WEB", "os": "linux", "role": "web_server", "value": 6, "services": ["http", "ssh", "imds"], "segment": "private"},
            {"id": "ec2api", "name": "EC2-API", "os": "linux", "role": "api_server", "value": 7, "services": ["spring", "ssh", "imds"], "segment": "private"},
            {"id": "rds", "name": "RDS", "os": "linux", "role": "database", "value": 9, "services": ["mysql"], "segment": "data"},
            {"id": "s3", "name": "S3-BACKUP", "os": "aws", "role": "storage", "value": 8, "services": ["s3"], "segment": "storage"},
            {"id": "lambda", "name": "LAMBDA", "os": "aws", "role": "serverless", "value": 5, "services": ["http"], "segment": "compute"},
            {"id": "iam", "name": "IAM", "os": "aws", "role": "identity", "value": 10, "services": [], "segment": "management"},
        ],
        "connections": [
            ("alb", "ec2web"), ("alb", "ec2api"), ("ec2web", "rds"), ("ec2api", "rds"),
            ("ec2web", "s3"), ("ec2api", "lambda"), ("lambda", "rds"),
        ],
        "entry_points": ["ec2web", "ec2api"],
        "objectives": ["rds", "iam"],
    },
    "ics": {
        "name": "ICS/SCADA",
        "hosts": [
            {"id": "icsfw", "name": "ICS-FW", "os": "linux", "role": "perimeter", "value": 9, "services": [], "segment": "perimeter"},
            {"id": "historian", "name": "HIST-01", "os": "windows", "role": "historian", "value": 7, "services": ["mssql", "http", "smb"], "segment": "ics_dmz"},
            {"id": "hmi01", "name": "HMI-01", "os": "windows", "role": "hmi", "value": 8, "services": ["rdp", "smb", "http"], "segment": "ics_control"},
            {"id": "ews", "name": "EWS-01", "os": "windows", "role": "engineering", "value": 9, "services": ["smb", "rdp"], "segment": "ics_control"},
            {"id": "plc01", "name": "PLC-01", "os": "firmware", "role": "plc", "value": 10, "services": ["modbus", "s7comm"], "segment": "ics_field"},
            {"id": "plc02", "name": "PLC-02", "os": "firmware", "role": "plc", "value": 10, "services": ["modbus"], "segment": "ics_field"},
            {"id": "rtu", "name": "RTU-01", "os": "firmware", "role": "rtu", "value": 10, "services": ["dnp3"], "segment": "ics_field"},
        ],
        "connections": [
            ("icsfw", "historian"), ("historian", "hmi01"), ("historian", "ews"),
            ("hmi01", "plc01"), ("hmi01", "plc02"), ("ews", "plc01"), ("ews", "plc02"), ("ews", "rtu"),
        ],
        "entry_points": ["historian"],
        "objectives": ["plc01", "plc02", "rtu"],
    },
}

# =============================================================================
# ATTACK GRAPH ENGINE
# =============================================================================
class AttackGraph:
    name = "Attack Graph Generator"
    description = "Generate and analyze all possible attack paths through a network"
    category = "ai"
    mitre = ["T1595", "T1190", "T1210"]

    def __init__(self, topology=None):
        self.hosts = {}
        self.connections = set()
        self.edges = []
        self.paths = []
        self.entry_points = []
        self.objectives = []
        if topology:
            self.load_topology(topology)

    def load_topology(self, key):
        if key not in TEMPLATES:
            print(f"Unknown topology: {key}. Available: {', '.join(TEMPLATES.keys())}")
            return
        t = TEMPLATES[key]
        self.hosts = {h["id"]: h for h in t["hosts"]}
        self.connections = set()
        for a, b in t["connections"]:
            self.connections.add((a, b))
            self.connections.add((b, a))
        self.entry_points = t["entry_points"]
        self.objectives = t["objectives"]
        self._generate_edges()
        print(f"Loaded topology: {t['name']} ({len(self.hosts)} hosts, {len(t['connections'])} connections)")

    def _can_reach(self, src, dst):
        return (src, dst) in self.connections or (dst, src) in self.connections

    def _generate_edges(self):
        self.edges = []
        for hid, host in self.hosts.items():
            for vuln in VULN_TECHNIQUES:
                if vuln["service"] in host.get("services", []):
                    reachable_from = [sid for sid in self.hosts if self._can_reach(sid, hid) or sid == hid]
                    for src in reachable_from:
                        self.edges.append({
                            "src": src, "dst": hid,
                            "technique": vuln["technique"], "mitre": vuln["mitre"],
                            "probability": vuln["probability"], "prereq": vuln["prereq"],
                            "result": vuln["result"], "cvss": vuln["cvss"],
                            "type": "exploit",
                        })
            for lat in LATERAL_TECHNIQUES:
                if (lat["target_os"] == "any" or lat["target_os"] in host.get("os", "")):
                    reachable_from = [sid for sid in self.hosts if self._can_reach(sid, hid)]
                    for src in reachable_from:
                        self.edges.append({
                            "src": src, "dst": hid,
                            "technique": lat["name"], "mitre": lat["mitre"],
                            "probability": lat["probability"], "prereq": lat["prereq"],
                            "result": "user_shell", "cvss": 8.0,
                            "type": "lateral",
                        })
        print(f"Generated {len(self.edges)} attack edges")

    def find_all_paths(self, max_depth=8):
        self.paths = []
        for entry in self.entry_points:
            for objective in self.objectives:
                self._dfs(entry, objective, [], set(), max_depth)
        self.paths.sort(key=lambda p: self._path_probability(p), reverse=True)
        print(f"Found {len(self.paths)} attack paths")
        return self.paths

    def _dfs(self, current, target, path, visited, max_depth):
        if len(path) >= max_depth:
            return
        if current == target and len(path) > 0:
            self.paths.append(list(path))
            return
        visited.add(current)
        for edge in self.edges:
            if edge["src"] == current and edge["dst"] not in visited:
                path.append(edge)
                self._dfs(edge["dst"], target, path, visited, max_depth)
                path.pop()
        visited.discard(current)

    def _path_probability(self, path):
        prob = 1.0
        for edge in path:
            prob *= edge["probability"]
        return prob

    def shortest_path(self, start, target):
        queue = deque([(start, [])])
        visited = {start}
        while queue:
            current, path = queue.popleft()
            if current == target:
                return path
            for edge in self.edges:
                if edge["src"] == current and edge["dst"] not in visited:
                    visited.add(edge["dst"])
                    queue.append((edge["dst"], path + [edge]))
        return None

    def find_chokepoints(self):
        if not self.paths:
            self.find_all_paths()
        host_count = defaultdict(int)
        for path in self.paths:
            hosts_in_path = set()
            for edge in path:
                hosts_in_path.add(edge["dst"])
            for h in hosts_in_path:
                host_count[h] += 1
        total = len(self.paths) if self.paths else 1
        chokepoints = []
        for hid, count in sorted(host_count.items(), key=lambda x: x[1], reverse=True):
            pct = count / total * 100
            if pct >= 30:
                host = self.hosts.get(hid, {})
                chokepoints.append({
                    "host": hid, "name": host.get("name", hid),
                    "paths_through": count, "percentage": round(pct, 1),
                    "role": host.get("role", "unknown"),
                })
        return chokepoints

    def critical_vulns(self):
        if not self.paths:
            self.find_all_paths()
        vuln_count = defaultdict(int)
        for path in self.paths:
            for edge in path:
                key = f"{edge['dst']}:{edge['technique']}"
                vuln_count[key] += 1
        total = len(self.paths) if self.paths else 1
        critical = []
        for key, count in sorted(vuln_count.items(), key=lambda x: x[1], reverse=True):
            hid, tech = key.split(":", 1)
            host = self.hosts.get(hid, {})
            critical.append({
                "host": hid, "host_name": host.get("name", hid),
                "technique": tech, "paths_affected": count,
                "percentage": round(count / total * 100, 1),
            })
        return critical[:20]

    def what_if(self, remove_vuln_host=None, remove_vuln_technique=None, add_control_host=None):
        original_edges = self.edges[:]
        if remove_vuln_host and remove_vuln_technique:
            self.edges = [e for e in self.edges if not (e["dst"] == remove_vuln_host and e["technique"] == remove_vuln_technique)]
        if add_control_host:
            self.edges = [e for e in self.edges if e["dst"] != add_control_host or e["probability"] > 0.7]
            for e in self.edges:
                if e["dst"] == add_control_host:
                    e["probability"] *= 0.3
        original_paths = self.paths[:]
        self.paths = []
        self.find_all_paths()
        result = {
            "original_paths": len(original_paths),
            "new_paths": len(self.paths),
            "paths_eliminated": len(original_paths) - len(self.paths),
            "reduction_pct": round((1 - len(self.paths) / max(len(original_paths), 1)) * 100, 1),
        }
        self.edges = original_edges
        self.paths = original_paths
        return result

    def prioritized_remediation(self):
        vulns = self.critical_vulns()
        chokepoints = self.find_chokepoints()
        remediation = []
        seen = set()
        for v in vulns[:10]:
            key = f"{v['host']}:{v['technique']}"
            if key in seen:
                continue
            seen.add(key)
            wi = self.what_if(remove_vuln_host=v["host"], remove_vuln_technique=v["technique"])
            remediation.append({
                "priority": len(remediation) + 1,
                "host": v["host_name"],
                "vulnerability": v["technique"],
                "paths_affected": v["paths_affected"],
                "paths_eliminated_if_fixed": wi["paths_eliminated"],
                "reduction_pct": wi["reduction_pct"],
            })
        return remediation

    def render_ascii(self):
        segments = defaultdict(list)
        for hid, host in self.hosts.items():
            segments[host.get("segment", "unknown")].append(host)
        lines = ["", "=== NETWORK TOPOLOGY ===", ""]
        for seg, hosts in segments.items():
            lines.append(f"  [{seg.upper()}]")
            for h in hosts:
                svcs = ", ".join(h.get("services", [])[:4])
                marker = "*" if h["id"] in self.objectives else (">" if h["id"] in self.entry_points else " ")
                lines.append(f"    {marker} {h['name']:12s} ({h['id']:8s})  services: {svcs}")
            lines.append("")
        lines.append("  Connections:")
        seen = set()
        for a, b in sorted(self.connections):
            key = tuple(sorted([a, b]))
            if key not in seen:
                seen.add(key)
                na = self.hosts.get(a, {}).get("name", a)
                nb = self.hosts.get(b, {}).get("name", b)
                lines.append(f"    {na} <-> {nb}")
        lines.append("")
        lines.append(f"  > = entry point, * = objective")
        return "\n".join(lines)

    def export_json(self):
        return json.dumps({
            "hosts": list(self.hosts.values()),
            "connections": list(self.connections),
            "edges": self.edges[:100],
            "paths": [[{"src": e["src"], "dst": e["dst"], "technique": e["technique"], "mitre": e["mitre"], "probability": e["probability"]} for e in p] for p in self.paths[:50]],
            "entry_points": self.entry_points,
            "objectives": self.objectives,
        }, indent=2)

    def run(self, confirm_fn=None):
        print("\n" + "=" * 60)
        print(" ATTACK GRAPH GENERATOR")
        print("=" * 60)
        print("\nAvailable topologies:")
        for key, t in TEMPLATES.items():
            print(f"  {key:12s} - {t['name']}")
        topo = input("\nSelect topology (or 'custom'): ").strip().lower()
        if topo == "custom":
            print("Custom topology not yet supported in standalone mode. Use the API.")
            return
        self.load_topology(topo)
        print(self.render_ascii())
        if confirm_fn and not confirm_fn("Generate all attack paths?"):
            return
        self.find_all_paths()
        print(f"\n--- TOP 10 ATTACK PATHS ---")
        for i, path in enumerate(self.paths[:10]):
            prob = self._path_probability(path)
            steps = " -> ".join([path[0]["src"]] + [e["dst"] for e in path])
            techniques = " | ".join([e["technique"] for e in path])
            print(f"\n  Path {i+1} (probability: {prob:.3f}):")
            print(f"    Route: {steps}")
            print(f"    Techniques: {techniques}")
        print(f"\n--- CHOKEPOINTS ---")
        for cp in self.find_chokepoints():
            print(f"  {cp['name']:12s} - {cp['percentage']:.0f}% of paths ({cp['paths_through']}/{len(self.paths)})")
        print(f"\n--- PRIORITIZED REMEDIATION ---")
        for r in self.prioritized_remediation():
            print(f"  #{r['priority']}: Fix '{r['vulnerability']}' on {r['host']} "
                  f"(eliminates {r['paths_eliminated_if_fixed']} paths, {r['reduction_pct']}% reduction)")


if __name__ == "__main__":
    ag = AttackGraph()
    ag.run()
