"""
AEGIS Engine — Central orchestration for the cyber operations platform.
Manages missions, dispatches modules, handles logging and evidence chain.
"""
import os
import sys
import uuid
import hashlib
import subprocess
import shutil
import json
import yaml
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core.db import MissionDB


class Mission:
    def __init__(self, data):
        self.id = data.get("id", "")
        self.name = data.get("name", "")
        self.target = data.get("target", "")
        self.scope = data.get("scope", "")
        self.classification = data.get("classification", "UNCLASSIFIED")
        self.status = data.get("status", "ACTIVE")
        self.operator = data.get("operator", "darknode")
        self.created = data.get("created", "")
        self.updated = data.get("updated", "")
        self.notes = data.get("notes", "")

    def __repr__(self):
        return f"Mission({self.id}: {self.name} -> {self.target} [{self.status}])"


class Result:
    def __init__(self, success, output="", findings=None, iocs=None, credentials=None):
        self.success = success
        self.output = output
        self.findings = findings or []
        self.iocs = iocs or []
        self.credentials = credentials or []


MODULES = {
    "recon": {
        "passive-recon": {"name": "Passive Reconnaissance", "desc": "OSINT, DNS, WHOIS, CT logs, subdomain enumeration", "risk": "passive", "tools": ["dig", "whois", "curl"]},
        "active-recon": {"name": "Active Reconnaissance", "desc": "Port scanning, service enumeration, OS detection", "risk": "active", "tools": ["nmap", "masscan"]},
        "web-recon": {"name": "Web Reconnaissance", "desc": "Web application fingerprinting, directory enumeration", "risk": "active", "tools": ["whatweb", "gobuster", "curl"]},
        "cloud-recon": {"name": "Cloud Reconnaissance", "desc": "Cloud asset discovery, S3/Azure/GCP enumeration", "risk": "active", "tools": ["curl"]},
        "social-recon": {"name": "Social Reconnaissance", "desc": "Employee and organization OSINT gathering", "risk": "passive", "tools": []},
    },
    "vuln": {
        "vuln-scanner": {"name": "Vulnerability Scanner", "desc": "CVE matching against discovered services", "risk": "passive", "tools": ["nmap"]},
        "web-audit": {"name": "Web Application Audit", "desc": "OWASP Top 10 testing, SQLi/XSS/SSRF checks", "risk": "active", "tools": ["nikto", "sqlmap"]},
        "config-audit": {"name": "Configuration Audit", "desc": "CIS benchmark compliance checking", "risk": "passive", "tools": []},
        "cred-audit": {"name": "Credential Audit", "desc": "Default and weak credential testing", "risk": "active", "tools": ["hydra"]},
        "crypto-audit": {"name": "Cryptography Audit", "desc": "TLS/SSL, certificate, cipher suite analysis", "risk": "passive", "tools": ["sslscan", "openssl"]},
    },
    "exploit": {
        "exploit-db": {"name": "Exploit Database", "desc": "Search and match exploits against findings", "risk": "passive", "tools": ["searchsploit"]},
        "payload-gen": {"name": "Payload Generator", "desc": "Multi-platform payload generation", "risk": "exploit", "tools": ["msfvenom"]},
        "post-exploit": {"name": "Post-Exploitation", "desc": "Post-compromise enumeration and data gathering", "risk": "exploit", "tools": []},
        "privesc-check": {"name": "Privilege Escalation", "desc": "Privilege escalation vector identification", "risk": "exploit", "tools": []},
    },
    "intel": {
        "threat-feeds": {"name": "Threat Intelligence Feeds", "desc": "IOC feed aggregation and correlation", "risk": "passive", "tools": ["curl"]},
        "mitre-mapper": {"name": "MITRE ATT&CK Mapper", "desc": "Map findings to ATT&CK techniques", "risk": "passive", "tools": []},
        "apt-tracker": {"name": "APT Group Tracker", "desc": "Track and identify threat actor TTPs", "risk": "passive", "tools": []},
        "darkweb-monitor": {"name": "Dark Web Monitor", "desc": "Monitor for organization mentions on dark web", "risk": "passive", "tools": ["tor", "curl"]},
    },
    "defense": {
        "ids-manager": {"name": "IDS Rule Manager", "desc": "Snort/Suricata rule management and deployment", "risk": "passive", "tools": ["snort", "suricata"]},
        "log-analyzer": {"name": "Log Analyzer", "desc": "Multi-format log analysis and anomaly detection", "risk": "passive", "tools": []},
        "incident-response": {"name": "Incident Response", "desc": "IR workflow automation and evidence collection", "risk": "passive", "tools": []},
        "forensics": {"name": "Digital Forensics", "desc": "Disk and memory forensic analysis", "risk": "passive", "tools": ["volatility", "autopsy"]},
        "honeypot-deploy": {"name": "Honeypot Deployment", "desc": "Deploy and manage honeypots and deception", "risk": "active", "tools": ["docker"]},
    },
    "crypto": {
        "crypto-suite": {"name": "Cryptographic Suite", "desc": "Encryption, decryption, hashing, signing operations", "risk": "passive", "tools": ["openssl"]},
        "stego": {"name": "Steganography", "desc": "Hide and extract data in media files", "risk": "passive", "tools": ["steghide"]},
        "covert-channel": {"name": "Covert Channels", "desc": "Covert communication channel setup", "risk": "active", "tools": []},
        "key-manager": {"name": "Key Manager", "desc": "PKI and key/certificate management", "risk": "passive", "tools": ["openssl", "gpg"]},
    },
    "network": {
        "packet-craft": {"name": "Packet Crafting", "desc": "Custom packet construction and injection", "risk": "active", "tools": ["scapy", "hping3"]},
        "traffic-analysis": {"name": "Traffic Analysis", "desc": "PCAP capture and protocol analysis", "risk": "passive", "tools": ["tcpdump", "tshark"]},
        "wireless": {"name": "Wireless Operations", "desc": "WiFi, Bluetooth, and RF analysis", "risk": "active", "tools": ["aircrack-ng", "bettercap"]},
        "tunnel": {"name": "Encrypted Tunneling", "desc": "Set up encrypted tunnels and pivots", "risk": "active", "tools": ["ssh", "chisel", "socat"]},
    },
    "ai": {
        "anomaly-detect": {"name": "Anomaly Detection", "desc": "ML-based anomaly detection in logs and traffic", "risk": "passive", "tools": []},
        "pattern-match": {"name": "Pattern Recognition", "desc": "Attack pattern identification and classification", "risk": "passive", "tools": []},
        "auto-hunt": {"name": "Automated Threat Hunting", "desc": "AI-driven threat hunting across data sources", "risk": "passive", "tools": []},
        "predictive": {"name": "Predictive Analysis", "desc": "Predict likely attack vectors and next steps", "risk": "passive", "tools": []},
    },
    "reporting": {
        "report-gen": {"name": "Report Generator", "desc": "Generate professional pentest/IR reports", "risk": "passive", "tools": []},
        "timeline": {"name": "Timeline Builder", "desc": "Construct incident timelines from evidence", "risk": "passive", "tools": []},
        "evidence-mgr": {"name": "Evidence Manager", "desc": "Chain of custody and evidence integrity", "risk": "passive", "tools": []},
        "brief": {"name": "Executive Briefing", "desc": "Generate executive-level threat briefings", "risk": "passive", "tools": []},
    },
}

DOMAIN_NAMES = {
    "recon": "Reconnaissance",
    "vuln": "Vulnerability Assessment",
    "exploit": "Exploitation",
    "intel": "Threat Intelligence",
    "defense": "Defensive Operations",
    "crypto": "Cryptography",
    "network": "Network Operations",
    "ai": "AI Analysis",
    "reporting": "Reporting",
}


class AegisEngine:
    def __init__(self, base_dir=None):
        self.base_dir = base_dir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.config = self._load_config()
        db_path = os.path.join(self.base_dir, self.config.get("database", {}).get("path", "missions/aegis.db"))
        self.db = MissionDB(db_path)
        self.current_mission = None
        self.log_file = os.path.join(self.base_dir, self.config.get("logging", {}).get("file", "aegis.log"))

    def _load_config(self):
        config_path = os.path.join(self.base_dir, "core", "config.yaml")
        if os.path.exists(config_path):
            with open(config_path) as f:
                data = yaml.safe_load(f)
                return data.get("aegis", {})
        return {}

    def create_mission(self, name, target, scope="", classification="UNCLASSIFIED"):
        mission_id = "M-" + datetime.utcnow().strftime("%Y%m%d") + "-" + uuid.uuid4().hex[:8].upper()
        operator = self.config.get("operator", "darknode")
        self.db.create_mission(mission_id, name, target, scope, classification, operator)
        mission_dir = os.path.join(self.base_dir, "missions", mission_id)
        os.makedirs(os.path.join(mission_dir, "evidence"), exist_ok=True)
        os.makedirs(os.path.join(mission_dir, "logs"), exist_ok=True)
        os.makedirs(os.path.join(mission_dir, "reports"), exist_ok=True)
        mission_data = self.db.get_mission(mission_id)
        self.current_mission = Mission(mission_data)
        self._log("MISSION_CREATED", f"Mission '{name}' created targeting {target}")
        return self.current_mission

    def load_mission(self, mission_id):
        data = self.db.get_mission(mission_id)
        if not data:
            return None
        self.current_mission = Mission(data)
        self._log("MISSION_LOADED", f"Mission '{data['name']}' loaded")
        return self.current_mission

    def list_missions(self):
        missions = self.db.list_missions()
        return [Mission(m) for m in missions]

    def check_tool(self, tool_name):
        return shutil.which(tool_name) is not None

    def check_module_tools(self, domain, module_key):
        if domain not in MODULES or module_key not in MODULES[domain]:
            return {}
        mod = MODULES[domain][module_key]
        return {t: self.check_tool(t) for t in mod.get("tools", [])}

    def run_command(self, command, timeout=None):
        timeout = timeout or self.config.get("modules", {}).get("timeout", 300)
        self._log("COMMAND_EXEC", command)
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=timeout
            )
            output = result.stdout + result.stderr
            self._log("COMMAND_RESULT", f"exit={result.returncode} len={len(output)}")
            return Result(success=result.returncode == 0, output=output)
        except subprocess.TimeoutExpired:
            self._log("COMMAND_TIMEOUT", f"Command timed out after {timeout}s")
            return Result(success=False, output=f"Command timed out after {timeout}s")
        except Exception as e:
            self._log("COMMAND_ERROR", str(e))
            return Result(success=False, output=str(e))

    def add_finding(self, severity, title, detail="", module="", mitre="",
                    host="", port=0, service="", cve="", cvss=0.0, remediation=""):
        if not self.current_mission:
            return
        self.db.add_finding(
            self.current_mission.id, severity, title, detail, module, mitre,
            "", host, port, service, cve, cvss, remediation
        )
        self._log("FINDING", f"[{severity}] {title}")

    def add_ioc(self, ioc_type, value, context="", confidence="medium", source=""):
        if not self.current_mission:
            return
        self.db.add_ioc(self.current_mission.id, ioc_type, value, context, confidence, source)
        self._log("IOC", f"[{ioc_type}] {value}")

    def add_credential(self, service, username, credential_type, value, host="", source=""):
        if not self.current_mission:
            return
        masked = value[:3] + "***" if len(value) > 3 else "***"
        self.db.add_credential(self.current_mission.id, service, host, username, credential_type, value, source)
        self._log("CREDENTIAL", f"{service}://{username}:{masked}@{host}")

    def log_action(self, command, output="", result="", module="", approved=True):
        if not self.current_mission:
            return
        self.db.add_action(self.current_mission.id, command, output, result,
                          self.config.get("operator", "darknode"), module, approved)

    def store_evidence(self, filepath, description="", source_module=""):
        if not self.current_mission or not os.path.exists(filepath):
            return None
        sha256 = MissionDB.hash_file(filepath)
        evidence_dir = os.path.join(self.base_dir, "missions", self.current_mission.id, "evidence")
        os.makedirs(evidence_dir, exist_ok=True)
        dest = os.path.join(evidence_dir, os.path.basename(filepath))
        shutil.copy2(filepath, dest)
        self.db.add_evidence(self.current_mission.id, os.path.basename(filepath), sha256, description, source_module)
        self._log("EVIDENCE", f"Stored {os.path.basename(filepath)} SHA256={sha256[:16]}...")
        return sha256

    def get_findings(self, severity=None, module=None):
        if not self.current_mission:
            return []
        return self.db.get_findings(self.current_mission.id, severity, module)

    def get_stats(self):
        if not self.current_mission:
            return {}
        return self.db.get_stats(self.current_mission.id)

    def get_actions(self):
        if not self.current_mission:
            return []
        return self.db.get_actions(self.current_mission.id)

    def get_iocs(self):
        if not self.current_mission:
            return []
        return self.db.get_iocs(self.current_mission.id)

    def get_credentials(self):
        if not self.current_mission:
            return []
        return self.db.get_credentials(self.current_mission.id)

    def get_evidence(self):
        if not self.current_mission:
            return []
        return self.db.get_evidence(self.current_mission.id)

    def generate_report(self, fmt="markdown"):
        if not self.current_mission:
            return ""
        m = self.current_mission
        stats = self.get_stats()
        findings = self.get_findings()
        actions = self.get_actions()
        iocs = self.get_iocs()
        creds = self.get_credentials()
        classification = m.classification

        lines = []
        if self.config.get("reporting", {}).get("classification_banner", True):
            lines.append(f"{'='*60}")
            lines.append(f"  {classification}")
            lines.append(f"{'='*60}")
            lines.append("")

        lines.append(f"# AEGIS Engagement Report")
        lines.append(f"")
        lines.append(f"**Mission:** {m.name}")
        lines.append(f"**Target:** {m.target}")
        lines.append(f"**Scope:** {m.scope}")
        lines.append(f"**Classification:** {classification}")
        lines.append(f"**Operator:** {m.operator}")
        lines.append(f"**Date:** {m.created}")
        lines.append(f"**Report Generated:** {datetime.utcnow().isoformat()}Z")
        lines.append("")

        lines.append("## Executive Summary")
        lines.append("")
        lines.append(f"This engagement identified **{stats['total_findings']}** findings:")
        lines.append(f"- **{stats['critical']}** Critical")
        lines.append(f"- **{stats['high']}** High")
        lines.append(f"- **{stats['medium']}** Medium")
        lines.append(f"- **{stats['low']}** Low")
        lines.append(f"- **{stats['info']}** Informational")
        lines.append("")
        lines.append(f"**{stats['credentials']}** credential(s) were obtained during testing.")
        lines.append(f"**{stats['iocs']}** indicator(s) of compromise were identified.")
        lines.append(f"**{stats['actions']}** actions were performed during the engagement.")
        lines.append("")

        lines.append("## Findings")
        lines.append("")
        for i, f in enumerate(findings, 1):
            sev = f["severity"]
            lines.append(f"### {i}. [{sev}] {f['title']}")
            if f.get("host"):
                lines.append(f"**Host:** {f['host']}" + (f":{f['port']}" if f.get("port") else ""))
            if f.get("cve"):
                lines.append(f"**CVE:** {f['cve']} | **CVSS:** {f['cvss']}")
            if f.get("mitre"):
                lines.append(f"**MITRE ATT&CK:** {f['mitre']}")
            if f.get("service"):
                lines.append(f"**Service:** {f['service']}")
            lines.append("")
            if f.get("detail"):
                lines.append(f"{f['detail']}")
                lines.append("")
            if f.get("remediation"):
                lines.append(f"**Remediation:** {f['remediation']}")
                lines.append("")

        if iocs:
            lines.append("## Indicators of Compromise")
            lines.append("")
            lines.append("| Type | Value | Confidence | Context |")
            lines.append("|------|-------|------------|---------|")
            for ioc in iocs:
                lines.append(f"| {ioc['ioc_type']} | `{ioc['value']}` | {ioc['confidence']} | {ioc['context']} |")
            lines.append("")

        if creds:
            lines.append("## Credentials Obtained")
            lines.append("")
            lines.append("| Service | Host | Username | Type |")
            lines.append("|---------|------|----------|------|")
            for c in creds:
                lines.append(f"| {c['service']} | {c['host']} | {c['username']} | {c['credential_type']} |")
            lines.append("")

        lines.append("## Actions Performed")
        lines.append("")
        for a in actions:
            lines.append(f"- `{a['created']}` [{a['module']}] `{a['command'][:100]}`")
        lines.append("")

        lines.append("## Remediation Roadmap")
        lines.append("")
        lines.append("1. **Immediate (0-24h):** Address all CRITICAL findings")
        lines.append("2. **Short-term (1-7d):** Remediate HIGH findings, rotate compromised credentials")
        lines.append("3. **Medium-term (1-4w):** Address MEDIUM findings, improve detection capabilities")
        lines.append("4. **Long-term (1-3mo):** Architectural improvements, security awareness training")
        lines.append("")

        if self.config.get("reporting", {}).get("classification_banner", True):
            lines.append(f"{'='*60}")
            lines.append(f"  {classification}")
            lines.append(f"{'='*60}")

        report_text = "\n".join(lines)
        report_dir = os.path.join(self.base_dir, "missions", m.id, "reports")
        os.makedirs(report_dir, exist_ok=True)
        report_path = os.path.join(report_dir, f"report-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.md")
        with open(report_path, "w") as f:
            f.write(report_text)
        self._log("REPORT_GENERATED", report_path)
        return report_text

    def _log(self, event_type, message):
        timestamp = datetime.utcnow().isoformat() + "Z"
        mission_id = self.current_mission.id if self.current_mission else "SYSTEM"
        entry = f"[{timestamp}] [{mission_id}] [{event_type}] {message}\n"
        try:
            with open(self.log_file, "a") as f:
                f.write(entry)
        except Exception:
            pass

    def close(self):
        self.db.close()
