#!/usr/bin/env python3
"""Deception technology operations — honeypots, honeytokens, tripwires, and canary deployment"""
import json, os, sys, hashlib, secrets, string
from datetime import datetime

HONEYPOT_TEMPLATES = [
    {"name": "SSH Honeypot (Cowrie)", "protocol": "SSH/Telnet", "interaction": "High",
     "description": "Medium-to-high interaction SSH/Telnet honeypot that logs brute force attempts, shell interaction, and file uploads",
     "docker_compose": """version: '3'
services:
  cowrie:
    image: cowrie/cowrie:latest
    container_name: cowrie-ssh
    ports:
      - "2222:2222"  # SSH
      - "2223:2223"  # Telnet
    volumes:
      - ./cowrie-data/log:/cowrie/cowrie-log
      - ./cowrie-data/downloads:/cowrie/cowrie-downloads
    environment:
      - COWRIE_HOSTNAME=prod-server-03
      - COWRIE_SSH_VERSION_STRING=SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
    restart: unless-stopped""",
     "key_config": ["Set realistic hostname", "Customize SSH banner to match environment", "Add fake filesystem content", "Configure credential logging", "Enable download capture"],
     "log_analysis": "Monitor cowrie.json for: login attempts (username/password pairs), commands executed, files uploaded/downloaded, session duration",
     "alerts": ["Any successful login", "Known attacker IP from threat intel", "Upload of executable files", "Privilege escalation attempts"],
     "mitre_detects": ["T1110", "T1021.004", "T1059", "T1105"]},
    {"name": "Web Application Honeypot (Snare/Tanner)", "protocol": "HTTP/HTTPS", "interaction": "Medium",
     "description": "Web application honeypot that emulates vulnerable web applications to capture attack payloads",
     "docker_compose": """version: '3'
services:
  snare:
    image: mushorg/snare:latest
    container_name: snare-web
    ports:
      - "8080:80"
    command: snare --port 80 --page-dir /opt/snare/pages
    restart: unless-stopped
  tanner:
    image: mushorg/tanner:latest
    container_name: tanner-analyzer
    ports:
      - "8090:8090"
    depends_on:
      - snare
    restart: unless-stopped""",
     "key_config": ["Clone a real website as bait content", "Configure vulnerability emulation (SQLi, XSS, LFI, RFI)", "Set up realistic error pages", "Enable payload logging"],
     "log_analysis": "Monitor tanner logs for: SQLi payloads, XSS attempts, path traversal, web shell uploads, scanner fingerprints",
     "alerts": ["SQL injection attempts", "File upload attempts", "Directory traversal", "Known scanner user agents"],
     "mitre_detects": ["T1190", "T1059", "T1505.003"]},
    {"name": "ICS/SCADA Honeypot (Conpot)", "protocol": "Modbus/S7comm/HTTP", "interaction": "Medium",
     "description": "Industrial control system honeypot emulating PLCs, RTUs, and HMIs",
     "docker_compose": """version: '3'
services:
  conpot:
    image: honeynet/conpot:latest
    container_name: conpot-ics
    ports:
      - "502:502"    # Modbus
      - "102:102"    # S7comm
      - "161:161/udp" # SNMP
      - "80:80"      # HTTP HMI
      - "21:21"      # FTP
    volumes:
      - ./conpot-data:/var/log/conpot
    restart: unless-stopped""",
     "key_config": ["Configure realistic device profile (Siemens S7-1200, Allen-Bradley)", "Set appropriate register values", "Customize HMI web interface"],
     "log_analysis": "Monitor for: Modbus read/write requests, S7comm function calls, SNMP community string testing, HMI access",
     "alerts": ["Any Modbus write operation", "S7comm connection from unexpected IP", "SNMP community string brute force"],
     "mitre_detects": ["T1046", "T1071", "T0855", "T0843"]},
    {"name": "Multi-Protocol Honeypot (Dionaea)", "protocol": "SMB/HTTP/FTP/MSSQL/MySQL/SIP", "interaction": "Low-Medium",
     "description": "Catches malware by emulating multiple vulnerable services",
     "docker_compose": """version: '3'
services:
  dionaea:
    image: dinotools/dionaea:latest
    container_name: dionaea-multi
    ports:
      - "21:21"     # FTP
      - "80:80"     # HTTP
      - "443:443"   # HTTPS
      - "445:445"   # SMB
      - "1433:1433" # MSSQL
      - "3306:3306" # MySQL
      - "5060:5060/udp" # SIP
    volumes:
      - ./dionaea-data:/opt/dionaea/var
    restart: unless-stopped""",
     "key_config": ["Enable binary capture for malware collection", "Configure service banners", "Set up GeoIP for source tracking"],
     "log_analysis": "Monitor for: exploit attempts, malware uploads, credential brute force across all services",
     "alerts": ["Malware binary captured", "SMB exploit attempt", "SQL injection payload"],
     "mitre_detects": ["T1190", "T1110", "T1105"]},
    {"name": "Network Honeypot (OpenCanary)", "protocol": "Multiple", "interaction": "Low",
     "description": "Lightweight honeypot that alerts on service access — ideal for internal network tripwires",
     "docker_compose": """version: '3'
services:
  opencanary:
    image: thinkst/opencanary:latest
    container_name: opencanary
    ports:
      - "21:21"
      - "22:22"
      - "80:80"
      - "443:443"
      - "445:445"
      - "3389:3389"
      - "3306:3306"
    volumes:
      - ./opencanary.conf:/root/.opencanary.conf
    restart: unless-stopped""",
     "key_config": ["Place on unused IPs in production subnets", "Name it like a real server (FILESRV-04, BACKUP-02)", "Configure alerting to SIEM/Slack/email"],
     "log_analysis": "Any connection to OpenCanary is suspicious — it should receive zero legitimate traffic",
     "alerts": ["ANY connection (this is the tripwire — any access means compromise)"],
     "mitre_detects": ["T1046", "T1021", "T1110"]},
]

HONEYTOKEN_GENERATORS = [
    {"name": "AWS Credential Honeytoken", "type": "credential",
     "description": "Fake AWS access key that triggers an alert when used",
     "creation": [
         "Create a dedicated IAM user with NO permissions (deny all policy)",
         "Generate access keys for this user",
         "Enable CloudTrail logging for API calls by this user",
         "Create a CloudWatch alarm for any API call from this access key",
         "Place the credentials in strategic locations",
     ],
     "placement": [".env files", "Git repositories (private)", "S3 buckets", "Developer workstations", "CI/CD configs", "Documentation wikis"],
     "alert_config": """# CloudWatch alarm for honeytoken usage
{
  "AlarmName": "HoneyToken-AWS-Key-Used",
  "MetricName": "honeytoken-api-calls",
  "Namespace": "CloudTrailMetrics",
  "Statistic": "Sum",
  "Period": 60,
  "Threshold": 1,
  "ComparisonOperator": "GreaterThanOrEqualToThreshold",
  "AlarmActions": ["arn:aws:sns:us-east-1:ACCOUNT:SecurityAlerts"]
}"""},
    {"name": "Active Directory Honeytoken Account", "type": "credential",
     "description": "Fake privileged AD account that alerts on authentication",
     "creation": [
         "Create AD user: svc_sqlbackup or admin_legacy (tempting names)",
         "Set a complex password and disable the account (or enable with logging)",
         "Add to a 'honey' OU with auditing enabled",
         "Set 'Account is sensitive and cannot be delegated'",
         "Monitor Event ID 4625/4624 for this account",
     ],
     "placement": ["Leave in LSASS memory on a 'compromised' honey workstation", "Reference in scripts or documentation", "Add SPN for Kerberoasting detection"],
     "splunk_alert": "index=wineventlog (EventCode=4624 OR EventCode=4625) Account_Name=\"svc_sqlbackup\" | table _time src_ip Account_Name EventCode"},
    {"name": "Database Canary Record", "type": "data",
     "description": "Fake database records that trigger alerts when accessed or exfiltrated",
     "creation": [
         "Insert fake records into production database tables",
         "Use realistic but traceable data (specific format, watermarked)",
         "Set up database audit logging for queries returning canary records",
         "Monitor for these specific values appearing outside the database",
     ],
     "placement": ["Customer tables (fake customer with known email)", "Employee tables (fake employee)", "Financial tables (specific transaction amounts)"],
     "example": "INSERT INTO customers (name, email, ssn) VALUES ('John Canary', 'canary-7f3a@monitoring.internal', '078-05-1120'); -- 078-05-1120 is the SSN used in the Lifelock CEO demo"},
    {"name": "Canary Document", "type": "file",
     "description": "Documents with embedded callbacks that alert when opened",
     "creation": [
         "Create a Word/PDF document with an embedded image from a canary URL",
         "The URL resolves to a tracking server (canarytokens.org or self-hosted)",
         "When the document is opened, the image fetch reveals the opener's IP",
         "Name the document temptingly: 'passwords.xlsx', 'salary_review_2024.docx'",
     ],
     "placement": ["Network shares", "Desktop of honeypot machines", "Email (send to honeytoken mailbox)", "USB drives for physical testing"]},
    {"name": "DNS Canary", "type": "network",
     "description": "Subdomain that alerts when resolved — detects DNS exfiltration and zone enumeration",
     "creation": [
         "Register a subdomain: canary-7f3a.internal.company.com",
         "Point it to a monitoring server or use canarytokens.org DNS",
         "Any DNS resolution of this subdomain triggers an alert",
         "Place references to this subdomain in honeypot configs, fake documents, or scripts",
     ],
     "placement": ["DNS zone files (will trigger on zone transfer)", "Configuration files", "Internal documentation", "Source code comments"]},
    {"name": "API Key Honeytoken", "type": "credential",
     "description": "Fake API keys in realistic formats that alert on use",
     "formats": {
         "Stripe": "sk_live_" + ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(24)),
         "GitHub": "ghp_" + ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36)),
         "AWS": "AKIA" + ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16)),
         "Slack": "xoxb-" + '-'.join(''.join(secrets.choice(string.digits) for _ in range(n)) for n in [12, 12, 24]),
     },
     "placement": [".env files", "Git repos", "CI/CD pipelines", "Developer notes", "Internal wikis"]},
]

TRIPWIRE_TEMPLATES = [
    {"name": "File Integrity Monitoring", "category": "file",
     "description": "Monitor critical files for unauthorized changes",
     "targets": ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config",
                 "/etc/crontab", "/var/spool/cron/", "C:\\Windows\\System32\\config\\SAM",
                 "C:\\Windows\\System32\\drivers\\etc\\hosts", "Web application source files"],
     "tools": ["AIDE", "OSSEC", "osquery", "Tripwire", "Sysmon (Event 11)"],
     "aide_config": "AIDE_RULE = p+i+n+u+g+s+b+m+c+sha256\n/etc AIDE_RULE\n/bin AIDE_RULE\n/sbin AIDE_RULE"},
    {"name": "Registry Monitoring (Windows)", "category": "registry",
     "description": "Monitor Windows registry keys used for persistence",
     "targets": ["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                 "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                 "HKLM\\SYSTEM\\CurrentControlSet\\Services",
                 "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                 "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"],
     "sysmon_config": """<Sysmon schemaversion="4.90">
  <EventFiltering>
    <RegistryEvent onmatch="include">
      <TargetObject condition="contains">CurrentVersion\\Run</TargetObject>
      <TargetObject condition="contains">\\Services\\</TargetObject>
      <TargetObject condition="contains">Winlogon</TargetObject>
      <TargetObject condition="contains">Image File Execution Options</TargetObject>
    </RegistryEvent>
  </EventFiltering>
</Sysmon>"""},
    {"name": "Network Tripwire (Darknet)", "category": "network",
     "description": "Monitor unused IP addresses that should never receive traffic",
     "setup": ["Assign unused IPs in each VLAN/subnet", "Configure port mirroring or host-based capture", "Any traffic to these IPs indicates scanning or lateral movement"],
     "detection": "iptables -A INPUT -d UNUSED_IP -j LOG --log-prefix 'TRIPWIRE: '"},
    {"name": "AD Tripwire", "category": "active_directory",
     "description": "Monitor for changes to sensitive AD objects",
     "targets": ["Domain Admins group membership", "AdminSDHolder container", "GPO modifications", "Schema changes", "Trust modifications", "KRBTGT account changes"],
     "splunk_query": "index=wineventlog (EventCode=4728 OR EventCode=4756) TargetUserName=\"Domain Admins\" | table _time SubjectUserName MemberName"},
    {"name": "Cloud Tripwire", "category": "cloud",
     "description": "Monitor for activity in unused cloud regions or unexpected resource creation",
     "targets": ["API calls from unused regions", "New IAM users/roles", "Security group modifications", "S3 bucket policy changes", "CloudTrail disable attempts"],
     "aws_config": """# CloudWatch alarm for API calls from unused regions
{
  "MetricFilters": [{
    "FilterPattern": "{ $.awsRegion != \"us-east-1\" && $.awsRegion != \"us-west-2\" }",
    "MetricName": "UnusedRegionActivity"
  }]
}"""},
]

DECEPTION_METRICS = {
    "coverage": {
        "description": "Which attack phases does deception cover?",
        "phases": [
            {"phase": "Reconnaissance", "deception": "Fake DNS records, honeypot services visible in scans", "coverage": "Medium"},
            {"phase": "Initial Access", "deception": "Web honeypots catch exploit attempts, credential honeytokens detect credential use", "coverage": "High"},
            {"phase": "Execution", "deception": "Honeypot OS captures executed commands", "coverage": "High"},
            {"phase": "Persistence", "deception": "File integrity tripwires detect new persistence mechanisms", "coverage": "Medium"},
            {"phase": "Lateral Movement", "deception": "Network tripwires detect scanning, honeytoken credentials detect PTH", "coverage": "High"},
            {"phase": "Collection", "deception": "Canary documents detect data access", "coverage": "Medium"},
            {"phase": "Exfiltration", "deception": "DNS canaries detect DNS tunneling, canary data in exfil indicates breach", "coverage": "Medium"},
        ],
    },
    "roi_formula": "ROI = (Average_Breach_Cost * Probability_of_Detection_Improvement - Deception_Cost) / Deception_Cost",
    "industry_data": {
        "average_breach_cost": 4450000,
        "average_dwell_time_days": 204,
        "deception_detection_improvement": 0.35,
        "deception_dwell_time_reduction_pct": 0.60,
    },
}


class DeceptionOps:
    name = "Deception Technology Operations"
    description = "Honeypot deployment, honeytoken generation, tripwire management, and deception program metrics"
    category = "defense"
    mitre = ["T1046", "T1110", "T1021", "T1190", "T1557"]

    def __init__(self, target=None, options=None):
        self.target = target
        self.options = options or {}
        self.findings = []

    def run(self, confirm_fn=None):
        print("\n" + "=" * 60)
        print("  DECEPTION OPERATIONS CENTER")
        print("=" * 60)
        while True:
            print("\n  [1] Honeypot Templates ({})".format(len(HONEYPOT_TEMPLATES)))
            print("  [2] Honeytoken Generators ({})".format(len(HONEYTOKEN_GENERATORS)))
            print("  [3] Tripwire Templates ({})".format(len(TRIPWIRE_TEMPLATES)))
            print("  [4] Generate Honeytokens Now")
            print("  [5] Deception Program Metrics / ROI")
            print("  [0] Exit")
            choice = input("\n  Select: ").strip()
            if choice == "1":
                self._honeypots()
            elif choice == "2":
                self._honeytokens()
            elif choice == "3":
                self._tripwires()
            elif choice == "4":
                self._generate_tokens()
            elif choice == "5":
                self._metrics()
            elif choice == "0":
                break

    def _honeypots(self):
        print("\n  --- Honeypot Templates ---")
        for i, hp in enumerate(HONEYPOT_TEMPLATES, 1):
            print(f"  [{i}] {hp['name']} ({hp['protocol']}, {hp['interaction']} interaction)")
        choice = input(f"\n  Select (1-{len(HONEYPOT_TEMPLATES)}): ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(HONEYPOT_TEMPLATES):
            hp = HONEYPOT_TEMPLATES[int(choice) - 1]
            print(f"\n  === {hp['name']} ===")
            print(f"  Protocol: {hp['protocol']}")
            print(f"  Interaction: {hp['interaction']}")
            print(f"  {hp['description']}")
            print(f"\n  Docker Compose:")
            print(hp["docker_compose"])
            print(f"\n  Key Configuration:")
            for item in hp["key_config"]:
                print(f"    - {item}")
            print(f"\n  Log Analysis: {hp['log_analysis']}")
            print(f"\n  Alert Triggers:")
            for alert in hp["alerts"]:
                print(f"    - {alert}")
            print(f"\n  MITRE Techniques Detected: {', '.join(hp['mitre_detects'])}")

    def _honeytokens(self):
        print("\n  --- Honeytoken Types ---")
        for i, ht in enumerate(HONEYTOKEN_GENERATORS, 1):
            print(f"  [{i}] {ht['name']} ({ht['type']})")
        choice = input(f"\n  Select (1-{len(HONEYTOKEN_GENERATORS)}): ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(HONEYTOKEN_GENERATORS):
            ht = HONEYTOKEN_GENERATORS[int(choice) - 1]
            print(f"\n  === {ht['name']} ===")
            print(f"  Type: {ht['type']}")
            print(f"  {ht['description']}")
            print(f"\n  Creation Steps:")
            for j, step in enumerate(ht["creation"], 1):
                print(f"    {j}. {step}")
            print(f"\n  Placement Recommendations:")
            for loc in ht["placement"]:
                print(f"    - {loc}")

    def _tripwires(self):
        print("\n  --- Tripwire Templates ---")
        for i, tw in enumerate(TRIPWIRE_TEMPLATES, 1):
            print(f"  [{i}] {tw['name']} ({tw['category']})")
        choice = input(f"\n  Select (1-{len(TRIPWIRE_TEMPLATES)}): ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(TRIPWIRE_TEMPLATES):
            tw = TRIPWIRE_TEMPLATES[int(choice) - 1]
            print(f"\n  === {tw['name']} ===")
            print(f"  Category: {tw['category']}")
            print(f"  {tw['description']}")
            if "targets" in tw:
                print(f"\n  Monitoring Targets:")
                for t in tw["targets"]:
                    print(f"    - {t}")

    def _generate_tokens(self):
        print("\n  --- Live Honeytoken Generator ---")
        print("\n  Generating fresh honeytokens:")
        for name, fmt in HONEYTOKEN_GENERATORS[5]["formats"].items():
            print(f"\n  {name}:")
            print(f"    {fmt}")
        print("\n  WARNING: These are fake credentials for deception use only.")
        print("  Place them where an attacker would find them.")

    def _metrics(self):
        print("\n  --- Deception Program Metrics ---")
        print("\n  Coverage by Attack Phase:")
        for phase in DECEPTION_METRICS["coverage"]["phases"]:
            print(f"    {phase['phase']:20s} [{phase['coverage']:6s}] {phase['deception']}")
        data = DECEPTION_METRICS["industry_data"]
        cost = data["average_breach_cost"]
        improvement = data["deception_detection_improvement"]
        deception_cost = 50000
        roi = (cost * improvement - deception_cost) / deception_cost * 100
        print(f"\n  ROI Calculation:")
        print(f"    Average breach cost:          ${cost:,.0f}")
        print(f"    Detection improvement:        {improvement*100:.0f}%")
        print(f"    Estimated deception cost:      ${deception_cost:,.0f}/year")
        print(f"    Estimated ROI:                {roi:.0f}%")
        print(f"\n    Dwell time reduction: ~{data['deception_dwell_time_reduction_pct']*100:.0f}% (from {data['average_dwell_time_days']} days avg)")

    def get_findings(self):
        return self.findings


if __name__ == "__main__":
    d = DeceptionOps()
    d.run()
