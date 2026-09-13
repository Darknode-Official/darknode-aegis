#!/usr/bin/env python3
"""SOC Operations Playbook Engine — alert investigation and response workflows."""
import json, os, sys
from datetime import datetime

class SOCPlaybook:
    name = "SOC Playbook Engine"
    description = "20 alert investigation playbooks with triage, investigation, containment, and escalation procedures"
    category = "defense"
    mitre = []

    def __init__(self, target=None, options=None):
        self.options = options or {}
        self.findings = []

    PLAYBOOKS = [
        {"id": "PB-001", "title": "Malware Detection Alert", "severity": "HIGH", "sla_minutes": 30,
         "description": "AV/EDR detected malware on an endpoint",
         "triage": ["Verify the alert is not a false positive (check file hash against VT/internal feeds)", "Identify the host, user, and file path", "Check if the malware was quarantined or just detected", "Determine the malware family if possible"],
         "investigation": ["Check process tree: what launched the malware?", "Review parent process (was it email client, browser, Office app?)", "Check for additional IOCs on the host (network connections, registry changes, scheduled tasks)", "Search SIEM for the file hash across all endpoints", "Check if the user clicked a link/opened attachment recently", "Review network logs for C2 callbacks from the host"],
         "containment": ["If not quarantined: isolate the endpoint from network", "Block the file hash on all endpoints via EDR", "Block any identified C2 domains/IPs at the firewall", "Disable the affected user account if credentials may be compromised", "Preserve memory dump and disk image for forensics"],
         "escalation": ["Escalate to IR team if: malware executed, lateral movement detected, or data exfiltration occurred", "Notify CISO if: multiple hosts affected or ransomware detected"],
         "false_positives": ["Legitimate security tools (Mimikatz in authorized pentest)", "Custom scripts flagged by heuristics", "Cracked software (still a policy violation)"],
         "true_positives": ["File hash matches known malware family", "Behavioral analysis shows code injection, persistence, or C2", "Multiple detection engines flag the file"],
         "mitre": ["T1204", "T1059"]},

        {"id": "PB-002", "title": "Phishing Email Reported", "severity": "MEDIUM", "sla_minutes": 60,
         "description": "User reported a suspicious email",
         "triage": ["Get the original email (EML file or headers)", "Check sender address and Reply-To for mismatch", "Analyze any URLs (defang first, check against threat intel)", "Analyze any attachments (sandbox or hash check)", "Check if other users received the same email"],
         "investigation": ["Parse email headers for originating IP and mail servers", "Check SPF/DKIM/DMARC results in headers", "If URL: check URL reputation, follow redirect chain (in sandbox), capture screenshot", "If attachment: detonate in sandbox, check for macros/scripts", "Search mail logs for same sender/subject across organization", "Check if any user clicked links or opened attachments"],
         "containment": ["Delete the email from all recipient mailboxes", "Block sender address/domain in email gateway", "Block any malicious URLs at proxy/firewall", "Block any malicious file hashes on endpoints", "If credentials entered on phishing site: force password reset"],
         "escalation": ["Escalate if: credentials were entered, malware was executed, or >50 users received the email"],
         "false_positives": ["Legitimate marketing emails that look suspicious", "Internal test phishing campaigns", "Spam (annoying but not malicious)"],
         "true_positives": ["Spoofed sender with failed SPF/DKIM", "URL leads to credential harvesting page", "Attachment contains malicious macro/script"],
         "mitre": ["T1566.001", "T1566.002"]},

        {"id": "PB-003", "title": "Brute Force Attack", "severity": "HIGH", "sla_minutes": 30,
         "description": "Multiple failed login attempts detected from single source",
         "triage": ["Identify source IP and target account(s)", "Determine the service being attacked (SSH, RDP, VPN, web app, AD)", "Check if any login was successful after the failures", "Check if source IP is internal or external"],
         "investigation": ["Geo-locate the source IP", "Check source IP reputation (known attacker, Tor exit, proxy)", "Determine attack volume (attempts per minute)", "Check if multiple accounts are targeted (credential stuffing vs single-account brute force)", "Review if the account(s) are now locked out", "Check for successful auth from the same IP"],
         "containment": ["Block the source IP at firewall/WAF", "Lock targeted accounts if compromise suspected", "Force password reset on any account with successful auth from the IP", "Implement temporary geo-blocking if attacks from specific region"],
         "escalation": ["Escalate if: successful login occurred, internal IP is source, or attack targets privileged accounts"],
         "false_positives": ["Forgotten passwords (single account, few attempts)", "Service account with expired credentials", "Misconfigured automation/monitoring tool"],
         "true_positives": ["High volume (>100 attempts/min)", "Multiple accounts targeted", "Successful login after many failures", "Source IP is known malicious"],
         "mitre": ["T1110.001", "T1110.003"]},

        {"id": "PB-004", "title": "Impossible Travel", "severity": "HIGH", "sla_minutes": 30,
         "description": "User authenticated from geographically distant locations in impossibly short time",
         "triage": ["Identify the user and both login locations", "Calculate the time between logins and physical distance", "Check if VPN or proxy could explain the discrepancy", "Verify with the user if possible"],
         "investigation": ["Review both sessions for suspicious activity", "Check for data access/download in either session", "Look for MFA bypass indicators", "Check user's typical login patterns and locations", "Verify device fingerprints for both sessions", "Check if the distant login matches known VPN exit nodes"],
         "containment": ["Revoke active sessions for the user", "Force MFA re-enrollment", "Reset password", "Enable enhanced monitoring on the account"],
         "escalation": ["Escalate if: data was accessed/exfiltrated, MFA was bypassed, or it's a privileged account"],
         "false_positives": ["VPN usage creating geographic discrepancy", "Cloud proxy/CASB routing", "Shared account (policy violation)"],
         "true_positives": ["No VPN explanation, different device fingerprints", "Suspicious activity in the remote session", "MFA was not triggered for one session"],
         "mitre": ["T1078"]},

        {"id": "PB-005", "title": "Privilege Escalation Detected", "severity": "CRITICAL", "sla_minutes": 15,
         "description": "User account gained elevated privileges unexpectedly",
         "triage": ["Identify the user, original privilege level, and new privileges", "Determine how privileges were escalated (group change, sudo, exploit)", "Check if the escalation was authorized via change management", "Identify the system where escalation occurred"],
         "investigation": ["Review the process tree leading to escalation", "Check for known privilege escalation exploits (kernel, SUID, service misconfig)", "Review command history before and after escalation", "Check for persistence mechanisms installed after gaining privileges", "Search for lateral movement from the escalated session", "Verify with the user's manager if the access was requested"],
         "containment": ["Revoke elevated privileges immediately", "Isolate the affected system", "Disable the user account pending investigation", "Check other systems for the same exploit/vulnerability"],
         "escalation": ["Always escalate privilege escalation to IR team", "Notify CISO if domain admin or root was achieved"],
         "false_positives": ["Authorized system administration", "Approved access change via IT ticketing system", "Automated provisioning system"],
         "true_positives": ["Exploit used (kernel, SUID, service abuse)", "No change request or approval exists", "Followed by reconnaissance or lateral movement"],
         "mitre": ["T1068", "T1548"]},

        {"id": "PB-006", "title": "Data Exfiltration Suspected", "severity": "CRITICAL", "sla_minutes": 15,
         "description": "Large outbound data transfer or unusual data movement detected",
         "triage": ["Identify the source host, user, and destination", "Determine the volume of data transferred", "Identify the protocol used (HTTP/S, DNS, FTP, cloud storage, email)", "Check if the destination is known/legitimate"],
         "investigation": ["Review what data was accessed before the transfer", "Check DLP alerts for sensitive data matches", "Analyze the transfer pattern (bulk vs. slow trickle)", "Check if data was encrypted/encoded before transfer", "Review the user's normal data access patterns", "Check for staging activity (compression, encryption of files)"],
         "containment": ["Block the destination IP/domain at firewall", "Revoke the user's access to sensitive data", "Isolate the source host", "Preserve network captures for forensic analysis", "Engage legal team if PII/regulated data is involved"],
         "escalation": ["Always escalate data exfiltration to CISO and legal", "Engage PR if customer data is involved"],
         "false_positives": ["Legitimate large file transfers (backups, migrations)", "Cloud sync services (OneDrive, Google Drive)", "Software updates or downloads"],
         "true_positives": ["Transfer to unknown external destination", "Data compressed/encrypted before transfer", "Transfer occurred outside business hours", "DNS tunneling patterns detected"],
         "mitre": ["T1048", "T1567"]},

        {"id": "PB-007", "title": "C2 Beacon Detected", "severity": "CRITICAL", "sla_minutes": 15,
         "description": "Regular interval callbacks to external host detected (command and control)",
         "triage": ["Identify the beacon interval and jitter pattern", "Identify the destination domain/IP", "Identify the affected host and user", "Determine the protocol (HTTP/S, DNS, ICMP)"],
         "investigation": ["Analyze the beacon traffic content (encrypted? known C2 framework?)", "Check destination against threat intel (known C2 infrastructure)", "JA3/JA3S fingerprint the TLS connection", "Review process on endpoint making the connections", "Check for other hosts communicating with the same destination", "Look for lateral movement from the affected host"],
         "containment": ["Block the C2 domain/IP at all egress points", "Isolate the affected host", "Identify and kill the beaconing process", "Check for persistence mechanisms", "Memory dump before cleanup"],
         "escalation": ["Always escalate C2 detection to IR team immediately"],
         "false_positives": ["Legitimate software update checks", "Monitoring/heartbeat services", "Browser auto-refresh on dashboards"],
         "true_positives": ["Regular interval with jitter (C2 signature)", "Destination is newly registered domain", "Process is suspicious (LOLBin, injected, renamed)", "JA3 matches known C2 framework"],
         "mitre": ["T1071", "T1573"]},

        {"id": "PB-008", "title": "DNS Anomaly", "severity": "MEDIUM", "sla_minutes": 60,
         "description": "Unusual DNS query patterns detected (tunneling, DGA, high entropy domains)",
         "triage": ["Identify the source host generating unusual queries", "Categorize the anomaly: high volume, long queries, DGA-like, known-bad domains", "Check if the destination is a legitimate DNS resolver"],
         "investigation": ["Analyze query entropy (high entropy = potential DGA or tunneling)", "Check query volume (DNS tunneling often shows >1000 queries/hour)", "Look for TXT record queries with Base64 data", "Check if queried domains exist or resolve to sinkhole", "Review the process making DNS queries on the endpoint"],
         "containment": ["Block the suspicious domains at DNS resolver", "If DNS tunneling: block the destination nameserver", "Isolate the affected host for investigation"],
         "escalation": ["Escalate if confirmed DNS tunneling or DGA-based malware"],
         "false_positives": ["CDN health checks", "Legitimate high-volume DNS (mail servers, web crawlers)", "DNSSEC validation queries"],
         "true_positives": ["Queries to newly registered domains", "TXT queries with encoded data", "Regular query pattern matching C2 beaconing", "Queries match known DGA algorithms"],
         "mitre": ["T1071.004", "T1568.002"]},

        {"id": "PB-009", "title": "Ransomware Activity", "severity": "CRITICAL", "sla_minutes": 5,
         "description": "Ransomware behavior detected (mass file encryption, shadow copy deletion)",
         "triage": ["IMMEDIATELY determine the scope: how many hosts affected?", "Identify the ransomware family if possible (from ransom note or extension)", "Check if encryption is still active or completed", "Identify patient zero (first infected host)"],
         "investigation": ["Check for shadow copy deletion (vssadmin delete shadows)", "Look for bcdedit /set commands (boot config changes)", "Identify the initial infection vector (email, RDP, exploit)", "Determine what data has been encrypted", "Check if backups are intact or encrypted too", "Look for data exfiltration before encryption (double extortion)"],
         "containment": ["DISCONNECT affected hosts from network immediately", "Do NOT power off - preserve memory for forensics", "Shut down network shares to prevent spread", "Disable RDP, PowerShell remoting, WMI on all systems", "Block the ransomware hash, C2 domains/IPs", "Isolate backup systems if not yet affected"],
         "escalation": ["Immediate escalation to CISO, CIO, legal, and executive team", "Engage external IR firm", "Do NOT pay ransom without legal/executive/law enforcement consultation", "Report to FBI IC3 (US) or relevant law enforcement"],
         "false_positives": ["Legitimate encryption software (disk encryption, file encryption tools)", "Backup software operations", "Database maintenance operations"],
         "true_positives": ["Ransom note files created", "File extensions changed en masse", "VSS/shadow copies deleted", "bcdedit modifications"],
         "mitre": ["T1486", "T1490"]},

        {"id": "PB-010", "title": "Lateral Movement Detected", "severity": "CRITICAL", "sla_minutes": 15,
         "description": "Internal host-to-host movement using remote execution tools detected",
         "triage": ["Identify source and destination hosts", "Identify the tool/technique (PsExec, WMI, WinRM, RDP, SSH)", "Determine the user account being used", "Check if this is authorized administration"],
         "investigation": ["Verify the user account legitimacy and authorization", "Check for credential theft on the source host (Mimikatz, LSASS dump)", "Map the full lateral movement path (where did they start, where have they been)", "Check each compromised host for persistence and data staging", "Review credential usage patterns (same creds across hosts = pass-the-hash/ticket)"],
         "containment": ["Reset credentials of the compromised account", "Isolate affected hosts", "Block lateral movement tools at endpoint (AppLocker/WDAC)", "Restrict admin shares (ADMIN$, C$) access", "Implement network segmentation to contain spread"],
         "escalation": ["Escalate to IR team if domain admin credentials are compromised", "Escalate to CISO if domain controller is reached"],
         "false_positives": ["Legitimate system administration", "IT deployment/patching operations", "Monitoring and management tools (SCCM, Ansible)"],
         "true_positives": ["Credentials used that shouldn't have access to target", "Unusual hours for admin activity", "PsExec/WMI from workstation to server (unusual direction)", "Multiple hosts accessed in rapid succession"],
         "mitre": ["T1021", "T1570"]},

        {"id": "PB-011", "title": "Cryptominer Detected", "severity": "MEDIUM", "sla_minutes": 60,
         "description": "Cryptocurrency mining activity detected on endpoint or server",
         "triage": ["Identify the affected host and the mining process", "Check CPU/GPU usage patterns", "Identify the mining pool connection", "Determine how the miner was installed"],
         "investigation": ["Check the process path and parent process", "Look for persistence mechanisms", "Determine initial infection vector", "Check if the miner was part of a larger compromise", "Search for the same miner across other hosts"],
         "containment": ["Kill the mining process", "Block mining pool domains/IPs at firewall", "Remove persistence mechanisms", "Patch the vulnerability that allowed initial access"],
         "escalation": ["Escalate if the miner was part of a larger compromise (initial access may have been more serious)"],
         "false_positives": ["Authorized cryptocurrency mining (rare in enterprise)", "High CPU usage from legitimate processes"],
         "true_positives": ["Connections to known mining pools", "Stratum protocol traffic", "Process name matches known miners (xmrig, ccminer, etc.)"],
         "mitre": ["T1496"]},

        {"id": "PB-012", "title": "Unauthorized Access Attempt", "severity": "HIGH", "sla_minutes": 30,
         "description": "Access attempt to restricted resource or system",
         "triage": ["Identify the user and the resource they attempted to access", "Determine if access was granted or denied", "Check the user's authorization level", "Verify with the user's manager if the access was expected"],
         "investigation": ["Review the user's recent activity pattern", "Check for privilege escalation attempts", "Determine if the user's account may be compromised", "Review access control logs for the resource"],
         "containment": ["If account compromise suspected: disable account, force password reset", "Review and tighten access controls on the target resource", "Implement monitoring for the specific resource"],
         "escalation": ["Escalate if: access was granted inappropriately, or the user's account appears compromised"],
         "false_positives": ["User exploring new systems", "Role change not yet reflected in permissions", "Mistyped resource path"],
         "true_positives": ["Repeated attempts to access multiple restricted resources", "Attempts during non-business hours", "Account shows other suspicious activity"],
         "mitre": ["T1078"]},
    ]

    SHIFT_HANDOFF_TEMPLATE = """
=== SOC SHIFT HANDOFF ===
Date: {date}
Outgoing Analyst: _____________
Incoming Analyst: _____________

ACTIVE INCIDENTS:
  1. [Ticket#] [Severity] [Brief description] [Status]
  2. [Ticket#] [Severity] [Brief description] [Status]

PENDING ACTIONS:
  - [ ] Action item 1 (assigned to: ___, due: ___)
  - [ ] Action item 2 (assigned to: ___, due: ___)

ESCALATIONS:
  - None / [Description of active escalation]

NOTABLE EVENTS:
  - [Brief description of anything unusual during shift]

TOOL STATUS:
  - SIEM: Operational / Degraded / Down
  - EDR: Operational / Degraded / Down
  - Firewall: Operational / Degraded / Down
  - Email Gateway: Operational / Degraded / Down

NOTES FOR NEXT SHIFT:
  _______________________________________________
"""

    ESCALATION_MATRIX = [
        {"severity": "P1 - Critical", "response_time": "15 minutes", "notify": ["SOC Lead", "IR Manager", "CISO"], "examples": "Active ransomware, confirmed data breach, APT detection, C2 beacon"},
        {"severity": "P2 - High", "response_time": "30 minutes", "notify": ["SOC Lead", "IR Manager"], "examples": "Successful exploitation, privilege escalation, brute force with success, malware execution"},
        {"severity": "P3 - Medium", "response_time": "4 hours", "notify": ["SOC Lead"], "examples": "Phishing email, brute force blocked, policy violation, cryptominer"},
        {"severity": "P4 - Low", "response_time": "24 hours", "notify": ["SOC Analyst (self)"], "examples": "Port scan, informational alerts, failed login attempts, vulnerability scan"},
    ]

    def list_playbooks(self):
        print("\n=== AEGIS SOC Playbooks ===\n")
        for pb in self.PLAYBOOKS:
            sev_color = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[33m", "LOW": "\033[92m"}.get(pb["severity"], "\033[0m")
            print(f"  {pb['id']} | {sev_color}{pb['severity']:8s}\033[0m | SLA: {pb['sla_minutes']:3d}min | {pb['title']}")

    def show_playbook(self, pb_id):
        pb = next((p for p in self.PLAYBOOKS if p["id"] == pb_id), None)
        if not pb:
            print(f"[!] Playbook {pb_id} not found")
            return
        print(f"\n{'='*60}")
        print(f"  {pb['id']}: {pb['title']}")
        print(f"  Severity: {pb['severity']} | SLA: {pb['sla_minutes']} minutes")
        print(f"{'='*60}")
        print(f"\n  {pb['description']}\n")
        sections = [("TRIAGE", "triage"), ("INVESTIGATION", "investigation"), ("CONTAINMENT", "containment"), ("ESCALATION", "escalation"), ("FALSE POSITIVES", "false_positives"), ("TRUE POSITIVE INDICATORS", "true_positives")]
        for title, key in sections:
            print(f"  --- {title} ---")
            for item in pb[key]:
                print(f"    - {item}")
            print()
        if pb.get("mitre"):
            print(f"  MITRE ATT&CK: {', '.join(pb['mitre'])}")

    def show_escalation_matrix(self):
        print("\n=== Escalation Matrix ===\n")
        for e in self.ESCALATION_MATRIX:
            print(f"  {e['severity']}")
            print(f"    Response Time: {e['response_time']}")
            print(f"    Notify: {', '.join(e['notify'])}")
            print(f"    Examples: {e['examples']}")
            print()

    def generate_handoff(self):
        return self.SHIFT_HANDOFF_TEMPLATE.format(date=datetime.now().strftime("%Y-%m-%d %H:%M"))

    def run(self, confirm_fn=None):
        print("\n[*] AEGIS SOC Playbook Engine")
        print(f"[*] {len(self.PLAYBOOKS)} playbooks available\n")
        self.list_playbooks()
        while True:
            try:
                choice = input("\n[AEGIS SOC] Enter playbook ID (e.g., PB-001), 'esc' for escalation matrix, 'handoff' for template, 'q' to quit: ").strip()
                if choice.lower() == 'q':
                    break
                elif choice.lower() == 'esc':
                    self.show_escalation_matrix()
                elif choice.lower() == 'handoff':
                    print(self.generate_handoff())
                else:
                    self.show_playbook(choice.upper())
            except EOFError:
                break

    def get_findings(self):
        return self.findings

if __name__ == "__main__":
    soc = SOCPlaybook()
    if len(sys.argv) > 1:
        soc.show_playbook(sys.argv[1].upper())
    else:
        soc.run()
