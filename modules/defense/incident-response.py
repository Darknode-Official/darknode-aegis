#!/usr/bin/env python3
"""AEGIS Incident Response — playbooks, evidence collection, and communication templates."""
import sys
from datetime import datetime

IR_PLAYBOOKS = {
    "ransomware": {
        "name": "Ransomware",
        "severity": "CRITICAL",
        "detection": ["Ransom note on endpoints", "Mass file encryption (.encrypted, .locked extensions)", "Shadow copy deletion (vssadmin delete shadows)", "High CPU usage across multiple hosts", "SIEM alert for known ransomware IOCs"],
        "triage": ["Identify patient zero (first infected host)", "Determine ransomware variant (ransom note, file extension, behavior)", "Assess scope: how many hosts are affected?", "Check if backups are intact and accessible", "Determine if data was exfiltrated before encryption (double extortion)"],
        "containment": ["Isolate affected hosts from the network immediately", "Block C2 domains/IPs at firewall and DNS", "Disable affected user accounts", "Shutdown unaffected critical servers to prevent spread", "Preserve memory dumps before reimaging"],
        "eradication": ["Identify and patch the initial access vector", "Remove persistence mechanisms (scheduled tasks, services, registry)", "Reset ALL credentials (domain admin first, then all users)", "Scan all hosts with updated AV/EDR signatures", "Verify backup integrity before restoration"],
        "recovery": ["Restore from clean backups (verify they're not encrypted)", "Rebuild compromised hosts from known-good images", "Restore data in priority order: critical systems first", "Monitor for re-infection for 72+ hours", "Gradually reconnect systems to network"],
        "lessons_learned": ["How did the attacker gain initial access?", "Why did lateral movement succeed?", "Were backups properly segmented?", "What detection gaps allowed the attack to progress?", "Update IR playbook based on findings"],
    },
    "data_breach": {
        "name": "Data Breach",
        "severity": "CRITICAL",
        "detection": ["Unusual data access patterns", "Large data transfers to external destinations", "DLP alerts", "Dark web monitoring alert", "Third-party notification (FBI, customer)"],
        "triage": ["Identify what data was accessed/exfiltrated", "Determine the scope: number of records, data types (PII, PHI, financial)", "Identify the access method and timeline", "Classify data sensitivity (public, internal, confidential, restricted)", "Engage legal counsel immediately"],
        "containment": ["Revoke compromised credentials", "Block attacker IP addresses", "Disable compromised accounts/API keys", "Implement additional monitoring on affected systems", "Preserve all forensic evidence"],
        "eradication": ["Identify and close the vulnerability exploited", "Remove any backdoors or persistence", "Reset affected credentials", "Patch affected systems"],
        "recovery": ["Notify affected individuals per regulatory requirements", "Offer credit monitoring if PII exposed", "Implement additional security controls", "Update data classification and access controls"],
        "lessons_learned": ["Was data at rest encrypted?", "Were access controls properly configured?", "Was DLP effective?", "Review data retention policies"],
    },
    "phishing": {
        "name": "Phishing Incident",
        "severity": "HIGH",
        "detection": ["User report of suspicious email", "Email gateway quarantine", "SIEM alert for known phishing indicators", "Credential use from unusual location"],
        "triage": ["Analyze email headers (SPF, DKIM, DMARC results)", "Check if user clicked link or opened attachment", "If clicked: check for credential entry", "If attachment opened: check for malware execution", "Determine how many users received the email"],
        "containment": ["Block sender domain/IP in email gateway", "Block malicious URLs at proxy/DNS", "Reset credentials of any user who entered them", "Quarantine affected endpoints", "Search mail logs for all recipients"],
        "eradication": ["Remove phishing emails from all mailboxes (admin purge)", "Scan affected endpoints for malware", "Reset any compromised credentials", "Block indicators at perimeter (IPs, domains, hashes)"],
        "recovery": ["Re-enable affected accounts with new credentials", "Send awareness notification to all users", "Update email filtering rules"],
        "lessons_learned": ["Did email gateway catch it? If not, why?", "How quickly did users report?", "Was MFA in place for compromised accounts?"],
    },
    "insider_threat": {
        "name": "Insider Threat",
        "severity": "HIGH",
        "detection": ["DLP alert for sensitive data transfer", "Unusual after-hours access", "Access to systems outside job role", "Mass file download", "HR escalation (disgruntled employee, resignation)"],
        "triage": ["Determine if activity is malicious or accidental", "Identify the user and their access level", "Determine what data was accessed or exfiltrated", "Check for policy violations", "Coordinate with HR and legal"],
        "containment": ["Do NOT alert the suspect yet (coordinate with HR/legal)", "Increase monitoring on the account", "Preserve forensic evidence", "Restrict access to most sensitive systems if justified"],
        "eradication": ["Disable accounts upon HR/legal approval", "Revoke all access (VPN, email, cloud, physical)", "Collect company devices", "Change shared credentials the insider had access to"],
        "recovery": ["Review and update access controls", "Implement least-privilege where missing", "Update UEBA/DLP rules based on behavior observed"],
        "lessons_learned": ["Were access controls following least privilege?", "Was user behavior analytics in place?", "Were data loss prevention controls adequate?"],
    },
}

EVIDENCE_COMMANDS = {
    "linux": {
        "memory": ["dd if=/dev/mem of=memory.dump bs=1M (requires root)", "LiME: insmod lime.ko 'path=/tmp/memory.lime format=lime'", "avml (Microsoft AVML): avml memory.lime"],
        "disk": ["dd if=/dev/sda of=disk.img bs=4M status=progress", "dcfldd if=/dev/sda of=disk.img hash=sha256 hashlog=hashes.txt", "ewfacquire /dev/sda (E01 format)"],
        "logs": ["tar czf logs.tar.gz /var/log/", "journalctl --since '24 hours ago' > journal.log", "cp /var/log/auth.log /var/log/syslog /evidence/"],
        "processes": ["ps auxf > processes.txt", "ls -la /proc/*/exe 2>/dev/null > proc_exe.txt", "lsof -i > open_connections.txt", "ss -tulnp > listening_ports.txt"],
        "network": ["ip a > network_config.txt", "ip route > routes.txt", "iptables -L -n -v > firewall.txt", "ss -tulnp > connections.txt", "cat /etc/resolv.conf > dns.txt"],
        "filesystem": ["find / -newer /tmp/timestamp -type f 2>/dev/null > recent_files.txt", "find / -perm -4000 -type f 2>/dev/null > suid.txt", "ls -laR /tmp /var/tmp /dev/shm > temp_files.txt"],
    },
    "windows": {
        "memory": ["winpmem_mini.exe memory.raw", "DumpIt.exe (automated)", "Magnet RAM Capture"],
        "disk": ["FTK Imager: File > Create Disk Image", "wmic shadowcopy create Volume=C:\\", "robocopy C:\\ D:\\evidence\\ /MIR /LOG:copy.log"],
        "logs": ["wevtutil epl Security C:\\evidence\\security.evtx", "wevtutil epl System C:\\evidence\\system.evtx", "wevtutil epl Application C:\\evidence\\application.evtx", "wevtutil epl Microsoft-Windows-Sysmon/Operational C:\\evidence\\sysmon.evtx"],
        "processes": ["tasklist /v > processes.txt", "wmic process list full > wmic_processes.txt", "netstat -ano > connections.txt", "Get-Process | Export-Csv processes.csv"],
        "registry": ["reg save HKLM\\SAM C:\\evidence\\sam.hiv", "reg save HKLM\\SYSTEM C:\\evidence\\system.hiv", "reg save HKLM\\SOFTWARE C:\\evidence\\software.hiv", "reg save HKCU C:\\evidence\\ntuser.hiv"],
        "filesystem": ["dir /s /b /a C:\\ > full_listing.txt", "forfiles /P C:\\ /S /D +0 /C \"cmd /c echo @path @fdate @ftime\" > recent.txt"],
    },
}


def generate_custody_form(case_id, examiner, description):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"""=== CHAIN OF CUSTODY FORM ===

Case ID: {case_id}
Date/Time: {now}
Examiner: {examiner}
Description: {description}

Evidence Item #: ___
Description: _______________________________________________
Serial/ID: _______________________________________________
Hash (SHA-256): _______________________________________________
Location Found: _______________________________________________
Condition: _______________________________________________

Transfer Log:
| Date/Time | From | To | Purpose | Signature |
|-----------|------|-----|---------|-----------|
| {now} | {examiner} | Evidence Locker | Initial Collection | _________ |
| _________ | __________ | __________ | _________________ | _________ |

Notes:
_______________________________________________

Examiner Signature: _______________________________________________
Date: {now}
"""


class IncidentResponse:
    """Incident response workflow automation."""

    def get_playbook(self, incident_type):
        return IR_PLAYBOOKS.get(incident_type.lower().replace(" ", "_"))

    def list_playbooks(self):
        return list(IR_PLAYBOOKS.keys())

    def evidence_commands(self, os_type):
        return EVIDENCE_COMMANDS.get(os_type.lower(), {})

    def generate_custody_form(self, case_id, examiner, description):
        return generate_custody_form(case_id, examiner, description)

    def run(self, confirm_fn=None):
        print("\n=== AEGIS Incident Response ===")
        print(f"Playbooks: {', '.join(self.list_playbooks())}")
        print("Commands: playbook <type>, evidence <linux|windows>, custody, quit\n")
        while True:
            cmd = input("[ir] > ").strip()
            if cmd.lower() in ("quit", "exit", "q"):
                break
            if cmd.lower().startswith("playbook "):
                pb = self.get_playbook(cmd[9:])
                if pb:
                    print(f"\n  === {pb['name']} Incident Response Playbook ===")
                    print(f"  Severity: {pb['severity']}\n")
                    for phase in ["detection", "triage", "containment", "eradication", "recovery", "lessons_learned"]:
                        print(f"  --- {phase.replace('_', ' ').title()} ---")
                        for step in pb.get(phase, []):
                            print(f"    - {step}")
                        print()
                else:
                    print(f"  Unknown incident type. Available: {', '.join(self.list_playbooks())}")
            elif cmd.lower().startswith("evidence "):
                os_type = cmd[9:].strip()
                cmds = self.evidence_commands(os_type)
                if cmds:
                    for cat, commands in cmds.items():
                        print(f"\n  --- {cat.title()} ---")
                        for c in commands:
                            print(f"    {c}")
                else:
                    print("  Use: evidence linux OR evidence windows")
            elif cmd.lower() == "custody":
                case_id = input("  Case ID: ").strip() or "AEGIS-001"
                examiner = input("  Examiner name: ").strip() or "Analyst"
                desc = input("  Description: ").strip() or "Digital forensic evidence"
                print(self.generate_custody_form(case_id, examiner, desc))
            else:
                print("  Commands: playbook <type>, evidence <os>, custody, quit")


if __name__ == "__main__":
    IncidentResponse().run()
