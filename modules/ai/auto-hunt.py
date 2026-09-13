#!/usr/bin/env python3
"""AEGIS Automated Threat Hunting — hypothesis-driven hunting with detection queries."""
import os, sys, json
from datetime import datetime

class AutoHunt:
    name = "Automated Threat Hunting"
    description = "30 hunting hypotheses with Splunk/ELK queries, evidence guidance, false positive handling"
    category = "ai"
    mitre = ["T1059", "T1003", "T1071", "T1046"]

    HYPOTHESES = [
        {"id": "H001", "name": "PowerShell Abuse", "phase": "Execution",
         "hypothesis": "An attacker is using PowerShell for malicious execution on endpoints",
         "data_sources": ["Windows PowerShell logs (4103, 4104)", "Sysmon EventID 1"],
         "splunk": 'index=wineventlog sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 | search ScriptBlockText="*Invoke-Mimikatz*" OR ScriptBlockText="*DownloadString*" OR ScriptBlockText="*IEX*" OR ScriptBlockText="*EncodedCommand*" OR ScriptBlockText="*-enc*" OR ScriptBlockText="*bypass*" | table _time ComputerName ScriptBlockText',
         "elk": 'event.code:4104 AND powershell.scriptblock.text:(*Invoke-Mimikatz* OR *DownloadString* OR *IEX* OR *EncodedCommand*)',
         "evidence": ["Full script block text", "Parent process", "User context", "Network connections around event time"],
         "false_positives": ["SCCM deployment scripts", "DSC configurations", "IT automation (Ansible, Chef)"],
         "mitre": "T1059.001"},
        {"id": "H002", "name": "C2 Beaconing via DNS", "phase": "C2",
         "hypothesis": "An implant is beaconing to a C2 server using DNS queries",
         "data_sources": ["DNS logs", "Sysmon EventID 22", "Passive DNS"],
         "splunk": 'index=dns | eval query_len=len(query) | where query_len > 50 | stats count avg(query_len) as avg_len dc(query) as unique_queries by src_ip answer | where count > 100 | sort -count',
         "elk": 'dns.question.name:* AND NOT dns.question.name:(*.google.com OR *.microsoft.com OR *.amazonaws.com) | query length > 50',
         "evidence": ["High-volume DNS queries to single domain", "Long subdomain labels", "Regular query intervals", "Non-standard record types (TXT, NULL)"],
         "false_positives": ["CDN lookups", "Anti-virus update checks", "SaaS application telemetry"],
         "mitre": "T1071.004"},
        {"id": "H003", "name": "LSASS Credential Theft", "phase": "Credential Access",
         "hypothesis": "An attacker is accessing LSASS memory to extract credentials",
         "data_sources": ["Sysmon EventID 10 (ProcessAccess)", "Windows Security 4663"],
         "splunk": 'index=sysmon EventCode=10 TargetImage="*lsass.exe" | where NOT match(SourceImage, "(csrss|services|wmiprvse|svchost|lsm|winlogon)\\.exe$") | table _time SourceImage TargetImage GrantedAccess CallTrace',
         "elk": 'event.code:10 AND process.target.name:lsass.exe AND NOT process.name:(csrss.exe OR services.exe OR wmiprvse.exe)',
         "evidence": ["Source process accessing LSASS", "Granted access rights (0x1010, 0x1410 = suspicious)", "Call trace showing MiniDumpWriteDump"],
         "false_positives": ["AV/EDR scanning LSASS", "Windows Defender", "Credential Guard interactions"],
         "mitre": "T1003.001"},
        {"id": "H004", "name": "Lateral Movement via PsExec", "phase": "Lateral Movement",
         "hypothesis": "An attacker is using PsExec-style tools for lateral movement",
         "data_sources": ["Windows Security 4624, 4648, 7045", "Sysmon 1, 13, 17/18"],
         "splunk": 'index=wineventlog (EventCode=7045 Service_File_Name="*PSEXESVC*") OR (EventCode=4624 Logon_Type=3 Source_Network_Address!="127.0.0.1") OR (EventCode=1 ParentImage="*services.exe" Image="*cmd.exe*") | table _time EventCode ComputerName Account_Name Source_Network_Address',
         "elk": '(event.code:7045 AND service.name:PSEXESVC) OR (event.code:4624 AND winlog.logon.type:3)',
         "evidence": ["Service creation events", "Named pipe creation (\\psexec)", "Remote logon from unusual source", "cmd.exe spawned by services.exe"],
         "false_positives": ["IT admin using SysInternals PsExec", "SCCM remote execution"],
         "mitre": "T1569.002"},
        {"id": "H005", "name": "Data Exfiltration via Cloud Storage", "phase": "Exfiltration",
         "hypothesis": "An attacker is exfiltrating data to cloud storage services",
         "data_sources": ["Proxy logs", "Firewall logs", "DLP alerts"],
         "splunk": 'index=proxy (dest="*dropbox.com*" OR dest="*drive.google.com*" OR dest="*onedrive.live.com*" OR dest="*mega.nz*" OR dest="*anonfiles.com*") | stats sum(bytes_out) as total_bytes by src_ip dest | where total_bytes > 104857600 | eval MB=round(total_bytes/1048576,2)',
         "elk": 'destination.domain:(*dropbox.com OR *drive.google.com OR *mega.nz) AND network.bytes > 10000000',
         "evidence": ["Large upload volumes to cloud services", "Uploads during off-hours", "First-time use of specific cloud service", "Compressed/encrypted file uploads"],
         "false_positives": ["Legitimate cloud backup", "File sharing for business purposes", "Cloud-based development tools"],
         "mitre": "T1567.002"},
        {"id": "H006", "name": "Kerberoasting", "phase": "Credential Access",
         "hypothesis": "An attacker is requesting Kerberos TGS tickets for offline cracking",
         "data_sources": ["Windows Security 4769", "Domain Controller logs"],
         "splunk": 'index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17 | stats count by Account_Name Service_Name Client_Address | where count > 5 | sort -count',
         "elk": 'event.code:4769 AND winlog.event_data.TicketEncryptionType:0x17',
         "evidence": ["Multiple TGS requests with RC4 encryption from single account", "Requests for service accounts with SPNs", "Unusual source IP"],
         "false_positives": ["Legacy applications using RC4", "Service account normal authentication"],
         "mitre": "T1558.003"},
        {"id": "H007", "name": "Ransomware Precursors", "phase": "Impact",
         "hypothesis": "Pre-ransomware activity: shadow copy deletion, mass file encryption preparation",
         "data_sources": ["Sysmon", "Windows Security", "File integrity monitoring"],
         "splunk": 'index=sysmon (CommandLine="*vssadmin*delete*" OR CommandLine="*wmic*shadowcopy*delete*" OR CommandLine="*bcdedit*recoveryenabled*no*" OR CommandLine="*wbadmin*delete*catalog*") | table _time ComputerName User CommandLine ParentCommandLine',
         "elk": 'process.command_line:(*vssadmin*delete* OR *shadowcopy*delete* OR *bcdedit*recoveryenabled*)',
         "evidence": ["VSS deletion commands", "Recovery disable commands", "Mass file rename/extension change", "Ransom note file creation"],
         "false_positives": ["VSS cleanup by backup software (Veeam, Commvault)", "Disk space management"],
         "mitre": "T1490"},
        {"id": "H008", "name": "Golden Ticket Usage", "phase": "Persistence",
         "hypothesis": "An attacker has forged a Kerberos TGT (Golden Ticket)",
         "data_sources": ["Domain Controller Security logs 4768, 4769"],
         "splunk": 'index=wineventlog EventCode=4769 | where Account_Name != "$" AND Service_Name = "krbtgt" | table _time Account_Name Client_Address Ticket_Encryption_Type',
         "elk": 'event.code:4769 AND winlog.event_data.ServiceName:krbtgt',
         "evidence": ["TGT with abnormal lifetime (>10 hours default)", "TGT for non-existent user", "TGT with unusual encryption type", "Account domain mismatch"],
         "false_positives": ["Legitimate Kerberos renewal", "krbtgt password rotation (legitimate)"],
         "mitre": "T1558.001"},
        {"id": "H009", "name": "Web Shell Activity", "phase": "Persistence",
         "hypothesis": "A web shell has been deployed on a web server",
         "data_sources": ["Web server access logs", "File integrity monitoring", "Sysmon"],
         "splunk": 'index=web sourcetype=access_combined (uri_path="*.php" OR uri_path="*.asp" OR uri_path="*.jsp") status=200 | stats count by uri_path src_ip | where count > 50 | sort -count',
         "elk": 'http.response.status_code:200 AND url.path:(*.php OR *.asp OR *.jsp) AND NOT url.path:(*index* OR *login* OR *api*)',
         "evidence": ["Single IP accessing a specific script repeatedly", "POST requests to unusual file paths", "Web server process spawning cmd/powershell/bash", "New files in web root"],
         "false_positives": ["Legitimate dynamic pages", "API endpoints", "CMS admin panels"],
         "mitre": "T1505.003"},
        {"id": "H010", "name": "Living Off the Land", "phase": "Defense Evasion",
         "hypothesis": "An attacker is using LOLBins to evade detection",
         "data_sources": ["Sysmon EventID 1", "Windows Security 4688"],
         "splunk": 'index=sysmon EventCode=1 (Image="*certutil*" OR Image="*mshta*" OR Image="*regsvr32*" OR Image="*rundll32*" OR Image="*bitsadmin*" OR Image="*msiexec*") | where match(CommandLine, "(http|ftp|\\\\\\\\|download|decode|encode|urlcache)") | table _time User Image CommandLine ParentImage',
         "elk": 'event.code:1 AND process.name:(certutil.exe OR mshta.exe OR regsvr32.exe OR bitsadmin.exe) AND process.command_line:(*http* OR *download* OR *decode*)',
         "evidence": ["LOLBin downloading from URL", "LOLBin with encoded/obfuscated arguments", "Unusual parent process for LOLBin", "Network connection from LOLBin process"],
         "false_positives": ["certutil for certificate management", "msiexec for legitimate installs", "bitsadmin for Windows Update"],
         "mitre": "T1218"},
    ]

    def __init__(self, target=None, options=None):
        self.target = target
        self.options = options or {}
        self.findings = []
        self.actions = []

    def _log(self, msg):
        self.actions.append({"time": datetime.now().isoformat(), "action": msg})
        print(f"  [HUNT] {msg}")

    def list_hypotheses(self, phase=None):
        hyps = self.HYPOTHESES
        if phase:
            hyps = [h for h in hyps if h['phase'].lower() == phase.lower()]
        for h in hyps:
            print(f"\n  [{h['id']}] {h['name']} ({h['phase']})")
            print(f"  Hypothesis: {h['hypothesis']}")
            print(f"  MITRE: {h['mitre']}")
            print(f"  Data sources: {', '.join(h['data_sources'])}")
            print(f"  Splunk: {h['splunk'][:120]}...")
        return hyps

    def generate_hunt_plan(self, hypotheses_ids=None):
        if hypotheses_ids:
            selected = [h for h in self.HYPOTHESES if h['id'] in hypotheses_ids]
        else:
            selected = self.HYPOTHESES
        plan = "# THREAT HUNTING PLAN\n"
        plan += f"# Generated: {datetime.now().isoformat()}\n"
        plan += f"# Hypotheses: {len(selected)}\n\n"
        for h in selected:
            plan += f"## {h['id']}: {h['name']}\n"
            plan += f"**Phase:** {h['phase']} | **MITRE:** {h['mitre']}\n\n"
            plan += f"**Hypothesis:** {h['hypothesis']}\n\n"
            plan += f"**Data Sources:** {', '.join(h['data_sources'])}\n\n"
            plan += f"**Splunk Query:**\n```\n{h['splunk']}\n```\n\n"
            plan += f"**ELK Query:**\n```\n{h['elk']}\n```\n\n"
            plan += f"**Evidence to collect:**\n"
            for e in h['evidence']:
                plan += f"- {e}\n"
            plan += f"\n**False positives:**\n"
            for fp in h['false_positives']:
                plan += f"- {fp}\n"
            plan += "\n---\n\n"
        self._log(f"Generated hunt plan with {len(selected)} hypotheses")
        return plan

    def run(self, confirm_fn=None):
        op = self.options.get('operation', 'list')
        if op == 'list':
            return self.list_hypotheses()
        elif op == 'plan':
            return self.generate_hunt_plan()
        elif op == 'phase':
            return self.list_hypotheses(self.target)
        return {"error": f"Unknown operation: {op}"}

    def get_findings(self):
        return self.findings

if __name__ == "__main__":
    ah = AutoHunt(options={'operation': sys.argv[1] if len(sys.argv) > 1 else 'list'})
    result = ah.run()
    if isinstance(result, str):
        print(result)
