#!/usr/bin/env python3
"""Advanced threat hunting engine — 40 hypotheses with Splunk/ELK queries organized by MITRE tactic"""
import sys
import json
from datetime import datetime

class ThreatHunt:
    name = "Threat Hunt Engine"
    description = "40 hunting hypotheses organized by MITRE tactic with Splunk and ELK detection queries"
    category = "defense"
    mitre = ["T1059", "T1053", "T1547", "T1003", "T1021", "T1048"]

    HYPOTHESES = [
        # Initial Access
        {"id": "H-IA-01", "tactic": "Initial Access", "title": "Unusual login sources", "mitre": "T1078",
         "description": "An attacker is using stolen credentials to log in from an unusual geographic location or IP range that has never been associated with the account.",
         "data_sources": ["Authentication logs", "VPN logs", "Cloud sign-in logs"],
         "splunk": 'index=auth action=success | stats values(src_ip) as ips dc(src_ip) as ip_count by user | where ip_count > 3 | table user ips ip_count',
         "elk": '(event.action:"login" OR event.action:"authentication") AND event.outcome:"success" | stats by source.ip, user.name',
         "evidence": ["Source IPs with geolocation", "Login timestamps", "User agent strings", "MFA status"],
         "false_positives": ["VPN users, travel, mobile hotspots, cloud-proxied connections"],
         "priority": "HIGH"},
        {"id": "H-IA-02", "tactic": "Initial Access", "title": "New OAuth applications", "mitre": "T1550.001",
         "description": "An attacker has registered a malicious OAuth application to maintain persistent access to a user's cloud account without needing credentials.",
         "data_sources": ["Azure AD sign-in logs", "Google Workspace admin logs", "Office 365 unified audit log"],
         "splunk": 'index=o365 Operation="Consent to application" | table CreationTime UserId ApplicationId',
         "elk": 'event.action:"Consent to application" | stats by user.name, o365.audit.ObjectId',
         "evidence": ["App registration details", "Permissions granted", "Publisher information"],
         "false_positives": ["IT-approved SaaS integrations, developer testing"],
         "priority": "HIGH"},
        {"id": "H-IA-03", "tactic": "Initial Access", "title": "Suspicious email forwarding rules", "mitre": "T1114.003",
         "description": "An attacker has created email forwarding rules to exfiltrate sensitive emails to an external address.",
         "data_sources": ["Exchange/O365 audit logs", "Mail flow rules"],
         "splunk": 'index=o365 Operation="New-InboxRule" | search ForwardTo=* OR RedirectTo=* | table CreationTime UserId ForwardTo RedirectTo',
         "elk": 'event.action:"New-InboxRule" AND (o365.audit.Parameters.ForwardTo:* OR o365.audit.Parameters.RedirectTo:*)',
         "evidence": ["Rule configuration", "External email addresses", "Creation timestamp"],
         "false_positives": ["User-created vacation rules, shared mailbox rules"],
         "priority": "CRITICAL"},

        # Execution
        {"id": "H-EX-01", "tactic": "Execution", "title": "Encoded PowerShell execution", "mitre": "T1059.001",
         "description": "An attacker is using Base64-encoded PowerShell commands to evade detection by command-line logging.",
         "data_sources": ["Sysmon Event ID 1", "Windows Security Event 4688", "PowerShell logs 4103/4104"],
         "splunk": 'index=sysmon EventCode=1 Image="*powershell*" CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR CommandLine="*FromBase64*" | table _time Computer User CommandLine',
         "elk": 'process.name:"powershell.exe" AND process.command_line:(*-enc* OR *EncodedCommand* OR *FromBase64*)',
         "evidence": ["Encoded command (decode with base64 -d)", "Parent process", "User context"],
         "false_positives": ["SCCM, DSC, legitimate admin scripts using encoding for special characters"],
         "priority": "HIGH"},
        {"id": "H-EX-02", "tactic": "Execution", "title": "WMI process creation", "mitre": "T1047",
         "description": "An attacker is using WMI to create processes on remote systems for lateral movement or command execution.",
         "data_sources": ["Sysmon Event ID 1 (parent=wmiprvse.exe)", "WMI-Activity operational log"],
         "splunk": 'index=sysmon EventCode=1 ParentImage="*wmiprvse.exe" | table _time Computer User Image CommandLine',
         "elk": 'process.parent.name:"wmiprvse.exe" AND event.code:"1"',
         "evidence": ["Child process details", "Remote connection source", "WMI query/consumer"],
         "false_positives": ["SCCM, monitoring tools, legitimate WMI scripts"],
         "priority": "MEDIUM"},
        {"id": "H-EX-03", "tactic": "Execution", "title": "LOLBIN abuse (mshta, regsvr32, certutil, rundll32)", "mitre": "T1218",
         "description": "An attacker is abusing legitimate Windows binaries (LOLBins) to download and execute payloads while evading application whitelisting.",
         "data_sources": ["Sysmon Event ID 1", "Windows Security 4688"],
         "splunk": 'index=sysmon EventCode=1 (Image="*mshta.exe" OR Image="*regsvr32.exe" OR Image="*certutil.exe" OR Image="*rundll32.exe" OR Image="*wscript.exe" OR Image="*cscript.exe" OR Image="*msiexec.exe") | where NOT match(CommandLine, "(?i)(sccm|configmgr|mcafee|symantec)") | table _time Computer User Image CommandLine',
         "elk": 'process.name:("mshta.exe" OR "regsvr32.exe" OR "certutil.exe" OR "rundll32.exe" OR "wscript.exe" OR "cscript.exe") AND NOT process.command_line:(*sccm* OR *configmgr*)',
         "evidence": ["Full command line", "Network connections from the process", "Downloaded files"],
         "false_positives": ["Software installations, Windows Updates, admin scripts"],
         "priority": "HIGH"},

        # Persistence
        {"id": "H-PE-01", "tactic": "Persistence", "title": "New services installed", "mitre": "T1543.003",
         "description": "An attacker has installed a malicious Windows service for persistence. Services run at SYSTEM level and survive reboots.",
         "data_sources": ["Windows System Event 7045", "Sysmon Event 6 (driver loaded)"],
         "splunk": 'index=wineventlog source="WinEventLog:System" EventCode=7045 | table _time ComputerName Service_Name Service_File_Name Service_Type Service_Start_Type Account',
         "elk": 'event.code:"7045" | stats by winlog.event_data.ServiceName, winlog.event_data.ImagePath',
         "evidence": ["Service name and path", "Service account", "File hash of service binary"],
         "false_positives": ["Software installations, Windows updates, security tools"],
         "priority": "HIGH"},
        {"id": "H-PE-02", "tactic": "Persistence", "title": "Scheduled task creation", "mitre": "T1053.005",
         "description": "An attacker has created a scheduled task to maintain persistence or execute commands at specific times.",
         "data_sources": ["Windows Security Event 4698", "Sysmon"],
         "splunk": 'index=wineventlog EventCode=4698 | table _time SubjectUserName TaskName TaskContent | sort -_time',
         "elk": 'event.code:"4698" | stats by winlog.event_data.SubjectUserName, winlog.event_data.TaskName',
         "evidence": ["Task name and XML content", "Trigger configuration", "Action executable path"],
         "false_positives": ["Windows Update, IT management tools, scheduled backups"],
         "priority": "HIGH"},
        {"id": "H-PE-03", "tactic": "Persistence", "title": "Registry Run key modification", "mitre": "T1547.001",
         "description": "An attacker has modified registry Run/RunOnce keys to execute malware on every user logon.",
         "data_sources": ["Sysmon Event 13 (registry value set)"],
         "splunk": 'index=sysmon EventCode=13 TargetObject="*CurrentVersion\\\\Run*" | table _time Computer Image TargetObject Details',
         "elk": 'event.code:"13" AND registry.path:*CurrentVersion\\\\Run*',
         "evidence": ["Registry key path", "Value data (executable path)", "Process that made the change"],
         "false_positives": ["Software installations, startup programs, user preferences"],
         "priority": "MEDIUM"},
        {"id": "H-PE-04", "tactic": "Persistence", "title": "Startup folder additions", "mitre": "T1547.001",
         "description": "An attacker has placed a malicious file or shortcut in the Startup folder.",
         "data_sources": ["Sysmon Event 11 (file created)"],
         "splunk": 'index=sysmon EventCode=11 TargetFilename="*\\\\Start Menu\\\\Programs\\\\Startup\\\\*" | table _time Computer Image TargetFilename',
         "elk": 'event.code:"11" AND file.path:*Startup*',
         "evidence": ["File path", "File hash", "Creating process"],
         "false_positives": ["Legitimate software adding startup entries"],
         "priority": "MEDIUM"},

        # Privilege Escalation
        {"id": "H-PR-01", "tactic": "Privilege Escalation", "title": "UAC bypass techniques", "mitre": "T1548.002",
         "description": "An attacker is bypassing User Account Control to elevate privileges without triggering a UAC prompt.",
         "data_sources": ["Sysmon Event 1", "Sysmon Event 13 (registry)"],
         "splunk": 'index=sysmon EventCode=1 (Image="*fodhelper.exe" OR Image="*eventvwr.exe" OR Image="*computerdefaults.exe" OR Image="*sdclt.exe") NOT User="SYSTEM" | table _time Computer User Image ParentImage CommandLine',
         "elk": 'process.name:("fodhelper.exe" OR "eventvwr.exe" OR "computerdefaults.exe" OR "sdclt.exe") AND NOT user.name:"SYSTEM"',
         "evidence": ["Auto-elevating binary used", "Spawned child process", "Registry modifications"],
         "false_positives": ["Legitimate use of these utilities (rare for non-admin users)"],
         "priority": "HIGH"},
        {"id": "H-PR-02", "tactic": "Privilege Escalation", "title": "Token manipulation / Potato attacks", "mitre": "T1134",
         "description": "An attacker is abusing Windows token impersonation (JuicyPotato, PrintSpoofer, SweetPotato) to escalate from service account to SYSTEM.",
         "data_sources": ["Sysmon Event 1", "Sysmon Event 10 (process access)"],
         "splunk": 'index=sysmon EventCode=1 (CommandLine="*JuicyPotato*" OR CommandLine="*PrintSpoofer*" OR CommandLine="*SweetPotato*" OR CommandLine="*GodPotato*" OR CommandLine="*RoguePotato*") | table _time Computer User Image CommandLine',
         "elk": 'process.command_line:(*JuicyPotato* OR *PrintSpoofer* OR *SweetPotato* OR *GodPotato*)',
         "evidence": ["Tool binary", "Spawned SYSTEM process", "COM object or named pipe used"],
         "false_positives": ["Authorized penetration testing"],
         "priority": "CRITICAL"},

        # Defense Evasion
        {"id": "H-DE-01", "tactic": "Defense Evasion", "title": "Timestomping detected", "mitre": "T1070.006",
         "description": "An attacker is modifying file timestamps to blend malicious files with legitimate system files.",
         "data_sources": ["Sysmon Event 2 (file creation time changed)"],
         "splunk": 'index=sysmon EventCode=2 | table _time Computer Image TargetFilename CreationUtcTime PreviousCreationUtcTime',
         "elk": 'event.code:"2" | stats by process.name, file.path',
         "evidence": ["Original vs modified timestamp", "Process that changed the time", "File in question"],
         "false_positives": ["Archive extraction, file copy operations, build tools"],
         "priority": "MEDIUM"},
        {"id": "H-DE-02", "tactic": "Defense Evasion", "title": "Security log cleared", "mitre": "T1070.001",
         "description": "An attacker has cleared Windows Security or System event logs to cover tracks.",
         "data_sources": ["Windows Security Event 1102", "System Event 104"],
         "splunk": 'index=wineventlog (EventCode=1102 OR EventCode=104) | table _time ComputerName SubjectUserName LogName',
         "elk": '(event.code:"1102" OR event.code:"104")',
         "evidence": ["Who cleared the log", "Which log was cleared", "Surrounding events before clearing"],
         "false_positives": ["Log rotation policies, admin maintenance (should be documented)"],
         "priority": "CRITICAL"},
        {"id": "H-DE-03", "tactic": "Defense Evasion", "title": "AMSI bypass attempt", "mitre": "T1562.001",
         "description": "An attacker is bypassing the Antimalware Scan Interface to run malicious scripts undetected.",
         "data_sources": ["PowerShell Script Block Logging (4104)", "Sysmon"],
         "splunk": 'index=wineventlog EventCode=4104 ScriptBlockText="*AmsiUtils*" OR ScriptBlockText="*amsiInitFailed*" OR ScriptBlockText="*SetValue*amsi*" | table _time Computer ScriptBlockText',
         "elk": 'event.code:"4104" AND powershell.script_block_text:(*AmsiUtils* OR *amsiInitFailed*)',
         "evidence": ["Full script block content", "Process and user", "What ran after the bypass"],
         "false_positives": ["Security researchers testing AMSI, red team exercises"],
         "priority": "CRITICAL"},
        {"id": "H-DE-04", "tactic": "Defense Evasion", "title": "Process hollowing / injection", "mitre": "T1055",
         "description": "An attacker is injecting code into legitimate processes to evade detection.",
         "data_sources": ["Sysmon Event 8 (CreateRemoteThread)", "Sysmon Event 10 (ProcessAccess)"],
         "splunk": 'index=sysmon EventCode=8 | where SourceImage!=TargetImage | table _time SourceImage TargetImage StartAddress StartFunction',
         "elk": 'event.code:"8" AND NOT (process.executable: winlog.event_data.TargetImage)',
         "evidence": ["Source and target process", "Thread start address", "Memory regions"],
         "false_positives": ["Security tools (EDR injection), debuggers, some .NET applications"],
         "priority": "HIGH"},

        # Credential Access
        {"id": "H-CA-01", "tactic": "Credential Access", "title": "LSASS memory access", "mitre": "T1003.001",
         "description": "An attacker is accessing LSASS process memory to extract credentials (Mimikatz, procdump, comsvcs.dll).",
         "data_sources": ["Sysmon Event 10 (ProcessAccess to lsass.exe)"],
         "splunk": 'index=sysmon EventCode=10 TargetImage="*lsass.exe" | where SourceImage!="*csrss.exe" AND SourceImage!="*services.exe" AND SourceImage!="*svchost.exe" AND SourceImage!="*MsMpEng.exe" | table _time Computer SourceImage GrantedAccess CallTrace',
         "elk": 'event.code:"10" AND process.target.name:"lsass.exe" AND NOT process.name:("csrss.exe" OR "services.exe" OR "svchost.exe" OR "MsMpEng.exe")',
         "evidence": ["Source process accessing LSASS", "Access mask (0x1010 = suspicious)", "Call trace"],
         "false_positives": ["EDR/AV scanning LSASS, Windows Credential Guard"],
         "priority": "CRITICAL"},
        {"id": "H-CA-02", "tactic": "Credential Access", "title": "Kerberoasting activity", "mitre": "T1558.003",
         "description": "An attacker is requesting TGS tickets for service accounts to crack offline.",
         "data_sources": ["Windows Security Event 4769"],
         "splunk": 'index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17 | stats count by Account_Name Service_Name Client_Address | where count > 5',
         "elk": 'event.code:"4769" AND winlog.event_data.TicketEncryptionType:"0x17" | stats by user.name, service.name',
         "evidence": ["RC4 (0x17) ticket requests", "Volume of requests", "Requesting user"],
         "false_positives": ["Legacy applications still using RC4, legitimate service ticket requests"],
         "priority": "HIGH"},
        {"id": "H-CA-03", "tactic": "Credential Access", "title": "DCSync replication", "mitre": "T1003.006",
         "description": "An attacker with domain admin privileges is replicating AD credentials using the DCSync technique.",
         "data_sources": ["Windows Security Event 4662"],
         "splunk": 'index=wineventlog EventCode=4662 Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*" | where SubjectUserName!="*$" | table _time SubjectUserName ObjectName',
         "elk": 'event.code:"4662" AND winlog.event_data.Properties:*1131f6aa*',
         "evidence": ["Non-DC account performing replication", "Replication GUIDs accessed"],
         "false_positives": ["Legitimate domain controller replication, Azure AD Connect"],
         "priority": "CRITICAL"},
        {"id": "H-CA-04", "tactic": "Credential Access", "title": "Credential files on disk", "mitre": "T1552.001",
         "description": "An attacker is searching for credential files (unattend.xml, web.config, .env, password files) on compromised systems.",
         "data_sources": ["Sysmon Event 1 (findstr/grep commands)", "File access logs"],
         "splunk": 'index=sysmon EventCode=1 (CommandLine="*findstr*password*" OR CommandLine="*findstr*credential*" OR CommandLine="*dir*unattend*" OR CommandLine="*type*web.config*" OR CommandLine="*find*password*") | table _time Computer User CommandLine',
         "elk": 'process.command_line:(*findstr*password* OR *findstr*credential* OR *dir*unattend* OR *find*password*)',
         "evidence": ["Search commands used", "Files accessed", "Data found"],
         "false_positives": ["IT auditing scripts, configuration management"],
         "priority": "MEDIUM"},

        # Discovery
        {"id": "H-DI-01", "tactic": "Discovery", "title": "Active Directory enumeration", "mitre": "T1087.002",
         "description": "An attacker is enumerating AD users, groups, and computers using net commands, PowerView, or BloodHound.",
         "data_sources": ["Sysmon Event 1", "Windows Security 4661/4662"],
         "splunk": 'index=sysmon EventCode=1 (CommandLine="*net user /domain*" OR CommandLine="*net group /domain*" OR CommandLine="*Get-ADUser*" OR CommandLine="*Get-ADGroup*" OR CommandLine="*Get-DomainUser*" OR Image="*SharpHound*" OR Image="*bloodhound*") | table _time Computer User CommandLine',
         "elk": 'process.command_line:(*net user /domain* OR *net group /domain* OR *Get-ADUser* OR *Get-DomainUser* OR *SharpHound*)',
         "evidence": ["Enumeration commands", "Data collected", "BloodHound zip output"],
         "false_positives": ["IT administrators, helpdesk, legitimate AD management"],
         "priority": "MEDIUM"},
        {"id": "H-DI-02", "tactic": "Discovery", "title": "Internal network scanning", "mitre": "T1046",
         "description": "An attacker is scanning the internal network from a compromised host to discover other targets.",
         "data_sources": ["Firewall logs", "IDS alerts", "Sysmon Event 3"],
         "splunk": 'index=sysmon EventCode=3 | stats dc(DestinationPort) as ports dc(DestinationIp) as targets by SourceIp | where ports > 20 OR targets > 10 | table SourceIp ports targets',
         "elk": 'event.code:"3" | stats by source.ip | where doc_count > 50',
         "evidence": ["Source IP", "Ports scanned", "Targets discovered"],
         "false_positives": ["Vulnerability scanners, monitoring tools, SCCM"],
         "priority": "HIGH"},

        # Lateral Movement
        {"id": "H-LM-01", "tactic": "Lateral Movement", "title": "PsExec / service-based lateral movement", "mitre": "T1569.002",
         "description": "An attacker is using PsExec or similar tools to execute commands on remote systems via SMB service creation.",
         "data_sources": ["Windows System Event 7045", "Sysmon Event 1"],
         "splunk": 'index=wineventlog EventCode=7045 (Service_File_Name="*PSEXESVC*" OR Service_File_Name="*\\\\ADMIN$*" OR Service_File_Name="*cmd.exe*" OR Service_File_Name="*powershell*") | table _time ComputerName Service_Name Service_File_Name Account',
         "elk": 'event.code:"7045" AND winlog.event_data.ImagePath:(*PSEXESVC* OR *ADMIN$* OR *cmd.exe* OR *powershell*)',
         "evidence": ["Service name and binary path", "Remote source", "Account used"],
         "false_positives": ["IT remote management, SCCM, legitimate PsExec use by admins"],
         "priority": "HIGH"},
        {"id": "H-LM-02", "tactic": "Lateral Movement", "title": "WinRM lateral movement", "mitre": "T1021.006",
         "description": "An attacker is using WinRM/PowerShell Remoting to execute commands on remote systems.",
         "data_sources": ["Windows Security 4624 (Logon Type 3)", "PowerShell logs", "WinRM operational logs"],
         "splunk": 'index=wineventlog EventCode=4624 Logon_Type=3 Authentication_Package=Kerberos | stats count by Source_Network_Address Account_Name Workstation_Name | where count > 5',
         "elk": 'event.code:"4624" AND winlog.event_data.LogonType:"3" AND winlog.event_data.AuthenticationPackageName:"Kerberos"',
         "evidence": ["Source IP", "Account used", "Commands executed"],
         "false_positives": ["Legitimate PowerShell remoting, configuration management"],
         "priority": "MEDIUM"},
        {"id": "H-LM-03", "tactic": "Lateral Movement", "title": "RDP lateral movement", "mitre": "T1021.001",
         "description": "An attacker is using RDP to move laterally within the network.",
         "data_sources": ["Windows Security 4624 (Type 10)", "TerminalServices-RemoteConnectionManager Event 1149"],
         "splunk": 'index=wineventlog EventCode=4624 Logon_Type=10 | table _time Source_Network_Address Account_Name Workstation_Name',
         "elk": 'event.code:"4624" AND winlog.event_data.LogonType:"10"',
         "evidence": ["Source IP", "Destination host", "Session duration"],
         "false_positives": ["Legitimate remote administration, help desk support"],
         "priority": "MEDIUM"},
        {"id": "H-LM-04", "tactic": "Lateral Movement", "title": "SMB file copy for staging", "mitre": "T1021.002",
         "description": "An attacker is copying tools or data to remote systems via SMB shares ($ADMIN, $C, custom shares).",
         "data_sources": ["Sysmon Event 11 (FileCreate on shares)", "Windows Security 5145"],
         "splunk": 'index=wineventlog EventCode=5145 RelativeTargetName="*.exe" OR RelativeTargetName="*.dll" OR RelativeTargetName="*.ps1" OR RelativeTargetName="*.bat" | table _time SubjectUserName ShareName RelativeTargetName IpAddress',
         "elk": 'event.code:"5145" AND file.name:(*.exe OR *.dll OR *.ps1 OR *.bat)',
         "evidence": ["File name and path", "Share accessed", "Source IP", "User account"],
         "false_positives": ["Software deployment, GPO-delivered scripts, file shares"],
         "priority": "MEDIUM"},

        # Collection
        {"id": "H-CO-01", "tactic": "Collection", "title": "Archive creation for staging", "mitre": "T1560.001",
         "description": "An attacker is creating archives (zip, rar, 7z) to stage data for exfiltration.",
         "data_sources": ["Sysmon Event 1 (process creation)", "Sysmon Event 11 (file creation)"],
         "splunk": 'index=sysmon EventCode=1 (Image="*7z*" OR Image="*rar*" OR Image="*zip*" OR CommandLine="*Compress-Archive*" OR CommandLine="*tar -c*") | table _time Computer User Image CommandLine',
         "elk": 'process.name:(*7z* OR *rar* OR *zip*) OR process.command_line:(*Compress-Archive* OR *tar -c*)',
         "evidence": ["Archive tool used", "Source directories", "Output file path and size"],
         "false_positives": ["Backup processes, developer workflows, legitimate archiving"],
         "priority": "MEDIUM"},

        # Command and Control
        {"id": "H-C2-01", "tactic": "C2", "title": "DNS beaconing", "mitre": "T1071.004",
         "description": "An attacker's implant is beaconing via DNS queries at regular intervals to a C2 domain.",
         "data_sources": ["DNS query logs", "Passive DNS"],
         "splunk": 'index=dns | stats count dc(query) as unique_queries by src_ip query | where count > 100 AND unique_queries < 5 | table src_ip query count',
         "elk": 'dns.question.name:* | stats by source.ip, dns.question.name | where doc_count > 100',
         "evidence": ["Queried domains", "Query frequency and jitter", "Entropy of subdomains"],
         "false_positives": ["NTP, Windows telemetry, security tools phoning home, CDN health checks"],
         "priority": "HIGH"},
        {"id": "H-C2-02", "tactic": "C2", "title": "HTTP/S beaconing", "mitre": "T1071.001",
         "description": "An attacker's implant is communicating with a C2 server over HTTP/S at regular intervals.",
         "data_sources": ["Proxy logs", "Firewall logs", "Zeek/Bro conn.log"],
         "splunk": 'index=proxy | stats count avg(bytes_out) as avg_bytes stdev(bytes_out) as std_bytes by src_ip dest | where count > 50 AND std_bytes < avg_bytes*0.1 | table src_ip dest count avg_bytes std_bytes',
         "elk": 'destination.ip:* AND source.bytes:* | stats by source.ip, destination.ip',
         "evidence": ["Connection intervals (look for jitter)", "Data sizes", "TLS certificate details", "JA3 hash"],
         "false_positives": ["Polling applications, auto-updaters, monitoring tools"],
         "priority": "HIGH"},
        {"id": "H-C2-03", "tactic": "C2", "title": "Domain fronting", "mitre": "T1090.004",
         "description": "An attacker is using domain fronting to disguise C2 traffic through legitimate CDN providers.",
         "data_sources": ["TLS logs (SNI vs Host header mismatch)", "Proxy logs"],
         "splunk": 'index=proxy | where ssl_subject != http_host | table _time src_ip ssl_subject http_host dest_ip | head 100',
         "elk": 'tls.client.server_name:* AND http.request.headers.host:* | where tls.client.server_name != http.request.headers.host',
         "evidence": ["SNI vs Host header mismatch", "CDN provider used", "Traffic patterns"],
         "false_positives": ["Some CDN configurations, load balancers, SaaS applications"],
         "priority": "HIGH"},

        # Exfiltration
        {"id": "H-EX-01", "tactic": "Exfiltration", "title": "Large data uploads", "mitre": "T1048",
         "description": "An attacker is exfiltrating data by uploading large volumes to external destinations.",
         "data_sources": ["Proxy logs", "Firewall logs", "DLP alerts"],
         "splunk": 'index=proxy | stats sum(bytes_out) as total_bytes by src_ip dest | where total_bytes > 104857600 | eval MB=round(total_bytes/1048576,2) | sort -MB | table src_ip dest MB',
         "elk": 'destination.bytes:>0 | stats by source.ip, destination.ip, sum(destination.bytes)',
         "evidence": ["Volume of data", "Destination", "Time of transfer", "Data type"],
         "false_positives": ["Cloud backup, file sync (OneDrive, Dropbox), video uploads, large email attachments"],
         "priority": "HIGH"},
        {"id": "H-EX-02", "tactic": "Exfiltration", "title": "Cloud storage exfiltration", "mitre": "T1567.002",
         "description": "An attacker is using cloud storage services (Google Drive, Dropbox, Mega, OneDrive) to exfiltrate data.",
         "data_sources": ["Proxy logs", "CASB logs", "Endpoint DLP"],
         "splunk": 'index=proxy dest="*drive.google.com*" OR dest="*dropbox.com*" OR dest="*mega.nz*" OR dest="*onedrive.live.com*" | stats sum(bytes_out) as total by src_ip dest | where total > 10485760 | eval MB=round(total/1048576,2) | table src_ip dest MB',
         "elk": 'destination.domain:(*drive.google.com* OR *dropbox.com* OR *mega.nz*) AND source.bytes:>0',
         "evidence": ["Cloud service used", "Volume uploaded", "User account", "Files uploaded"],
         "false_positives": ["Legitimate cloud storage use, file sharing, backups"],
         "priority": "MEDIUM"},
        {"id": "H-EX-03", "tactic": "Exfiltration", "title": "DNS tunneling exfiltration", "mitre": "T1048.003",
         "description": "An attacker is encoding data into DNS queries to exfiltrate through DNS, bypassing traditional egress controls.",
         "data_sources": ["DNS query logs", "Passive DNS"],
         "splunk": 'index=dns | eval query_len=len(query) | where query_len > 50 | stats count avg(query_len) as avg_len by src_ip query | where count > 20 | table src_ip query avg_len count',
         "elk": 'dns.question.name.length:>50 | stats by source.ip, dns.question.registered_domain',
         "evidence": ["Long subdomain queries", "High entropy in query names", "Volume and frequency", "Authoritative NS for the domain"],
         "false_positives": ["DKIM validation queries, anti-spam lookups, some CDN/SaaS DNS"],
         "priority": "HIGH"},
    ]

    ENV_PRIORITIES = {
        "corporate": ["H-CA-01", "H-CA-02", "H-CA-03", "H-LM-01", "H-PE-01", "H-PE-02", "H-EX-01", "H-DE-03", "H-IA-01"],
        "healthcare": ["H-IA-01", "H-EX-01", "H-CA-01", "H-PE-01", "H-DE-02", "H-PR-01", "H-LM-01"],
        "financial": ["H-IA-01", "H-CA-03", "H-EX-01", "H-EX-02", "H-LM-01", "H-C2-01", "H-DE-02"],
        "cloud": ["H-IA-02", "H-IA-03", "H-EX-02", "H-DI-01", "H-C2-03", "H-PR-01"],
        "ics": ["H-DI-02", "H-LM-01", "H-PE-01", "H-C2-01", "H-DE-02", "H-EX-01"],
    }

    def __init__(self, target=None, options=None):
        self.target = target
        self.options = options or {}
        self.findings = []
        self.hunt_results = []

    def run(self, confirm_fn=None):
        print(f"\n[THREAT-HUNT] Threat Hunting Engine")
        print("=" * 60)
        mode = self.options.get("mode", "list")
        if mode == "list":
            self.list_hypotheses()
        elif mode == "detail":
            hyp_id = self.options.get("hypothesis")
            self.show_hypothesis(hyp_id)
        elif mode == "prioritize":
            env_type = self.options.get("environment", "corporate")
            self.prioritize_for_environment(env_type)
        elif mode == "report":
            self.generate_hunt_report()
        return self.findings

    def list_hypotheses(self):
        print(f"\n  {len(self.HYPOTHESES)} hunting hypotheses available:\n")
        current_tactic = ""
        for h in self.HYPOTHESES:
            if h["tactic"] != current_tactic:
                current_tactic = h["tactic"]
                print(f"\n  [{current_tactic.upper()}]")
            priority_color = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[33m", "LOW": "\033[32m"}
            color = priority_color.get(h["priority"], "")
            reset = "\033[0m" if color else ""
            print(f"    {h['id']:10s} {color}[{h['priority']:8s}]{reset} {h['title']} ({h['mitre']})")

    def show_hypothesis(self, hyp_id):
        h = next((x for x in self.HYPOTHESES if x["id"] == hyp_id), None)
        if not h:
            print(f"  [!] Hypothesis '{hyp_id}' not found")
            return
        print(f"\n  Hypothesis: {h['title']}")
        print(f"  ID: {h['id']}  |  Tactic: {h['tactic']}  |  MITRE: {h['mitre']}  |  Priority: {h['priority']}")
        print(f"\n  Description:")
        print(f"    {h['description']}")
        print(f"\n  Data Sources:")
        for ds in h["data_sources"]:
            print(f"    - {ds}")
        print(f"\n  Splunk Query:")
        print(f"    {h['splunk']}")
        print(f"\n  ELK Query:")
        print(f"    {h['elk']}")
        print(f"\n  Evidence to Collect:")
        for e in h["evidence"]:
            print(f"    - {e}")
        print(f"\n  False Positives:")
        for fp in h["false_positives"]:
            print(f"    - {fp}")

    def prioritize_for_environment(self, env_type):
        priority_ids = self.ENV_PRIORITIES.get(env_type, self.ENV_PRIORITIES["corporate"])
        print(f"\n  Priority hypotheses for {env_type.upper()} environment:")
        print(f"  (Ordered by likelihood and impact)\n")
        for i, hid in enumerate(priority_ids, 1):
            h = next((x for x in self.HYPOTHESES if x["id"] == hid), None)
            if h:
                print(f"  {i}. [{h['priority']:8s}] {h['title']} ({h['mitre']})")

    def generate_hunt_report(self):
        report = []
        report.append("=" * 60)
        report.append("THREAT HUNTING REPORT")
        report.append(f"Generated: {datetime.now().isoformat()}")
        report.append("=" * 60)
        report.append("")
        report.append(f"Hypotheses executed: {len(self.hunt_results)}")
        report.append(f"Findings: {len(self.findings)}")
        report.append("")
        for r in self.hunt_results:
            report.append(f"  [{r.get('status', 'UNKNOWN')}] {r.get('hypothesis', 'N/A')}: {r.get('result', 'N/A')}")
        return "\n".join(report)

    def get_findings(self):
        return self.findings


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "list"
    opts = {"mode": mode}
    if mode == "detail" and len(sys.argv) > 2:
        opts["hypothesis"] = sys.argv[2]
    if mode == "prioritize" and len(sys.argv) > 2:
        opts["environment"] = sys.argv[2]
    hunt = ThreatHunt(options=opts)
    hunt.run()
