#!/usr/bin/env python3
"""Built-in Sigma detection rules for AEGIS threat detection."""

SIGMA_RULES = [
    # === Credential Access ===
    {"title": "Mimikatz Usage", "id": "aegis-0001", "status": "stable", "description": "Detects Mimikatz execution via process name or command line arguments", "logsource": {"product": "windows", "service": "sysmon", "category": "process_creation"}, "detection": {"selection": {"Image|endswith": ["\\mimikatz.exe", "\\mimilib.dll"], "CommandLine|contains": ["sekurlsa", "kerberos::list", "lsadump", "token::elevate", "privilege::debug"]}, "condition": "selection"}, "level": "critical", "mitre": ["T1003.001", "T1003.002"], "falsepositives": ["Legitimate security testing with documented authorization"]},
    {"title": "LSASS Memory Access", "id": "aegis-0002", "status": "stable", "description": "Detects process accessing LSASS memory (credential dumping indicator)", "logsource": {"product": "windows", "service": "sysmon", "category": "process_access"}, "detection": {"selection": {"TargetImage|endswith": "\\lsass.exe", "GrantedAccess|contains": ["0x1010", "0x1410", "0x1438", "0x143a"]}, "filter": {"SourceImage|endswith": ["\\csrss.exe", "\\lsm.exe", "\\wmiprvse.exe", "\\svchost.exe"]}, "condition": "selection and not filter"}, "level": "critical", "mitre": ["T1003.001"], "falsepositives": ["AV/EDR scanning LSASS", "Windows Defender"]},
    {"title": "Kerberoasting via GetUserSPNs", "id": "aegis-0003", "status": "stable", "description": "Detects Kerberos TGS requests for service accounts (Kerberoasting)", "logsource": {"product": "windows", "service": "security"}, "detection": {"selection": {"EventID": 4769, "TicketEncryptionType": "0x17", "ServiceName|endswith": "$"}, "condition": "selection"}, "level": "high", "mitre": ["T1558.003"], "falsepositives": ["Legitimate service ticket requests"]},
    {"title": "DCSync Attack", "id": "aegis-0004", "status": "stable", "description": "Detects DCSync replication requests from non-DC sources", "logsource": {"product": "windows", "service": "security"}, "detection": {"selection": {"EventID": 4662, "Properties|contains": ["1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"]}, "condition": "selection"}, "level": "critical", "mitre": ["T1003.006"], "falsepositives": ["Legitimate domain controller replication"]},
    {"title": "Credential Dumping via comsvcs.dll", "id": "aegis-0005", "status": "stable", "description": "Detects LSASS process dump using comsvcs.dll MiniDump", "logsource": {"product": "windows", "service": "sysmon"}, "detection": {"selection": {"CommandLine|contains|all": ["comsvcs", "MiniDump"]}, "condition": "selection"}, "level": "critical", "mitre": ["T1003.001"], "falsepositives": ["Rare"]},
    # === Execution ===
    {"title": "Suspicious PowerShell Encoded Command", "id": "aegis-0010", "status": "stable", "description": "Detects PowerShell execution with encoded or obfuscated commands", "logsource": {"product": "windows", "service": "sysmon", "category": "process_creation"}, "detection": {"selection": {"Image|endswith": "\\powershell.exe", "CommandLine|contains": ["-enc", "-EncodedCommand", "FromBase64String", "IEX", "Invoke-Expression", "DownloadString", "Net.WebClient"]}, "condition": "selection"}, "level": "high", "mitre": ["T1059.001", "T1027"], "falsepositives": ["Administrative scripts using encoded commands"]},
    {"title": "WMIC Process Creation", "id": "aegis-0011", "status": "stable", "description": "Detects WMIC used for remote process creation", "logsource": {"product": "windows", "service": "sysmon"}, "detection": {"selection": {"Image|endswith": "\\wmic.exe", "CommandLine|contains": ["process call create", "node:"]}, "condition": "selection"}, "level": "high", "mitre": ["T1047"], "falsepositives": ["Administrative remote management"]},
    {"title": "Suspicious Certutil Usage", "id": "aegis-0012", "status": "stable", "description": "Detects certutil used for file download or encoding (LOLBin abuse)", "logsource": {"product": "windows", "service": "sysmon"}, "detection": {"selection": {"Image|endswith": "\\certutil.exe", "CommandLine|contains": ["-urlcache", "-decode", "-encode", "-f http"]}, "condition": "selection"}, "level": "high", "mitre": ["T1105", "T1140"], "falsepositives": ["Legitimate certificate management"]},
    {"title": "Mshta.exe Execution", "id": "aegis-0013", "status": "stable", "description": "Detects mshta.exe executing HTA or inline scripts", "logsource": {"product": "windows", "service": "sysmon"}, "detection": {"selection": {"Image|endswith": "\\mshta.exe", "CommandLine|contains": ["javascript:", "vbscript:", "http://", "https://"]}, "condition": "selection"}, "level": "high", "mitre": ["T1218.005"], "falsepositives": ["Legacy internal applications"]},
    {"title": "Regsvr32 AppLocker Bypass", "id": "aegis-0014", "status": "stable", "description": "Detects regsvr32 Squiblydoo attack for AppLocker bypass", "logsource": {"product": "windows", "service": "sysmon"}, "detection": {"selection": {"Image|endswith": "\\regsvr32.exe", "CommandLine|contains": ["/s /n /u /i:", "scrobj.dll"]}, "condition": "selection"}, "level": "high", "mitre": ["T1218.010"], "falsepositives": ["Rare"]},
    {"title": "Cscript/Wscript Suspicious Execution", "id": "aegis-0015", "status": "stable", "description": "Detects Windows Script Host executing scripts from suspicious locations", "logsource": {"product": "windows", "service": "sysmon"}, "detection": {"selection": {"Image|endswith": ["\\cscript.exe", "\\wscript.exe"], "CommandLine|contains": ["\\Temp\\", "\\AppData\\", "\\Downloads\\", "http://"]}, "condition": "selection"}, "level": "medium", "mitre": ["T1059.005"], "falsepositives": ["Logon scripts in temp folders"]},
    # === Persistence ===
    {"title": "Registry Run Key Modification", "id": "aegis-0020", "status": "stable", "description": "Detects modification of registry Run/RunOnce keys for persistence", "logsource": {"product": "windows", "service": "sysmon", "category": "registry_set"}, "detection": {"selection": {"TargetObject|contains": ["\\CurrentVersion\\Run\\", "\\CurrentVersion\\RunOnce\\"]}, "filter": {"Image|endswith": ["\\msiexec.exe", "\\explorer.exe"]}, "condition": "selection and not filter"}, "level": "medium", "mitre": ["T1547.001"], "falsepositives": ["Software installation"]},
    {"title": "Scheduled Task Creation", "id": "aegis-0021", "status": "stable", "description": "Detects creation of scheduled tasks via schtasks.exe", "logsource": {"product": "windows", "service": "security"}, "detection": {"selection": {"EventID": 4698}, "condition": "selection"}, "level": "medium", "mitre": ["T1053.005"], "falsepositives": ["Administrative task creation"]},
    {"title": "New Service Installation", "id": "aegis-0022", "status": "stable", "description": "Detects new Windows service installation", "logsource": {"product": "windows", "service": "system"}, "detection": {"selection": {"EventID": 7045}, "condition": "selection"}, "level": "medium", "mitre": ["T1543.003"], "falsepositives": ["Legitimate software installation"]},
    {"title": "WMI Event Subscription Persistence", "id": "aegis-0023", "status": "stable", "description": "Detects WMI permanent event consumer creation for fileless persistence", "logsource": {"product": "windows", "service": "sysmon", "category": "wmi_event"}, "detection": {"selection": {"EventType": "WmiConsumerEvent"}, "condition": "selection"}, "level": "high", "mitre": ["T1546.003"], "falsepositives": ["SCCM and monitoring tools"]},
    {"title": "Startup Folder Modification", "id": "aegis-0024", "status": "stable", "description": "Detects files created in user or system startup folders", "logsource": {"product": "windows", "service": "sysmon", "category": "file_creation"}, "detection": {"selection": {"TargetFilename|contains": ["\\Start Menu\\Programs\\Startup\\", "\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\"]}, "condition": "selection"}, "level": "medium", "mitre": ["T1547.001"], "falsepositives": ["Software installation shortcuts"]},
    # === Lateral Movement ===
    {"title": "PsExec Service Installation", "id": "aegis-0030", "status": "stable", "description": "Detects PsExec tool usage via service installation", "logsource": {"product": "windows", "service": "system"}, "detection": {"selection": {"EventID": 7045, "ServiceName|contains": ["PSEXESVC", "RemComSvc"]}, "condition": "selection"}, "level": "high", "mitre": ["T1569.002", "T1570"], "falsepositives": ["Legitimate PsExec admin usage"]},
    {"title": "Remote Desktop Connection", "id": "aegis-0031", "status": "stable", "description": "Detects successful RDP logon from remote host", "logsource": {"product": "windows", "service": "security"}, "detection": {"selection": {"EventID": 4624, "LogonType": 10}, "condition": "selection"}, "level": "low", "mitre": ["T1021.001"], "falsepositives": ["Legitimate RDP sessions"]},
    {"title": "WinRM Remote Execution", "id": "aegis-0032", "status": "stable", "description": "Detects Windows Remote Management PowerShell remoting", "logsource": {"product": "windows", "service": "sysmon"}, "detection": {"selection": {"Image|endswith": "\\wsmprovhost.exe"}, "condition": "selection"}, "level": "medium", "mitre": ["T1021.006"], "falsepositives": ["Administrative remote management"]},
    {"title": "SMB Named Pipe Connection", "id": "aegis-0033", "status": "stable", "description": "Detects remote service creation via SMB named pipes (Impacket tools)", "logsource": {"product": "windows", "service": "security"}, "detection": {"selection": {"EventID": 5145, "ShareName": "\\\\*\\IPC$", "RelativeTargetName|contains": ["svcctl", "atsvc", "samr"]}, "condition": "selection"}, "level": "high", "mitre": ["T1021.002"], "falsepositives": ["Domain controllers performing replication"]},
    # === Defense Evasion ===
    {"title": "Event Log Cleared", "id": "aegis-0040", "status": "stable", "description": "Detects clearing of Windows Security event log", "logsource": {"product": "windows", "service": "security"}, "detection": {"selection": {"EventID": 1102}, "condition": "selection"}, "level": "high", "mitre": ["T1070.001"], "falsepositives": ["Administrative maintenance"]},
    {"title": "AMSI Bypass Attempt", "id": "aegis-0041", "status": "stable", "description": "Detects attempts to bypass Antimalware Scan Interface", "logsource": {"product": "windows", "service": "sysmon"}, "detection": {"selection": {"CommandLine|contains": ["AmsiInitFailed", "amsiContext", "AmsiUtils", "amsi.dll"]}, "condition": "selection"}, "level": "critical", "mitre": ["T1562.001"], "falsepositives": ["Security research"]},
    {"title": "Disabling Windows Defender", "id": "aegis-0042", "status": "stable", "description": "Detects attempts to disable Windows Defender via registry or command", "logsource": {"product": "windows", "service": "sysmon"}, "detection": {"selection": {"CommandLine|contains": ["DisableAntiSpyware", "Set-MpPreference -DisableRealtimeMonitoring", "sc stop WinDefend"]}, "condition": "selection"}, "level": "high", "mitre": ["T1562.001"], "falsepositives": ["Administrative Defender management"]},
    {"title": "Timestomping Detected", "id": "aegis-0043", "status": "stable", "description": "Detects file timestamp manipulation using known tools", "logsource": {"product": "windows", "service": "sysmon"}, "detection": {"selection": {"CommandLine|contains": ["timestomp", "SetFileTime", "touch -t"]}, "condition": "selection"}, "level": "high", "mitre": ["T1070.006"], "falsepositives": ["Rare"]},
    # === Discovery ===
    {"title": "Bloodhound/SharpHound Execution", "id": "aegis-0050", "status": "stable", "description": "Detects BloodHound data collection tools", "logsource": {"product": "windows", "service": "sysmon"}, "detection": {"selection": {"Image|endswith": ["\\SharpHound.exe", "\\BloodHound.exe"], "CommandLine|contains": ["CollectionMethod", "-c All", "--CollectionMethods"]}, "condition": "selection"}, "level": "critical", "mitre": ["T1087.002", "T1069.002"], "falsepositives": ["Authorized red team assessments"]},
    {"title": "Network Share Enumeration", "id": "aegis-0051", "status": "stable", "description": "Detects enumeration of network shares via net.exe", "logsource": {"product": "windows", "service": "sysmon"}, "detection": {"selection": {"Image|endswith": "\\net.exe", "CommandLine|contains": ["view", "share", "use"]}, "condition": "selection"}, "level": "low", "mitre": ["T1135"], "falsepositives": ["Administrative tasks"]},
    {"title": "AdFind Usage", "id": "aegis-0052", "status": "stable", "description": "Detects AdFind Active Directory enumeration tool", "logsource": {"product": "windows", "service": "sysmon"}, "detection": {"selection": {"Image|endswith": "\\AdFind.exe", "CommandLine|contains": ["-f", "objectcategory", "trustdmp"]}, "condition": "selection"}, "level": "high", "mitre": ["T1018", "T1087.002"], "falsepositives": ["AD administration"]},
    # === Exfiltration ===
    {"title": "Rclone Data Exfiltration", "id": "aegis-0060", "status": "stable", "description": "Detects rclone usage for data exfiltration (used by multiple ransomware groups)", "logsource": {"product": "windows", "service": "sysmon"}, "detection": {"selection": {"Image|endswith": "\\rclone.exe", "CommandLine|contains": ["copy", "sync", "mega:", "s3:", "ftp:"]}, "condition": "selection"}, "level": "critical", "mitre": ["T1567.002"], "falsepositives": ["Legitimate backup operations"]},
    {"title": "Large Outbound Data Transfer", "id": "aegis-0061", "status": "stable", "description": "Detects unusually large outbound data transfers", "logsource": {"product": "firewall"}, "detection": {"selection": {"bytes_out|gt": 100000000, "direction": "outbound"}, "condition": "selection"}, "level": "medium", "mitre": ["T1048"], "falsepositives": ["Cloud backups, software updates"]},
    # === Linux ===
    {"title": "Linux Reverse Shell", "id": "aegis-0070", "status": "stable", "description": "Detects common reverse shell commands on Linux", "logsource": {"product": "linux", "service": "auditd"}, "detection": {"selection": {"a0|contains": ["/dev/tcp/", "bash -i >& ", "nc -e", "ncat -e", "python -c 'import socket", "perl -e 'use Socket"]}, "condition": "selection"}, "level": "critical", "mitre": ["T1059.004"], "falsepositives": ["CTF/lab environments"]},
    {"title": "Linux Privilege Escalation via SUID", "id": "aegis-0071", "status": "stable", "description": "Detects execution of SUID binaries commonly abused for privilege escalation", "logsource": {"product": "linux", "service": "auditd"}, "detection": {"selection": {"key": "suid_exec", "a0|endswith": ["/find", "/vim", "/nmap", "/python", "/perl", "/awk", "/env"]}, "condition": "selection"}, "level": "high", "mitre": ["T1548.001"], "falsepositives": ["Legitimate use of these utilities"]},
    {"title": "Linux Crontab Modification", "id": "aegis-0072", "status": "stable", "description": "Detects modification of cron jobs which may indicate persistence", "logsource": {"product": "linux", "service": "syslog"}, "detection": {"selection": {"program": "CRON", "message|contains": ["REPLACE", "INSTALL"]}, "condition": "selection"}, "level": "medium", "mitre": ["T1053.003"], "falsepositives": ["Legitimate cron job updates"]},
    {"title": "SSH Authorized Keys Modification", "id": "aegis-0073", "status": "stable", "description": "Detects modification of SSH authorized_keys file for persistence", "logsource": {"product": "linux", "service": "auditd"}, "detection": {"selection": {"key": "ssh_keys", "path|contains": ".ssh/authorized_keys"}, "condition": "selection"}, "level": "high", "mitre": ["T1098.004"], "falsepositives": ["Legitimate SSH key management"]},
    {"title": "Passwd/Shadow File Access", "id": "aegis-0074", "status": "stable", "description": "Detects access to sensitive credential files", "logsource": {"product": "linux", "service": "auditd"}, "detection": {"selection": {"path|contains": ["/etc/shadow", "/etc/gshadow"]}, "filter": {"exe|endswith": ["/login", "/sshd", "/sudo", "/su", "/passwd", "/chage"]}, "condition": "selection and not filter"}, "level": "high", "mitre": ["T1003.008"], "falsepositives": ["Backup processes"]},
    # === Cloud ===
    {"title": "AWS Root Account Usage", "id": "aegis-0080", "status": "stable", "description": "Detects usage of AWS root account which should be avoided", "logsource": {"product": "aws", "service": "cloudtrail"}, "detection": {"selection": {"userIdentity.type": "Root"}, "condition": "selection"}, "level": "critical", "mitre": ["T1078.004"], "falsepositives": ["Initial account setup"]},
    {"title": "AWS CloudTrail Disabled", "id": "aegis-0081", "status": "stable", "description": "Detects CloudTrail logging being stopped or deleted", "logsource": {"product": "aws", "service": "cloudtrail"}, "detection": {"selection": {"eventName": ["StopLogging", "DeleteTrail", "UpdateTrail"]}, "condition": "selection"}, "level": "critical", "mitre": ["T1562.008"], "falsepositives": ["Trail reconfiguration"]},
    {"title": "AWS S3 Bucket Policy Changed", "id": "aegis-0082", "status": "stable", "description": "Detects S3 bucket policy modifications that may expose data", "logsource": {"product": "aws", "service": "cloudtrail"}, "detection": {"selection": {"eventName": ["PutBucketPolicy", "PutBucketAcl", "PutBucketPublicAccessBlock"]}, "condition": "selection"}, "level": "high", "mitre": ["T1530"], "falsepositives": ["Legitimate policy updates"]},
    {"title": "AWS IAM User Created", "id": "aegis-0083", "status": "stable", "description": "Detects creation of new IAM users", "logsource": {"product": "aws", "service": "cloudtrail"}, "detection": {"selection": {"eventName": "CreateUser"}, "condition": "selection"}, "level": "medium", "mitre": ["T1136.003"], "falsepositives": ["Normal user provisioning"]},
    {"title": "Azure AD Suspicious Sign-In", "id": "aegis-0084", "status": "stable", "description": "Detects sign-in from risky IP or impossible travel", "logsource": {"product": "azure", "service": "signinlogs"}, "detection": {"selection": {"riskState": ["confirmedCompromised", "atRisk"], "riskDetail|contains": ["impossibleTravel", "maliciousIPAddress"]}, "condition": "selection"}, "level": "high", "mitre": ["T1078.004"], "falsepositives": ["VPN usage causing geographic anomalies"]},
]

def get_all_rules():
    return SIGMA_RULES

def get_rules_by_level(level):
    return [r for r in SIGMA_RULES if r["level"] == level]

def get_rules_by_mitre(technique_id):
    return [r for r in SIGMA_RULES if technique_id in r.get("mitre", [])]

def search_rules(query):
    q = query.lower()
    return [r for r in SIGMA_RULES if q in r["title"].lower() or q in r["description"].lower()]

def export_yaml(rule):
    """Export a rule as YAML-formatted string."""
    mitre_tags = " ".join(f"attack.{m.lower()}" for m in rule.get("mitre", []))
    ls = rule["logsource"]
    det = rule["detection"]
    return f"""title: {rule['title']}
id: {rule['id']}
status: {rule['status']}
description: {rule['description']}
logsource:
    product: {ls.get('product', 'unknown')}
    service: {ls.get('service', 'unknown')}
detection:
    {det}
level: {rule['level']}
tags:
    - {mitre_tags}
falsepositives:
    - {'; '.join(rule.get('falsepositives', ['Unknown']))}
"""

def get_stats():
    total = len(SIGMA_RULES)
    by_level = {}
    by_product = {}
    for r in SIGMA_RULES:
        by_level[r["level"]] = by_level.get(r["level"], 0) + 1
        prod = r["logsource"].get("product", "unknown")
        by_product[prod] = by_product.get(prod, 0) + 1
    return {"total": total, "by_level": by_level, "by_product": by_product}

if __name__ == "__main__":
    stats = get_stats()
    print(f"AEGIS Sigma Rules: {stats['total']} rules")
    print(f"  By level: {stats['by_level']}")
    print(f"  By product: {stats['by_product']}")
