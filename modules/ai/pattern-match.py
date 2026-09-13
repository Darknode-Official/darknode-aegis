#!/usr/bin/env python3
"""AEGIS Attack Pattern Recognition — detect kill chain phases and MITRE techniques in logs."""
import os, sys, re, json
from datetime import datetime
from collections import defaultdict

class PatternMatcher:
    name = "Attack Pattern Recognition"
    description = "Detect kill chain patterns, MITRE techniques, and correlate events across log sources"
    category = "ai"
    mitre = ["T1059", "T1046", "T1003", "T1071"]

    PATTERNS = [
        {"name": "Port Scan", "phase": "Reconnaissance", "mitre": "T1046", "confidence": "high",
         "regex": r"(?:SYN|connect)\s+scan|Nmap|masscan|rustscan|\b(?:\d+\s+open\s+ports?|port\s+\d+\s+open)",
         "description": "Network port scanning activity detected",
         "false_positives": "Legitimate vulnerability scanners, monitoring tools"},
        {"name": "DNS Enumeration", "phase": "Reconnaissance", "mitre": "T1595.002", "confidence": "medium",
         "regex": r"AXFR|zone transfer|dnsenum|dnsrecon|fierce|subfinder|amass|sublist3r",
         "description": "DNS enumeration or zone transfer attempt",
         "false_positives": "DNS administration, authorized security scanning"},
        {"name": "Brute Force Login", "phase": "Initial Access", "mitre": "T1110", "confidence": "high",
         "regex": r"Failed password|authentication fail|invalid password|login failed|401 Unauthorized.*(?:repeated|multiple)",
         "description": "Multiple failed authentication attempts indicating brute force",
         "false_positives": "Forgotten passwords, misconfigured service accounts"},
        {"name": "Web Shell Upload", "phase": "Persistence", "mitre": "T1505.003", "confidence": "high",
         "regex": r"(?:POST|PUT).*\.(php|asp|aspx|jsp|jspx|war)\b.*(?:200|201)|webshell|c99|r57|b374k",
         "description": "Potential web shell upload detected",
         "false_positives": "Legitimate file uploads, CMS plugin installations"},
        {"name": "PowerShell Execution", "phase": "Execution", "mitre": "T1059.001", "confidence": "medium",
         "regex": r"powershell|pwsh|IEX|Invoke-Expression|DownloadString|EncodedCommand|-enc\s|bypass\s+exec",
         "description": "PowerShell execution, possibly encoded or downloading payloads",
         "false_positives": "Legitimate PowerShell administration, SCCM, DSC"},
        {"name": "Credential Dumping", "phase": "Credential Access", "mitre": "T1003", "confidence": "critical",
         "regex": r"mimikatz|sekurlsa|lsadump|hashdump|procdump.*lsass|comsvcs.*MiniDump|ntdsutil.*ifm",
         "description": "Credential dumping tool or technique detected",
         "false_positives": "Extremely rare in legitimate use"},
        {"name": "Lateral Movement (PsExec)", "phase": "Lateral Movement", "mitre": "T1569.002", "confidence": "high",
         "regex": r"psexec|PSEXESVC|RemComSvc|wmiexec|smbexec|atexec|dcomexec",
         "description": "Lateral movement tool execution detected",
         "false_positives": "Legitimate admin tools (SysInternals PsExec)"},
        {"name": "Pass-the-Hash", "phase": "Lateral Movement", "mitre": "T1550.002", "confidence": "high",
         "regex": r"pass.the.hash|pth-|sekurlsa::pth|Logon_Type.*9.*NewCredentials",
         "description": "Pass-the-hash authentication technique detected",
         "false_positives": "Rare — investigate immediately"},
        {"name": "Kerberoasting", "phase": "Credential Access", "mitre": "T1558.003", "confidence": "high",
         "regex": r"kerberoast|GetUserSPNs|TGS.REP|4769.*0x17.*RC4|Rubeus.*kerberoast",
         "description": "Kerberos ticket request for offline cracking (Kerberoasting)",
         "false_positives": "Legitimate Kerberos service access (check for RC4 vs AES)"},
        {"name": "DCSync", "phase": "Credential Access", "mitre": "T1003.006", "confidence": "critical",
         "regex": r"dcsync|DRSGetNCChanges|lsadump::dcsync|Directory Replication|4662.*1131f6",
         "description": "DCSync attack — domain replication protocol abuse to extract credentials",
         "false_positives": "Legitimate domain controller replication (check source)"},
        {"name": "Scheduled Task Persistence", "phase": "Persistence", "mitre": "T1053.005", "confidence": "medium",
         "regex": r"schtasks\s+/create|New-ScheduledTask|4698|at\s+\d+:\d+\s+/",
         "description": "Scheduled task creation for persistence",
         "false_positives": "Legitimate scheduled tasks, Windows Update, backup jobs"},
        {"name": "Service Creation", "phase": "Persistence", "mitre": "T1543.003", "confidence": "medium",
         "regex": r"sc\s+create|New-Service|4697|7045.*Service\s+installed",
         "description": "New Windows service installed (potential persistence)",
         "false_positives": "Software installation, driver updates"},
        {"name": "Registry Autorun", "phase": "Persistence", "mitre": "T1547.001", "confidence": "medium",
         "regex": r"CurrentVersion\\Run|Winlogon\\Shell|Userinit|AppInit_DLLs|Image\s+File\s+Exec",
         "description": "Registry autorun modification for persistence",
         "false_positives": "Software installation, legitimate startup programs"},
        {"name": "Data Staging", "phase": "Collection", "mitre": "T1074", "confidence": "medium",
         "regex": r"rar\s+a\s|7z\s+a\s|tar\s+czf|zip\s+-r|compress.*archive|staging|exfil",
         "description": "Data compression/staging before exfiltration",
         "false_positives": "Legitimate backup operations, log rotation"},
        {"name": "C2 Beacon", "phase": "Command and Control", "mitre": "T1071", "confidence": "high",
         "regex": r"beacon|callback|heartbeat|checkin|c2|command.and.control|cobaltstrike|sliver|meterpreter",
         "description": "Command and control communication indicators",
         "false_positives": "Health check endpoints, monitoring heartbeats"},
        {"name": "DNS Tunneling", "phase": "Exfiltration", "mitre": "T1048.003", "confidence": "high",
         "regex": r"iodine|dnscat|dns2tcp|dnsexfiltrator|dns.*tunnel",
         "description": "DNS tunneling tool or unusually encoded DNS traffic",
         "false_positives": "Legitimate DNS services, CDN lookups"},
        {"name": "Shadow Copy Deletion", "phase": "Impact", "mitre": "T1490", "confidence": "critical",
         "regex": r"vssadmin.*delete|wmic.*shadowcopy.*delete|bcdedit.*recoveryenabled.*no|wbadmin.*delete",
         "description": "Volume shadow copy deletion — pre-ransomware indicator",
         "false_positives": "Extremely rare in legitimate use — investigate immediately"},
        {"name": "LOLBIN Usage", "phase": "Defense Evasion", "mitre": "T1218", "confidence": "medium",
         "regex": r"certutil.*-urlcache|mshta.*http|regsvr32.*/s.*/u|rundll32.*javascript|bitsadmin.*transfer|msiexec.*/q.*http",
         "description": "Living-off-the-land binary abuse for download/execution",
         "false_positives": "Legitimate software installation, certificate management"},
        {"name": "Log Clearing", "phase": "Defense Evasion", "mitre": "T1070.001", "confidence": "critical",
         "regex": r"wevtutil\s+cl|Clear-EventLog|1102.*audit log was cleared|rm\s+.*\.log|truncate.*log",
         "description": "Event log or log file clearing — anti-forensics",
         "false_positives": "Log rotation (check if automated and scheduled)"},
        {"name": "Reverse Shell", "phase": "Execution", "mitre": "T1059", "confidence": "critical",
         "regex": r"bash\s+-i\s+>&.*\/dev\/tcp|nc\s+-e\s+\/bin|python.*socket.*connect.*subprocess|php\s+-r.*fsockopen|reverse.shell",
         "description": "Reverse shell command execution",
         "false_positives": "Almost never legitimate — investigate immediately"},
    ]

    def __init__(self, target=None, options=None):
        self.target = target
        self.options = options or {}
        self.findings = []
        self.actions = []

    def _log(self, msg):
        self.actions.append({"time": datetime.now().isoformat(), "action": msg})
        print(f"  [PATTERN] {msg}")

    def scan_logs(self, log_path, confirm_fn=None):
        if confirm_fn and not confirm_fn(f"Scan {log_path} for attack patterns?"):
            return {"status": "cancelled"}
        if not os.path.isfile(log_path):
            return {"error": f"File not found: {log_path}"}
        with open(log_path, 'r', errors='ignore') as f:
            lines = f.readlines()
        matches = []
        phase_counts = defaultdict(int)
        for i, line in enumerate(lines):
            for pattern in self.PATTERNS:
                if re.search(pattern['regex'], line, re.I):
                    match = {
                        'line_number': i + 1,
                        'pattern': pattern['name'],
                        'phase': pattern['phase'],
                        'mitre': pattern['mitre'],
                        'confidence': pattern['confidence'],
                        'line': line.strip()[:300],
                    }
                    matches.append(match)
                    phase_counts[pattern['phase']] += 1
                    self.findings.append({
                        'severity': 'critical' if pattern['confidence'] == 'critical' else 'high' if pattern['confidence'] == 'high' else 'medium',
                        'title': f"{pattern['name']} ({pattern['phase']})",
                        'detail': f"Line {i+1}: {line.strip()[:200]}",
                        'mitre': pattern['mitre']
                    })
        kill_chain_coverage = {}
        phases_order = ['Reconnaissance', 'Initial Access', 'Execution', 'Persistence', 'Credential Access',
                        'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration', 'Impact', 'Defense Evasion']
        for phase in phases_order:
            kill_chain_coverage[phase] = phase_counts.get(phase, 0)
        active_phases = [p for p, c in kill_chain_coverage.items() if c > 0]
        if len(active_phases) >= 4:
            self.findings.insert(0, {
                'severity': 'critical',
                'title': f"Multi-phase attack detected ({len(active_phases)} kill chain phases)",
                'detail': f"Active phases: {', '.join(active_phases)}",
                'mitre': 'TA0001-TA0040'
            })
        self._log(f"Pattern scan: {len(matches)} matches across {len(active_phases)} kill chain phases")
        return {
            'file': log_path,
            'total_lines': len(lines),
            'matches': matches,
            'kill_chain_coverage': kill_chain_coverage,
            'active_phases': active_phases,
            'findings': self.findings,
        }

    def correlate(self, results_list):
        all_ips = defaultdict(set)
        all_phases = set()
        for result in results_list:
            for match in result.get('matches', []):
                ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', match.get('line', ''))
                for ip in ips:
                    all_ips[ip].add(match['phase'])
                all_phases.add(match['phase'])
        correlated = []
        for ip, phases in all_ips.items():
            if len(phases) >= 2:
                correlated.append({'ip': ip, 'phases': list(phases), 'phase_count': len(phases)})
        return {'correlated_ips': sorted(correlated, key=lambda x: -x['phase_count']), 'total_phases': len(all_phases)}

    def run(self, confirm_fn=None):
        if not self.target:
            return {"error": "Provide log file path as target"}
        return self.scan_logs(self.target, confirm_fn)

    def get_findings(self):
        return self.findings

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: pattern-match.py <log_file>")
        sys.exit(1)
    pm = PatternMatcher(sys.argv[1])
    result = pm.run()
    print(f"\n  Matches: {len(result.get('matches', []))}")
    print(f"  Kill chain phases: {', '.join(result.get('active_phases', []))}")
    for f in result.get('findings', [])[:20]:
        print(f"  [{f['severity'].upper()}] {f['title']}")
