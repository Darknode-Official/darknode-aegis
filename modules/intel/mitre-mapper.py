#!/usr/bin/env python3
"""AEGIS MITRE ATT&CK Mapper — technique mapping, coverage analysis, and detection rule generation."""
import sys, json

TACTICS = [
    {"id": "TA0043", "name": "Reconnaissance", "techniques": [
        {"id": "T1595", "name": "Active Scanning", "desc": "Scan victim IP blocks, vuln scanning"},
        {"id": "T1592", "name": "Gather Victim Host Info", "desc": "Hardware, software, client configs"},
        {"id": "T1589", "name": "Gather Victim Identity Info", "desc": "Credentials, email addresses, names"},
        {"id": "T1590", "name": "Gather Victim Network Info", "desc": "Domain, DNS, IP, topology"},
        {"id": "T1591", "name": "Gather Victim Org Info", "desc": "Business relationships, roles, locations"},
        {"id": "T1598", "name": "Phishing for Information", "desc": "Spearphishing to gather info"},
        {"id": "T1597", "name": "Search Closed Sources", "desc": "Threat intel, purchased data"},
        {"id": "T1596", "name": "Search Open Tech Databases", "desc": "DNS, WHOIS, cert transparency"},
        {"id": "T1593", "name": "Search Open Websites/Domains", "desc": "Social media, search engines"},
        {"id": "T1594", "name": "Search Victim-Owned Websites", "desc": "Corporate website recon"},
    ]},
    {"id": "TA0042", "name": "Resource Development", "techniques": [
        {"id": "T1583", "name": "Acquire Infrastructure", "desc": "Domains, servers, botnets, web services"},
        {"id": "T1586", "name": "Compromise Accounts", "desc": "Social media, email accounts"},
        {"id": "T1584", "name": "Compromise Infrastructure", "desc": "Domains, servers, botnets"},
        {"id": "T1587", "name": "Develop Capabilities", "desc": "Malware, exploits, certificates"},
        {"id": "T1585", "name": "Establish Accounts", "desc": "Social media, email for ops"},
        {"id": "T1588", "name": "Obtain Capabilities", "desc": "Malware, tools, exploits, certs"},
        {"id": "T1608", "name": "Stage Capabilities", "desc": "Upload malware, link targets"},
    ]},
    {"id": "TA0001", "name": "Initial Access", "techniques": [
        {"id": "T1189", "name": "Drive-by Compromise", "desc": "Exploit browser visiting compromised site"},
        {"id": "T1190", "name": "Exploit Public-Facing App", "desc": "Exploit web app, VPN, firewall"},
        {"id": "T1133", "name": "External Remote Services", "desc": "VPN, RDP, Citrix, SSH"},
        {"id": "T1200", "name": "Hardware Additions", "desc": "Rogue device, USB, implant"},
        {"id": "T1566", "name": "Phishing", "desc": "Spearphishing attachment/link/service"},
        {"id": "T1091", "name": "Replication Through Removable Media", "desc": "USB worm"},
        {"id": "T1195", "name": "Supply Chain Compromise", "desc": "Compromise software supply chain"},
        {"id": "T1199", "name": "Trusted Relationship", "desc": "Abuse trusted third-party access"},
        {"id": "T1078", "name": "Valid Accounts", "desc": "Use stolen/default credentials"},
    ]},
    {"id": "TA0002", "name": "Execution", "techniques": [
        {"id": "T1059", "name": "Command and Scripting Interpreter", "desc": "PowerShell, bash, Python, VBScript"},
        {"id": "T1203", "name": "Exploitation for Client Execution", "desc": "Browser, Office exploit"},
        {"id": "T1559", "name": "Inter-Process Communication", "desc": "COM, DDE"},
        {"id": "T1106", "name": "Native API", "desc": "Direct Windows API calls"},
        {"id": "T1053", "name": "Scheduled Task/Job", "desc": "Cron, at, schtasks"},
        {"id": "T1129", "name": "Shared Modules", "desc": "Load shared library/DLL"},
        {"id": "T1072", "name": "Software Deployment Tools", "desc": "SCCM, Ansible, Chef"},
        {"id": "T1569", "name": "System Services", "desc": "Service execution"},
        {"id": "T1204", "name": "User Execution", "desc": "User runs malicious file/link"},
        {"id": "T1047", "name": "Windows Management Instrumentation", "desc": "WMI for execution"},
    ]},
    {"id": "TA0003", "name": "Persistence", "techniques": [
        {"id": "T1098", "name": "Account Manipulation", "desc": "SSH keys, permissions"},
        {"id": "T1197", "name": "BITS Jobs", "desc": "Background Intelligent Transfer Service"},
        {"id": "T1547", "name": "Boot or Logon Autostart", "desc": "Registry Run keys, startup folder"},
        {"id": "T1037", "name": "Boot or Logon Init Scripts", "desc": "Logon scripts"},
        {"id": "T1136", "name": "Create Account", "desc": "Local, domain, or cloud account"},
        {"id": "T1543", "name": "Create or Modify System Process", "desc": "Services, launch daemons"},
        {"id": "T1546", "name": "Event Triggered Execution", "desc": "WMI, AppInit DLLs, trap"},
        {"id": "T1574", "name": "Hijack Execution Flow", "desc": "DLL hijacking, PATH interception"},
        {"id": "T1505", "name": "Server Software Component", "desc": "Web shells, transport agent"},
        {"id": "T1053", "name": "Scheduled Task/Job", "desc": "Persistence via scheduled tasks"},
    ]},
    {"id": "TA0004", "name": "Privilege Escalation", "techniques": [
        {"id": "T1548", "name": "Abuse Elevation Control", "desc": "UAC bypass, sudo, setuid"},
        {"id": "T1134", "name": "Access Token Manipulation", "desc": "Token impersonation/theft"},
        {"id": "T1547", "name": "Boot or Logon Autostart", "desc": "Run elevated at boot"},
        {"id": "T1068", "name": "Exploitation for Privilege Escalation", "desc": "Kernel exploit, service exploit"},
        {"id": "T1055", "name": "Process Injection", "desc": "DLL injection, process hollowing"},
        {"id": "T1053", "name": "Scheduled Task/Job", "desc": "Run as SYSTEM via schtasks"},
    ]},
    {"id": "TA0005", "name": "Defense Evasion", "techniques": [
        {"id": "T1140", "name": "Deobfuscate/Decode", "desc": "Decode encoded payloads at runtime"},
        {"id": "T1070", "name": "Indicator Removal", "desc": "Clear logs, timestomp, file deletion"},
        {"id": "T1036", "name": "Masquerading", "desc": "Rename files to look legitimate"},
        {"id": "T1027", "name": "Obfuscated Files or Information", "desc": "Encoding, encryption, packing"},
        {"id": "T1055", "name": "Process Injection", "desc": "Inject code into legitimate process"},
        {"id": "T1218", "name": "System Binary Proxy Execution", "desc": "LOLBins — mshta, rundll32, regsvr32"},
        {"id": "T1562", "name": "Impair Defenses", "desc": "Disable AV, firewall, EDR, logging"},
        {"id": "T1112", "name": "Modify Registry", "desc": "Hide in registry"},
        {"id": "T1497", "name": "Virtualization/Sandbox Evasion", "desc": "Detect VM/sandbox, change behavior"},
        {"id": "T1202", "name": "Indirect Command Execution", "desc": "Use pcalua, forfiles to bypass logging"},
    ]},
    {"id": "TA0006", "name": "Credential Access", "techniques": [
        {"id": "T1110", "name": "Brute Force", "desc": "Password guessing, credential stuffing"},
        {"id": "T1003", "name": "OS Credential Dumping", "desc": "SAM, LSASS, /etc/shadow, DCSync"},
        {"id": "T1552", "name": "Unsecured Credentials", "desc": "Files, registry, env vars, browser"},
        {"id": "T1558", "name": "Steal or Forge Kerberos Tickets", "desc": "Golden/silver ticket, Kerberoast"},
        {"id": "T1539", "name": "Steal Web Session Cookie", "desc": "Browser cookie theft"},
        {"id": "T1111", "name": "Multi-Factor Auth Interception", "desc": "MFA fatigue, token theft"},
        {"id": "T1056", "name": "Input Capture", "desc": "Keylogging, credential interception"},
        {"id": "T1557", "name": "Adversary-in-the-Middle", "desc": "LLMNR/NBNS poisoning, ARP spoof"},
    ]},
    {"id": "TA0007", "name": "Discovery", "techniques": [
        {"id": "T1087", "name": "Account Discovery", "desc": "Enumerate user accounts"},
        {"id": "T1082", "name": "System Information Discovery", "desc": "OS version, hardware info"},
        {"id": "T1083", "name": "File and Directory Discovery", "desc": "Browse filesystem"},
        {"id": "T1046", "name": "Network Service Discovery", "desc": "Port scanning"},
        {"id": "T1135", "name": "Network Share Discovery", "desc": "Enumerate SMB shares"},
        {"id": "T1069", "name": "Permission Groups Discovery", "desc": "Local/domain group enumeration"},
        {"id": "T1057", "name": "Process Discovery", "desc": "List running processes"},
        {"id": "T1018", "name": "Remote System Discovery", "desc": "Discover other hosts"},
        {"id": "T1016", "name": "System Network Config Discovery", "desc": "ifconfig, ipconfig, route"},
        {"id": "T1049", "name": "System Network Connections Discovery", "desc": "netstat, ss"},
    ]},
    {"id": "TA0008", "name": "Lateral Movement", "techniques": [
        {"id": "T1210", "name": "Exploitation of Remote Services", "desc": "Exploit vuln on remote host"},
        {"id": "T1534", "name": "Internal Spearphishing", "desc": "Phish from compromised account"},
        {"id": "T1570", "name": "Lateral Tool Transfer", "desc": "Transfer tools between hosts"},
        {"id": "T1021", "name": "Remote Services", "desc": "RDP, SSH, SMB, WinRM, VNC"},
        {"id": "T1550", "name": "Use Alternate Authentication Material", "desc": "Pass-the-Hash/Ticket"},
    ]},
    {"id": "TA0009", "name": "Collection", "techniques": [
        {"id": "T1560", "name": "Archive Collected Data", "desc": "Compress/encrypt before exfil"},
        {"id": "T1005", "name": "Data from Local System", "desc": "Collect files from disk"},
        {"id": "T1039", "name": "Data from Network Shared Drive", "desc": "Collect from SMB/NFS"},
        {"id": "T1025", "name": "Data from Removable Media", "desc": "USB, external drive"},
        {"id": "T1074", "name": "Data Staged", "desc": "Consolidate data before exfil"},
        {"id": "T1114", "name": "Email Collection", "desc": "Outlook, Exchange, IMAP"},
        {"id": "T1113", "name": "Screen Capture", "desc": "Screenshot desktop"},
    ]},
    {"id": "TA0011", "name": "Command and Control", "techniques": [
        {"id": "T1071", "name": "Application Layer Protocol", "desc": "HTTP/S, DNS, SMTP for C2"},
        {"id": "T1132", "name": "Data Encoding", "desc": "Encode C2 communications"},
        {"id": "T1001", "name": "Data Obfuscation", "desc": "Junk data, steganography"},
        {"id": "T1573", "name": "Encrypted Channel", "desc": "TLS, custom crypto for C2"},
        {"id": "T1008", "name": "Fallback Channels", "desc": "Backup C2 infrastructure"},
        {"id": "T1105", "name": "Ingress Tool Transfer", "desc": "Download tools to victim"},
        {"id": "T1572", "name": "Protocol Tunneling", "desc": "DNS tunneling, SSH tunneling"},
        {"id": "T1090", "name": "Proxy", "desc": "Multi-hop proxy, domain fronting"},
        {"id": "T1102", "name": "Web Service", "desc": "Dead drop on cloud services"},
    ]},
    {"id": "TA0010", "name": "Exfiltration", "techniques": [
        {"id": "T1041", "name": "Exfiltration Over C2 Channel", "desc": "Send data over existing C2"},
        {"id": "T1011", "name": "Exfiltration Over Other Network Medium", "desc": "Bluetooth, RF"},
        {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "desc": "DNS, ICMP, SMTP"},
        {"id": "T1567", "name": "Exfiltration Over Web Service", "desc": "Cloud storage, paste sites"},
        {"id": "T1029", "name": "Scheduled Transfer", "desc": "Exfil at specific times"},
        {"id": "T1537", "name": "Transfer Data to Cloud Account", "desc": "Copy to attacker cloud"},
    ]},
    {"id": "TA0040", "name": "Impact", "techniques": [
        {"id": "T1531", "name": "Account Access Removal", "desc": "Lock out users"},
        {"id": "T1485", "name": "Data Destruction", "desc": "Wipe disks, delete files"},
        {"id": "T1486", "name": "Data Encrypted for Impact", "desc": "Ransomware"},
        {"id": "T1565", "name": "Data Manipulation", "desc": "Alter data integrity"},
        {"id": "T1491", "name": "Defacement", "desc": "Website defacement"},
        {"id": "T1561", "name": "Disk Wipe", "desc": "MBR wipe, full disk wipe"},
        {"id": "T1499", "name": "Endpoint Denial of Service", "desc": "Crash services"},
        {"id": "T1498", "name": "Network Denial of Service", "desc": "DDoS"},
        {"id": "T1496", "name": "Resource Hijacking", "desc": "Cryptomining"},
        {"id": "T1489", "name": "Service Stop", "desc": "Stop critical services"},
    ]},
]


class MitreMapper:
    """MITRE ATT&CK technique mapper and coverage analyzer."""

    def __init__(self):
        self.matrix = TACTICS
        self.all_techniques = {}
        for tactic in self.matrix:
            for tech in tactic["techniques"]:
                self.all_techniques[tech["id"]] = {"tactic": tactic["name"], "tactic_id": tactic["id"], **tech}

    def get_technique(self, technique_id):
        return self.all_techniques.get(technique_id)

    def search(self, query):
        q = query.lower()
        return [t for t in self.all_techniques.values() if q in t["id"].lower() or q in t["name"].lower() or q in t["desc"].lower()]

    def coverage_analysis(self, detected_techniques):
        results = []
        for tactic in self.matrix:
            total = len(tactic["techniques"])
            detected = sum(1 for t in tactic["techniques"] if t["id"] in detected_techniques)
            pct = (detected / total * 100) if total else 0
            results.append({"tactic": tactic["name"], "total": total, "detected": detected, "pct": pct})
        return results

    def gap_analysis(self, detected_techniques):
        gaps = []
        for tactic in self.matrix:
            for tech in tactic["techniques"]:
                if tech["id"] not in detected_techniques:
                    gaps.append({"tactic": tactic["name"], "id": tech["id"], "name": tech["name"], "desc": tech["desc"]})
        return gaps

    def generate_navigator_json(self, techniques, color="#ff6666"):
        layers = {"name": "AEGIS Coverage", "versions": {"navigator": "4.8", "layer": "4.4", "attack": "13"}, "domain": "enterprise-attack", "techniques": []}
        for tid in techniques:
            layers["techniques"].append({"techniqueID": tid, "color": color, "enabled": True})
        return json.dumps(layers, indent=2)

    def heatmap(self, detected_techniques=None):
        detected = set(detected_techniques or [])
        lines = ["\n  === MITRE ATT&CK Coverage Heatmap ===\n"]
        for tactic in self.matrix:
            total = len(tactic["techniques"])
            det = sum(1 for t in tactic["techniques"] if t["id"] in detected)
            pct = (det / total * 100) if total else 0
            bar = "#" * int(pct / 5) + "-" * (20 - int(pct / 5))
            lines.append(f"  {tactic['name']:30s} [{bar}] {pct:5.1f}% ({det}/{total})")
        return "\n".join(lines)

    def run(self, confirm_fn=None):
        print(f"\n=== AEGIS MITRE ATT&CK Mapper === ({len(self.all_techniques)} techniques)")
        print("Commands: search <query>, technique <ID>, coverage <T1xxx,T1yyy,...>, gaps <T1xxx,...>, heatmap, export <T1xxx,...>, list, quit\n")
        while True:
            cmd = input("[mitre] > ").strip()
            if cmd.lower() in ("quit", "exit", "q"):
                break
            if cmd.lower().startswith("search "):
                results = self.search(cmd[7:])
                for t in results:
                    print(f"  {t['id']:10s} [{t['tactic']:25s}] {t['name']} — {t['desc']}")
            elif cmd.lower().startswith("technique "):
                t = self.get_technique(cmd[10:].strip().upper())
                if t:
                    print(f"  ID: {t['id']}")
                    print(f"  Name: {t['name']}")
                    print(f"  Tactic: {t['tactic']}")
                    print(f"  Description: {t['desc']}")
                else:
                    print("  Technique not found.")
            elif cmd.lower().startswith("coverage ") or cmd.lower().startswith("gaps "):
                is_gaps = cmd.lower().startswith("gaps")
                techs = [t.strip().upper() for t in cmd.split(" ", 1)[1].split(",")]
                if is_gaps:
                    gaps = self.gap_analysis(techs)
                    print(f"  {len(gaps)} undetected techniques:")
                    for g in gaps[:30]:
                        print(f"  {g['id']:10s} [{g['tactic']:25s}] {g['name']}")
                else:
                    cov = self.coverage_analysis(techs)
                    for c in cov:
                        print(f"  {c['tactic']:30s} {c['detected']}/{c['total']} ({c['pct']:.0f}%)")
            elif cmd.lower() == "heatmap":
                print(self.heatmap())
            elif cmd.lower() == "list":
                for tactic in self.matrix:
                    print(f"\n  --- {tactic['name']} ({tactic['id']}) ---")
                    for t in tactic["techniques"]:
                        print(f"  {t['id']:10s} {t['name']}")
            else:
                print("  Commands: search, technique, coverage, gaps, heatmap, list, quit")


if __name__ == "__main__":
    MitreMapper().run()
