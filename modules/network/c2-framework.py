#!/usr/bin/env python3
"""C2 Framework Reference and Detection — command and control framework comparison and hunting."""
import sys

class C2Framework:
    name = "C2 Framework Reference"
    description = "C2 framework comparison, detection signatures, and hunting queries"
    category = "network"
    mitre = ["T1071", "T1573", "T1572"]

    def __init__(self, target=None, options=None):
        self.options = options or {}
        self.findings = []

    FRAMEWORKS = [
        {
            "name": "Cobalt Strike",
            "type": "Commercial (cracked widely available)",
            "language": "Java (server) / C (beacon)",
            "protocols": ["HTTP/S", "DNS", "SMB named pipes", "TCP"],
            "architecture": "Team server + operator clients. Beacon payload calls back to team server. Supports staged and stageless payloads.",
            "features": ["Malleable C2 profiles", "Process injection", "Token manipulation", "Lateral movement (psexec, wmi, winrm)", "SOCKS proxy", "Port forwarding", "Screenshot/keylogger", "Mimikatz integration", "BOF (Beacon Object Files)"],
            "default_ports": [80, 443, 53, 445],
            "detection": {
                "ja3": "72a589da586844d7f0818ce684948eea (default HTTPS)",
                "ja3s": "f176ba63b4d68e576b5ba345bec2c7b7 (default server)",
                "user_agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
                "default_uri": ["/submit.php", "/pixel", "/__utm.gif", "/ga.js", "/fwlink"],
                "named_pipe": ["\\\\.\\pipe\\msagent_*", "\\\\.\\pipe\\MSSE-*", "\\\\.\\pipe\\postex_*"],
                "process_injection": "CreateRemoteThread into rundll32.exe, dllhost.exe, or svchost.exe",
                "sleep_pattern": "Default 60s sleep with 0% jitter (highly regular beaconing)",
                "ssl_cert": "Default self-signed cert with serial 146473198 (often customized)",
            },
            "sigma_rule": "title: Cobalt Strike Beacon Detection\nlogsource:\n  product: windows\n  service: sysmon\ndetection:\n  selection_pipe:\n    EventID: 17\n    PipeName|startswith:\n      - '\\\\msagent_'\n      - '\\\\MSSE-'\n      - '\\\\postex_'\n  selection_process:\n    EventID: 1\n    ParentImage|endswith: '\\\\rundll32.exe'\n    Image|endswith: '\\\\rundll32.exe'\n  condition: selection_pipe or selection_process\nlevel: critical",
            "yara_rule": 'rule CobaltStrike_Beacon { strings: $s1 = "%s as %s\\\\%s" $s2 = "beacon.dll" $s3 = "ReflectiveLoader" $x1 = { 69 68 69 68 69 6B } condition: uint16(0) == 0x5A4D and (2 of ($s*) or $x1) }',
            "hunting_queries": {
                "splunk": 'index=sysmon EventCode=17 PipeName="\\\\*msagent_*" OR PipeName="\\\\*MSSE-*" OR PipeName="\\\\*postex_*"\n| table _time ComputerName Image PipeName',
                "elk": 'event.code: 17 AND winlog.event_data.PipeName: (*msagent_* OR *MSSE-* OR *postex_*)',
            },
            "prevalence": "Most widely used C2 by both red teams and threat actors. Cracked versions are ubiquitous in criminal operations.",
        },
        {
            "name": "Sliver",
            "type": "Open source (BishopFox)",
            "language": "Go",
            "protocols": ["mTLS", "HTTP/S", "DNS", "WireGuard", "TCP"],
            "architecture": "Server + operator console. Implants (sessions or beacons) compiled per-operation with unique crypto keys. No staging needed.",
            "features": ["Cross-platform (Win/Lin/Mac)", "mTLS with per-implant keys", "Process injection", "Pivoting", "Armory (extension packages)", "SOCKS5", "Port forwarding", "In-memory .NET assembly execution", "BOF support", "Cursed Chrome (browser pivoting)"],
            "default_ports": [443, 8888, 31337],
            "detection": {
                "ja3": "Varies (Go TLS library fingerprint)",
                "user_agent": "Go-http-client/2.0 (if not customized)",
                "binary_strings": ["sliverpb", "StartBeaconLoop", "GetActiveC2"],
                "process_pattern": "Large Go binary (>8MB) with stripped symbols",
                "dll_injection": "Uses RtlCreateUserThread or QueueUserAPC for injection",
            },
            "sigma_rule": "title: Sliver C2 Implant Detection\nlogsource:\n  product: windows\n  service: sysmon\ndetection:\n  selection:\n    EventID: 1\n    Hashes|contains: 'sliverpb'\n  selection_network:\n    EventID: 3\n    DestinationPort:\n      - 8888\n      - 31337\n  condition: selection or selection_network\nlevel: high",
            "yara_rule": 'rule Sliver_Implant { strings: $s1 = "sliverpb" $s2 = "StartBeaconLoop" $s3 = "GetActiveC2" $go = "Go build" condition: uint16(0) == 0x5A4D and ($go and 1 of ($s*)) }',
            "hunting_queries": {
                "splunk": 'index=proxy user_agent="Go-http-client*" | stats count by src_ip dest_ip dest_port | where count > 50',
                "elk": 'user_agent.original: "Go-http-client*"',
            },
            "prevalence": "Rising adoption as free Cobalt Strike alternative. Used by APT29 and multiple ransomware groups since 2022.",
        },
        {
            "name": "Havoc",
            "type": "Open source",
            "language": "C/C++ (implant) / Go+Qt (server/UI)",
            "protocols": ["HTTP/S", "SMB"],
            "architecture": "Teamserver with Qt GUI. Demon agent with configurable sleep, injection, and evasion options.",
            "features": ["Indirect syscalls", "Sleep obfuscation (Ekko, Zilean)", "Stack spoofing", "Token vault", "BOF support", "Dotnet inline execution", "Process injection (multiple techniques)", "Proxy support"],
            "default_ports": [443, 40056],
            "detection": {
                "user_agent": "Custom (configurable in profile)",
                "sleep_obfuscation": "Uses Ekko/Zilean/Foliage for sleep encryption — memory is encrypted during sleep",
                "syscalls": "Uses indirect syscalls to bypass EDR hooks",
                "binary_strings": ["Demon", "TRANSPORT_HTTP", "DemonConfig"],
            },
            "sigma_rule": "title: Havoc C2 Demon Agent\nlogsource:\n  product: windows\n  service: sysmon\ndetection:\n  selection:\n    EventID: 1\n    CommandLine|contains: 'Demon'\n  condition: selection\nlevel: high",
            "hunting_queries": {
                "splunk": 'index=sysmon EventCode=3 NOT dest_ip IN (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) | stats count values(dest_port) by Image dest_ip | where count > 100',
            },
            "prevalence": "Growing adoption in 2023-2024. Modern evasion techniques make it harder to detect than Cobalt Strike.",
        },
        {
            "name": "Mythic",
            "type": "Open source (its_a_feature_)",
            "language": "Python/Go (server) / Various (agents)",
            "protocols": ["HTTP/S", "TCP", "WebSocket", "P2P"],
            "architecture": "Dockerized server with web UI. Modular agent system — different agents for different needs (Apollo for Windows, Medusa for Python, Poseidon for Go/Linux).",
            "features": ["Web-based UI", "Multiple agent types", "SOCKS proxy", "File browser", "Process browser", "Task queueing", "Artifact tracking", "MITRE mapping", "Reporting"],
            "default_ports": [443, 7443],
            "detection": {
                "network_pattern": "POST requests with JSON payloads to consistent URI paths",
                "docker": "Docker containers on the C2 server with specific image names",
                "agents": "Apollo (C#), Medusa (Python), Poseidon (Go), Apfell (macOS), Athena (C#)",
            },
            "hunting_queries": {
                "splunk": 'index=proxy http_method=POST uri_path="/api/*" | stats count by src_ip dest_ip uri_path | where count > 50',
            },
            "prevalence": "Popular in red team training. Agent modularity makes it versatile. Growing criminal adoption.",
        },
        {
            "name": "Brute Ratel C4",
            "type": "Commercial",
            "language": "C/C++",
            "protocols": ["HTTP/S", "DNS over HTTPS", "SMB", "TCP"],
            "architecture": "Ratel server + operator. Badger payload with advanced evasion. Designed to bypass EDR.",
            "features": ["DNS over HTTPS for C2", "Syscall-level evasion", "Stack/thread spoofing", "Sleep obfuscation", "LDAP sentinel (AD enumeration)", "SMB pivot", "Token manipulation", "Inline .NET", "Screenshot"],
            "default_ports": [443, 8443],
            "detection": {
                "ja3": "Varies (custom TLS implementation)",
                "binary_strings": ["badger_", "brc4", "DarkVortex"],
                "sleep_pattern": "Advanced sleep obfuscation with heap encryption",
                "dns_doh": "DNS over HTTPS requests to custom resolvers",
                "evasion": "Uses direct/indirect syscalls, no usermode hooks",
            },
            "yara_rule": 'rule BruteRatel { strings: $s1 = "badger_" $s2 = "brc4" $s3 = "DarkVortex" condition: 2 of ($s*) }',
            "hunting_queries": {
                "splunk": 'index=dns query_type=HTTPS OR index=proxy dest_port=443 uri_path="/dns-query" | stats count by src_ip dest_ip',
            },
            "prevalence": "Used by APT groups and ransomware operators. Leaked/cracked version appeared in 2022. Harder to detect than Cobalt Strike.",
        },
        {
            "name": "Covenant",
            "type": "Open source",
            "language": "C# (.NET)",
            "protocols": ["HTTP/S", "SMB"],
            "architecture": ".NET Core web application with Blazor UI. Grunt (implant) communicates via listeners.",
            "features": [".NET assembly execution", "Task-based operation", "User management", "Graph visualization", "Listener management", "Launcher generation"],
            "default_ports": [80, 443],
            "detection": {
                "binary_strings": ["Grunt", "Covenant", "GruntHTTP"],
                "network_pattern": "Cookie-based session tracking, specific URI patterns",
            },
            "prevalence": "Popular for C# red teaming. Development slowed since 2021. Still used in training.",
        },
        {
            "name": "PoshC2",
            "type": "Open source",
            "language": "Python (server) / PowerShell/C# (implants)",
            "protocols": ["HTTP/S"],
            "architecture": "Python server with PowerShell and C# implant options. Daisy-chaining for internal pivoting.",
            "features": ["PowerShell implant", "C# implant", "Daisy-chaining", "Lateral movement", "Credential harvesting", "Shellcode injection"],
            "default_ports": [443],
            "detection": {
                "powershell": "PowerShell script block logging (Event ID 4104) will capture implant code",
                "user_agent": "Configurable but default patterns are detectable",
            },
            "prevalence": "Used by some red teams. PowerShell-heavy approach is increasingly detected by modern EDR.",
        },
        {
            "name": "Empire/Starkiller",
            "type": "Open source (BC Security)",
            "language": "Python (server) / PowerShell/Python/C# (agents)",
            "protocols": ["HTTP/S"],
            "architecture": "RESTful server with Starkiller GUI. Multiple agent types. Modular post-exploitation.",
            "features": ["350+ modules", "PowerShell agent", "Python agent", "C# agent", "Malleable C2 (HTTP listener profiles)", "Credential harvesting", "Lateral movement"],
            "default_ports": [443, 1337],
            "detection": {
                "powershell": "PowerShell v5+ script block logging captures agent code",
                "amsi": "AMSI will detect default Empire payloads (bypasses commonly used)",
                "binary_strings": ["empire", "stager", "get_task_list"],
            },
            "prevalence": "Legacy framework, revived by BC Security. Still used but declining vs newer options.",
        },
    ]

    DETECTION_METHODOLOGY = [
        {"phase": "Network Detection", "techniques": [
            "JA3/JA3S fingerprinting: hash TLS Client Hello parameters to identify C2 frameworks",
            "Beacon analysis: detect regular-interval callbacks with statistical analysis (std dev of connection intervals < threshold)",
            "DNS anomaly detection: long TXT queries, high entropy subdomains, unusual query volume",
            "User-Agent analysis: detect default or anomalous user agents",
            "URI pattern analysis: repeated requests to the same unusual paths",
            "Certificate analysis: self-signed certs, unusual validity periods, missing SANs",
            "Data volume analysis: asymmetric traffic patterns (small requests, large responses)",
        ]},
        {"phase": "Endpoint Detection", "techniques": [
            "Process injection detection: monitor for CreateRemoteThread, NtMapViewOfSection from unusual parents",
            "Named pipe analysis: monitor for C2-associated pipe names (Sysmon Event ID 17/18)",
            "In-memory detection: scan process memory for known C2 signatures",
            "Sleep obfuscation detection: detect encrypted memory regions that change periodically",
            "Syscall monitoring: detect direct/indirect syscall usage bypassing ntdll hooks",
            "PE metadata analysis: detect unsigned or anomalously signed binaries",
            "AMSI/ETW monitoring: detect bypass attempts",
        ]},
        {"phase": "Behavioral Detection", "techniques": [
            "Process tree analysis: detect processes spawning unusual children (Word spawning PowerShell)",
            "Credential access: monitor LSASS access, SAM file access, Kerberos ticket requests",
            "Lateral movement patterns: RPC/SMB/WinRM from workstations to servers",
            "Discovery commands: rapid succession of whoami, net user, systeminfo, ipconfig",
            "Persistence installation: registry modifications, scheduled tasks, service creation",
            "Data staging: compression or encryption of files before exfiltration",
        ]},
    ]

    def list_frameworks(self):
        print("\n=== C2 Framework Comparison ===\n")
        print(f"  {'Name':<20} {'Type':<35} {'Protocols':<30} {'Prevalence'}")
        print(f"  {'-'*20} {'-'*35} {'-'*30} {'-'*40}")
        for fw in self.FRAMEWORKS:
            print(f"  {fw['name']:<20} {fw['type']:<35} {', '.join(fw['protocols'][:3]):<30} {fw.get('prevalence', 'N/A')[:60]}")

    def show_framework(self, name):
        fw = next((f for f in self.FRAMEWORKS if f["name"].lower() == name.lower()), None)
        if not fw:
            print(f"[!] Framework '{name}' not found")
            return
        print(f"\n{'='*60}")
        print(f"  {fw['name']}")
        print(f"{'='*60}")
        print(f"\n  Type: {fw['type']}")
        print(f"  Language: {fw['language']}")
        print(f"  Protocols: {', '.join(fw['protocols'])}")
        print(f"  Default Ports: {', '.join(str(p) for p in fw.get('default_ports', []))}")
        print(f"\n  Architecture:\n    {fw['architecture']}")
        print(f"\n  Features:")
        for feat in fw.get("features", []):
            print(f"    - {feat}")
        print(f"\n  Detection Indicators:")
        for k, v in fw.get("detection", {}).items():
            if isinstance(v, list):
                print(f"    {k}: {', '.join(v)}")
            else:
                print(f"    {k}: {v}")
        if fw.get("sigma_rule"):
            print(f"\n  Sigma Rule:")
            for line in fw["sigma_rule"].split("\n"):
                print(f"    {line}")
        if fw.get("yara_rule"):
            print(f"\n  YARA Rule:")
            print(f"    {fw['yara_rule']}")
        if fw.get("hunting_queries"):
            print(f"\n  Hunting Queries:")
            for engine, query in fw["hunting_queries"].items():
                print(f"    [{engine}] {query}")
        print(f"\n  Prevalence: {fw.get('prevalence', 'Unknown')}")

    def show_detection_methodology(self):
        print("\n=== C2 Detection Methodology ===\n")
        for phase in self.DETECTION_METHODOLOGY:
            print(f"\n  --- {phase['phase']} ---")
            for tech in phase["techniques"]:
                print(f"    - {tech}")

    def run(self, confirm_fn=None):
        print("\n[*] AEGIS C2 Framework Reference")
        self.list_frameworks()
        while True:
            try:
                choice = input("\n[AEGIS C2] Enter framework name, 'detect' for methodology, 'q' to quit: ").strip()
                if choice.lower() == 'q':
                    break
                elif choice.lower() == 'detect':
                    self.show_detection_methodology()
                else:
                    self.show_framework(choice)
            except EOFError:
                break

    def get_findings(self):
        return self.findings

if __name__ == "__main__":
    c2 = C2Framework()
    if len(sys.argv) > 1:
        c2.show_framework(sys.argv[1])
    else:
        c2.run()
