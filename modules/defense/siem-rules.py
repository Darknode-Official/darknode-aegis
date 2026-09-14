#!/usr/bin/env python3
"""
AEGIS SIEM Rule Engine
========================
Sigma rule editor and validator, multi-platform rule conversion,
MITRE ATT&CK coverage mapping, detection engineering workflow,
and alert tuning simulation.

EDUCATIONAL USE ONLY - All operations are simulated for training purposes.
"""

import os
import sys
import json
import uuid
import random
import datetime
import argparse
from collections import defaultdict

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.tree import Tree
    from rich.text import Text
    from rich.syntax import Syntax
except ImportError:
    print("[!] rich library required: pip install rich")
    sys.exit(1)

console = Console()

# ─── Sigma Rule Templates ──────────────────────────────────────────────
SIGMA_RULES = [
    {
        "id": "sigma-001",
        "title": "Suspicious PowerShell Encoded Command",
        "status": "stable",
        "level": "high",
        "description": "Detects PowerShell executed with encoded command parameter",
        "author": "AEGIS Sigma",
        "date": "2024-09-01",
        "references": ["https://attack.mitre.org/techniques/T1059/001/"],
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection": {
                "Image|endswith": ["\\powershell.exe", "\\pwsh.exe"],
                "CommandLine|contains": ["-enc", "-EncodedCommand", "-e "],
            },
            "condition": "selection",
        },
        "mitre_attack": ["T1059.001"],
        "tags": ["attack.execution", "attack.t1059.001"],
        "falsepositives": ["Legitimate administrative scripts using encoding"],
        "sigma_yaml": """title: Suspicious PowerShell Encoded Command
id: {id}
status: stable
level: high
description: Detects PowerShell with encoded command
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
        CommandLine|contains:
            - '-enc'
            - '-EncodedCommand'
            - '-e '
    condition: selection
falsepositives:
    - Legitimate admin scripts
tags:
    - attack.execution
    - attack.t1059.001""",
    },
    {
        "id": "sigma-002",
        "title": "Shadow Copy Deletion via vssadmin",
        "status": "stable",
        "level": "critical",
        "description": "Detects deletion of shadow copies which is common in ransomware",
        "author": "AEGIS Sigma",
        "date": "2024-09-01",
        "references": ["https://attack.mitre.org/techniques/T1490/"],
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection": {
                "Image|endswith": "\\vssadmin.exe",
                "CommandLine|contains|all": ["delete", "shadows"],
            },
            "condition": "selection",
        },
        "mitre_attack": ["T1490"],
        "tags": ["attack.impact", "attack.t1490"],
        "falsepositives": ["Legitimate shadow copy management"],
        "sigma_yaml": """title: Shadow Copy Deletion via vssadmin
id: {id}
status: stable
level: critical
description: Detects shadow copy deletion (ransomware indicator)
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\vssadmin.exe'
        CommandLine|contains|all:
            - 'delete'
            - 'shadows'
    condition: selection
falsepositives:
    - Legitimate shadow copy management
tags:
    - attack.impact
    - attack.t1490""",
    },
    {
        "id": "sigma-003",
        "title": "Mimikatz Usage Detection",
        "status": "stable",
        "level": "critical",
        "description": "Detects Mimikatz credential harvesting tool via process or command patterns",
        "author": "AEGIS Sigma",
        "date": "2024-09-01",
        "references": ["https://attack.mitre.org/techniques/T1003/001/"],
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection_binary": {"Image|endswith": "\\mimikatz.exe"},
            "selection_cmd": {
                "CommandLine|contains": ["sekurlsa::logonpasswords", "sekurlsa::wdigest",
                                          "lsadump::sam", "lsadump::dcsync"],
            },
            "condition": "selection_binary or selection_cmd",
        },
        "mitre_attack": ["T1003.001"],
        "tags": ["attack.credential_access", "attack.t1003.001"],
        "falsepositives": ["Security testing tools"],
        "sigma_yaml": """title: Mimikatz Usage Detection
id: {id}
status: stable
level: critical
description: Detects Mimikatz credential harvesting
logsource:
    category: process_creation
    product: windows
detection:
    selection_binary:
        Image|endswith: '\\mimikatz.exe'
    selection_cmd:
        CommandLine|contains:
            - 'sekurlsa::logonpasswords'
            - 'sekurlsa::wdigest'
            - 'lsadump::sam'
            - 'lsadump::dcsync'
    condition: selection_binary or selection_cmd
tags:
    - attack.credential_access
    - attack.t1003.001""",
    },
    {
        "id": "sigma-004",
        "title": "LSASS Process Access",
        "status": "stable",
        "level": "high",
        "description": "Detects processes accessing LSASS memory for credential theft",
        "author": "AEGIS Sigma",
        "date": "2024-09-01",
        "references": ["https://attack.mitre.org/techniques/T1003/001/"],
        "logsource": {"category": "process_access", "product": "windows"},
        "detection": {
            "selection": {
                "TargetImage|endswith": "\\lsass.exe",
                "GrantedAccess|contains": ["0x1010", "0x1410", "0x1F0FFF", "0x1F1FFF"],
            },
            "filter": {
                "SourceImage|endswith": [
                    "\\svchost.exe", "\\lsm.exe", "\\csrss.exe",
                    "\\MsMpEng.exe", "\\MRT.exe",
                ],
            },
            "condition": "selection and not filter",
        },
        "mitre_attack": ["T1003.001"],
        "tags": ["attack.credential_access", "attack.t1003.001"],
        "falsepositives": ["Antivirus solutions", "Legitimate debugging"],
        "sigma_yaml": """title: LSASS Process Access
id: {id}
status: stable
level: high
description: Detects LSASS memory access for credential theft
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1410'
            - '0x1F0FFF'
    filter:
        SourceImage|endswith:
            - '\\svchost.exe'
            - '\\MsMpEng.exe'
    condition: selection and not filter
tags:
    - attack.credential_access""",
    },
    {
        "id": "sigma-005",
        "title": "WMI Event Subscription Persistence",
        "status": "stable",
        "level": "high",
        "description": "Detects WMI event subscription creation for persistence",
        "author": "AEGIS Sigma",
        "date": "2024-09-01",
        "references": ["https://attack.mitre.org/techniques/T1546/003/"],
        "logsource": {"category": "wmi_event", "product": "windows"},
        "detection": {
            "selection": {
                "EventID": [19, 20, 21],
            },
            "condition": "selection",
        },
        "mitre_attack": ["T1546.003"],
        "tags": ["attack.persistence", "attack.t1546.003"],
        "falsepositives": ["SCCM operations", "Legitimate WMI monitoring"],
        "sigma_yaml": """title: WMI Event Subscription Persistence
id: {id}
status: stable
level: high
description: Detects WMI event subscription persistence
logsource:
    category: wmi_event
    product: windows
detection:
    selection:
        EventID:
            - 19
            - 20
            - 21
    condition: selection
tags:
    - attack.persistence
    - attack.t1546.003""",
    },
    {
        "id": "sigma-006",
        "title": "Suspicious Service Installation",
        "status": "stable",
        "level": "high",
        "description": "Detects suspicious service installations often used for persistence or lateral movement",
        "author": "AEGIS Sigma",
        "date": "2024-09-01",
        "references": ["https://attack.mitre.org/techniques/T1543/003/"],
        "logsource": {"category": "system", "product": "windows"},
        "detection": {
            "selection": {
                "EventID": 7045,
                "ServiceFileName|contains": [
                    "\\Temp\\", "\\tmp\\", "cmd.exe", "powershell",
                    "COMSPEC", "rundll32", "regsvr32",
                ],
            },
            "condition": "selection",
        },
        "mitre_attack": ["T1543.003"],
        "tags": ["attack.persistence", "attack.t1543.003"],
        "falsepositives": ["Legitimate software installation"],
        "sigma_yaml": """title: Suspicious Service Installation
id: {id}
status: stable
level: high
description: Detects suspicious service installations
logsource:
    category: system
    product: windows
detection:
    selection:
        EventID: 7045
        ServiceFileName|contains:
            - '\\Temp\\'
            - 'cmd.exe'
            - 'powershell'
    condition: selection
tags:
    - attack.persistence
    - attack.t1543.003""",
    },
    {
        "id": "sigma-007",
        "title": "Kerberoasting Service Ticket Request",
        "status": "stable",
        "level": "high",
        "description": "Detects Kerberos service ticket requests that may indicate Kerberoasting",
        "author": "AEGIS Sigma",
        "date": "2024-09-01",
        "references": ["https://attack.mitre.org/techniques/T1558/003/"],
        "logsource": {"category": "kerberos", "product": "windows"},
        "detection": {
            "selection": {
                "EventID": 4769,
                "TicketEncryptionType": "0x17",
                "ServiceName|endswith": "$",
            },
            "filter": {"ServiceName": "krbtgt"},
            "condition": "selection and not filter",
        },
        "mitre_attack": ["T1558.003"],
        "tags": ["attack.credential_access", "attack.t1558.003"],
        "falsepositives": ["Legacy systems using RC4 encryption"],
        "sigma_yaml": """title: Kerberoasting Service Ticket Request
id: {id}
status: stable
level: high
description: Detects Kerberoasting via RC4 TGS requests
logsource:
    category: kerberos
    product: windows
detection:
    selection:
        EventID: 4769
        TicketEncryptionType: '0x17'
    filter:
        ServiceName: 'krbtgt'
    condition: selection and not filter
tags:
    - attack.credential_access
    - attack.t1558.003""",
    },
    {
        "id": "sigma-008",
        "title": "Remote Desktop Protocol Lateral Movement",
        "status": "stable",
        "level": "medium",
        "description": "Detects RDP connections from unusual sources indicating lateral movement",
        "author": "AEGIS Sigma",
        "date": "2024-09-01",
        "references": ["https://attack.mitre.org/techniques/T1021/001/"],
        "logsource": {"category": "authentication", "product": "windows"},
        "detection": {
            "selection": {
                "EventID": 4624,
                "LogonType": 10,
            },
            "condition": "selection",
        },
        "mitre_attack": ["T1021.001"],
        "tags": ["attack.lateral_movement", "attack.t1021.001"],
        "falsepositives": ["Legitimate RDP administration"],
        "sigma_yaml": """title: RDP Lateral Movement
id: {id}
status: stable
level: medium
description: Detects RDP lateral movement
logsource:
    category: authentication
    product: windows
detection:
    selection:
        EventID: 4624
        LogonType: 10
    condition: selection
tags:
    - attack.lateral_movement
    - attack.t1021.001""",
    },
]

# ─── MITRE ATT&CK Technique Coverage ──────────────────────────────────
MITRE_TECHNIQUES_ALL = {
    "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "Execution"},
    "T1047":     {"name": "WMI", "tactic": "Execution"},
    "T1053.005": {"name": "Scheduled Task", "tactic": "Persistence"},
    "T1547.001": {"name": "Registry Run Keys", "tactic": "Persistence"},
    "T1543.003": {"name": "Windows Service", "tactic": "Persistence"},
    "T1546.003": {"name": "WMI Event Subscription", "tactic": "Persistence"},
    "T1574.001": {"name": "DLL Search Order Hijacking", "tactic": "Persistence"},
    "T1548.002": {"name": "UAC Bypass", "tactic": "Privilege Escalation"},
    "T1134.001": {"name": "Token Impersonation", "tactic": "Privilege Escalation"},
    "T1068":     {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    "T1055":     {"name": "Process Injection", "tactic": "Defense Evasion"},
    "T1070.006": {"name": "Timestomping", "tactic": "Defense Evasion"},
    "T1027":     {"name": "Obfuscated Files", "tactic": "Defense Evasion"},
    "T1036.005": {"name": "Match Legitimate Name", "tactic": "Defense Evasion"},
    "T1562.001": {"name": "Disable Security Tools", "tactic": "Defense Evasion"},
    "T1003.001": {"name": "LSASS Memory", "tactic": "Credential Access"},
    "T1003.002": {"name": "SAM Database", "tactic": "Credential Access"},
    "T1558.003": {"name": "Kerberoasting", "tactic": "Credential Access"},
    "T1003.006": {"name": "DCSync", "tactic": "Credential Access"},
    "T1110.003": {"name": "Password Spraying", "tactic": "Credential Access"},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "Lateral Movement"},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    "T1021.006": {"name": "Windows Remote Management", "tactic": "Lateral Movement"},
    "T1570":     {"name": "Lateral Tool Transfer", "tactic": "Lateral Movement"},
    "T1486":     {"name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1490":     {"name": "Inhibit System Recovery", "tactic": "Impact"},
    "T1489":     {"name": "Service Stop", "tactic": "Impact"},
    "T1485":     {"name": "Data Destruction", "tactic": "Impact"},
}


class SIEMRuleEngine:
    """
    SIEM Rule Engine

    Sigma rule management, cross-platform conversion, MITRE ATT&CK
    coverage analysis, and detection engineering workflow.

    Usage:
        engine = SIEMRuleEngine()
        engine.run()
    """

    HELP_TEXT = """
AEGIS SIEM Rule Engine
========================
Detection rule management and engineering platform.

Commands:
  list                  List all Sigma rules
  view <rule_id>        View rule details and YAML
  convert <rule_id>     Convert rule to Splunk SPL / Elastic KQL / QRadar AQL
  coverage              Map detection coverage against MITRE ATT&CK
  gaps                  Identify detection gaps
  tune <rule_id>        Simulate alert tuning
  test <rule_id>        Test rule against sample logs
  workflow              Detection engineering workflow
  validate              Validate all rules
  help                  Show this help message

Options:
  --format <fmt>        splunk | elastic | qradar (default: splunk)
  --output <file>       Export results to JSON
"""

    def __init__(self):
        """Initialize the SIEM Rule Engine."""
        self.rules = SIGMA_RULES
        self.test_results = []
        self._verify_authorization()

    def _verify_authorization(self):
        """Verify operator authorization."""
        console.print(Panel(
            "[bold yellow]AUTHORIZATION CHECK[/bold yellow]\n\n"
            "This module manages simulated SIEM detection rules.\n"
            "All rules, conversions, and test results are educational examples.\n"
            "For production use, validate rules in your specific SIEM environment.",
            title="AEGIS SIEM Rule Engine",
            border_style="yellow"
        ))

    def list_rules(self):
        """List all Sigma rules in the engine."""
        table = Table(title=f"Sigma Rules ({len(self.rules)})")
        table.add_column("ID", style="dim", width=12)
        table.add_column("Title", style="cyan", width=35)
        table.add_column("Level", width=10)
        table.add_column("Status", style="green", width=8)
        table.add_column("MITRE", style="yellow", width=12)
        table.add_column("Tags", style="dim", width=25)

        for rule in self.rules:
            level_style = {
                "critical": "red bold", "high": "red",
                "medium": "yellow", "low": "green",
            }.get(rule["level"], "white")
            table.add_row(
                rule["id"],
                rule["title"],
                Text(rule["level"].upper(), style=level_style),
                rule["status"],
                ", ".join(rule.get("mitre_attack", [])),
                ", ".join(rule.get("tags", [])[:2]),
            )
        console.print(table)

    def view_rule(self, rule_id="sigma-001"):
        """View detailed Sigma rule."""
        rule = next((r for r in self.rules if r["id"] == rule_id), None)
        if not rule:
            console.print(f"[red]Rule not found: {rule_id}[/red]")
            return

        console.print(Panel(
            f"[bold]{rule['title']}[/bold]\n\n"
            f"ID:          {rule['id']}\n"
            f"Level:       {rule['level'].upper()}\n"
            f"Status:      {rule['status']}\n"
            f"Author:      {rule['author']}\n"
            f"Date:        {rule['date']}\n"
            f"Description: {rule['description']}\n"
            f"MITRE:       {', '.join(rule.get('mitre_attack', []))}\n"
            f"FP:          {', '.join(rule.get('falsepositives', []))}",
            title=f"Sigma Rule: {rule_id}",
            border_style="cyan",
        ))

        # Display YAML
        yaml_content = rule.get("sigma_yaml", "").format(id=rule["id"])
        console.print(Panel(
            Syntax(yaml_content, "yaml", theme="monokai", line_numbers=True),
            title="Sigma YAML",
            border_style="yellow",
        ))

    def convert_rule(self, rule_id="sigma-001", target="splunk"):
        """Convert Sigma rule to SIEM-specific query."""
        rule = next((r for r in self.rules if r["id"] == rule_id), None)
        if not rule:
            console.print(f"[red]Rule not found: {rule_id}[/red]")
            return

        detection = rule.get("detection", {})
        conversions = {}

        # Generate platform-specific conversions
        if "selection" in detection:
            sel = detection["selection"]

            # Splunk SPL
            conditions = []
            for field, values in sel.items():
                base_field = field.split("|")[0]
                modifier = field.split("|")[1] if "|" in field else ""
                if isinstance(values, list):
                    if "contains" in modifier:
                        or_parts = [f'{base_field}="*{v}*"' for v in values]
                        conditions.append(f"({' OR '.join(or_parts)})")
                    elif "endswith" in modifier:
                        or_parts = [f'{base_field}="*{v}"' for v in values]
                        conditions.append(f"({' OR '.join(or_parts)})")
                    else:
                        or_parts = [f'{base_field}="{v}"' for v in values]
                        conditions.append(f"({' OR '.join(or_parts)})")
                else:
                    if "contains" in modifier:
                        conditions.append(f'{base_field}="*{values}*"')
                    elif "endswith" in modifier:
                        conditions.append(f'{base_field}="*{values}"')
                    else:
                        conditions.append(f'{base_field}="{values}"')

            conversions["splunk"] = {
                "name": "Splunk SPL",
                "query": f'index=windows sourcetype=WinEventLog:Security\n| where {" AND ".join(conditions)}\n| table _time, host, user, {", ".join(set(f.split("|")[0] for f in sel.keys()))}\n| sort -_time',
            }

            # Elastic KQL
            kql_parts = []
            for field, values in sel.items():
                base_field = field.split("|")[0]
                modifier = field.split("|")[1] if "|" in field else ""
                if isinstance(values, list):
                    if "contains" in modifier:
                        or_parts = [f'{base_field}:*{v}*' for v in values]
                    elif "endswith" in modifier:
                        or_parts = [f'{base_field}:*{v}' for v in values]
                    else:
                        or_parts = [f'{base_field}:"{v}"' for v in values]
                    kql_parts.append(f"({' or '.join(or_parts)})")
                else:
                    if "contains" in modifier:
                        kql_parts.append(f'{base_field}:*{values}*')
                    else:
                        kql_parts.append(f'{base_field}:"{values}"')

            conversions["elastic"] = {
                "name": "Elastic KQL",
                "query": f'event.category:"process" and\n{" and ".join(kql_parts)}',
            }

            # QRadar AQL
            aql_parts = []
            for field, values in sel.items():
                base_field = field.split("|")[0].replace("Image", "\"Process Path\"").replace("CommandLine", "\"Process CommandLine\"")
                modifier = field.split("|")[1] if "|" in field else ""
                if isinstance(values, list):
                    if "contains" in modifier:
                        or_parts = [f"{base_field} LIKE '%{v}%'" for v in values]
                    elif "endswith" in modifier:
                        or_parts = [f"{base_field} LIKE '%{v}'" for v in values]
                    else:
                        or_parts = [f"{base_field} = '{v}'" for v in values]
                    aql_parts.append(f"({' OR '.join(or_parts)})")
                else:
                    aql_parts.append(f"{base_field} LIKE '%{values}%'")

            conversions["qradar"] = {
                "name": "QRadar AQL",
                "query": f'SELECT * FROM events\nWHERE {" AND ".join(aql_parts)}\nLAST 24 HOURS',
            }

        # Display conversions
        for platform, conv in conversions.items():
            lang = {"splunk": "sql", "elastic": "text", "qradar": "sql"}.get(platform, "text")
            console.print(Panel(
                Syntax(conv["query"], lang, theme="monokai"),
                title=f"{conv['name']} Conversion: {rule['title']}",
                border_style="green" if platform == target else "dim",
            ))

        return conversions

    def analyze_coverage(self):
        """Map detection coverage against MITRE ATT&CK."""
        console.print(Panel(
            "[bold cyan]MITRE ATT&CK DETECTION COVERAGE[/bold cyan]\n\n"
            "Mapping Sigma rules to MITRE ATT&CK techniques...",
            title="Coverage Analysis",
            border_style="cyan",
        ))

        covered_techniques = set()
        for rule in self.rules:
            for tech in rule.get("mitre_attack", []):
                covered_techniques.add(tech)

        # Coverage by tactic
        tactics = defaultdict(lambda: {"total": 0, "covered": 0, "techniques": []})
        for tech_id, info in MITRE_TECHNIQUES_ALL.items():
            tactic = info["tactic"]
            tactics[tactic]["total"] += 1
            if tech_id in covered_techniques:
                tactics[tactic]["covered"] += 1
                tactics[tactic]["techniques"].append(f"[green]{tech_id}[/green]")
            else:
                tactics[tactic]["techniques"].append(f"[red]{tech_id}[/red]")

        table = Table(title="Detection Coverage by Tactic")
        table.add_column("Tactic", style="cyan", width=25)
        table.add_column("Covered", justify="right")
        table.add_column("Total", justify="right")
        table.add_column("Coverage", justify="right")
        table.add_column("Techniques", style="dim", width=40)

        for tactic, info in sorted(tactics.items()):
            pct = (info["covered"] / info["total"] * 100) if info["total"] > 0 else 0
            pct_style = "green" if pct >= 60 else "yellow" if pct >= 30 else "red"
            table.add_row(
                tactic,
                str(info["covered"]),
                str(info["total"]),
                Text(f"{pct:.0f}%", style=pct_style),
                ", ".join(info["techniques"]),
            )
        console.print(table)

        # Overall coverage
        total_techniques = len(MITRE_TECHNIQUES_ALL)
        covered_count = len(covered_techniques)
        overall_pct = (covered_count / total_techniques * 100) if total_techniques > 0 else 0
        overall_style = "green" if overall_pct >= 50 else "yellow" if overall_pct >= 25 else "red"

        console.print(Panel(
            f"[bold]Overall MITRE ATT&CK Coverage: [{overall_style}]{overall_pct:.1f}%[/{overall_style}][/bold]\n\n"
            f"Techniques Covered:   {covered_count}\n"
            f"Total Techniques:     {total_techniques}\n"
            f"Detection Rules:      {len(self.rules)}\n"
            f"Coverage Gaps:        {total_techniques - covered_count}",
            title="Coverage Summary",
            border_style=overall_style,
        ))

    def identify_gaps(self):
        """Identify detection gaps in MITRE ATT&CK coverage."""
        covered = set()
        for rule in self.rules:
            for tech in rule.get("mitre_attack", []):
                covered.add(tech)

        gaps = {tid: info for tid, info in MITRE_TECHNIQUES_ALL.items() if tid not in covered}

        console.print(Panel(
            f"[bold red]DETECTION GAPS[/bold red]\n\n"
            f"Found {len(gaps)} uncovered MITRE ATT&CK techniques.",
            title="Gap Analysis",
            border_style="red",
        ))

        table = Table(title=f"Uncovered Techniques ({len(gaps)})")
        table.add_column("Technique", style="yellow", width=12)
        table.add_column("Name", style="white", width=30)
        table.add_column("Tactic", style="cyan", width=25)
        table.add_column("Priority", width=10)

        priority_map = {
            "Credential Access": "CRITICAL",
            "Defense Evasion": "HIGH",
            "Privilege Escalation": "HIGH",
            "Lateral Movement": "HIGH",
            "Impact": "CRITICAL",
            "Execution": "MEDIUM",
            "Persistence": "MEDIUM",
        }

        for tid, info in sorted(gaps.items()):
            priority = priority_map.get(info["tactic"], "MEDIUM")
            pri_style = {"CRITICAL": "red bold", "HIGH": "red", "MEDIUM": "yellow"}.get(priority, "white")
            table.add_row(tid, info["name"], info["tactic"], Text(priority, style=pri_style))
        console.print(table)

    def simulate_alert_tuning(self, rule_id="sigma-001"):
        """Simulate alert tuning with false positive estimation."""
        rule = next((r for r in self.rules if r["id"] == rule_id), None)
        if not rule:
            console.print(f"[red]Rule not found: {rule_id}[/red]")
            return

        console.print(Panel(
            f"[bold cyan]ALERT TUNING: {rule['title']}[/bold cyan]\n\n"
            f"Simulating alert data to estimate false positive rate...",
            title="Alert Tuning",
            border_style="cyan",
        ))

        total_alerts = random.randint(500, 5000)
        true_positives = int(total_alerts * random.uniform(0.1, 0.6))
        false_positives = total_alerts - true_positives
        fp_rate = false_positives / total_alerts

        # Simulate tuning iterations
        tuning_history = []
        current_fp = fp_rate
        current_total = total_alerts
        for i in range(4):
            action = random.choice([
                "Added process path exclusion",
                "Added user account whitelist",
                "Added parent process filter",
                "Refined command line pattern",
                "Added time-based suppression",
            ])
            reduction = random.uniform(0.15, 0.45)
            new_fp = current_fp * (1 - reduction)
            new_total = int(current_total * (1 - reduction * 0.8))
            tuning_history.append({
                "iteration": i + 1,
                "action": action,
                "alerts": new_total,
                "fp_rate": new_fp,
                "reduction": f"{reduction*100:.0f}%",
            })
            current_fp = new_fp
            current_total = new_total

        table = Table(title=f"Alert Tuning History: {rule['title']}")
        table.add_column("Iteration", style="dim", justify="right")
        table.add_column("Action", style="cyan", width=30)
        table.add_column("Alerts/Day", justify="right")
        table.add_column("FP Rate", justify="right")
        table.add_column("Reduction", style="green", justify="right")

        # Baseline row
        table.add_row("0", "[dim]Baseline (no tuning)[/dim]",
                       str(total_alerts), f"[red]{fp_rate*100:.1f}%[/red]", "-")

        for t in tuning_history:
            fp_style = "green" if t["fp_rate"] < 0.1 else "yellow" if t["fp_rate"] < 0.3 else "red"
            table.add_row(
                str(t["iteration"]),
                t["action"],
                str(t["alerts"]),
                Text(f"{t['fp_rate']*100:.1f}%", style=fp_style),
                t["reduction"],
            )
        console.print(table)

        final_fp = tuning_history[-1]["fp_rate"] if tuning_history else fp_rate
        final_style = "green" if final_fp < 0.1 else "yellow" if final_fp < 0.2 else "red"
        console.print(Panel(
            f"[bold]Final FP Rate: [{final_style}]{final_fp*100:.1f}%[/{final_style}][/bold]\n\n"
            f"Original Alerts/Day: {total_alerts}\n"
            f"Tuned Alerts/Day:    {tuning_history[-1]['alerts'] if tuning_history else total_alerts}\n"
            f"Overall Reduction:   {((total_alerts - tuning_history[-1]['alerts']) / total_alerts * 100):.0f}%",
            title="Tuning Result",
            border_style=final_style,
        ))

    def test_rule_against_logs(self, rule_id="sigma-001"):
        """Test a rule against sample log data."""
        rule = next((r for r in self.rules if r["id"] == rule_id), None)
        if not rule:
            console.print(f"[red]Rule not found: {rule_id}[/red]")
            return

        console.print(Panel(
            f"[bold cyan]RULE TESTING: {rule['title']}[/bold cyan]\n\n"
            f"Testing rule against sample log corpus...",
            title="Rule Testing",
            border_style="cyan",
        ))

        sample_logs = random.randint(10000, 100000)
        matches = random.randint(5, 50)
        true_matches = int(matches * random.uniform(0.6, 0.95))
        false_matches = matches - true_matches

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Testing against log corpus...", total=100)
            for _ in range(100):
                progress.advance(task)

        console.print(Panel(
            f"[bold green]TEST COMPLETE[/bold green]\n\n"
            f"Logs Processed:   {sample_logs:,}\n"
            f"Total Matches:    {matches}\n"
            f"True Positives:   [green]{true_matches}[/green]\n"
            f"False Positives:  [red]{false_matches}[/red]\n"
            f"Precision:        {true_matches/matches*100:.1f}%\n"
            f"Processing Time:  {random.uniform(0.5, 5.0):.2f}s",
            title="Test Results",
            border_style="green",
        ))

    def detection_engineering_workflow(self):
        """Display detection engineering workflow."""
        stages = [
            {"stage": "1. Threat Research", "tasks": [
                "Identify relevant threats and TTPs",
                "Review threat intelligence reports",
                "Map to MITRE ATT&CK framework",
                "Identify data sources needed",
            ]},
            {"stage": "2. Rule Development", "tasks": [
                "Write Sigma rule in YAML format",
                "Validate rule syntax",
                "Add metadata (author, date, references)",
                "Map to MITRE ATT&CK techniques",
            ]},
            {"stage": "3. Testing", "tasks": [
                "Test against benign log data (false positive check)",
                "Test against attack simulation data (true positive check)",
                "Measure detection latency",
                "Validate across different environments",
            ]},
            {"stage": "4. Deployment", "tasks": [
                "Convert to target SIEM format (SPL/KQL/AQL)",
                "Deploy to staging environment",
                "Monitor for 48-72 hours",
                "Adjust thresholds based on alert volume",
            ]},
            {"stage": "5. Tuning & Maintenance", "tasks": [
                "Review false positive rate weekly",
                "Add exclusions for known benign patterns",
                "Update for new threat intelligence",
                "Document tuning decisions",
                "Retire obsolete rules",
            ]},
        ]

        tree = Tree("[bold]Detection Engineering Workflow[/bold]")
        for stage_info in stages:
            branch = tree.add(f"[cyan]{stage_info['stage']}[/cyan]")
            for task in stage_info["tasks"]:
                branch.add(f"[ ] {task}")
        console.print(tree)

    def validate_rules(self):
        """Validate all Sigma rules for correctness."""
        console.print(Panel(
            "[bold cyan]RULE VALIDATION[/bold cyan]\n\n"
            f"Validating {len(self.rules)} Sigma rules...",
            title="Validation",
            border_style="cyan",
        ))

        table = Table(title="Validation Results")
        table.add_column("Rule ID", style="dim")
        table.add_column("Title", style="cyan", width=35)
        table.add_column("Syntax", width=8)
        table.add_column("Fields", width=8)
        table.add_column("MITRE", width=8)
        table.add_column("Overall", width=8)

        all_pass = True
        for rule in self.rules:
            syntax_ok = bool(rule.get("detection"))
            fields_ok = all(k in rule for k in ["id", "title", "level", "description"])
            mitre_ok = bool(rule.get("mitre_attack"))
            overall = syntax_ok and fields_ok and mitre_ok
            if not overall:
                all_pass = False

            table.add_row(
                rule["id"],
                rule["title"],
                "[green]PASS[/green]" if syntax_ok else "[red]FAIL[/red]",
                "[green]PASS[/green]" if fields_ok else "[red]FAIL[/red]",
                "[green]PASS[/green]" if mitre_ok else "[red]FAIL[/red]",
                "[green]PASS[/green]" if overall else "[red]FAIL[/red]",
            )
        console.print(table)

        status = "[green]All rules valid[/green]" if all_pass else "[red]Some rules have issues[/red]"
        console.print(f"\nValidation Status: {status}")

    def run(self):
        """Main execution entry point."""
        self.list_rules()
        console.print("\n")
        self.view_rule("sigma-001")
        console.print("\n")
        self.convert_rule("sigma-001", "splunk")
        console.print("\n")
        self.analyze_coverage()
        console.print("\n")
        self.identify_gaps()
        console.print("\n")
        self.validate_rules()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="AEGIS SIEM Rule Engine -- Educational Use Only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("command", nargs="?", default="run",
                        choices=["run", "list", "view", "convert", "coverage",
                                 "gaps", "tune", "test", "workflow", "validate", "help"],
                        help="Command to execute")
    parser.add_argument("--rule", "-r", default="sigma-001",
                        help="Rule ID to operate on")
    parser.add_argument("--format", "-f", default="splunk",
                        choices=["splunk", "elastic", "qradar"],
                        help="Target SIEM format for conversion")
    parser.add_argument("--output", "-o", default=None,
                        help="Export results to JSON file")

    args = parser.parse_args()
    engine = SIEMRuleEngine()

    if args.command == "help":
        console.print(engine.HELP_TEXT)
    elif args.command == "list":
        engine.list_rules()
    elif args.command == "view":
        engine.view_rule(args.rule)
    elif args.command == "convert":
        engine.convert_rule(args.rule, args.format)
    elif args.command == "coverage":
        engine.analyze_coverage()
    elif args.command == "gaps":
        engine.identify_gaps()
    elif args.command == "tune":
        engine.simulate_alert_tuning(args.rule)
    elif args.command == "test":
        engine.test_rule_against_logs(args.rule)
    elif args.command == "workflow":
        engine.detection_engineering_workflow()
    elif args.command == "validate":
        engine.validate_rules()
    else:
        engine.run()

    if args.output:
        data = {
            "rules": [{k: v for k, v in r.items() if k != "sigma_yaml"} for r in engine.rules],
            "test_results": engine.test_results,
        }
        with open(args.output, "w") as f:
            json.dump(data, f, indent=2, default=str)
        console.print(f"[green]Results exported to {args.output}[/green]")


if __name__ == "__main__":
    main()
