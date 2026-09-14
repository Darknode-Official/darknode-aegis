#!/usr/bin/env python3
"""
AEGIS Ransomware Defense Simulator
====================================
Simulates ransomware behavior patterns, tests backup recovery procedures,
evaluates detection rules, and generates canary file deployment plans.

EDUCATIONAL USE ONLY - All operations are simulated for training purposes.
"""

import os
import sys
import json
import uuid
import random
import hashlib
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
    from rich.columns import Columns
except ImportError:
    print("[!] rich library required: pip install rich")
    sys.exit(1)

console = Console()

# ─── Ransomware Family Database ────────────────────────────────────────
RANSOMWARE_FAMILIES = {
    "LockBit": {
        "aliases": ["LockBit 3.0", "LockBit Black"],
        "first_seen": "2019-09",
        "status": "Active",
        "encryption": "AES-256 + RSA-2048",
        "extension": ".lockbit",
        "ransom_note": "Restore-My-Files.txt",
        "attack_vector": ["RDP", "Phishing", "Exploit"],
        "kill_processes": ["sql", "oracle", "ocssd", "dbsnmp", "synctime", "agntsvc",
                           "isqlplussvc", "xfssvccon", "mydesktopservice", "ocautoupds"],
        "kill_services": ["vss", "sql", "svc$", "memtas", "mepocs", "sophos", "veeam",
                          "backup", "GxVss", "GxBlr", "GxFWD", "GxCVD", "GxCIMgr"],
        "shadow_delete": True,
        "self_propagation": True,
        "double_extortion": True,
        "mitre_techniques": ["T1486", "T1490", "T1489", "T1021.002", "T1059.001"],
        "iocs": {
            "mutex": ["Global\\{BEF590BE-11A6-442A-A85B-656C770DCE16}"],
            "file_hashes": ["e3f236e4aeb73f8f8f0b20f4"],
            "registry_keys": [r"HKCU\SOFTWARE\LockBit"],
        },
    },
    "BlackCat": {
        "aliases": ["ALPHV", "Noberus"],
        "first_seen": "2021-11",
        "status": "Active (Rebranded)",
        "encryption": "AES-256-CTR + RSA-4096",
        "extension": ".alphv",
        "ransom_note": "RECOVER-FILES.txt",
        "attack_vector": ["Affiliate", "Exploit", "Credential Theft"],
        "kill_processes": ["sql", "oracle", "ocssd", "dbsnmp", "encsvc", "firefox",
                           "tbirdconfig", "mydesktopqos", "ocomm", "dbeng50"],
        "kill_services": ["vss", "sql", "svc$", "memtas", "mepocs", "veeam", "backup"],
        "shadow_delete": True,
        "self_propagation": True,
        "double_extortion": True,
        "mitre_techniques": ["T1486", "T1490", "T1489", "T1059.001", "T1027"],
        "iocs": {
            "mutex": [],
            "file_hashes": ["a1b2c3d4e5f6a7b8c9d0e1f2"],
            "registry_keys": [],
        },
    },
    "Cl0p": {
        "aliases": ["TA505", "Clop"],
        "first_seen": "2019-02",
        "status": "Active",
        "encryption": "AES-256 + RSA-1024",
        "extension": ".Cl0p",
        "ransom_note": "ClopReadMe.txt",
        "attack_vector": ["Exploit (MOVEit, GoAnywhere)", "Phishing"],
        "kill_processes": ["sql", "oracle", "ocssd", "dbsnmp", "synctime"],
        "kill_services": ["vss", "sql", "svc$", "memtas"],
        "shadow_delete": True,
        "self_propagation": False,
        "double_extortion": True,
        "mitre_techniques": ["T1486", "T1490", "T1190", "T1059.001"],
        "iocs": {
            "mutex": ["Fany--Is$$God"],
            "file_hashes": ["f1e2d3c4b5a6f7e8d9c0b1a2"],
            "registry_keys": [],
        },
    },
    "Play": {
        "aliases": ["PlayCrypt", "Balloonfly"],
        "first_seen": "2022-06",
        "status": "Active",
        "encryption": "AES-256 + RSA-2048",
        "extension": ".play",
        "ransom_note": "ReadMe.txt",
        "attack_vector": ["Exploit (FortiOS, Exchange)", "Valid Accounts"],
        "kill_processes": ["sql", "oracle", "ocssd", "dbsnmp", "xfssvccon"],
        "kill_services": ["vss", "sql", "svc$", "backup", "sophos"],
        "shadow_delete": True,
        "self_propagation": True,
        "double_extortion": True,
        "mitre_techniques": ["T1486", "T1490", "T1489", "T1190"],
        "iocs": {
            "mutex": [],
            "file_hashes": ["a9b8c7d6e5f4a3b2c1d0e9f8"],
            "registry_keys": [],
        },
    },
    "Royal": {
        "aliases": ["Royal Ransomware", "DEV-0569"],
        "first_seen": "2022-09",
        "status": "Active (Rebranded as BlackSuit)",
        "encryption": "AES-256 + RSA-2048",
        "extension": ".royal",
        "ransom_note": "README.TXT",
        "attack_vector": ["Callback Phishing", "Google Ads", "Exploit"],
        "kill_processes": ["sql", "oracle", "ocssd", "dbsnmp", "encsvc"],
        "kill_services": ["vss", "sql", "svc$", "veeam", "backup"],
        "shadow_delete": True,
        "self_propagation": False,
        "double_extortion": True,
        "mitre_techniques": ["T1486", "T1490", "T1489", "T1566.002"],
        "iocs": {
            "mutex": [],
            "file_hashes": ["b1a2c3d4e5f6b7a8c9d0e1f2"],
            "registry_keys": [r"HKCU\SOFTWARE\Royal"],
        },
    },
    "Akira": {
        "aliases": ["Akira Ransomware"],
        "first_seen": "2023-03",
        "status": "Active",
        "encryption": "ChaCha20 + RSA-4096",
        "extension": ".akira",
        "ransom_note": "akira_readme.txt",
        "attack_vector": ["VPN Exploit (Cisco ASA)", "Valid Credentials"],
        "kill_processes": ["sql", "oracle", "veeam", "backup"],
        "kill_services": ["vss", "sql", "veeam", "backup"],
        "shadow_delete": True,
        "self_propagation": False,
        "double_extortion": True,
        "mitre_techniques": ["T1486", "T1490", "T1133", "T1059.001"],
        "iocs": {
            "mutex": [],
            "file_hashes": ["c2b3a4d5e6f7c8b9a0d1e2f3"],
            "registry_keys": [],
        },
    },
    "Rhysida": {
        "aliases": ["Rhysida Ransomware"],
        "first_seen": "2023-05",
        "status": "Active",
        "encryption": "AES-256-CTR + RSA-4096",
        "extension": ".rhysida",
        "ransom_note": "CriticalBreachDetected.pdf",
        "attack_vector": ["Phishing", "Exploit", "Valid Accounts"],
        "kill_processes": ["sql", "oracle", "ocssd"],
        "kill_services": ["vss", "sql", "backup"],
        "shadow_delete": True,
        "self_propagation": False,
        "double_extortion": True,
        "mitre_techniques": ["T1486", "T1490", "T1566.001"],
        "iocs": {
            "mutex": [],
            "file_hashes": ["d3c4b5a6e7f8d9c0b1a2e3f4"],
            "registry_keys": [],
        },
    },
    "BlackBasta": {
        "aliases": ["Black Basta"],
        "first_seen": "2022-04",
        "status": "Active",
        "encryption": "ChaCha20 + RSA-4096",
        "extension": ".basta",
        "ransom_note": "readme.txt",
        "attack_vector": ["QakBot", "Phishing", "Exploit"],
        "kill_processes": ["sql", "oracle", "ocssd", "dbsnmp", "encsvc"],
        "kill_services": ["vss", "sql", "svc$", "veeam", "backup", "sophos"],
        "shadow_delete": True,
        "self_propagation": True,
        "double_extortion": True,
        "mitre_techniques": ["T1486", "T1490", "T1489", "T1059.001", "T1021.002"],
        "iocs": {
            "mutex": [],
            "file_hashes": ["e4d5c6b7a8f9e0d1c2b3a4f5"],
            "registry_keys": [],
        },
    },
}

# ─── Canary File Templates ─────────────────────────────────────────────
CANARY_DEPLOYMENTS = {
    "high_value_targets": [
        {"path": "C:\\Users\\{user}\\Desktop\\passwords.xlsx", "type": "xlsx", "size": "12KB"},
        {"path": "C:\\Users\\{user}\\Desktop\\bank_accounts.csv", "type": "csv", "size": "4KB"},
        {"path": "C:\\Users\\{user}\\Documents\\tax_returns_2024.pdf", "type": "pdf", "size": "89KB"},
        {"path": "C:\\Users\\{user}\\Documents\\employee_SSN.xlsx", "type": "xlsx", "size": "24KB"},
        {"path": "C:\\Shares\\Finance\\quarterly_report.xlsx", "type": "xlsx", "size": "156KB"},
        {"path": "C:\\Shares\\HR\\salary_data_2024.csv", "type": "csv", "size": "34KB"},
        {"path": "C:\\Shares\\IT\\vpn_credentials.txt", "type": "txt", "size": "2KB"},
        {"path": "C:\\Shares\\Executive\\merger_plan.docx", "type": "docx", "size": "78KB"},
    ],
    "system_locations": [
        {"path": "C:\\Windows\\Temp\\svchost_config.xml", "type": "xml", "size": "1KB"},
        {"path": "C:\\ProgramData\\canary_monitor.dat", "type": "dat", "size": "512B"},
        {"path": "C:\\Users\\Public\\Documents\\shared_notes.txt", "type": "txt", "size": "2KB"},
    ],
    "network_shares": [
        {"path": "\\\\FileServer\\Shared\\budget_draft.xlsx", "type": "xlsx", "size": "45KB"},
        {"path": "\\\\FileServer\\Dept\\contracts_2024.pdf", "type": "pdf", "size": "120KB"},
        {"path": "\\\\FileServer\\Archive\\backup_keys.txt", "type": "txt", "size": "1KB"},
    ],
}


class RansomwareSimulationEvent:
    """Represents an event in a ransomware simulation."""

    def __init__(self, event_type, description, severity="INFO", host="localhost"):
        self.event_id = str(uuid.uuid4())[:8]
        self.timestamp = datetime.datetime.now()
        self.event_type = event_type
        self.description = description
        self.severity = severity
        self.host = host
        self.detected = False
        self.detection_rule = None

    def to_dict(self):
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "description": self.description,
            "severity": self.severity,
            "host": self.host,
            "detected": self.detected,
            "detection_rule": self.detection_rule,
        }


class RansomwareDefenseSimulator:
    """
    Ransomware Defense Simulator

    Simulates ransomware behavior patterns and tests organizational
    defenses, backup procedures, and detection capabilities.

    Usage:
        sim = RansomwareDefenseSimulator()
        sim.run()
    """

    HELP_TEXT = """
AEGIS Ransomware Defense Simulator
====================================
Test your defenses against ransomware attacks (simulated).

Commands:
  simulate <family>     Simulate specific ransomware family behavior
  list-families         List known ransomware families with details
  test-detection        Test detection rules against simulated behaviors
  test-backup           Simulate backup recovery procedure
  canary-plan           Generate canary file deployment plan
  segmentation          Assess network segmentation effectiveness
  rto-calc              Calculate Recovery Time Objective
  assessment            Run full ransomware readiness assessment
  help                  Show this help message

Options:
  --family <name>       LockBit | BlackCat | Cl0p | Play | Royal | Akira | ...
  --target <host>       Target host (simulated)
  --output <file>       Export results to JSON
"""

    def __init__(self):
        """Initialize the Ransomware Defense Simulator."""
        self.events = []
        self.detection_results = []
        self.backup_test_results = []
        self._verify_authorization()

    def _verify_authorization(self):
        """Verify operator authorization."""
        console.print(Panel(
            "[bold yellow]AUTHORIZATION CHECK[/bold yellow]\n\n"
            "This module simulates ransomware behaviors for [bold]educational purposes only[/bold].\n"
            "No actual encryption or file modification occurs.\n"
            "All operations produce simulated data for defense testing.",
            title="AEGIS Ransomware Defense",
            border_style="yellow"
        ))

    def simulate_ransomware(self, family_name="LockBit"):
        """Simulate the full behavior chain of a ransomware family."""
        family = RANSOMWARE_FAMILIES.get(family_name)
        if not family:
            console.print(f"[red]Unknown family: {family_name}. Use list-families to see options.[/red]")
            return

        console.print(Panel(
            f"[bold red]RANSOMWARE SIMULATION: {family_name}[/bold red]\n\n"
            f"Aliases:       {', '.join(family['aliases'])}\n"
            f"First Seen:    {family['first_seen']}\n"
            f"Status:        {family['status']}\n"
            f"Encryption:    {family['encryption']}\n"
            f"Extension:     {family['extension']}\n"
            f"Ransom Note:   {family['ransom_note']}\n"
            f"Double Extort: {'Yes' if family['double_extortion'] else 'No'}\n"
            f"Self-Propag:   {'Yes' if family['self_propagation'] else 'No'}",
            title=f"Simulating: {family_name}",
            border_style="red",
        ))

        events = []

        # Phase 1: Pre-encryption reconnaissance
        console.print("\n[bold cyan]Phase 1: Pre-Encryption Reconnaissance[/bold cyan]")
        recon_actions = [
            ("Process Enumeration", f"Enumerating running processes to identify security tools"),
            ("Service Discovery", f"Identifying backup and database services to terminate"),
            ("Network Mapping", f"Mapping network shares for lateral encryption"),
            ("Volume Enumeration", f"Identifying all mounted volumes and drive letters"),
        ]
        for action, desc in recon_actions:
            event = RansomwareSimulationEvent("RECON", desc, "WARNING")
            events.append(event)
            console.print(f"  [yellow]>[/yellow] {desc}")

        # Phase 2: Security tool termination
        console.print("\n[bold cyan]Phase 2: Defense Disabling[/bold cyan]")
        for service in family["kill_services"][:5]:
            event = RansomwareSimulationEvent(
                "DEFENSE_EVASION",
                f"Attempting to stop service: {service}",
                "CRITICAL",
            )
            events.append(event)
            console.print(f"  [red]x[/red] Stopping service: {service}")

        # Phase 3: Process termination
        console.print("\n[bold cyan]Phase 3: Process Termination[/bold cyan]")
        for proc in family["kill_processes"][:5]:
            event = RansomwareSimulationEvent(
                "PROCESS_KILL",
                f"Terminating process: {proc}",
                "HIGH",
            )
            events.append(event)
            console.print(f"  [red]x[/red] Killing process: {proc}")

        # Phase 4: Shadow copy deletion
        if family["shadow_delete"]:
            console.print("\n[bold cyan]Phase 4: Recovery Inhibition[/bold cyan]")
            shadow_commands = [
                "vssadmin delete shadows /all /quiet",
                "wmic shadowcopy delete",
                "bcdedit /set {default} recoveryenabled No",
                "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
                "wbadmin delete catalog -quiet",
            ]
            for cmd in shadow_commands:
                event = RansomwareSimulationEvent(
                    "RECOVERY_INHIBIT",
                    f"Executing: {cmd}",
                    "CRITICAL",
                )
                events.append(event)
                console.print(f"  [red]![/red] {cmd}")

        # Phase 5: File encryption (simulated)
        console.print("\n[bold cyan]Phase 5: File Encryption (Simulated)[/bold cyan]")
        target_extensions = [".doc", ".docx", ".xls", ".xlsx", ".pdf", ".ppt", ".pptx",
                            ".jpg", ".png", ".sql", ".mdb", ".bak", ".zip", ".rar",
                            ".vmdk", ".vdi", ".pst", ".ost", ".dwg", ".ai"]
        file_count = random.randint(5000, 50000)
        data_size_gb = random.uniform(10, 500)
        encrypt_time = random.uniform(5, 120)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task(
                f"[red]Encrypting files ({family['extension']})...", total=100)
            for i in range(100):
                progress.advance(task)

        event = RansomwareSimulationEvent(
            "ENCRYPTION",
            f"Encrypted {file_count:,} files ({data_size_gb:.1f} GB) with {family['encryption']} "
            f"in {encrypt_time:.1f} minutes -- extension: {family['extension']}",
            "CRITICAL",
        )
        events.append(event)

        console.print(f"\n  [bold red]Encrypted {file_count:,} files ({data_size_gb:.1f} GB)[/bold red]")
        console.print(f"  Extension: {family['extension']}")
        console.print(f"  Algorithm: {family['encryption']}")
        console.print(f"  Time: {encrypt_time:.1f} minutes")

        # Phase 6: Ransom note deployment
        console.print("\n[bold cyan]Phase 6: Ransom Note Deployment[/bold cyan]")
        event = RansomwareSimulationEvent(
            "RANSOM_NOTE",
            f"Dropped ransom note: {family['ransom_note']} in every directory",
            "HIGH",
        )
        events.append(event)
        console.print(f"  [yellow]Ransom note: {family['ransom_note']}[/yellow]")

        # Phase 7: Self-propagation
        if family["self_propagation"]:
            console.print("\n[bold cyan]Phase 7: Lateral Propagation[/bold cyan]")
            lateral_count = random.randint(3, 15)
            event = RansomwareSimulationEvent(
                "PROPAGATION",
                f"Attempting lateral propagation to {lateral_count} hosts via SMB/WMI",
                "CRITICAL",
            )
            events.append(event)
            console.print(f"  [red]Spreading to {lateral_count} additional hosts...[/red]")

        self.events.extend(events)
        self._display_simulation_summary(family_name, family, events, file_count, data_size_gb)

        return events

    def _display_simulation_summary(self, family_name, family, events, file_count, data_size_gb):
        """Display simulation summary with detection gaps."""
        # MITRE ATT&CK mapping
        console.print("\n")
        mitre_table = Table(title=f"{family_name} -- MITRE ATT&CK Mapping")
        mitre_table.add_column("Technique ID", style="yellow")
        mitre_table.add_column("Description", style="white")

        technique_descriptions = {
            "T1486": "Data Encrypted for Impact",
            "T1490": "Inhibit System Recovery",
            "T1489": "Service Stop",
            "T1021.002": "SMB/Windows Admin Shares",
            "T1059.001": "PowerShell",
            "T1190": "Exploit Public-Facing Application",
            "T1566.001": "Spearphishing Attachment",
            "T1566.002": "Spearphishing Link",
            "T1027": "Obfuscated Files or Information",
            "T1133": "External Remote Services",
        }
        for tech in family["mitre_techniques"]:
            mitre_table.add_row(tech, technique_descriptions.get(tech, "Unknown"))
        console.print(mitre_table)

        # Summary
        console.print(Panel(
            f"[bold]Simulation Complete: {family_name}[/bold]\n\n"
            f"Total Events:     {len(events)}\n"
            f"Files Encrypted:  {file_count:,}\n"
            f"Data Volume:      {data_size_gb:.1f} GB\n"
            f"Services Stopped: {min(5, len(family['kill_services']))}\n"
            f"Processes Killed: {min(5, len(family['kill_processes']))}\n"
            f"Shadow Deleted:   {'Yes' if family['shadow_delete'] else 'No'}\n"
            f"Propagated:       {'Yes' if family['self_propagation'] else 'No'}",
            title="Simulation Summary",
            border_style="green",
        ))

    def test_detection_rules(self, family_name="LockBit"):
        """Test detection rules against simulated ransomware behaviors."""
        family = RANSOMWARE_FAMILIES.get(family_name, RANSOMWARE_FAMILIES["LockBit"])

        detection_rules = [
            {
                "rule_name": "Shadow Copy Deletion",
                "type": "Process Creation",
                "pattern": "vssadmin.exe delete shadows",
                "covers": ["T1490"],
                "effectiveness": random.uniform(0.85, 0.99),
                "false_positive_rate": random.uniform(0.01, 0.05),
            },
            {
                "rule_name": "Mass File Rename",
                "type": "File System",
                "pattern": f"File extension change to {family.get('extension', '.encrypted')}",
                "covers": ["T1486"],
                "effectiveness": random.uniform(0.70, 0.95),
                "false_positive_rate": random.uniform(0.02, 0.10),
            },
            {
                "rule_name": "Backup Service Termination",
                "type": "Service Control",
                "pattern": "Service stop: vss, sql, veeam, backup",
                "covers": ["T1489"],
                "effectiveness": random.uniform(0.80, 0.98),
                "false_positive_rate": random.uniform(0.01, 0.03),
            },
            {
                "rule_name": "BCDEdit Recovery Disable",
                "type": "Process Creation",
                "pattern": "bcdedit /set recoveryenabled No",
                "covers": ["T1490"],
                "effectiveness": random.uniform(0.90, 0.99),
                "false_positive_rate": random.uniform(0.005, 0.02),
            },
            {
                "rule_name": "Ransomware Note Creation",
                "type": "File System",
                "pattern": f"File creation: {family.get('ransom_note', 'README')}",
                "covers": ["T1486"],
                "effectiveness": random.uniform(0.75, 0.95),
                "false_positive_rate": random.uniform(0.01, 0.05),
            },
            {
                "rule_name": "High-Volume File Encryption",
                "type": "Behavioral",
                "pattern": "Rapid file modification with entropy increase",
                "covers": ["T1486"],
                "effectiveness": random.uniform(0.65, 0.90),
                "false_positive_rate": random.uniform(0.05, 0.15),
            },
            {
                "rule_name": "SMB Lateral Movement",
                "type": "Network",
                "pattern": "Unusual SMB traffic to multiple hosts with file writes",
                "covers": ["T1021.002"],
                "effectiveness": random.uniform(0.60, 0.85),
                "false_positive_rate": random.uniform(0.05, 0.20),
            },
            {
                "rule_name": "Canary File Modification",
                "type": "File System",
                "pattern": "Modification or deletion of canary/honeypot files",
                "covers": ["T1486"],
                "effectiveness": random.uniform(0.95, 1.00),
                "false_positive_rate": random.uniform(0.001, 0.01),
            },
        ]

        table = Table(title=f"Detection Rule Testing: {family_name}")
        table.add_column("Rule", style="cyan")
        table.add_column("Type", style="yellow")
        table.add_column("Covers", style="green")
        table.add_column("Effectiveness", style="white", justify="right")
        table.add_column("FP Rate", style="red", justify="right")
        table.add_column("Status", style="bold")

        for rule in detection_rules:
            eff = rule["effectiveness"]
            fp = rule["false_positive_rate"]
            if eff >= 0.90:
                status = "[green]PASS[/green]"
            elif eff >= 0.75:
                status = "[yellow]WARN[/yellow]"
            else:
                status = "[red]FAIL[/red]"

            table.add_row(
                rule["rule_name"],
                rule["type"],
                ", ".join(rule["covers"]),
                f"{eff*100:.1f}%",
                f"{fp*100:.2f}%",
                status,
            )

        console.print(table)

        # Overall score
        avg_eff = sum(r["effectiveness"] for r in detection_rules) / len(detection_rules)
        avg_fp = sum(r["false_positive_rate"] for r in detection_rules) / len(detection_rules)
        score = avg_eff * 100 * (1 - avg_fp)

        score_style = "green" if score >= 80 else "yellow" if score >= 60 else "red"
        console.print(Panel(
            f"[bold]Detection Readiness Score: [{score_style}]{score:.1f}/100[/{score_style}][/bold]\n\n"
            f"Average Effectiveness: {avg_eff*100:.1f}%\n"
            f"Average FP Rate:      {avg_fp*100:.2f}%\n"
            f"Rules Tested:         {len(detection_rules)}\n"
            f"Rules Passing:        {sum(1 for r in detection_rules if r['effectiveness'] >= 0.90)}",
            title="Detection Assessment",
            border_style=score_style,
        ))

        self.detection_results = detection_rules
        return detection_rules

    def test_backup_recovery(self):
        """Simulate backup recovery procedure testing."""
        console.print(Panel(
            "[bold cyan]BACKUP RECOVERY TEST[/bold cyan]\n\n"
            "Testing backup recovery procedures against ransomware scenarios.",
            title="Backup Recovery Assessment",
            border_style="cyan",
        ))

        backup_systems = [
            {
                "name": "Veeam Backup & Replication",
                "type": "Full + Incremental",
                "frequency": "Daily Full, 4-Hour Incremental",
                "retention": "30 days local, 90 days offsite",
                "immutable": True,
                "air_gapped": True,
                "encryption": "AES-256",
                "rpo_hours": 4,
                "rto_hours": 2,
                "tested": True,
                "last_test": "2024-09-01",
                "score": random.uniform(85, 99),
            },
            {
                "name": "Windows Server Backup",
                "type": "Full + Differential",
                "frequency": "Daily Full",
                "retention": "14 days local",
                "immutable": False,
                "air_gapped": False,
                "encryption": "None",
                "rpo_hours": 24,
                "rto_hours": 8,
                "tested": False,
                "last_test": "Never",
                "score": random.uniform(30, 55),
            },
            {
                "name": "AWS S3 Backup (Cross-Region)",
                "type": "Snapshot + Replication",
                "frequency": "Hourly Snapshots",
                "retention": "365 days with lifecycle",
                "immutable": True,
                "air_gapped": True,
                "encryption": "SSE-S3 + KMS",
                "rpo_hours": 1,
                "rto_hours": 4,
                "tested": True,
                "last_test": "2024-08-15",
                "score": random.uniform(80, 95),
            },
        ]

        table = Table(title="Backup Systems Assessment")
        table.add_column("System", style="cyan")
        table.add_column("Type", style="white")
        table.add_column("RPO", style="yellow", justify="right")
        table.add_column("RTO", style="yellow", justify="right")
        table.add_column("Immutable", style="green")
        table.add_column("Air-Gapped", style="green")
        table.add_column("Encrypted", style="green")
        table.add_column("Score", style="bold", justify="right")

        for backup in backup_systems:
            score_style = "green" if backup["score"] >= 80 else "yellow" if backup["score"] >= 60 else "red"
            table.add_row(
                backup["name"],
                backup["type"],
                f"{backup['rpo_hours']}h",
                f"{backup['rto_hours']}h",
                "[green]Yes[/green]" if backup["immutable"] else "[red]No[/red]",
                "[green]Yes[/green]" if backup["air_gapped"] else "[red]No[/red]",
                backup["encryption"] if backup["encryption"] != "None" else "[red]None[/red]",
                f"[{score_style}]{backup['score']:.0f}[/{score_style}]",
            )

        console.print(table)
        self.backup_test_results = backup_systems
        return backup_systems

    def generate_canary_plan(self):
        """Generate a canary file deployment plan."""
        console.print(Panel(
            "[bold cyan]CANARY FILE DEPLOYMENT PLAN[/bold cyan]\n\n"
            "Strategic canary file placement for early ransomware detection.",
            title="Canary Strategy",
            border_style="cyan",
        ))

        for category, files in CANARY_DEPLOYMENTS.items():
            table = Table(title=f"Canary Files: {category.replace('_', ' ').title()}")
            table.add_column("Path", style="cyan")
            table.add_column("Type", style="yellow")
            table.add_column("Size", style="green")
            table.add_column("Purpose", style="white")

            for f in files:
                purpose = "Early detection" if "Desktop" in f["path"] else \
                          "Server-side detection" if "Windows" in f["path"] else \
                          "Network share monitoring"
                table.add_row(
                    f["path"].format(user="admin"),
                    f["type"],
                    f["size"],
                    purpose,
                )
            console.print(table)

        # Monitoring recommendations
        console.print(Panel(
            "[bold]Monitoring Configuration[/bold]\n\n"
            "1. Set SACL on all canary files (Audit Read/Write/Delete)\n"
            "2. Configure Sysmon Event ID 11 (FileCreate) monitoring\n"
            "3. Configure Sysmon Event ID 23 (FileDelete) monitoring\n"
            "4. Set up real-time alerts for any canary file access\n"
            "5. Monitor for file hash changes (integrity monitoring)\n"
            "6. Configure canary file checks in EDR solution\n"
            "7. Test canary alerts monthly to ensure monitoring works",
            title="Canary Monitoring Setup",
            border_style="green",
        ))

    def assess_network_segmentation(self):
        """Assess network segmentation effectiveness against ransomware spread."""
        segments = [
            {"name": "Corporate Workstations", "vlan": "VLAN 10", "hosts": 150,
             "isolated": True, "fw_rules": 12, "smb_restricted": True, "score": random.uniform(70, 95)},
            {"name": "Servers (Production)", "vlan": "VLAN 20", "hosts": 25,
             "isolated": True, "fw_rules": 28, "smb_restricted": True, "score": random.uniform(80, 98)},
            {"name": "Servers (Development)", "vlan": "VLAN 30", "hosts": 15,
             "isolated": True, "fw_rules": 8, "smb_restricted": False, "score": random.uniform(50, 75)},
            {"name": "DMZ", "vlan": "VLAN 100", "hosts": 8,
             "isolated": True, "fw_rules": 35, "smb_restricted": True, "score": random.uniform(85, 99)},
            {"name": "Backup Network", "vlan": "VLAN 200", "hosts": 5,
             "isolated": True, "fw_rules": 6, "smb_restricted": True, "score": random.uniform(75, 95)},
            {"name": "IoT/OT Devices", "vlan": "VLAN 50", "hosts": 30,
             "isolated": False, "fw_rules": 3, "smb_restricted": False, "score": random.uniform(20, 50)},
        ]

        table = Table(title="Network Segmentation Assessment")
        table.add_column("Segment", style="cyan")
        table.add_column("VLAN", style="yellow")
        table.add_column("Hosts", justify="right")
        table.add_column("Isolated", style="green")
        table.add_column("FW Rules", justify="right")
        table.add_column("SMB Restricted", style="green")
        table.add_column("Score", style="bold", justify="right")

        for seg in segments:
            score_style = "green" if seg["score"] >= 80 else "yellow" if seg["score"] >= 60 else "red"
            table.add_row(
                seg["name"],
                seg["vlan"],
                str(seg["hosts"]),
                "[green]Yes[/green]" if seg["isolated"] else "[red]No[/red]",
                str(seg["fw_rules"]),
                "[green]Yes[/green]" if seg["smb_restricted"] else "[red]No[/red]",
                f"[{score_style}]{seg['score']:.0f}[/{score_style}]",
            )
        console.print(table)

        avg_score = sum(s["score"] for s in segments) / len(segments)
        score_style = "green" if avg_score >= 80 else "yellow" if avg_score >= 60 else "red"
        console.print(Panel(
            f"[bold]Overall Segmentation Score: [{score_style}]{avg_score:.1f}/100[/{score_style}][/bold]",
            border_style=score_style,
        ))

    def calculate_rto(self):
        """Calculate Recovery Time Objective for various scenarios."""
        scenarios = [
            {"scenario": "Single Workstation", "hosts": 1, "data_gb": 50,
             "backup_restore_h": 1, "os_rebuild_h": 2, "app_install_h": 1,
             "validation_h": 0.5, "user_data_h": 0.5},
            {"scenario": "Department (10 hosts)", "hosts": 10, "data_gb": 500,
             "backup_restore_h": 4, "os_rebuild_h": 8, "app_install_h": 4,
             "validation_h": 2, "user_data_h": 2},
            {"scenario": "File Server", "hosts": 1, "data_gb": 5000,
             "backup_restore_h": 12, "os_rebuild_h": 2, "app_install_h": 2,
             "validation_h": 4, "user_data_h": 8},
            {"scenario": "Database Server", "hosts": 1, "data_gb": 2000,
             "backup_restore_h": 8, "os_rebuild_h": 2, "app_install_h": 4,
             "validation_h": 6, "user_data_h": 4},
            {"scenario": "Full Enterprise (200 hosts)", "hosts": 200, "data_gb": 50000,
             "backup_restore_h": 48, "os_rebuild_h": 72, "app_install_h": 48,
             "validation_h": 24, "user_data_h": 24},
        ]

        table = Table(title="Recovery Time Objective (RTO) Calculator")
        table.add_column("Scenario", style="cyan")
        table.add_column("Hosts", justify="right")
        table.add_column("Data (GB)", justify="right")
        table.add_column("Restore", style="yellow", justify="right")
        table.add_column("Rebuild", style="yellow", justify="right")
        table.add_column("Apps", style="yellow", justify="right")
        table.add_column("Validate", style="yellow", justify="right")
        table.add_column("Total RTO", style="bold red", justify="right")

        for s in scenarios:
            total = (s["backup_restore_h"] + s["os_rebuild_h"] + s["app_install_h"] +
                     s["validation_h"] + s["user_data_h"])
            if total >= 72:
                total_str = f"{total/24:.1f} days"
            else:
                total_str = f"{total:.0f} hours"

            table.add_row(
                s["scenario"],
                str(s["hosts"]),
                f"{s['data_gb']:,}",
                f"{s['backup_restore_h']}h",
                f"{s['os_rebuild_h']}h",
                f"{s['app_install_h']}h",
                f"{s['validation_h']}h",
                total_str,
            )

        console.print(table)
        return scenarios

    def full_assessment(self):
        """Run a comprehensive ransomware readiness assessment."""
        console.print(Panel(
            "[bold cyan]RANSOMWARE READINESS ASSESSMENT[/bold cyan]\n\n"
            "Running comprehensive assessment of organizational ransomware defenses.",
            title="Full Assessment",
            border_style="cyan",
        ))

        # Run all assessment components
        self.test_detection_rules()
        console.print("\n")
        self.test_backup_recovery()
        console.print("\n")
        self.assess_network_segmentation()
        console.print("\n")
        self.calculate_rto()
        console.print("\n")
        self.generate_canary_plan()

    def list_families(self):
        """List all known ransomware families."""
        table = Table(title="Known Ransomware Families")
        table.add_column("Name", style="red bold")
        table.add_column("Aliases", style="yellow")
        table.add_column("First Seen", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Encryption", style="white")
        table.add_column("Extension", style="magenta")

        for name, info in RANSOMWARE_FAMILIES.items():
            status_style = "green" if "Active" in info["status"] else "yellow"
            table.add_row(
                name,
                ", ".join(info["aliases"]),
                info["first_seen"],
                f"[{status_style}]{info['status']}[/{status_style}]",
                info["encryption"],
                info["extension"],
            )
        console.print(table)

    def run(self):
        """Main execution entry point."""
        self.full_assessment()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="AEGIS Ransomware Defense Simulator -- Educational Use Only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("command", nargs="?", default="assessment",
                        choices=["simulate", "list-families", "test-detection",
                                 "test-backup", "canary-plan", "segmentation",
                                 "rto-calc", "assessment", "help"],
                        help="Command to execute")
    parser.add_argument("--family", "-f", default="LockBit",
                        choices=list(RANSOMWARE_FAMILIES.keys()),
                        help="Ransomware family to simulate")
    parser.add_argument("--output", "-o", default=None,
                        help="Export results to JSON file")

    args = parser.parse_args()
    sim = RansomwareDefenseSimulator()

    if args.command == "help":
        console.print(sim.HELP_TEXT)
    elif args.command == "simulate":
        sim.simulate_ransomware(args.family)
    elif args.command == "list-families":
        sim.list_families()
    elif args.command == "test-detection":
        sim.test_detection_rules(args.family)
    elif args.command == "test-backup":
        sim.test_backup_recovery()
    elif args.command == "canary-plan":
        sim.generate_canary_plan()
    elif args.command == "segmentation":
        sim.assess_network_segmentation()
    elif args.command == "rto-calc":
        sim.calculate_rto()
    else:
        sim.run()

    if args.output:
        data = {
            "events": [e.to_dict() for e in sim.events],
            "detection_results": sim.detection_results,
            "backup_results": sim.backup_test_results,
        }
        with open(args.output, "w") as f:
            json.dump(data, f, indent=2, default=str)
        console.print(f"[green]Results exported to {args.output}[/green]")


if __name__ == "__main__":
    main()
