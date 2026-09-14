#!/usr/bin/env python3
"""
AEGIS Digital Forensics Suite
===============================
Comprehensive digital forensics toolkit with disk image analysis,
timeline generation, registry analysis, browser artifact extraction,
email analysis, metadata extraction, and evidence management.

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
    from rich.syntax import Syntax
except ImportError:
    print("[!] rich library required: pip install rich")
    sys.exit(1)

console = Console()

# ─── Forensic Artifact Locations ───────────────────────────────────────
WINDOWS_ARTIFACTS = {
    "Registry Hives": {
        "SAM": {"path": r"C:\Windows\System32\config\SAM",
                "description": "Security Account Manager - local user accounts and passwords",
                "key_areas": ["User accounts", "Password hashes", "Account policies", "Last login times"]},
        "SYSTEM": {"path": r"C:\Windows\System32\config\SYSTEM",
                   "description": "System configuration - hardware, services, mount points",
                   "key_areas": ["Computer name", "Timezone", "Network interfaces", "Services", "MountedDevices"]},
        "SOFTWARE": {"path": r"C:\Windows\System32\config\SOFTWARE",
                     "description": "Software configuration - installed programs, system settings",
                     "key_areas": ["Installed programs", "Run keys", "Windows version", "Network profiles"]},
        "SECURITY": {"path": r"C:\Windows\System32\config\SECURITY",
                     "description": "Security policies and audit configuration",
                     "key_areas": ["Audit policies", "Security policies", "LSA secrets"]},
        "NTUSER.DAT": {"path": r"C:\Users\{username}\NTUSER.DAT",
                       "description": "Per-user registry hive - user preferences and activities",
                       "key_areas": ["RecentDocs", "UserAssist", "TypedPaths", "RunMRU", "MountPoints2"]},
        "UsrClass.dat": {"path": r"C:\Users\{username}\AppData\Local\Microsoft\Windows\UsrClass.dat",
                         "description": "User class registry hive - shell bag data",
                         "key_areas": ["ShellBags", "BagMRU", "File access patterns"]},
    },
    "Event Logs": {
        "Security": {"path": r"C:\Windows\System32\winevt\Logs\Security.evtx",
                     "description": "Authentication, authorization, and audit events",
                     "key_events": ["4624 Logon", "4625 Failed Logon", "4648 Explicit Logon",
                                    "4672 Special Privileges", "4720 Account Created",
                                    "4732 Member Added to Group"]},
        "System": {"path": r"C:\Windows\System32\winevt\Logs\System.evtx",
                   "description": "System component events - services, drivers, hardware",
                   "key_events": ["7045 Service Installed", "7036 Service Start/Stop",
                                  "1074 Shutdown/Restart", "6005/6006 EventLog Start/Stop"]},
        "Application": {"path": r"C:\Windows\System32\winevt\Logs\Application.evtx",
                        "description": "Application-specific events",
                        "key_events": ["1000 Application Error", "1001 Application Hang",
                                       "11707/11724 Install/Uninstall"]},
        "PowerShell": {"path": r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx",
                       "description": "PowerShell execution and script block logging",
                       "key_events": ["4103 Module Logging", "4104 Script Block Logging",
                                      "4688 Process Creation"]},
        "Sysmon": {"path": r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx",
                   "description": "Sysmon advanced monitoring events",
                   "key_events": ["1 Process Create", "3 Network Connect", "7 Image Load",
                                  "8 CreateRemoteThread", "10 Process Access",
                                  "11 File Create", "13 Registry Value Set"]},
    },
    "File System Artifacts": {
        "$MFT": {"path": r"C:\$MFT", "description": "Master File Table - metadata for all NTFS files",
                 "analysis": "Parse with MFTECmd or analyzeMFT for complete file listing"},
        "$UsnJrnl": {"path": r"C:\$Extend\$UsnJrnl:$J",
                     "description": "USN Journal - file system change journal",
                     "analysis": "Parse with MFTECmd /usn for file creation/deletion/rename events"},
        "$LogFile": {"path": r"C:\$LogFile",
                     "description": "NTFS transaction log for recovery",
                     "analysis": "Contains recent file system transactions"},
        "Prefetch": {"path": r"C:\Windows\Prefetch\*.pf",
                     "description": "Application execution artifacts (run count, timestamps)",
                     "analysis": "Parse with PECmd for execution timeline"},
        "Amcache": {"path": r"C:\Windows\AppCompat\Programs\Amcache.hve",
                    "description": "Application compatibility cache - execution evidence",
                    "analysis": "Parse with AmcacheParser for program execution history"},
        "SRUM": {"path": r"C:\Windows\System32\SRU\SRUDB.dat",
                 "description": "System Resource Usage Monitor - network/app usage data",
                 "analysis": "Parse with SrumECmd for network usage and app execution"},
    },
    "Browser Artifacts": {
        "Chrome History": {"path": r"C:\Users\{user}\AppData\Local\Google\Chrome\User Data\Default\History",
                           "type": "SQLite", "tables": ["urls", "visits", "downloads"]},
        "Chrome Cookies": {"path": r"C:\Users\{user}\AppData\Local\Google\Chrome\User Data\Default\Cookies",
                           "type": "SQLite", "tables": ["cookies"]},
        "Chrome Login Data": {"path": r"C:\Users\{user}\AppData\Local\Google\Chrome\User Data\Default\Login Data",
                               "type": "SQLite", "tables": ["logins"]},
        "Firefox Places": {"path": r"C:\Users\{user}\AppData\Roaming\Mozilla\Firefox\Profiles\*.default\places.sqlite",
                           "type": "SQLite", "tables": ["moz_places", "moz_historyvisits"]},
        "Edge History": {"path": r"C:\Users\{user}\AppData\Local\Microsoft\Edge\User Data\Default\History",
                         "type": "SQLite", "tables": ["urls", "visits", "downloads"]},
    },
    "User Activity": {
        "Recent Files": {"path": r"C:\Users\{user}\AppData\Roaming\Microsoft\Windows\Recent\*.lnk",
                         "description": "Recently accessed files via LNK shortcuts"},
        "Jump Lists": {"path": r"C:\Users\{user}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms",
                       "description": "Task bar jump list data - recent/pinned files per application"},
        "Shellbags": {"path": "Registry (UsrClass.dat)",
                      "description": "Folder access and window positioning history"},
        "UserAssist": {"path": "Registry (NTUSER.DAT)",
                       "description": "ROT13-encoded program execution counts and timestamps"},
        "Thumbcache": {"path": r"C:\Users\{user}\AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db",
                       "description": "Thumbnail cache - evidence of viewed images/files"},
    },
}

LINUX_ARTIFACTS = {
    "System Logs": {
        "/var/log/auth.log": "Authentication events (SSH, sudo, su)",
        "/var/log/syslog": "General system messages",
        "/var/log/kern.log": "Kernel messages",
        "/var/log/wtmp": "Login records (parse with 'last')",
        "/var/log/btmp": "Failed login attempts (parse with 'lastb')",
        "/var/log/lastlog": "Last login for each user",
        "/var/log/secure": "Security/auth messages (RHEL/CentOS)",
        "/var/log/audit/audit.log": "SELinux/auditd events",
        "/var/log/cron": "Cron job execution logs",
    },
    "User Artifacts": {
        "~/.bash_history": "Bash command history",
        "~/.zsh_history": "Zsh command history",
        "~/.ssh/known_hosts": "SSH host key fingerprints",
        "~/.ssh/authorized_keys": "Authorized SSH public keys",
        "~/.gnupg/": "GPG keys and encrypted data",
        "~/.local/share/Trash/": "Deleted files in trash",
        "~/.config/": "Application configuration files",
    },
    "System Configuration": {
        "/etc/passwd": "User accounts",
        "/etc/shadow": "Password hashes (requires root)",
        "/etc/group": "Group memberships",
        "/etc/sudoers": "Sudo configuration",
        "/etc/crontab": "System-wide cron jobs",
        "/var/spool/cron/crontabs/": "Per-user cron jobs",
        "/etc/hosts": "Static hostname resolution",
        "/etc/resolv.conf": "DNS resolver configuration",
    },
    "Persistence Locations": {
        "/etc/rc.local": "Startup script (legacy)",
        "/etc/init.d/": "SysV init scripts",
        "/etc/systemd/system/": "Systemd service units",
        "/etc/cron.d/": "Cron job directories",
        "/etc/profile.d/": "Shell startup scripts",
        "~/.bashrc": "User bash startup",
        "~/.profile": "User login startup",
    },
}


class ForensicEvidence:
    """Represents a piece of digital evidence."""

    def __init__(self, evidence_type, source, description, data=None):
        self.evidence_id = str(uuid.uuid4())[:12]
        self.timestamp = datetime.datetime.now()
        self.evidence_type = evidence_type
        self.source = source
        self.description = description
        self.data = data or {}
        self.hash_sha256 = hashlib.sha256(
            json.dumps(self.data, default=str, sort_keys=True).encode()
        ).hexdigest()
        self.chain_of_custody = [
            {"action": "Acquired", "by": "AEGIS Forensics",
             "timestamp": self.timestamp.isoformat(), "notes": "Initial acquisition"}
        ]

    def add_custody_entry(self, action, by, notes=""):
        self.chain_of_custody.append({
            "action": action, "by": by,
            "timestamp": datetime.datetime.now().isoformat(), "notes": notes,
        })

    def to_dict(self):
        return {
            "evidence_id": self.evidence_id,
            "timestamp": self.timestamp.isoformat(),
            "type": self.evidence_type,
            "source": self.source,
            "description": self.description,
            "hash_sha256": self.hash_sha256,
            "chain_of_custody": self.chain_of_custody,
        }


class TimelineEvent:
    """Represents an event in a forensic timeline."""

    def __init__(self, timestamp, source, event_type, description,
                 artifact=None, user=None):
        self.timestamp = timestamp
        self.source = source
        self.event_type = event_type
        self.description = description
        self.artifact = artifact
        self.user = user

    def to_dict(self):
        return {
            "timestamp": self.timestamp.isoformat() if isinstance(self.timestamp, datetime.datetime) else self.timestamp,
            "source": self.source,
            "event_type": self.event_type,
            "description": self.description,
            "artifact": self.artifact,
            "user": self.user,
        }


class DigitalForensicsSuite:
    """
    Digital Forensics Suite

    Comprehensive forensic analysis toolkit for disk images,
    file systems, registry, browser artifacts, and evidence management.

    Usage:
        suite = DigitalForensicsSuite()
        suite.run()
    """

    HELP_TEXT = """
AEGIS Digital Forensics Suite
===============================
Comprehensive digital forensics analysis toolkit.

Commands:
  disk-analysis         Simulate disk image analysis workflow
  timeline              Generate forensic timeline (MACB)
  registry              Analyze Windows registry hives
  browser               Extract browser artifacts
  email-analysis        Analyze email headers
  metadata              Extract document/image metadata
  evidence              Manage evidence chain of custody
  artifacts             List forensic artifact locations
  report                Generate forensic report
  help                  Show this help message

Options:
  --image <path>        Disk image path (simulated)
  --os <type>           windows | linux (default: windows)
  --user <name>         Username for user-specific artifacts
  --output <file>       Export results to JSON
"""

    def __init__(self):
        """Initialize the Digital Forensics Suite."""
        self.evidence_items = []
        self.timeline_events = []
        self.findings = []
        self._verify_authorization()

    def _verify_authorization(self):
        """Verify operator authorization."""
        console.print(Panel(
            "[bold yellow]AUTHORIZATION CHECK[/bold yellow]\n\n"
            "This module simulates digital forensics analysis for [bold]educational purposes[/bold].\n"
            "All disk images, artifacts, and evidence are simulated data.\n"
            "For real forensics, use certified tools and follow proper chain of custody.",
            title="AEGIS Digital Forensics",
            border_style="yellow"
        ))

    def disk_image_analysis(self, image_path="evidence.E01"):
        """Simulate disk image analysis workflow."""
        console.print(Panel(
            f"[bold cyan]DISK IMAGE ANALYSIS[/bold cyan]\n\n"
            f"Image:     {image_path}\n"
            f"Format:    Expert Witness Format (E01)\n"
            f"Acquired:  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Examiner:  AEGIS Digital Forensics",
            title="Disk Analysis",
            border_style="cyan",
        ))

        # Simulated image metadata
        image_info = {
            "format": "E01 (Expert Witness Format)",
            "size_bytes": random.randint(50_000_000_000, 500_000_000_000),
            "sectors": random.randint(100_000_000, 1_000_000_000),
            "sector_size": 512,
            "md5": hashlib.md5(f"image_{image_path}".encode()).hexdigest(),
            "sha256": hashlib.sha256(f"image_{image_path}".encode()).hexdigest(),
            "filesystem": random.choice(["NTFS", "NTFS", "ext4", "APFS"]),
            "os_version": "Windows 10 Enterprise 21H2",
            "computer_name": f"WKS-{random.randint(100, 999)}",
            "timezone": "UTC-5 (Eastern)",
            "last_shutdown": (datetime.datetime.now() - datetime.timedelta(hours=random.randint(1, 48))).isoformat(),
        }

        # Hash verification
        console.print("\n[bold]Step 1: Hash Verification[/bold]")
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Calculating image hash...", total=100)
            for i in range(100):
                progress.advance(task)

        console.print(f"  MD5:    [green]{image_info['md5']}[/green]")
        console.print(f"  SHA256: [green]{image_info['sha256']}[/green]")
        console.print(f"  [bold green]Hash verification: PASSED[/bold green]")

        # Image information
        console.print("\n[bold]Step 2: Image Information[/bold]")
        info_table = Table(title="Disk Image Details")
        info_table.add_column("Property", style="cyan")
        info_table.add_column("Value", style="white")

        size_gb = image_info["size_bytes"] / (1024**3)
        for key, val in [
            ("Format", image_info["format"]),
            ("Size", f"{size_gb:.1f} GB ({image_info['size_bytes']:,} bytes)"),
            ("Sectors", f"{image_info['sectors']:,}"),
            ("Sector Size", f"{image_info['sector_size']} bytes"),
            ("File System", image_info["filesystem"]),
            ("OS Version", image_info["os_version"]),
            ("Computer Name", image_info["computer_name"]),
            ("Timezone", image_info["timezone"]),
            ("Last Shutdown", image_info["last_shutdown"]),
        ]:
            info_table.add_row(key, str(val))
        console.print(info_table)

        # Partition layout
        console.print("\n[bold]Step 3: Partition Layout[/bold]")
        partitions = [
            {"id": 0, "type": "EFI System", "start": 0, "size_mb": 100, "fs": "FAT32"},
            {"id": 1, "type": "Microsoft Reserved", "start": 100, "size_mb": 16, "fs": "None"},
            {"id": 2, "type": "Basic Data", "start": 116, "size_mb": int(size_gb * 1024 - 616), "fs": "NTFS"},
            {"id": 3, "type": "Recovery", "start": int(size_gb * 1024 - 500), "size_mb": 500, "fs": "NTFS"},
        ]
        part_table = Table(title="Partition Table (GPT)")
        part_table.add_column("#", style="dim")
        part_table.add_column("Type", style="cyan")
        part_table.add_column("Start (MB)", justify="right")
        part_table.add_column("Size (MB)", justify="right")
        part_table.add_column("Filesystem", style="yellow")

        for p in partitions:
            part_table.add_row(
                str(p["id"]), p["type"],
                f"{p['start_mb'] if 'start_mb' in p else p['start']:,}",
                f"{p['size_mb']:,}", p["fs"],
            )
        console.print(part_table)

        # Create evidence item
        evidence = ForensicEvidence("disk_image", image_path,
                                    f"Disk image analysis of {image_path}", image_info)
        self.evidence_items.append(evidence)

        return image_info

    def generate_timeline(self, days_back=7):
        """Generate forensic timeline with MACB timestamps."""
        console.print(Panel(
            f"[bold cyan]FORENSIC TIMELINE GENERATION[/bold cyan]\n\n"
            f"Generating MACB timeline for last {days_back} days...\n"
            f"M=Modified  A=Accessed  C=Changed  B=Born(Created)",
            title="Timeline Generation",
            border_style="cyan",
        ))

        base_time = datetime.datetime.now() - datetime.timedelta(days=days_back)
        events = []

        # Generate simulated timeline events
        event_templates = [
            {"source": "Prefetch", "type": "Execution",
             "desc": "notepad.exe executed (Run Count: {count})", "user": "admin"},
            {"source": "Registry", "type": "Persistence",
             "desc": "Run key added: HKCU\\...\\Run\\UpdateHelper", "user": "SYSTEM"},
            {"source": "Event Log", "type": "Authentication",
             "desc": "Logon Type 3 (Network) from 10.0.0.50", "user": "admin"},
            {"source": "Event Log", "type": "Failed Auth",
             "desc": "Failed logon attempt (Event 4625) for user admin", "user": "admin"},
            {"source": "$MFT", "type": "File Created",
             "desc": "C:\\Users\\admin\\Desktop\\suspicious.exe created", "user": None},
            {"source": "$MFT", "type": "File Modified",
             "desc": "C:\\Windows\\Temp\\payload.dll modified", "user": None},
            {"source": "$UsnJrnl", "type": "File Renamed",
             "desc": "C:\\Temp\\data.txt renamed to C:\\Temp\\data.encrypted", "user": None},
            {"source": "Browser", "type": "Web Activity",
             "desc": "Visited https://suspicious-download.example.com/tool.zip", "user": "admin"},
            {"source": "Browser", "type": "Download",
             "desc": "Downloaded tool.zip from external URL", "user": "admin"},
            {"source": "Sysmon", "type": "Process Create",
             "desc": "powershell.exe -enc [Base64] spawned by cmd.exe", "user": "admin"},
            {"source": "Sysmon", "type": "Network Connect",
             "desc": "svchost.exe connected to 198.51.100.42:443", "user": "SYSTEM"},
            {"source": "Sysmon", "type": "DNS Query",
             "desc": "DNS query for c2-server.example.com", "user": None},
            {"source": "Event Log", "type": "Service Install",
             "desc": "Service 'WindowsUpdateHelper' installed (Event 7045)", "user": "SYSTEM"},
            {"source": "Event Log", "type": "Logoff",
             "desc": "User admin logged off (Event 4634)", "user": "admin"},
            {"source": "$MFT", "type": "File Deleted",
             "desc": "C:\\Users\\admin\\Downloads\\exploit.exe deleted", "user": None},
            {"source": "Registry", "type": "USB Device",
             "desc": "USB device connected: SanDisk Ultra (S/N: 4C530123456789)", "user": None},
            {"source": "Amcache", "type": "Execution",
             "desc": "First execution of mimikatz.exe recorded", "user": None},
            {"source": "SRUM", "type": "Network Usage",
             "desc": "chrome.exe: 2.4GB network data transferred", "user": "admin"},
        ]

        for i in range(40):
            template = random.choice(event_templates)
            timestamp = base_time + datetime.timedelta(
                hours=random.randint(0, days_back * 24),
                minutes=random.randint(0, 59),
                seconds=random.randint(0, 59),
            )
            desc = template["desc"].format(count=random.randint(1, 50))
            event = TimelineEvent(
                timestamp=timestamp,
                source=template["source"],
                event_type=template["type"],
                description=desc,
                user=template.get("user"),
            )
            events.append(event)

        events.sort(key=lambda e: e.timestamp)
        self.timeline_events = events

        # Display timeline
        table = Table(title=f"Forensic Timeline ({len(events)} events)")
        table.add_column("Timestamp", style="dim", width=20)
        table.add_column("MACB", style="yellow", width=6)
        table.add_column("Source", style="cyan", width=12)
        table.add_column("Type", style="green", width=16)
        table.add_column("Description", style="white", width=50)
        table.add_column("User", style="dim", width=8)

        for event in events[:25]:
            macb = random.choice(["M...", ".A..", "..C.", "...B", "MA..", "M.CB", "MACB"])
            type_style = {
                "Execution": "red", "Persistence": "red bold",
                "Failed Auth": "yellow", "File Created": "green",
                "Process Create": "red", "Network Connect": "magenta",
            }.get(event.event_type, "white")

            table.add_row(
                event.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                macb,
                event.source,
                Text(event.event_type, style=type_style),
                event.description[:50],
                event.user or "-",
            )

        if len(events) > 25:
            table.add_row("...", "...", "...", Text("...", style="dim"),
                          f"({len(events) - 25} more events)", "...")

        console.print(table)
        return events

    def analyze_registry(self):
        """Analyze Windows registry hives for forensic artifacts."""
        console.print(Panel(
            "[bold cyan]REGISTRY ANALYSIS[/bold cyan]\n\n"
            "Analyzing Windows registry hives for forensic artifacts...",
            title="Registry Forensics",
            border_style="cyan",
        ))

        # SAM Analysis
        console.print("\n[bold]SAM Hive Analysis (User Accounts)[/bold]")
        users = [
            {"rid": 500, "name": "Administrator", "enabled": True,
             "last_login": "2024-09-10 14:32:15", "login_count": 42, "failed": 3},
            {"rid": 501, "name": "Guest", "enabled": False,
             "last_login": "Never", "login_count": 0, "failed": 0},
            {"rid": 1001, "name": "admin", "enabled": True,
             "last_login": "2024-09-12 08:45:22", "login_count": 156, "failed": 12},
            {"rid": 1002, "name": "svc_backup", "enabled": True,
             "last_login": "2024-09-11 02:00:01", "login_count": 365, "failed": 0},
            {"rid": 1003, "name": "temp_user", "enabled": True,
             "last_login": "2024-09-12 23:58:44", "login_count": 3, "failed": 0},
        ]

        user_table = Table(title="SAM: Local User Accounts")
        user_table.add_column("RID", style="dim")
        user_table.add_column("Username", style="cyan")
        user_table.add_column("Enabled", width=8)
        user_table.add_column("Last Login", style="yellow")
        user_table.add_column("Login Count", justify="right")
        user_table.add_column("Failed", justify="right", style="red")

        for user in users:
            user_table.add_row(
                str(user["rid"]),
                user["name"],
                "[green]Yes[/green]" if user["enabled"] else "[red]No[/red]",
                user["last_login"],
                str(user["login_count"]),
                str(user["failed"]),
            )
        console.print(user_table)

        # Persistence mechanisms
        console.print("\n[bold]Persistence Analysis (Run Keys)[/bold]")
        run_keys = [
            {"key": r"HKLM\...\Run", "name": "SecurityHealth", "value": r"%ProgramFiles%\Windows Defender\MSASCuiL.exe",
             "suspicious": False},
            {"key": r"HKLM\...\Run", "name": "WindowsUpdateHelper", "value": r"C:\ProgramData\update.exe -silent",
             "suspicious": True},
            {"key": r"HKCU\...\Run", "name": "OneDrive", "value": r"C:\Users\admin\AppData\Local\Microsoft\OneDrive\OneDrive.exe",
             "suspicious": False},
            {"key": r"HKCU\...\Run", "name": "SyncService", "value": r"C:\Users\admin\AppData\Local\Temp\svc.exe",
             "suspicious": True},
        ]

        run_table = Table(title="Registry Run Keys")
        run_table.add_column("Key", style="dim", width=15)
        run_table.add_column("Name", style="cyan")
        run_table.add_column("Value", style="white", width=50)
        run_table.add_column("Status", width=12)

        for rk in run_keys:
            status = "[red bold]SUSPICIOUS[/red bold]" if rk["suspicious"] else "[green]Normal[/green]"
            val_style = "red" if rk["suspicious"] else "white"
            run_table.add_row(rk["key"], rk["name"], Text(rk["value"], style=val_style), status)
        console.print(run_table)

        # UserAssist
        console.print("\n[bold]UserAssist Analysis (Program Execution)[/bold]")
        userassist = [
            {"program": "cmd.exe", "run_count": 45, "last_run": "2024-09-12 23:55:10",
             "focus_time": "02:15:30", "suspicious": False},
            {"program": "powershell.exe", "run_count": 28, "last_run": "2024-09-12 23:58:00",
             "focus_time": "01:45:20", "suspicious": True},
            {"program": "mimikatz.exe", "run_count": 3, "last_run": "2024-09-12 23:50:15",
             "focus_time": "00:05:44", "suspicious": True},
            {"program": "chrome.exe", "run_count": 312, "last_run": "2024-09-12 22:30:00",
             "focus_time": "48:12:00", "suspicious": False},
            {"program": "psexec.exe", "run_count": 5, "last_run": "2024-09-12 23:52:33",
             "focus_time": "00:02:15", "suspicious": True},
        ]

        ua_table = Table(title="UserAssist: Program Execution")
        ua_table.add_column("Program", style="cyan")
        ua_table.add_column("Run Count", justify="right")
        ua_table.add_column("Last Run", style="yellow")
        ua_table.add_column("Focus Time", justify="right")
        ua_table.add_column("Status", width=12)

        for ua in userassist:
            status = "[red bold]SUSPICIOUS[/red bold]" if ua["suspicious"] else "[green]Normal[/green]"
            name_style = "red bold" if ua["suspicious"] else "cyan"
            ua_table.add_row(
                Text(ua["program"], style=name_style),
                str(ua["run_count"]),
                ua["last_run"],
                ua["focus_time"],
                status,
            )
        console.print(ua_table)

    def extract_browser_artifacts(self, browser="chrome"):
        """Extract browser forensic artifacts."""
        console.print(Panel(
            f"[bold cyan]BROWSER ARTIFACT EXTRACTION[/bold cyan]\n\n"
            f"Extracting artifacts from {browser.title()}...",
            title="Browser Forensics",
            border_style="cyan",
        ))

        # Browsing history
        console.print("\n[bold]Browsing History (Last 20 entries)[/bold]")
        history = [
            {"url": "https://mail.google.com/", "title": "Gmail",
             "visits": 45, "last_visit": "2024-09-12 22:30:00", "suspicious": False},
            {"url": "https://docs.google.com/spreadsheets/d/1abc...", "title": "Budget 2024",
             "visits": 12, "last_visit": "2024-09-12 21:00:00", "suspicious": False},
            {"url": "https://mega.nz/folder/abcde", "title": "MEGA - Cloud Upload",
             "visits": 3, "last_visit": "2024-09-12 23:45:00", "suspicious": True},
            {"url": "https://pastebin.com/raw/XyZ123", "title": "Pastebin",
             "visits": 5, "last_visit": "2024-09-12 23:30:00", "suspicious": True},
            {"url": "https://github.com/attacker/c2-framework", "title": "C2 Framework",
             "visits": 2, "last_visit": "2024-09-12 23:20:00", "suspicious": True},
            {"url": "https://stackoverflow.com/questions/12345", "title": "Stack Overflow",
             "visits": 8, "last_visit": "2024-09-12 20:00:00", "suspicious": False},
            {"url": "https://web.whatsapp.com/", "title": "WhatsApp Web",
             "visits": 25, "last_visit": "2024-09-12 22:00:00", "suspicious": False},
        ]

        hist_table = Table(title="Browser History")
        hist_table.add_column("URL", style="white", width=45)
        hist_table.add_column("Title", style="cyan", width=20)
        hist_table.add_column("Visits", justify="right")
        hist_table.add_column("Last Visit", style="yellow")
        hist_table.add_column("Flag", width=12)

        for h in history:
            flag = "[red bold]SUSPICIOUS[/red bold]" if h["suspicious"] else "[green]Normal[/green]"
            url_style = "red" if h["suspicious"] else "white"
            hist_table.add_row(
                Text(h["url"][:45], style=url_style),
                h["title"][:20],
                str(h["visits"]),
                h["last_visit"],
                flag,
            )
        console.print(hist_table)

        # Downloads
        console.print("\n[bold]Download History[/bold]")
        downloads = [
            {"filename": "report_q4.xlsx", "url": "https://intranet.company.com/reports/report_q4.xlsx",
             "size": "2.4 MB", "date": "2024-09-10", "suspicious": False},
            {"filename": "tool.zip", "url": "https://github.com/attacker/tool/releases/tool.zip",
             "size": "5.1 MB", "date": "2024-09-12", "suspicious": True},
            {"filename": "update.exe", "url": "https://suspicious-cdn.example.com/update.exe",
             "size": "892 KB", "date": "2024-09-12", "suspicious": True},
        ]

        dl_table = Table(title="Downloads")
        dl_table.add_column("File", style="cyan")
        dl_table.add_column("Source URL", style="white", width=40)
        dl_table.add_column("Size", justify="right")
        dl_table.add_column("Date", style="yellow")
        dl_table.add_column("Flag", width=12)

        for dl in downloads:
            flag = "[red bold]SUSPICIOUS[/red bold]" if dl["suspicious"] else "[green]Normal[/green]"
            file_style = "red bold" if dl["suspicious"] else "cyan"
            dl_table.add_row(
                Text(dl["filename"], style=file_style),
                dl["url"][:40],
                dl["size"],
                dl["date"],
                flag,
            )
        console.print(dl_table)

    def analyze_email_headers(self):
        """Analyze email headers for forensic investigation."""
        console.print(Panel(
            "[bold cyan]EMAIL HEADER ANALYSIS[/bold cyan]\n\n"
            "Analyzing email headers for phishing indicators and routing...",
            title="Email Forensics",
            border_style="cyan",
        ))

        headers = {
            "From": "support@microsoft-security.example.com",
            "Reply-To": "attacker@protonmail.com",
            "To": "victim@company.com",
            "Subject": "Urgent: Your account has been compromised",
            "Date": "Thu, 12 Sep 2024 15:30:00 -0400",
            "Message-ID": "<5f8a9b2c@mail.example.com>",
            "X-Mailer": "Microsoft Outlook 16.0",
            "MIME-Version": "1.0",
            "Content-Type": "multipart/mixed; boundary=boundary123",
            "X-Originating-IP": "[198.51.100.42]",
        }

        received_hops = [
            {"server": "mail.company.com", "from": "mx3.example.com", "proto": "ESMTPS", "time": "15:30:15"},
            {"server": "mx3.example.com", "from": "relay.attacker-infra.com", "proto": "SMTP", "time": "15:30:10"},
            {"server": "relay.attacker-infra.com", "from": "mail.example.com", "proto": "SMTP", "time": "15:30:05"},
        ]

        # Header analysis
        header_table = Table(title="Email Headers")
        header_table.add_column("Header", style="cyan", width=18)
        header_table.add_column("Value", style="white", width=50)
        header_table.add_column("Analysis", style="yellow", width=30)

        analyses = {
            "From": "[red]Domain mismatch - not microsoft.com[/red]",
            "Reply-To": "[red]Different from 'From' - phishing indicator[/red]",
            "To": "[green]Legitimate recipient[/green]",
            "Subject": "[yellow]Urgency language - social engineering[/yellow]",
            "X-Originating-IP": "[red]Known malicious IP range[/red]",
            "X-Mailer": "[yellow]Claimed Outlook but headers inconsistent[/yellow]",
        }

        for key, value in headers.items():
            analysis = analyses.get(key, "[dim]Normal[/dim]")
            header_table.add_row(key, value, analysis)
        console.print(header_table)

        # Authentication results
        console.print("\n[bold]Email Authentication Results[/bold]")
        auth_table = Table(title="SPF / DKIM / DMARC")
        auth_table.add_column("Check", style="cyan")
        auth_table.add_column("Result", width=10)
        auth_table.add_column("Details", style="white")

        auth_table.add_row("SPF", "[red]FAIL[/red]",
                           "Sender IP not authorized for microsoft-security.example.com")
        auth_table.add_row("DKIM", "[red]FAIL[/red]",
                           "No valid DKIM signature found")
        auth_table.add_row("DMARC", "[red]FAIL[/red]",
                           "Policy: reject; Alignment: fail")
        console.print(auth_table)

        # Received hops
        console.print("\n[bold]Mail Routing (Received Headers)[/bold]")
        hop_table = Table(title="Mail Hops (newest first)")
        hop_table.add_column("Hop", style="dim")
        hop_table.add_column("Server", style="cyan")
        hop_table.add_column("From", style="yellow")
        hop_table.add_column("Protocol", style="green")
        hop_table.add_column("Time", style="dim")

        for i, hop in enumerate(received_hops):
            hop_table.add_row(str(i + 1), hop["server"], hop["from"], hop["proto"], hop["time"])
        console.print(hop_table)

        # Verdict
        console.print(Panel(
            "[bold red]VERDICT: PHISHING EMAIL[/bold red]\n\n"
            "Indicators:\n"
            "  - From domain impersonates Microsoft\n"
            "  - Reply-To differs from sender (attacker inbox)\n"
            "  - SPF, DKIM, and DMARC all fail\n"
            "  - Originating IP from known malicious range\n"
            "  - Urgency language in subject line\n"
            "  - Suspicious routing through attacker infrastructure",
            title="Analysis Result",
            border_style="red",
        ))

    def extract_metadata(self):
        """Extract metadata from documents and images."""
        console.print(Panel(
            "[bold cyan]METADATA EXTRACTION[/bold cyan]\n\n"
            "Extracting metadata from documents and images...",
            title="Metadata Analysis",
            border_style="cyan",
        ))

        documents = [
            {
                "filename": "project_plan.docx", "type": "Microsoft Word",
                "author": "John Smith", "last_author": "admin",
                "created": "2024-08-15 10:30:00", "modified": "2024-09-12 14:22:00",
                "revision": 15, "company": "ACME Corp",
                "total_edit_time": "04:35:00", "pages": 12,
            },
            {
                "filename": "budget_2024.xlsx", "type": "Microsoft Excel",
                "author": "Finance Team", "last_author": "jdoe",
                "created": "2024-01-05 09:00:00", "modified": "2024-09-11 16:45:00",
                "revision": 42, "company": "ACME Corp",
                "total_edit_time": "12:20:00", "pages": 5,
            },
            {
                "filename": "screenshot.png", "type": "PNG Image",
                "width": 1920, "height": 1080, "color_depth": 32,
                "software": "Snipping Tool", "dpi": 96,
                "created": "2024-09-12 23:45:00",
            },
            {
                "filename": "photo.jpg", "type": "JPEG Image",
                "camera": "iPhone 15 Pro", "gps_lat": 40.7128, "gps_lon": -74.0060,
                "exposure": "1/125", "iso": 100, "focal_length": "6.86mm",
                "created": "2024-09-10 12:30:00", "software": "iOS 17.5",
            },
        ]

        for doc in documents:
            table = Table(title=f"Metadata: {doc['filename']}")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="white")

            for key, val in doc.items():
                if key != "filename":
                    display_key = key.replace("_", " ").title()
                    if "gps" in key:
                        val = f"[red]{val} (LOCATION DATA)[/red]"
                    table.add_row(display_key, str(val))
            console.print(table)

    def manage_evidence(self):
        """Display evidence chain of custody management."""
        if not self.evidence_items:
            # Create sample evidence
            self.evidence_items.append(ForensicEvidence(
                "disk_image", "evidence.E01", "Primary disk image from suspect workstation"))
            self.evidence_items.append(ForensicEvidence(
                "memory_dump", "memdump.raw", "RAM capture from suspect workstation"))
            self.evidence_items.append(ForensicEvidence(
                "network_capture", "traffic.pcap", "Network traffic capture from monitoring port"))

        table = Table(title="Evidence Registry")
        table.add_column("Evidence ID", style="dim")
        table.add_column("Type", style="cyan")
        table.add_column("Source", style="yellow")
        table.add_column("Description", style="white", width=35)
        table.add_column("SHA-256", style="dim", width=20)
        table.add_column("Custody Entries", justify="right")

        for ev in self.evidence_items:
            table.add_row(
                ev.evidence_id,
                ev.evidence_type,
                ev.source,
                ev.description[:35],
                ev.hash_sha256[:20] + "...",
                str(len(ev.chain_of_custody)),
            )
        console.print(table)

    def list_artifacts(self, os_type="windows"):
        """List forensic artifact locations for reference."""
        if os_type == "windows":
            for category, artifacts in WINDOWS_ARTIFACTS.items():
                tree = Tree(f"[bold cyan]{category}[/bold cyan]")
                for name, info in artifacts.items():
                    if isinstance(info, dict):
                        path = info.get("path", "")
                        desc = info.get("description", "")
                        branch = tree.add(f"[yellow]{name}[/yellow]: {path}")
                        branch.add(f"[dim]{desc}[/dim]")
                    else:
                        tree.add(f"[yellow]{name}[/yellow]: {info}")
                console.print(tree)
        else:
            for category, artifacts in LINUX_ARTIFACTS.items():
                tree = Tree(f"[bold cyan]{category}[/bold cyan]")
                for path, desc in artifacts.items():
                    tree.add(f"[yellow]{path}[/yellow]: {desc}")
                console.print(tree)

    def generate_report(self, output_file=None):
        """Generate comprehensive forensic report."""
        report = {
            "report_id": str(uuid.uuid4())[:12],
            "generated": datetime.datetime.now().isoformat(),
            "examiner": "AEGIS Digital Forensics Suite",
            "case_info": {
                "case_number": f"DF-{random.randint(1000, 9999)}",
                "classification": "CONFIDENTIAL",
                "subject": "Simulated forensic investigation",
            },
            "evidence_count": len(self.evidence_items),
            "timeline_events": len(self.timeline_events),
            "findings": [
                "Suspicious executables found in temp directories",
                "Unauthorized program execution (mimikatz, psexec)",
                "Data exfiltration indicators (MEGA, Pastebin access)",
                "Persistence mechanisms installed (registry run keys)",
                "Lateral movement tools used (PsExec)",
                "Phishing email identified as initial access vector",
            ],
            "evidence": [e.to_dict() for e in self.evidence_items],
            "timeline": [e.to_dict() for e in self.timeline_events[:50]],
        }

        console.print(Panel(
            f"[bold green]FORENSIC REPORT GENERATED[/bold green]\n\n"
            f"Report ID:      {report['report_id']}\n"
            f"Case Number:    {report['case_info']['case_number']}\n"
            f"Evidence Items: {report['evidence_count']}\n"
            f"Timeline Events:{report['timeline_events']}\n"
            f"Key Findings:   {len(report['findings'])}",
            title="Forensic Report",
            border_style="green",
        ))

        if output_file:
            with open(output_file, "w") as f:
                json.dump(report, f, indent=2)
            console.print(f"[green]Report exported to {output_file}[/green]")

        return report

    def run(self):
        """Main execution entry point."""
        self.disk_image_analysis()
        console.print("\n")
        self.generate_timeline()
        console.print("\n")
        self.analyze_registry()
        console.print("\n")
        self.extract_browser_artifacts()
        console.print("\n")
        self.analyze_email_headers()
        console.print("\n")
        self.extract_metadata()
        console.print("\n")
        self.manage_evidence()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="AEGIS Digital Forensics Suite -- Educational Use Only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("command", nargs="?", default="run",
                        choices=["run", "disk-analysis", "timeline", "registry",
                                 "browser", "email-analysis", "metadata",
                                 "evidence", "artifacts", "report", "help"],
                        help="Command to execute")
    parser.add_argument("--image", "-i", default="evidence.E01",
                        help="Disk image path (simulated)")
    parser.add_argument("--os", default="windows",
                        choices=["windows", "linux"],
                        help="Operating system type")
    parser.add_argument("--output", "-o", default=None,
                        help="Export results to JSON file")

    args = parser.parse_args()
    suite = DigitalForensicsSuite()

    if args.command == "help":
        console.print(suite.HELP_TEXT)
    elif args.command == "disk-analysis":
        suite.disk_image_analysis(args.image)
    elif args.command == "timeline":
        suite.generate_timeline()
    elif args.command == "registry":
        suite.analyze_registry()
    elif args.command == "browser":
        suite.extract_browser_artifacts()
    elif args.command == "email-analysis":
        suite.analyze_email_headers()
    elif args.command == "metadata":
        suite.extract_metadata()
    elif args.command == "evidence":
        suite.manage_evidence()
    elif args.command == "artifacts":
        suite.list_artifacts(args.os)
    elif args.command == "report":
        suite.generate_report(args.output)
    else:
        suite.run()


if __name__ == "__main__":
    main()
