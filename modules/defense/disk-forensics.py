#!/usr/bin/env python3
"""Disk forensics operations — image acquisition, filesystem analysis, artifact extraction"""
import os, sys, subprocess, hashlib, json
from datetime import datetime

class DiskForensics:
    name = "Disk Forensics Toolkit"
    description = "Disk image acquisition, filesystem analysis, Windows/Linux/macOS artifact extraction, timeline generation"
    category = "defense"
    mitre = ["T1005", "T1083", "T1070", "T1070.006"]

    ACQUISITION = {
        "Linux": [
            {"tool": "dd", "cmd": "sudo dd if=/dev/sda of=evidence.raw bs=4M status=progress", "verify": "md5sum evidence.raw", "notes": "Standard Unix tool. Slow but universal. Always verify hash."},
            {"tool": "dcfldd", "cmd": "sudo dcfldd if=/dev/sda of=evidence.raw hash=md5,sha256 hashlog=hashes.log bs=4M", "verify": "Built-in hash verification", "notes": "DoD Computer Forensics Lab fork of dd. Built-in hashing and split output."},
            {"tool": "dc3dd", "cmd": "sudo dc3dd if=/dev/sda of=evidence.raw hash=md5 hash=sha256 log=audit.log", "verify": "Built-in hash log", "notes": "DoD Cyber Crime Center fork. Enhanced logging and hashing."},
            {"tool": "ewfacquire", "cmd": "sudo ewfacquire /dev/sda -t evidence -f encase6 -c deflate -S 2G", "verify": "ewfverify evidence.E01", "notes": "EnCase E01 format. Compressed, split files, built-in hash."},
        ],
        "Windows": [
            {"tool": "FTK Imager CLI", "cmd": "ftkimager \\\\.\\PhysicalDrive0 evidence --e01 --compress 6", "verify": "ftkimager --verify evidence.E01", "notes": "Free tool from AccessData. Supports E01, raw, AFF."},
            {"tool": "Arsenal Image Mounter", "cmd": "aim_cli.exe --mount --readonly evidence.E01", "verify": "Built-in", "notes": "Mount forensic images as read-only drives for analysis."},
        ],
        "Best Practices": [
            "Always use a hardware write-blocker or software write-protection",
            "Calculate hash BEFORE and AFTER acquisition",
            "Document: date, time, tool, examiner, hash values",
            "Store on a separate evidence drive, never the original",
            "Maintain chain of custody documentation",
            "Create at least 2 copies of the evidence",
            "Verify hash of each copy matches the original",
        ],
    }

    WINDOWS_ARTIFACTS = {
        "Registry": [
            {"artifact": "SAM", "path": "C:\\Windows\\System32\\config\\SAM", "reveals": "Local user accounts, password hashes, account policies", "tools": "RegRipper, Registry Explorer, regedit"},
            {"artifact": "SYSTEM", "path": "C:\\Windows\\System32\\config\\SYSTEM", "reveals": "Computer name, timezone, network interfaces, mounted devices, services, ControlSet", "tools": "RegRipper, Registry Explorer"},
            {"artifact": "SOFTWARE", "path": "C:\\Windows\\System32\\config\\SOFTWARE", "reveals": "Installed software, OS version, NetworkList (WiFi history), app paths", "tools": "RegRipper, Registry Explorer"},
            {"artifact": "NTUSER.DAT", "path": "C:\\Users\\<user>\\NTUSER.DAT", "reveals": "User-specific: Run keys, MRU lists, typed URLs, search history, UserAssist", "tools": "RegRipper, Registry Explorer"},
            {"artifact": "UsrClass.dat", "path": "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat", "reveals": "Shellbags (folder access history with timestamps)", "tools": "ShellBags Explorer, RegRipper"},
            {"artifact": "Amcache.hve", "path": "C:\\Windows\\AppCompat\\Programs\\Amcache.hve", "reveals": "Program execution: SHA1 hash, path, size, first run time, publisher", "tools": "AmcacheParser (Eric Zimmerman)"},
        ],
        "Event Logs": [
            {"artifact": "Security.evtx", "path": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "reveals": "Logon/logoff (4624/4625/4634), privilege use (4672), account mgmt (4720-4740), object access", "tools": "Event Viewer, EvtxECmd, hayabusa, chainsaw"},
            {"artifact": "System.evtx", "path": "C:\\Windows\\System32\\winevt\\Logs\\System.evtx", "reveals": "Service changes (7034-7045), system time change, shutdown/startup", "tools": "Event Viewer, EvtxECmd"},
            {"artifact": "PowerShell Operational", "path": "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx", "reveals": "Script block logging (4104), module logging (4103), full command reconstruction", "tools": "Event Viewer, EvtxECmd"},
            {"artifact": "Sysmon", "path": "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx", "reveals": "Process creation (1), network (3), file create (11), registry (12-14), DNS (22)", "tools": "Event Viewer, EvtxECmd, hayabusa"},
            {"artifact": "Task Scheduler", "path": "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-TaskScheduler%4Operational.evtx", "reveals": "Scheduled task creation/execution/deletion", "tools": "Event Viewer, EvtxECmd"},
            {"artifact": "TerminalServices", "path": "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx", "reveals": "RDP sessions: logon (21), reconnect (25), disconnect (24)", "tools": "Event Viewer, EvtxECmd"},
        ],
        "Execution Artifacts": [
            {"artifact": "Prefetch", "path": "C:\\Windows\\Prefetch\\*.pf", "reveals": "Last 8 execution times, run count, files/dirs referenced, volume info", "tools": "PECmd (Eric Zimmerman), WinPrefetchView"},
            {"artifact": "ShimCache/AppCompatCache", "path": "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache", "reveals": "Executables seen by the OS (may not have executed), timestamps", "tools": "AppCompatCacheParser, ShimCacheParser"},
            {"artifact": "SRUM", "path": "C:\\Windows\\System32\\sru\\SRUDB.dat", "reveals": "30-60 days of app resource usage: network bytes, CPU time, per-user", "tools": "SrumECmd (Eric Zimmerman)"},
            {"artifact": "BAM/DAM", "path": "SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings", "reveals": "Background Activity Moderator: last execution time of programs", "tools": "Registry Explorer, RegRipper"},
        ],
        "File Access": [
            {"artifact": "Shellbags", "path": "UsrClass.dat + NTUSER.DAT", "reveals": "Folder access history: path, access time, window position, view settings", "tools": "ShellBags Explorer"},
            {"artifact": "Jump Lists", "path": "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations", "reveals": "Recent files opened by each application, with timestamps and paths", "tools": "JLECmd (Eric Zimmerman)"},
            {"artifact": "LNK Files", "path": "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\*.lnk", "reveals": "Target path, MAC times, volume info, sometimes network paths", "tools": "LECmd (Eric Zimmerman)"},
            {"artifact": "Recent Files", "path": "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs", "reveals": "Recently accessed files by extension", "tools": "RegRipper, Registry Explorer"},
            {"artifact": "MRU Lists", "path": "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32", "reveals": "Files opened via Open/Save dialogs, typed paths", "tools": "RegRipper"},
        ],
        "USB": [
            {"artifact": "USBSTOR", "path": "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR", "reveals": "USB device: vendor, product, serial number, first/last connect time", "tools": "RegRipper, USBDeview"},
            {"artifact": "DeviceClasses", "path": "SYSTEM\\CurrentControlSet\\Control\\DeviceClasses", "reveals": "Device class GUIDs with timestamps", "tools": "Registry Explorer"},
            {"artifact": "setupapi.dev.log", "path": "C:\\Windows\\INF\\setupapi.dev.log", "reveals": "First time a USB device was connected (install timestamp)", "tools": "Text editor, grep"},
            {"artifact": "Event ID 20001", "path": "Microsoft-Windows-DeviceSetupManager Operational", "reveals": "Driver installation for USB devices", "tools": "Event Viewer"},
        ],
        "Browser": [
            {"artifact": "Chrome History", "path": "C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History", "reveals": "URLs visited, search terms, downloads, timestamps (SQLite)", "tools": "DB Browser for SQLite, Hindsight"},
            {"artifact": "Firefox History", "path": "C:\\Users\\<user>\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*.default\\places.sqlite", "reveals": "URLs, bookmarks, downloads, visit timestamps (SQLite)", "tools": "DB Browser for SQLite"},
            {"artifact": "Edge History", "path": "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History", "reveals": "Same as Chrome (Chromium-based)", "tools": "DB Browser for SQLite, Hindsight"},
            {"artifact": "Browser Cache", "path": "Various per browser", "reveals": "Cached web content, images, scripts — can reveal accessed sites", "tools": "ChromeCacheView, MozillaCacheView"},
        ],
        "Communication": [
            {"artifact": "Outlook PST/OST", "path": "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Outlook\\*.ost", "reveals": "Emails, attachments, contacts, calendar — critical for BEC/phishing cases", "tools": "pffexport, Kernel Outlook PST Viewer"},
            {"artifact": "Teams/Skype", "path": "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Teams\\IndexedDB", "reveals": "Chat messages, file transfers, call logs", "tools": "SQLite browser, custom parsers"},
        ],
        "Cloud Sync": [
            {"artifact": "OneDrive", "path": "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\OneDrive\\logs", "reveals": "Synced files, upload/download activity, deleted files", "tools": "OneDriveExplorer"},
            {"artifact": "Dropbox", "path": "C:\\Users\\<user>\\AppData\\Local\\Dropbox\\instance1\\filecache.dbx", "reveals": "Synced files, sharing activity", "tools": "SQLite browser"},
        ],
    }

    LINUX_ARTIFACTS = {
        "Logs": [
            {"artifact": "/var/log/auth.log", "reveals": "Authentication: SSH logins, sudo usage, su attempts, PAM events", "tools": "grep, awk, journalctl"},
            {"artifact": "/var/log/syslog", "reveals": "System events: services, kernel messages, cron execution", "tools": "grep, journalctl"},
            {"artifact": "/var/log/kern.log", "reveals": "Kernel messages: module loading, hardware events, USB", "tools": "grep, dmesg"},
            {"artifact": "/var/log/btmp", "reveals": "Failed login attempts (binary)", "tools": "lastb"},
            {"artifact": "/var/log/wtmp", "reveals": "Login/logout history (binary)", "tools": "last"},
            {"artifact": "/var/log/lastlog", "reveals": "Last login per user (binary)", "tools": "lastlog"},
            {"artifact": "/var/log/apt/history.log", "reveals": "Package install/remove history", "tools": "cat, grep"},
            {"artifact": "journalctl", "reveals": "Systemd journal: all system and service logs", "tools": "journalctl --since '2024-01-01' --until '2024-01-02'"},
        ],
        "User Activity": [
            {"artifact": "~/.bash_history", "reveals": "Command history (may be cleared by attacker)", "tools": "cat, strings"},
            {"artifact": "~/.zsh_history", "reveals": "Zsh command history", "tools": "cat"},
            {"artifact": "~/.python_history", "reveals": "Python REPL history", "tools": "cat"},
            {"artifact": "~/.mysql_history", "reveals": "MySQL command history", "tools": "cat"},
            {"artifact": "~/.ssh/known_hosts", "reveals": "SSH servers connected to", "tools": "cat"},
            {"artifact": "~/.ssh/authorized_keys", "reveals": "SSH keys authorized for access (persistence!)", "tools": "cat, diff against known-good"},
        ],
        "System Config": [
            {"artifact": "/etc/passwd", "reveals": "User accounts, home dirs, shells — new accounts = persistence", "tools": "cat, diff"},
            {"artifact": "/etc/shadow", "reveals": "Password hashes, password change dates", "tools": "cat (root only)"},
            {"artifact": "/etc/sudoers", "reveals": "Sudo privileges — modified = privilege escalation", "tools": "cat, visudo"},
            {"artifact": "/etc/crontab + /var/spool/cron/", "reveals": "Scheduled tasks (persistence mechanism)", "tools": "cat, crontab -l"},
            {"artifact": "/etc/systemd/system/", "reveals": "Custom systemd services (persistence)", "tools": "systemctl list-unit-files"},
        ],
        "Process/Network": [
            {"artifact": "/proc/<pid>/", "reveals": "Live process info: cmdline, environ, fd, maps, exe link", "tools": "cat, ls -la"},
            {"artifact": "/proc/net/tcp", "reveals": "Active TCP connections (live system)", "tools": "cat, ss -tulnp"},
            {"artifact": "Loaded modules", "reveals": "Kernel modules (rootkit detection)", "tools": "lsmod, cat /proc/modules"},
        ],
    }

    MACOS_ARTIFACTS = {
        "System": [
            {"artifact": "Unified Log", "reveals": "All system, app, and kernel logs since macOS 10.12", "tools": "log show --predicate 'process == \"sshd\"' --last 24h"},
            {"artifact": "FSEvents", "path": "/.fseventsd/", "reveals": "File system events: creation, modification, deletion", "tools": "FSEventsParser"},
            {"artifact": "KnowledgeC.db", "path": "~/Library/Application Support/Knowledge/knowledgeC.db", "reveals": "App usage, device activity, interactions", "tools": "APOLLO, SQLite browser"},
            {"artifact": "Spotlight metadata", "path": "/.Spotlight-V100/", "reveals": "File metadata index: content, dates, file types", "tools": "mdls, mdfind"},
        ],
        "Persistence": [
            {"artifact": "LaunchAgents", "path": "~/Library/LaunchAgents/ + /Library/LaunchAgents/", "reveals": "User-level and system-level persistent programs", "tools": "ls, plutil, launchctl list"},
            {"artifact": "LaunchDaemons", "path": "/Library/LaunchDaemons/", "reveals": "System-level daemons (root persistence)", "tools": "ls, plutil"},
            {"artifact": "Login Items", "path": "~/Library/Application Support/com.apple.backgroundtaskmanagementagent/", "reveals": "Programs launched at user login", "tools": "sfltool dumpbtm"},
        ],
        "Security": [
            {"artifact": "QuarantineEventsV2", "path": "~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2", "reveals": "Downloaded files: URL, date, application used", "tools": "SQLite browser"},
            {"artifact": "Keychain", "path": "~/Library/Keychains/", "reveals": "Stored passwords, certificates, keys", "tools": "security dump-keychain"},
            {"artifact": "TCC.db", "path": "~/Library/Application Support/com.apple.TCC/TCC.db", "reveals": "Privacy permission grants (camera, mic, disk access)", "tools": "SQLite browser"},
        ],
    }

    TIMELINE_TOOLS = [
        {"tool": "plaso/log2timeline", "desc": "Creates super timelines from disk images", "cmd": "log2timeline.py --storage-file timeline.plaso evidence.raw && psort.py -o l2tcsv -w timeline.csv timeline.plaso", "notes": "Most comprehensive timeline tool. Parses 100+ artifact types."},
        {"tool": "MFTECmd", "desc": "Parse NTFS $MFT for file timeline", "cmd": "MFTECmd.exe -f $MFT --csv output/", "notes": "Eric Zimmerman tool. Fast MFT parsing with all timestamps."},
        {"tool": "MACTIME", "desc": "Create timeline from Sleuth Kit bodyfile", "cmd": "fls -r -m / evidence.raw > bodyfile.txt && mactime -b bodyfile.txt > timeline.txt", "notes": "Part of The Sleuth Kit. Simple but effective."},
        {"tool": "hayabusa", "desc": "Windows event log fast forensics", "cmd": "hayabusa csv-timeline -d ./logs/ -o timeline.csv", "notes": "Sigma-based detection + timeline from Windows event logs. Very fast."},
        {"tool": "chainsaw", "desc": "Rapid Windows event log analysis", "cmd": "chainsaw hunt ./logs/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml", "notes": "Sigma rule hunting across event logs."},
    ]

    ANALYSIS_TOOLS = [
        {"tool": "Autopsy", "desc": "Open-source digital forensics platform (GUI)", "url": "https://www.autopsy.com/", "notes": "Built on Sleuth Kit. Full-featured GUI. Timeline, keyword search, hash lookup, carving."},
        {"tool": "The Sleuth Kit", "desc": "CLI forensic analysis tools", "url": "https://www.sleuthkit.org/", "notes": "fls, icat, istat, mmls, fsstat — the foundation of disk forensics."},
        {"tool": "RegRipper", "desc": "Windows registry parser", "url": "https://github.com/keydet89/RegRipper3.0", "notes": "Plugin-based registry analysis. Essential for Windows forensics."},
        {"tool": "Eric Zimmerman Tools", "desc": "Suite of forensic parsers", "url": "https://ericzimmerman.github.io/", "notes": "MFTECmd, PECmd, LECmd, JLECmd, AmcacheParser, AppCompatCacheParser, SrumECmd, EvtxECmd, ShellBags Explorer, Registry Explorer, Timeline Explorer"},
        {"tool": "KAPE", "desc": "Kroll Artifact Parser and Extractor", "url": "https://www.kroll.com/kape", "notes": "Automated collection and processing of forensic artifacts."},
    ]

    def __init__(self, target=None, options=None):
        self.target = target or ""
        self.options = options or {}
        self.findings = []
        self.actions = []

    def run(self, confirm_fn=None):
        confirm = confirm_fn or (lambda msg: input(f"\n[?] {msg} [y/N]: ").strip().lower() == "y")
        print(f"\n[AEGIS] Disk Forensics Toolkit")
        print(f"{'='*60}")

        while True:
            print("\n  [1] Image Acquisition Guide")
            print("  [2] Windows Artifacts Reference")
            print("  [3] Linux Artifacts Reference")
            print("  [4] macOS Artifacts Reference")
            print("  [5] Timeline Tools")
            print("  [6] Analysis Tools Reference")
            print("  [7] Analyze a Disk Image")
            print("  [8] Hash a File/Image")
            print("  [0] Exit")

            choice = input("\n  Choice: ").strip()
            if choice == "0":
                break
            elif choice == "1":
                self._show_acquisition()
            elif choice == "2":
                self._show_artifacts("Windows", self.WINDOWS_ARTIFACTS)
            elif choice == "3":
                self._show_artifacts("Linux", self.LINUX_ARTIFACTS)
            elif choice == "4":
                self._show_artifacts("macOS", self.MACOS_ARTIFACTS)
            elif choice == "5":
                self._show_timeline_tools()
            elif choice == "6":
                self._show_analysis_tools()
            elif choice == "7":
                self._analyze_image(confirm)
            elif choice == "8":
                self._hash_file()

    def _show_acquisition(self):
        print("\n[Disk Image Acquisition]")
        for platform, items in self.ACQUISITION.items():
            print(f"\n  --- {platform} ---")
            if isinstance(items[0], dict):
                for t in items:
                    print(f"\n  {t['tool']}")
                    print(f"    Command: {t['cmd']}")
                    print(f"    Verify:  {t['verify']}")
                    print(f"    Notes:   {t['notes']}")
            else:
                for item in items:
                    print(f"    - {item}")

    def _show_artifacts(self, name, artifacts):
        print(f"\n[{name} Forensic Artifacts]")
        for category, items in artifacts.items():
            print(f"\n  --- {category} ({len(items)} artifacts) ---")
            for a in items:
                print(f"\n  {a['artifact']}")
                if "path" in a:
                    print(f"    Path:    {a['path']}")
                print(f"    Reveals: {a['reveals']}")
                print(f"    Tools:   {a['tools']}")

    def _show_timeline_tools(self):
        print("\n[Timeline Generation Tools]")
        for t in self.TIMELINE_TOOLS:
            print(f"\n  {t['tool']}")
            print(f"    {t['desc']}")
            print(f"    Command: {t['cmd']}")
            print(f"    Notes:   {t['notes']}")

    def _show_analysis_tools(self):
        print("\n[Forensic Analysis Tools]")
        for t in self.ANALYSIS_TOOLS:
            print(f"\n  {t['tool']}")
            print(f"    {t['desc']}")
            print(f"    URL:   {t['url']}")
            print(f"    Notes: {t['notes']}")

    def _analyze_image(self, confirm):
        path = input("\n  Image path: ").strip()
        if not path or not os.path.exists(path):
            print("  [!] File not found")
            return

        mmls_available = False
        try:
            subprocess.run(["mmls", "--version"], capture_output=True, timeout=5)
            mmls_available = True
        except Exception:
            pass

        if mmls_available and confirm(f"Run mmls (partition table) on {path}?"):
            try:
                result = subprocess.run(["mmls", path], capture_output=True, text=True, timeout=30)
                print(result.stdout if result.stdout else result.stderr)
            except Exception as e:
                print(f"  [!] Error: {e}")
        else:
            print("  Install The Sleuth Kit for disk analysis: sudo apt install sleuthkit")

    def _hash_file(self):
        path = input("\n  File path: ").strip()
        if not path or not os.path.isfile(path):
            print("  [!] File not found")
            return
        print(f"  Hashing {path}...")
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        print(f"  MD5:    {md5.hexdigest()}")
        print(f"  SHA1:   {sha1.hexdigest()}")
        print(f"  SHA256: {sha256.hexdigest()}")
        self.findings.append({"severity": "info", "title": f"File hashed: {os.path.basename(path)}", "detail": f"SHA256: {sha256.hexdigest()}"})

    def get_findings(self):
        return self.findings

if __name__ == "__main__":
    d = DiskForensics()
    d.run()
