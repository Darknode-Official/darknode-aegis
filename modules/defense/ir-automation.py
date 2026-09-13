#!/usr/bin/env python3
"""Incident response automation — evidence collection, containment, eradication, recovery, communications"""
import os, sys, subprocess, hashlib, json
from datetime import datetime

class IRAutomation:
    name = "IR Automation Framework"
    description = "Automated evidence collection scripts, containment actions, eradication checklists, recovery workflows, communication templates"
    category = "defense"
    mitre = ["T1070", "T1485", "T1486", "T1498"]

    WINDOWS_COLLECTION_SCRIPT = r'''# AEGIS Windows Evidence Collection Script
# Run as Administrator in PowerShell
# Collects volatile and non-volatile evidence

$OutDir = "C:\AEGIS_Evidence_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$Log = "$OutDir\_collection.log"

function Log($msg) { $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"; "$ts $msg" | Tee-Object -FilePath $Log -Append }

Log "[START] Evidence collection on $env:COMPUTERNAME"

# System Info
Log "[COLLECT] System information"
systeminfo > "$OutDir\systeminfo.txt" 2>&1
whoami /all > "$OutDir\whoami.txt" 2>&1
hostname > "$OutDir\hostname.txt" 2>&1

# Running Processes
Log "[COLLECT] Running processes"
Get-Process | Select-Object Id,ProcessName,Path,StartTime,CPU,WorkingSet64 | Export-Csv "$OutDir\processes.csv" -NoTypeInformation
wmic process list full > "$OutDir\processes_wmic.txt" 2>&1
Get-CimInstance Win32_Process | Select-Object ProcessId,Name,CommandLine,ParentProcessId,ExecutablePath,CreationDate | Export-Csv "$OutDir\processes_cmdline.csv" -NoTypeInformation

# Network Connections
Log "[COLLECT] Network connections"
netstat -anob > "$OutDir\netstat.txt" 2>&1
Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | Export-Csv "$OutDir\tcp_connections.csv" -NoTypeInformation
Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess | Export-Csv "$OutDir\udp_endpoints.csv" -NoTypeInformation
ipconfig /all > "$OutDir\ipconfig.txt" 2>&1
route print > "$OutDir\routes.txt" 2>&1
arp -a > "$OutDir\arp.txt" 2>&1
ipconfig /displaydns > "$OutDir\dns_cache.txt" 2>&1

# Scheduled Tasks
Log "[COLLECT] Scheduled tasks"
schtasks /query /fo csv /v > "$OutDir\schtasks.csv" 2>&1
Get-ScheduledTask | Select-Object TaskName,TaskPath,State,Author,Date | Export-Csv "$OutDir\schtasks_ps.csv" -NoTypeInformation

# Services
Log "[COLLECT] Services"
Get-Service | Select-Object Name,DisplayName,Status,StartType | Export-Csv "$OutDir\services.csv" -NoTypeInformation
wmic service get name,displayname,pathname,startmode,state /format:csv > "$OutDir\services_wmic.csv" 2>&1

# Registry Autoruns
Log "[COLLECT] Registry autorun entries"
$RunKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($key in $RunKeys) {
    if (Test-Path $key) {
        Get-ItemProperty $key 2>$null | Out-File "$OutDir\autoruns_registry.txt" -Append
    }
}

# Event Logs (last 24 hours)
Log "[COLLECT] Event logs (last 24hr)"
$Yesterday = (Get-Date).AddDays(-1)
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$Yesterday} -MaxEvents 5000 -ErrorAction SilentlyContinue | Export-Csv "$OutDir\eventlog_security.csv" -NoTypeInformation
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$Yesterday} -MaxEvents 5000 -ErrorAction SilentlyContinue | Export-Csv "$OutDir\eventlog_system.csv" -NoTypeInformation
Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$Yesterday} -MaxEvents 2000 -ErrorAction SilentlyContinue | Export-Csv "$OutDir\eventlog_application.csv" -NoTypeInformation

# Installed Software
Log "[COLLECT] Installed software"
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | Export-Csv "$OutDir\installed_software.csv" -NoTypeInformation

# User Accounts
Log "[COLLECT] User accounts and groups"
net user > "$OutDir\users.txt" 2>&1
net localgroup > "$OutDir\groups.txt" 2>&1
net localgroup Administrators > "$OutDir\administrators.txt" 2>&1

# Active Sessions
Log "[COLLECT] Active sessions"
quser > "$OutDir\sessions.txt" 2>&1
query session > "$OutDir\sessions_query.txt" 2>&1

# Open File Handles
Log "[COLLECT] Open file handles"
openfiles /query > "$OutDir\openfiles.txt" 2>&1

# Prefetch
Log "[COLLECT] Prefetch files"
if (Test-Path "C:\Windows\Prefetch") {
    Get-ChildItem "C:\Windows\Prefetch\*.pf" | Select-Object Name,CreationTime,LastWriteTime,Length | Export-Csv "$OutDir\prefetch.csv" -NoTypeInformation
}

# Browser History (Chrome)
Log "[COLLECT] Browser history"
$ChromeHistory = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
if (Test-Path $ChromeHistory) { Copy-Item $ChromeHistory "$OutDir\chrome_history.sqlite" -Force 2>$null }

# Firewall Rules
Log "[COLLECT] Firewall rules"
netsh advfirewall firewall show rule name=all > "$OutDir\firewall_rules.txt" 2>&1

# Hash the collection
Log "[HASH] Hashing collected evidence"
Get-ChildItem "$OutDir" -File | ForEach-Object { $hash = Get-FileHash $_.FullName -Algorithm SHA256; "$($hash.Hash)  $($_.Name)" | Out-File "$OutDir\_hashes.txt" -Append }

Log "[COMPLETE] Evidence collected to $OutDir"
Write-Host "`nEvidence saved to: $OutDir" -ForegroundColor Green
'''

    LINUX_COLLECTION_SCRIPT = r'''#!/bin/bash
# AEGIS Linux Evidence Collection Script
# Run as root

OUTDIR="/tmp/aegis_evidence_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"
LOG="$OUTDIR/_collection.log"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "$LOG"; }

log "[START] Evidence collection on $(hostname)"

# System Info
log "[COLLECT] System information"
uname -a > "$OUTDIR/uname.txt" 2>&1
cat /etc/os-release > "$OUTDIR/os-release.txt" 2>&1
hostname > "$OUTDIR/hostname.txt" 2>&1
id > "$OUTDIR/id.txt" 2>&1
uptime > "$OUTDIR/uptime.txt" 2>&1
date > "$OUTDIR/date.txt" 2>&1
timedatectl > "$OUTDIR/timezone.txt" 2>&1

# Processes
log "[COLLECT] Running processes"
ps auxwwf > "$OUTDIR/ps_aux.txt" 2>&1
ps -eo pid,ppid,user,stat,args --sort=-pcpu > "$OUTDIR/ps_sorted.txt" 2>&1
top -bn1 > "$OUTDIR/top.txt" 2>&1

# For each process, get /proc info
log "[COLLECT] Process details from /proc"
for pid in $(ls /proc | grep -E '^[0-9]+$' | head -200); do
    if [ -f "/proc/$pid/cmdline" ]; then
        echo "PID=$pid CMD=$(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null)" >> "$OUTDIR/proc_cmdlines.txt"
    fi
done

# Network
log "[COLLECT] Network connections"
ss -tulnp > "$OUTDIR/ss_listening.txt" 2>&1
ss -antp > "$OUTDIR/ss_all_tcp.txt" 2>&1
netstat -antup > "$OUTDIR/netstat.txt" 2>&1
ip a > "$OUTDIR/ip_addr.txt" 2>&1
ip route > "$OUTDIR/ip_route.txt" 2>&1
arp -an > "$OUTDIR/arp.txt" 2>&1
cat /etc/resolv.conf > "$OUTDIR/resolv.txt" 2>&1
iptables -L -n -v > "$OUTDIR/iptables.txt" 2>&1

# Cron Jobs
log "[COLLECT] Cron jobs"
crontab -l > "$OUTDIR/crontab_root.txt" 2>&1
for user in $(cut -d: -f1 /etc/passwd); do
    crontab -u "$user" -l > "$OUTDIR/crontab_${user}.txt" 2>/dev/null
done
ls -la /etc/cron.d/ > "$OUTDIR/cron_d.txt" 2>&1
cat /etc/crontab > "$OUTDIR/etc_crontab.txt" 2>&1

# Systemd
log "[COLLECT] Systemd services and timers"
systemctl list-units --type=service --all > "$OUTDIR/systemd_services.txt" 2>&1
systemctl list-timers --all > "$OUTDIR/systemd_timers.txt" 2>&1
systemctl list-unit-files > "$OUTDIR/systemd_unit_files.txt" 2>&1

# Auth Logs
log "[COLLECT] Authentication logs"
cp /var/log/auth.log "$OUTDIR/auth.log" 2>/dev/null
cp /var/log/secure "$OUTDIR/secure.log" 2>/dev/null
last -50 > "$OUTDIR/last.txt" 2>&1
lastb -20 > "$OUTDIR/lastb.txt" 2>&1
lastlog > "$OUTDIR/lastlog.txt" 2>&1

# Users
log "[COLLECT] User accounts and sudo"
cat /etc/passwd > "$OUTDIR/passwd.txt" 2>&1
cat /etc/shadow > "$OUTDIR/shadow.txt" 2>&1
cat /etc/sudoers > "$OUTDIR/sudoers.txt" 2>&1
cat /etc/group > "$OUTDIR/group.txt" 2>&1

# SSH
log "[COLLECT] SSH configuration and keys"
cat /etc/ssh/sshd_config > "$OUTDIR/sshd_config.txt" 2>&1
for user_home in /home/* /root; do
    user=$(basename "$user_home")
    if [ -d "$user_home/.ssh" ]; then
        mkdir -p "$OUTDIR/ssh_$user"
        cp "$user_home/.ssh/authorized_keys" "$OUTDIR/ssh_$user/" 2>/dev/null
        cp "$user_home/.ssh/known_hosts" "$OUTDIR/ssh_$user/" 2>/dev/null
        ls -la "$user_home/.ssh/" > "$OUTDIR/ssh_$user/listing.txt" 2>&1
    fi
done

# Open Files
log "[COLLECT] Open files"
lsof -nP > "$OUTDIR/lsof.txt" 2>&1

# Kernel Modules
log "[COLLECT] Loaded kernel modules"
lsmod > "$OUTDIR/lsmod.txt" 2>&1

# Disk
log "[COLLECT] Mount points and disk usage"
mount > "$OUTDIR/mount.txt" 2>&1
df -h > "$OUTDIR/df.txt" 2>&1
fdisk -l > "$OUTDIR/fdisk.txt" 2>&1

# Package Listing
log "[COLLECT] Installed packages"
dpkg -l > "$OUTDIR/dpkg.txt" 2>/dev/null
rpm -qa > "$OUTDIR/rpm.txt" 2>/dev/null

# Bash History
log "[COLLECT] Shell history"
for user_home in /home/* /root; do
    user=$(basename "$user_home")
    cp "$user_home/.bash_history" "$OUTDIR/bash_history_$user.txt" 2>/dev/null
    cp "$user_home/.zsh_history" "$OUTDIR/zsh_history_$user.txt" 2>/dev/null
done

# Hash evidence
log "[HASH] Hashing collected evidence"
find "$OUTDIR" -type f -not -name "_hashes.txt" -exec sha256sum {} \; > "$OUTDIR/_hashes.txt" 2>/dev/null

log "[COMPLETE] Evidence collected to $OUTDIR"
echo -e "\nEvidence saved to: $OUTDIR"
'''

    CONTAINMENT_ACTIONS = {
        "Network Isolation": {
            "Windows": [
                {"action": "Disable network adapters", "cmd": 'Get-NetAdapter | Disable-NetAdapter -Confirm:$false', "risk": "Host becomes unreachable for remote investigation"},
                {"action": "Block all outbound except investigation IP", "cmd": 'netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound\nnetsh advfirewall firewall add rule name="Allow IR" dir=out action=allow remoteip=<IR_IP>', "risk": "Blocks all network but IR team access"},
                {"action": "Null route to C2 IP", "cmd": 'route add <C2_IP> mask 255.255.255.255 0.0.0.0', "risk": "Only blocks specific IP, attacker may have backup C2"},
            ],
            "Linux": [
                {"action": "Drop all traffic except investigation", "cmd": 'iptables -P INPUT DROP\niptables -P OUTPUT DROP\niptables -P FORWARD DROP\niptables -A INPUT -s <IR_IP> -j ACCEPT\niptables -A OUTPUT -d <IR_IP> -j ACCEPT', "risk": "Host unreachable except from IR team"},
                {"action": "Block specific C2 IP", "cmd": 'iptables -A OUTPUT -d <C2_IP> -j DROP', "risk": "Only blocks known C2, attacker may pivot"},
                {"action": "Disable interface", "cmd": 'ip link set <interface> down', "risk": "Complete isolation, no remote access"},
            ],
        },
        "Account Lockout": {
            "Windows": [
                {"action": "Disable compromised account", "cmd": 'Disable-ADAccount -Identity <username>', "risk": "User cannot work until re-enabled"},
                {"action": "Reset password", "cmd": 'Set-ADAccountPassword -Identity <username> -Reset -NewPassword (ConvertTo-SecureString "TempP@ss123!" -AsPlainText -Force)', "risk": "User needs new password"},
                {"action": "Revoke all sessions", "cmd": 'Revoke-AzureADUserAllRefreshToken -ObjectId <user_objectid>', "risk": "User logged out everywhere"},
            ],
            "Linux": [
                {"action": "Lock account", "cmd": 'usermod -L <username>', "risk": "User cannot authenticate"},
                {"action": "Expire password", "cmd": 'passwd -e <username>', "risk": "Forces password change at next login"},
                {"action": "Kill all user sessions", "cmd": 'pkill -KILL -u <username>', "risk": "All user processes terminated"},
            ],
        },
        "Service Shutdown": {
            "Windows": [
                {"action": "Stop malicious service", "cmd": 'Stop-Service -Name <service> -Force\nSet-Service -Name <service> -StartupType Disabled', "risk": "Service-dependent applications may fail"},
                {"action": "Kill malicious process", "cmd": 'Stop-Process -Id <PID> -Force', "risk": "Process restarts if persistence exists"},
            ],
            "Linux": [
                {"action": "Stop and disable service", "cmd": 'systemctl stop <service>\nsystemctl disable <service>', "risk": "Dependent services may fail"},
                {"action": "Kill process", "cmd": 'kill -9 <PID>', "risk": "Process restarts if persistence exists"},
            ],
        },
    }

    ERADICATION_CHECKLISTS = {
        "Ransomware": [
            "Identify ransomware family (check ransom note, file extension, ID Ransomware)",
            "Check for decryptor availability (nomoreransom.org)",
            "Remove ransomware executable and associated files",
            "Remove persistence: scheduled tasks, services, registry Run keys",
            "Remove dropped scripts and batch files",
            "Clean temporary directories",
            "Scan with updated AV/EDR",
            "Check for lateral movement — other hosts may be compromised",
            "Verify backups are clean before restoration",
            "Rebuild from known-good image if uncertain",
        ],
        "RAT/Backdoor": [
            "Identify all C2 communication channels and block them",
            "Remove malware binary and all dropped components",
            "Remove persistence mechanisms (services, scheduled tasks, registry, startup)",
            "Check for additional backdoors (web shells, SSH keys, new accounts)",
            "Remove any created user accounts",
            "Rotate ALL credentials on affected systems",
            "Check for keylogger captures and assume credentials compromised",
            "Review firewall rules for attacker-added entries",
            "Scan all systems in the same network segment",
        ],
        "Web Shell": [
            "Identify all web shell files (YARA scan web directories)",
            "Remove web shell files",
            "Patch the vulnerability that allowed upload",
            "Review web server logs for other exploitation attempts",
            "Check for privilege escalation from web shell",
            "Reset web application credentials and API keys",
            "Review database for injected content",
            "Harden file upload functionality",
            "Implement WAF rules",
        ],
        "Credential Theft": [
            "Force password reset for ALL affected accounts",
            "Revoke and regenerate all API keys and tokens",
            "Rotate service account passwords",
            "Invalidate all active sessions",
            "Check for golden/silver ticket attacks (reset krbtgt twice)",
            "Review for unauthorized access using stolen credentials",
            "Enable MFA on all accounts",
            "Monitor for credential reuse attempts",
        ],
    }

    COMMUNICATION_TEMPLATES = {
        "Executive Notification": '''
SECURITY INCIDENT NOTIFICATION — {classification}

Date: {date}
Incident ID: {incident_id}
Severity: {severity}

SUMMARY:
{summary}

CURRENT STATUS:
- Containment: {containment_status}
- Investigation: {investigation_status}
- Business Impact: {impact}

ACTIONS TAKEN:
{actions}

NEXT STEPS:
{next_steps}

ESTIMATED RESOLUTION: {eta}

Contact: {contact}
''',
        "Technical Report": '''
INCIDENT TECHNICAL REPORT — {classification}

1. INCIDENT OVERVIEW
   ID: {incident_id}
   Date Detected: {detect_date}
   Date Reported: {report_date}
   Severity: {severity}
   Type: {incident_type}
   Status: {status}

2. AFFECTED SYSTEMS
{affected_systems}

3. TIMELINE
{timeline}

4. ROOT CAUSE
{root_cause}

5. INDICATORS OF COMPROMISE
{iocs}

6. ACTIONS TAKEN
{actions}

7. EVIDENCE COLLECTED
{evidence}

8. REMEDIATION STEPS
{remediation}

9. LESSONS LEARNED
{lessons}

Prepared by: {analyst}
Date: {date}
''',
        "Regulatory - GDPR 72hr": '''
DATA BREACH NOTIFICATION — GDPR Article 33

To: {supervisory_authority}
Date: {date}

1. NATURE OF THE BREACH
{breach_description}

2. CATEGORIES AND APPROXIMATE NUMBER OF DATA SUBJECTS
{data_subjects}

3. CATEGORIES AND APPROXIMATE NUMBER OF RECORDS
{records}

4. NAME AND CONTACT OF DPO
{dpo_contact}

5. LIKELY CONSEQUENCES
{consequences}

6. MEASURES TAKEN OR PROPOSED
{measures}

This notification is made within 72 hours of becoming aware of the breach as required by GDPR Article 33.
''',
        "Customer Notification": '''
IMPORTANT: Security Incident Notice

Dear {customer_name},

We are writing to inform you of a security incident that may have affected your personal information.

WHAT HAPPENED:
{what_happened}

WHAT INFORMATION WAS INVOLVED:
{data_involved}

WHAT WE ARE DOING:
{our_actions}

WHAT YOU CAN DO:
- Change your password immediately
- Enable two-factor authentication
- Monitor your accounts for suspicious activity
- Consider placing a fraud alert with credit bureaus
{additional_steps}

FOR MORE INFORMATION:
{contact_info}

We sincerely apologize for this incident and are committed to protecting your information.

{company_name}
{date}
''',
    }

    RECOVERY_CHECKLIST = [
        {"phase": "Validation", "steps": [
            "Confirm all malware/backdoors have been removed",
            "Verify no persistence mechanisms remain",
            "Scan with multiple AV/EDR engines",
            "Check for rootkits (chkrootkit, rkhunter on Linux)",
            "Verify file integrity against known-good hashes",
        ]},
        {"phase": "System Rebuild", "steps": [
            "Rebuild from known-good image if any doubt",
            "Apply all security patches before reconnecting",
            "Harden configuration per CIS benchmarks",
            "Change all local admin passwords",
            "Update and enable endpoint protection",
        ]},
        {"phase": "Credential Reset", "steps": [
            "Reset passwords for all affected users (force change at login)",
            "Reset all service account passwords",
            "Rotate all API keys, tokens, and certificates",
            "Reset krbtgt password TWICE (for golden ticket mitigation)",
            "Revoke and reissue all certificates if CA was compromised",
            "Reset WiFi passwords if wireless network was involved",
        ]},
        {"phase": "Network Reconnection", "steps": [
            "Reconnect to isolated network segment first",
            "Monitor closely for signs of reinfection",
            "Gradually restore network connectivity",
            "Verify firewall rules are correct",
            "Enable enhanced logging on reconnected systems",
        ]},
        {"phase": "Service Restoration", "steps": [
            "Restore critical services first (AD, DNS, email)",
            "Restore business applications in priority order",
            "Restore from verified clean backups",
            "Test each service before declaring operational",
            "Communicate restoration status to stakeholders",
        ]},
        {"phase": "Monitoring Enhancement", "steps": [
            "Deploy additional detection rules based on incident IOCs",
            "Increase logging verbosity for 30-90 days",
            "Enable additional SIEM correlation rules",
            "Schedule follow-up threat hunts",
            "Brief SOC team on new indicators to watch for",
        ]},
    ]

    def __init__(self, target=None, options=None):
        self.target = target or ""
        self.options = options or {}
        self.findings = []
        self.actions = []

    def run(self, confirm_fn=None):
        confirm = confirm_fn or (lambda msg: input(f"\n[?] {msg} [y/N]: ").strip().lower() == "y")
        print(f"\n[AEGIS] Incident Response Automation")
        print(f"{'='*60}")

        while True:
            print("\n  [1] Generate Windows Evidence Collection Script")
            print("  [2] Generate Linux Evidence Collection Script")
            print("  [3] Containment Actions")
            print("  [4] Eradication Checklists")
            print("  [5] Recovery Workflow")
            print("  [6] Communication Templates")
            print("  [7] Run Evidence Collection (this host)")
            print("  [0] Exit")

            choice = input("\n  Choice: ").strip()
            if choice == "0":
                break
            elif choice == "1":
                self._generate_script("Windows", self.WINDOWS_COLLECTION_SCRIPT)
            elif choice == "2":
                self._generate_script("Linux", self.LINUX_COLLECTION_SCRIPT)
            elif choice == "3":
                self._show_containment()
            elif choice == "4":
                self._show_eradication()
            elif choice == "5":
                self._show_recovery()
            elif choice == "6":
                self._show_templates()
            elif choice == "7":
                self._collect_evidence(confirm)

    def _generate_script(self, platform, script):
        print(f"\n[{platform} Evidence Collection Script]")
        ext = ".ps1" if platform == "Windows" else ".sh"
        path = input(f"  Save to (default: aegis_collect{ext}): ").strip() or f"aegis_collect{ext}"
        with open(path, "w") as f:
            f.write(script)
        if platform == "Linux":
            os.chmod(path, 0o755)
        print(f"  Script saved to: {path}")
        print(f"  Run {'as Administrator' if platform == 'Windows' else 'as root'}: {'powershell -ExecutionPolicy Bypass -File ' + path if platform == 'Windows' else 'sudo bash ' + path}")

    def _show_containment(self):
        print("\n[Containment Actions]")
        for category, platforms in self.CONTAINMENT_ACTIONS.items():
            print(f"\n  === {category} ===")
            for platform, actions in platforms.items():
                print(f"\n  --- {platform} ---")
                for a in actions:
                    print(f"\n  Action: {a['action']}")
                    print(f"  Command: {a['cmd']}")
                    print(f"  Risk:    {a['risk']}")

    def _show_eradication(self):
        print("\n[Eradication Checklists]")
        for incident_type, steps in self.ERADICATION_CHECKLISTS.items():
            print(f"\n  === {incident_type} ===")
            for i, step in enumerate(steps, 1):
                print(f"  [ ] {i}. {step}")

    def _show_recovery(self):
        print("\n[Recovery Workflow]")
        for phase in self.RECOVERY_CHECKLIST:
            print(f"\n  === Phase: {phase['phase']} ===")
            for i, step in enumerate(phase['steps'], 1):
                print(f"  [ ] {i}. {step}")

    def _show_templates(self):
        print("\n[Communication Templates]")
        for name, template in self.COMMUNICATION_TEMPLATES.items():
            print(f"\n  === {name} ===")
            print(template[:500] + "..." if len(template) > 500 else template)
            save = input(f"\n  Save {name} template to file? [y/N]: ").strip().lower()
            if save == "y":
                fname = name.lower().replace(" ", "_").replace("-", "_") + ".txt"
                with open(fname, "w") as f:
                    f.write(template)
                print(f"  Saved to: {fname}")

    def _collect_evidence(self, confirm):
        import platform as plat
        is_linux = plat.system() == "Linux"
        if not is_linux:
            print("  [!] Live collection only supported on Linux from this module")
            print("  Use the generated PowerShell script for Windows")
            return

        if not confirm("Collect evidence from THIS system? (creates files in /tmp)"):
            return

        outdir = f"/tmp/aegis_evidence_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(outdir, exist_ok=True)
        print(f"\n  Collecting to: {outdir}")

        commands = [
            ("uname.txt", "uname -a"),
            ("hostname.txt", "hostname"),
            ("ps_aux.txt", "ps auxwwf"),
            ("ss_all.txt", "ss -tulnp"),
            ("ip_addr.txt", "ip a"),
            ("ip_route.txt", "ip route"),
            ("arp.txt", "arp -an"),
            ("mount.txt", "mount"),
            ("df.txt", "df -h"),
            ("lsmod.txt", "lsmod"),
            ("last.txt", "last -20"),
            ("id.txt", "id"),
            ("env.txt", "env"),
        ]

        for fname, cmd in commands:
            try:
                result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=15)
                with open(os.path.join(outdir, fname), "w") as f:
                    f.write(result.stdout)
                print(f"  [+] {fname}")
            except Exception as e:
                print(f"  [-] {fname}: {e}")

        # Hash everything
        with open(os.path.join(outdir, "_hashes.txt"), "w") as hf:
            for fname in os.listdir(outdir):
                fpath = os.path.join(outdir, fname)
                if os.path.isfile(fpath) and fname != "_hashes.txt":
                    h = hashlib.sha256(open(fpath, "rb").read()).hexdigest()
                    hf.write(f"{h}  {fname}\n")

        print(f"\n  Evidence collected to: {outdir}")
        self.findings.append({"severity": "info", "title": "Evidence collected", "detail": f"Output: {outdir}"})

    def get_findings(self):
        return self.findings

if __name__ == "__main__":
    ir = IRAutomation()
    ir.run()
