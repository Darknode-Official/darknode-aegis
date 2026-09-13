#!/usr/bin/env python3
"""Advanced memory forensics toolkit — Volatility reference, acquisition, analysis methodology"""
import os, sys, subprocess, hashlib, json
from datetime import datetime

class MemoryForensics:
    name = "Memory Forensics Toolkit"
    description = "Advanced memory dump analysis with Volatility 3 reference, acquisition guides, and malware detection"
    category = "defense"
    mitre = ["T1003", "T1055", "T1014", "T1106"]

    VOLATILITY3_PLUGINS = {
        "Process Analysis": [
            {"plugin": "windows.pslist", "desc": "List running processes via PsActiveProcessHead", "reveals": "Active processes with PID, PPID, creation time", "look_for": "Unusual process names, unexpected parent-child relationships, processes with suspicious creation times", "mitre": "T1057", "cmd": "vol -f <dump> windows.pslist"},
            {"plugin": "windows.pstree", "desc": "Display process tree hierarchy", "reveals": "Parent-child process relationships", "look_for": "cmd.exe/powershell.exe spawned by unusual parents (excel.exe, outlook.exe, w3wp.exe)", "mitre": "T1059", "cmd": "vol -f <dump> windows.pstree"},
            {"plugin": "windows.psscan", "desc": "Scan for EPROCESS structures in memory", "reveals": "All processes including terminated and hidden ones", "look_for": "Processes found by psscan but missing from pslist (DKOM hiding)", "mitre": "T1014", "cmd": "vol -f <dump> windows.psscan"},
            {"plugin": "windows.handles", "desc": "List open handles for processes", "reveals": "Files, registry keys, mutexes, events held by processes", "look_for": "Handles to sensitive files, named mutexes (malware markers), handles to other processes", "mitre": "T1106", "cmd": "vol -f <dump> windows.handles --pid <PID>"},
            {"plugin": "windows.dlllist", "desc": "List loaded DLLs per process", "reveals": "All DLLs loaded by a process with full paths", "look_for": "DLLs loaded from temp/user directories, DLLs with no path, unexpected DLLs in system processes", "mitre": "T1055.001", "cmd": "vol -f <dump> windows.dlllist --pid <PID>"},
            {"plugin": "windows.cmdline", "desc": "Show process command line arguments", "reveals": "Full command line used to start each process", "look_for": "Encoded PowerShell (-enc), suspicious arguments, credential harvesting commands", "mitre": "T1059.001", "cmd": "vol -f <dump> windows.cmdline"},
            {"plugin": "windows.envars", "desc": "Display environment variables per process", "reveals": "Environment variables for each process", "look_for": "Modified PATH, suspicious env vars, credential leaks in environment", "mitre": "T1082", "cmd": "vol -f <dump> windows.envars --pid <PID>"},
            {"plugin": "windows.sessions", "desc": "List Windows sessions", "reveals": "Active logon sessions with authentication info", "look_for": "Multiple concurrent sessions, sessions from unexpected users", "mitre": "T1078", "cmd": "vol -f <dump> windows.sessions"},
            {"plugin": "windows.getsids", "desc": "Show SIDs for each process", "reveals": "Security identifiers (privileges) of each process", "look_for": "Processes running as SYSTEM unexpectedly, privilege escalation indicators", "mitre": "T1134", "cmd": "vol -f <dump> windows.getsids"},
            {"plugin": "windows.privileges", "desc": "Show process token privileges", "reveals": "Enabled/disabled privileges per process", "look_for": "SeDebugPrivilege, SeImpersonatePrivilege, SeBackupPrivilege enabled", "mitre": "T1134.001", "cmd": "vol -f <dump> windows.privileges --pid <PID>"},
        ],
        "Memory Analysis": [
            {"plugin": "windows.memmap", "desc": "Map process memory regions", "reveals": "Virtual address space layout with permissions", "look_for": "RWX regions (code injection), large private allocations", "mitre": "T1055", "cmd": "vol -f <dump> windows.memmap --pid <PID>"},
            {"plugin": "windows.vadinfo", "desc": "Detailed VAD (Virtual Address Descriptor) info", "reveals": "Memory region permissions, types, and mapped files", "look_for": "PAGE_EXECUTE_READWRITE regions not backed by files, injected code", "mitre": "T1055", "cmd": "vol -f <dump> windows.vadinfo --pid <PID>"},
            {"plugin": "windows.vadwalk", "desc": "Walk the VAD tree", "reveals": "Complete virtual address space with allocation types", "look_for": "Anomalous allocations, memory regions with unusual protections", "mitre": "T1055", "cmd": "vol -f <dump> windows.vadwalk --pid <PID>"},
            {"plugin": "windows.vadtree", "desc": "Display VAD tree as hierarchy", "reveals": "VAD tree structure showing memory layout", "look_for": "Orphaned VAD entries, modified VAD tree structure", "mitre": "T1055", "cmd": "vol -f <dump> windows.vadtree --pid <PID>"},
        ],
        "Network": [
            {"plugin": "windows.netscan", "desc": "Scan for network connections and sockets", "reveals": "TCP/UDP connections with local/remote addresses, states, owning PID", "look_for": "Connections to known C2 IPs, unusual ports, ESTABLISHED connections from unexpected processes", "mitre": "T1071", "cmd": "vol -f <dump> windows.netscan"},
            {"plugin": "windows.netstat", "desc": "Network connections via kernel structures", "reveals": "Active network connections similar to netstat", "look_for": "Same as netscan, cross-reference both for completeness", "mitre": "T1071", "cmd": "vol -f <dump> windows.netstat"},
        ],
        "Registry": [
            {"plugin": "windows.registry.hivelist", "desc": "List registry hives in memory", "reveals": "All loaded registry hives with virtual offsets", "look_for": "Non-standard hives, hives loaded from unusual locations", "mitre": "T1012", "cmd": "vol -f <dump> windows.registry.hivelist"},
            {"plugin": "windows.registry.printkey", "desc": "Print registry key values", "reveals": "Registry key contents at a specified path", "look_for": "Persistence mechanisms in Run/RunOnce, services, Winlogon, Shell", "mitre": "T1547.001", "cmd": "vol -f <dump> windows.registry.printkey --key 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'"},
            {"plugin": "windows.registry.userassist", "desc": "Parse UserAssist registry entries", "reveals": "Programs executed by the user with run counts and timestamps", "look_for": "Execution of hacking tools, suspicious programs, encoded entries", "mitre": "T1059", "cmd": "vol -f <dump> windows.registry.userassist"},
            {"plugin": "windows.registry.certificates", "desc": "Extract certificates from registry", "reveals": "Installed certificates in certificate stores", "look_for": "Rogue CA certificates, self-signed certs used for MITM", "mitre": "T1553.004", "cmd": "vol -f <dump> windows.registry.certificates"},
        ],
        "Malware Detection": [
            {"plugin": "windows.malfind", "desc": "Find injected/hidden code in process memory", "reveals": "Memory regions with RWX permissions containing executable code not backed by files", "look_for": "MZ headers in memory (injected PE), shellcode (0xFC 0x48), encoded payloads", "mitre": "T1055", "cmd": "vol -f <dump> windows.malfind"},
            {"plugin": "windows.callbacks", "desc": "List kernel notification callbacks", "reveals": "Registered kernel callbacks (process creation, image load, registry)", "look_for": "Callbacks pointing to non-standard drivers, rootkit hooks", "mitre": "T1014", "cmd": "vol -f <dump> windows.callbacks"},
            {"plugin": "windows.ssdt", "desc": "Show System Service Descriptor Table", "reveals": "SSDT entries mapping syscall numbers to kernel functions", "look_for": "Hooked SSDT entries pointing outside ntoskrnl/win32k (rootkit)", "mitre": "T1014", "cmd": "vol -f <dump> windows.ssdt"},
            {"plugin": "windows.modules", "desc": "List loaded kernel modules", "reveals": "All loaded kernel drivers with paths and addresses", "look_for": "Unsigned drivers, drivers loaded from temp directories, known malicious driver names", "mitre": "T1014", "cmd": "vol -f <dump> windows.modules"},
            {"plugin": "windows.modscan", "desc": "Scan for kernel module structures", "reveals": "All kernel modules including unloaded/hidden ones", "look_for": "Modules found by modscan but missing from modules (hidden drivers)", "mitre": "T1014", "cmd": "vol -f <dump> windows.modscan"},
            {"plugin": "windows.driverscan", "desc": "Scan for driver objects", "reveals": "All driver objects in kernel memory", "look_for": "Drivers without corresponding module, suspicious IRP dispatch tables", "mitre": "T1014", "cmd": "vol -f <dump> windows.driverscan"},
            {"plugin": "windows.driverirp", "desc": "Show IRP dispatch table for drivers", "reveals": "Function pointers for each IRP major function per driver", "look_for": "IRP handlers pointing to non-driver memory (IRP hooking rootkit)", "mitre": "T1014", "cmd": "vol -f <dump> windows.driverirp"},
            {"plugin": "windows.svcscan", "desc": "Scan for Windows service records", "reveals": "Service configurations including binary paths and start types", "look_for": "Services with unusual binary paths, services pointing to temp/user directories", "mitre": "T1543.003", "cmd": "vol -f <dump> windows.svcscan"},
        ],
        "File System": [
            {"plugin": "windows.filescan", "desc": "Scan for file objects in memory", "reveals": "All file objects with full paths, even deleted files", "look_for": "Suspicious file paths, files in temp directories, known malware filenames", "mitre": "T1083", "cmd": "vol -f <dump> windows.filescan"},
            {"plugin": "windows.dumpfiles", "desc": "Extract files from memory", "reveals": "Reconstructed files from memory (executables, documents, etc.)", "look_for": "Malware binaries, dropped payloads, exfiltrated data", "mitre": "T1005", "cmd": "vol -f <dump> windows.dumpfiles --pid <PID>"},
            {"plugin": "windows.mftscan", "desc": "Scan for MFT entries", "reveals": "NTFS Master File Table entries with timestamps", "look_for": "Recently created/modified files, timestomped files (MACE inconsistency)", "mitre": "T1070.006", "cmd": "vol -f <dump> windows.mftscan"},
        ],
        "Timeline": [
            {"plugin": "timeliner.Timeliner", "desc": "Create a comprehensive timeline from all artifacts", "reveals": "Chronological timeline combining process, file, registry, network events", "look_for": "Sequence of attacker actions, lateral movement timing, persistence establishment", "mitre": "multiple", "cmd": "vol -f <dump> timeliner.Timeliner"},
        ],
        "Linux": [
            {"plugin": "linux.pslist", "desc": "List running processes", "reveals": "Process list from task_struct linked list", "look_for": "Unusual processes, processes with suspicious command lines", "mitre": "T1057", "cmd": "vol -f <dump> linux.pslist"},
            {"plugin": "linux.pstree", "desc": "Process tree hierarchy", "reveals": "Parent-child relationships", "look_for": "Shell spawned by web server, reverse shell processes", "mitre": "T1059", "cmd": "vol -f <dump> linux.pstree"},
            {"plugin": "linux.bash", "desc": "Recover bash command history from memory", "reveals": "Commands typed by users including cleared history", "look_for": "Reconnaissance commands, credential access, data staging", "mitre": "T1059.004", "cmd": "vol -f <dump> linux.bash"},
            {"plugin": "linux.check_afinfo", "desc": "Check network protocol handler modifications", "reveals": "Hooked network protocol functions", "look_for": "Modified af_ops indicating packet filtering rootkit", "mitre": "T1014", "cmd": "vol -f <dump> linux.check_afinfo"},
            {"plugin": "linux.check_creds", "desc": "Check for credential structure modifications", "reveals": "Process credential anomalies", "look_for": "Processes with unexpected UID 0, modified credentials", "mitre": "T1068", "cmd": "vol -f <dump> linux.check_creds"},
            {"plugin": "linux.check_idt", "desc": "Check Interrupt Descriptor Table", "reveals": "IDT entries and handlers", "look_for": "Modified IDT entries pointing to suspicious code", "mitre": "T1014", "cmd": "vol -f <dump> linux.check_idt"},
            {"plugin": "linux.check_modules", "desc": "Check loaded kernel modules for anomalies", "reveals": "Kernel modules and their integrity", "look_for": "Hidden modules, modules not in /proc/modules", "mitre": "T1014", "cmd": "vol -f <dump> linux.check_modules"},
            {"plugin": "linux.check_syscall", "desc": "Check system call table for hooks", "reveals": "Syscall table entries", "look_for": "Hooked syscalls pointing outside kernel text", "mitre": "T1014", "cmd": "vol -f <dump> linux.check_syscall"},
            {"plugin": "linux.elfs", "desc": "List ELF binaries in process memory", "reveals": "Loaded ELF files per process", "look_for": "Injected shared libraries, preloaded malicious .so", "mitre": "T1055.009", "cmd": "vol -f <dump> linux.elfs"},
            {"plugin": "linux.keyboard_notifiers", "desc": "Check keyboard notification callbacks", "reveals": "Registered keyboard event handlers", "look_for": "Keylogger modules registered as keyboard notifiers", "mitre": "T1056.001", "cmd": "vol -f <dump> linux.keyboard_notifiers"},
            {"plugin": "linux.lsmod", "desc": "List loaded kernel modules", "reveals": "All loaded kernel modules with sizes", "look_for": "Unknown or suspicious kernel modules", "mitre": "T1547.006", "cmd": "vol -f <dump> linux.lsmod"},
            {"plugin": "linux.lsof", "desc": "List open files per process", "reveals": "All open file descriptors", "look_for": "Processes with open sockets, deleted but open files", "mitre": "T1083", "cmd": "vol -f <dump> linux.lsof"},
            {"plugin": "linux.malfind", "desc": "Find suspicious memory regions", "reveals": "Executable memory regions without file backing", "look_for": "Injected shellcode, in-memory payloads", "mitre": "T1055", "cmd": "vol -f <dump> linux.malfind"},
            {"plugin": "linux.mount", "desc": "List mounted filesystems", "reveals": "All mount points and filesystem types", "look_for": "Suspicious mounts, NFS shares, tmpfs with unusual content", "mitre": "T1078", "cmd": "vol -f <dump> linux.mount"},
            {"plugin": "linux.netstat", "desc": "List network connections", "reveals": "TCP/UDP connections with PIDs", "look_for": "Connections to C2, reverse shells, unusual ports", "mitre": "T1071", "cmd": "vol -f <dump> linux.netstat"},
            {"plugin": "linux.proc_maps", "desc": "Process memory maps", "reveals": "Memory regions with permissions per process", "look_for": "RWX anonymous regions, injected code", "mitre": "T1055", "cmd": "vol -f <dump> linux.proc_maps --pid <PID>"},
            {"plugin": "linux.sockstat", "desc": "Socket statistics", "reveals": "Detailed socket information", "look_for": "Listening backdoors, raw sockets", "mitre": "T1071", "cmd": "vol -f <dump> linux.sockstat"},
            {"plugin": "linux.tty_check", "desc": "Check TTY device handlers", "reveals": "TTY line discipline handlers", "look_for": "Hooked TTY handlers (keystroke interception)", "mitre": "T1056", "cmd": "vol -f <dump> linux.tty_check"},
        ],
    }

    ACQUISITION_TOOLS = {
        "Windows": [
            {"tool": "WinPmem", "type": "CLI", "desc": "Open-source memory acquisition by Rekall project", "cmd": "winpmem_mini_x64.exe output.raw", "format": "Raw", "notes": "Smallest footprint, recommended for incident response"},
            {"tool": "DumpIt", "type": "CLI", "desc": "Comae memory acquisition tool", "cmd": "DumpIt.exe", "format": "Raw", "notes": "Double-click to run, outputs to current directory. Very simple to use."},
            {"tool": "FTK Imager", "type": "GUI", "desc": "AccessData forensic imager with memory capture", "cmd": "File > Capture Memory...", "format": "Raw", "notes": "Also captures pagefile. GUI-based, good for less technical responders."},
            {"tool": "Belkasoft RAM Capturer", "type": "GUI", "desc": "Free memory capture tool", "cmd": "Run and click Capture", "format": "Raw", "notes": "Specifically designed to work with analysis-aware malware"},
            {"tool": "Magnet RAM Capture", "type": "GUI", "desc": "Free tool from Magnet Forensics", "cmd": "Run and select output", "format": "Raw", "notes": "Simple GUI, exports raw format compatible with most analysis tools"},
        ],
        "Linux": [
            {"tool": "LiME", "type": "Kernel Module", "desc": "Linux Memory Extractor kernel module", "cmd": "sudo insmod lime.ko 'path=/tmp/dump.lime format=lime'", "format": "LiME/Raw", "notes": "Must compile against target kernel headers. Most reliable Linux acquisition."},
            {"tool": "/proc/kcore", "type": "Built-in", "desc": "Kernel virtual file representing physical memory", "cmd": "sudo dd if=/proc/kcore of=/tmp/dump.core", "format": "ELF core", "notes": "Available on all Linux systems but may not capture all memory regions"},
            {"tool": "AVML", "type": "CLI", "desc": "Azure VM Memory Loader by Microsoft", "cmd": "sudo ./avml output.lime", "format": "LiME", "notes": "Static binary, no kernel module needed. Works on most Linux kernels."},
            {"tool": "fmem", "type": "Kernel Module", "desc": "Kernel module creating /dev/fmem device", "cmd": "sudo insmod fmem.ko && sudo dd if=/dev/fmem of=dump.raw bs=1M", "format": "Raw", "notes": "Creates a device node for memory access"},
        ],
        "macOS": [
            {"tool": "osxpmem", "type": "CLI", "desc": "macOS memory acquisition from Rekall project", "cmd": "sudo osxpmem -o output.aff4", "format": "AFF4", "notes": "Requires kernel extension approval in modern macOS"},
            {"tool": "MacQuisition", "type": "GUI", "desc": "Commercial macOS forensic tool by BlackBag", "cmd": "GUI-based", "format": "Multiple", "notes": "Commercial tool, handles T2/M1 chip challenges"},
        ],
        "Remote": [
            {"tool": "F-Response", "type": "Network", "desc": "Remote forensic access over network", "cmd": "Deploy agent, connect via iSCSI", "format": "Live access", "notes": "Exposes remote memory as local device. Commercial."},
            {"tool": "GRR Rapid Response", "type": "Agent", "desc": "Google's incident response framework", "cmd": "Deploy GRR agent, use web console", "format": "Multiple", "notes": "Open source, scalable, supports memory acquisition across fleet"},
            {"tool": "Velociraptor", "type": "Agent", "desc": "Endpoint monitoring and response tool", "cmd": "Deploy agent, use VQL for collection", "format": "Multiple", "notes": "Open source, VQL query language, very flexible"},
        ],
    }

    ANALYSIS_METHODOLOGY = [
        {"phase": "Acquisition", "steps": [
            "Verify write-blocker or read-only access to evidence",
            "Document the acquisition: time, tool used, hash of output",
            "Calculate MD5 and SHA256 of the memory dump",
            "Record system time and timezone from the target",
            "Note the operating system version and architecture",
        ]},
        {"phase": "Profile Identification", "steps": [
            "Determine OS version and architecture from the dump",
            "Vol3: vol -f dump.raw windows.info (or linux.info)",
            "Verify the profile produces valid results with pslist",
        ]},
        {"phase": "Process Analysis", "steps": [
            "Run pslist and pstree to enumerate all processes",
            "Compare pslist vs psscan to find hidden processes (DKOM)",
            "Review process command lines for suspicious arguments",
            "Check parent-child relationships for anomalies",
            "Look for processes with unexpected privileges",
            "Cross-reference process creation times with incident timeline",
        ]},
        {"phase": "Network Analysis", "steps": [
            "Run netscan to enumerate all network connections",
            "Identify connections to external IPs",
            "Check for listening backdoors on unusual ports",
            "Cross-reference network connections with process list",
            "Look for DNS resolution artifacts in memory strings",
        ]},
        {"phase": "Code Injection Detection", "steps": [
            "Run malfind to identify injected code regions",
            "Look for MZ/PE headers in non-file-backed memory",
            "Check VAD permissions for RWX anonymous regions",
            "Dump suspicious regions for further analysis",
            "Scan dumped regions with YARA rules",
        ]},
        {"phase": "Persistence Mechanisms", "steps": [
            "Check registry Run/RunOnce keys",
            "Examine services for suspicious entries",
            "Look for scheduled tasks",
            "Check for DLL search order hijacking",
            "Examine Winlogon and Shell registry values",
            "Look for WMI event subscriptions",
        ]},
        {"phase": "Credential Extraction", "steps": [
            "Check for credential structures in LSASS memory",
            "Look for cached domain credentials",
            "Check for Kerberos tickets in memory",
            "Look for cleartext passwords in process memory",
            "Check browser processes for saved credentials",
        ]},
        {"phase": "Timeline Construction", "steps": [
            "Run timeliner to create a comprehensive timeline",
            "Correlate process creation, file access, and network events",
            "Identify the initial compromise time",
            "Map lateral movement across the timeline",
            "Document the complete attack chain",
        ]},
    ]

    MALWARE_INDICATORS = {
        "Code Injection": [
            {"pattern": "Process Hollowing", "indicator": "Legitimate process with replaced code section, VAD shows committed memory with RWX but no file backing. Process image path differs from actual code.", "detection": "malfind shows PE header (MZ/4D5A) in memory not backed by the expected executable", "mitre": "T1055.012"},
            {"pattern": "Reflective DLL Injection", "indicator": "DLL loaded into process memory without appearing in PEB module list. No corresponding file on disk.", "detection": "dlllist misses it but malfind detects executable code. Look for ReflectiveLoader export.", "mitre": "T1055.001"},
            {"pattern": "Thread Injection (CreateRemoteThread)", "indicator": "Thread in target process with start address pointing to injected code region", "detection": "threads plugin shows thread with start address in non-module memory", "mitre": "T1055.003"},
            {"pattern": "APC Injection", "indicator": "Asynchronous Procedure Call queued to thread in target process", "detection": "Check thread APC queues, look for alertable wait states", "mitre": "T1055.004"},
            {"pattern": "AtomBombing", "indicator": "Code written to global atom table, then triggered via APC in target process", "detection": "Unusual atom table entries containing shellcode-like data", "mitre": "T1055"},
            {"pattern": "Early Bird Injection", "indicator": "APC queued to main thread of suspended process before it resumes", "detection": "Process created in suspended state with queued APCs", "mitre": "T1055.004"},
        ],
        "API Hooking": [
            {"pattern": "IAT Hooking", "indicator": "Import Address Table entries modified to point to attacker code", "detection": "Compare IAT entries against known-good values for the DLL version", "mitre": "T1056"},
            {"pattern": "EAT Hooking", "indicator": "Export Address Table of system DLLs modified", "detection": "Verify ntdll.dll and kernel32.dll export addresses against clean copies", "mitre": "T1056"},
            {"pattern": "Inline Hooking", "indicator": "First bytes of API function replaced with JMP to hook function", "detection": "Disassemble first 5-15 bytes of APIs, look for JMP/CALL instructions", "mitre": "T1056"},
        ],
        "Rootkit Indicators": [
            {"pattern": "DKOM (Direct Kernel Object Manipulation)", "indicator": "Process unlinked from ActiveProcessLinks doubly-linked list", "detection": "Compare pslist (walks list) vs psscan (carves structures) - discrepancy = hidden process", "mitre": "T1014"},
            {"pattern": "SSDT Hooking", "indicator": "System Service Descriptor Table entries modified to point outside ntoskrnl", "detection": "ssdt plugin shows entries pointing to non-standard addresses", "mitre": "T1014"},
            {"pattern": "IRP Hooking", "indicator": "Driver IRP dispatch table modified to intercept I/O operations", "detection": "driverirp plugin shows dispatch functions outside driver's address range", "mitre": "T1014"},
            {"pattern": "IDT Hooking", "indicator": "Interrupt Descriptor Table handlers replaced", "detection": "check_idt (Linux) or manual IDT verification", "mitre": "T1014"},
        ],
    }

    YARA_MEMORY_RULES = [
        {"name": "Cobalt_Strike_Beacon", "rule": 'rule CobaltStrike_Beacon {\n  strings:\n    $s1 = "%s (admin)" ascii\n    $s2 = "%s as %s\\\\%s" ascii\n    $s3 = "beacon.dll" ascii\n    $s4 = "ReflectiveLoader" ascii\n    $config = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? }\n  condition:\n    2 of ($s*) or $config\n}'},
        {"name": "Mimikatz_Memory", "rule": 'rule Mimikatz_Memory {\n  strings:\n    $s1 = "sekurlsa" ascii wide\n    $s2 = "kerberos" ascii wide\n    $s3 = "wdigest" ascii wide\n    $s4 = "gentilkiwi" ascii wide\n    $s5 = "mimikatz" ascii wide nocase\n  condition:\n    3 of them\n}'},
        {"name": "Metasploit_Meterpreter", "rule": 'rule Meterpreter_Memory {\n  strings:\n    $s1 = "metsrv.dll" ascii\n    $s2 = "stdapi" ascii\n    $s3 = "core_channel" ascii\n    $s4 = "packet_transmit" ascii\n    $reflective = "ReflectiveLoader" ascii\n  condition:\n    2 of ($s*) or $reflective\n}'},
        {"name": "Empire_Agent", "rule": 'rule Empire_Agent {\n  strings:\n    $s1 = "import base64" ascii\n    $s2 = "from Crypto" ascii\n    $s3 = "staging_key" ascii\n    $s4 = "get_task" ascii\n  condition:\n    3 of them\n}'},
        {"name": "Sliver_Implant", "rule": 'rule Sliver_Implant {\n  strings:\n    $s1 = "sliverpb" ascii\n    $s2 = "StartBeaconLoop" ascii\n    $s3 = "GatherSystemInfo" ascii\n    $go = "Go build" ascii\n  condition:\n    2 of ($s*) and $go\n}'},
        {"name": "Generic_Shellcode", "rule": 'rule Generic_Shellcode {\n  strings:\n    $sc1 = { FC 48 83 E4 F0 }  // x64 cld; and rsp, -0x10\n    $sc2 = { FC E8 ?? 00 00 00 } // x64 cld; call\n    $sc3 = { 31 C9 64 8B 41 30 } // x86 xor ecx,ecx; mov eax,fs:[ecx+0x30]\n    $sc4 = { 60 89 E5 31 C0 64 8B 50 30 } // x86 pushad; mov ebp,esp\n  condition:\n    any of them\n}'},
        {"name": "Encoded_PowerShell", "rule": 'rule Encoded_Powershell {\n  strings:\n    $enc1 = "-enc " ascii nocase\n    $enc2 = "-encodedcommand " ascii nocase\n    $enc3 = "FromBase64String" ascii\n    $enc4 = "[Convert]::" ascii\n    $iex = "Invoke-Expression" ascii nocase\n  condition:\n    any of ($enc*) and $iex\n}'},
        {"name": "Credential_Dumper", "rule": 'rule Credential_Dumper {\n  strings:\n    $s1 = "lsass.exe" ascii wide nocase\n    $s2 = "sekurlsa" ascii wide\n    $s3 = "SAM\\\\Domains\\\\Account" wide\n    $s4 = "NTDS.dit" ascii wide nocase\n    $s5 = "procdump" ascii wide nocase\n  condition:\n    2 of them\n}'},
        {"name": "Ransomware_Indicators", "rule": 'rule Ransomware_Behavior {\n  strings:\n    $s1 = "vssadmin delete shadows" ascii nocase\n    $s2 = "bcdedit /set" ascii nocase\n    $s3 = "wbadmin delete" ascii nocase\n    $s4 = "recoveryenabled no" ascii nocase\n    $s5 = ".onion" ascii\n    $s6 = "bitcoin" ascii nocase\n    $ransom = /YOUR FILES (HAVE BEEN|ARE) ENCRYPTED/i\n  condition:\n    2 of ($s*) or $ransom\n}'},
        {"name": "Keylogger", "rule": 'rule Keylogger_Indicators {\n  strings:\n    $api1 = "GetAsyncKeyState" ascii\n    $api2 = "SetWindowsHookEx" ascii\n    $api3 = "GetForegroundWindow" ascii\n    $api4 = "GetWindowText" ascii\n    $log = /keylog|keystroke|keypress/i\n  condition:\n    2 of ($api*) or $log\n}'},
        {"name": "Process_Injection_API", "rule": 'rule Process_Injection {\n  strings:\n    $api1 = "VirtualAllocEx" ascii\n    $api2 = "WriteProcessMemory" ascii\n    $api3 = "CreateRemoteThread" ascii\n    $api4 = "NtCreateThreadEx" ascii\n    $api5 = "QueueUserAPC" ascii\n    $api6 = "NtMapViewOfSection" ascii\n  condition:\n    ($api1 and $api2 and $api3) or ($api1 and $api2 and $api4) or $api5 or $api6\n}'},
        {"name": "Persistence_Registry", "rule": 'rule Registry_Persistence {\n  strings:\n    $r1 = "CurrentVersion\\\\Run" wide ascii\n    $r2 = "CurrentVersion\\\\RunOnce" wide ascii\n    $r3 = "Winlogon\\\\Shell" wide ascii\n    $r4 = "Image File Execution" wide ascii\n    $r5 = "AppInit_DLLs" wide ascii\n  condition:\n    any of them\n}'},
    ]

    def __init__(self, target=None, options=None):
        self.target = target or ""
        self.options = options or {}
        self.findings = []
        self.actions = []

    def run(self, confirm_fn=None):
        confirm = confirm_fn or (lambda msg: input(f"\n[?] {msg} [y/N]: ").strip().lower() == "y")
        print(f"\n[AEGIS] Memory Forensics Toolkit")
        print(f"{'='*60}")

        while True:
            print("\n  [1] Volatility 3 Plugin Reference")
            print("  [2] Memory Acquisition Guide")
            print("  [3] Analysis Methodology")
            print("  [4] Malware Indicators in Memory")
            print("  [5] YARA Rules for Memory Scanning")
            print("  [6] Analyze a Memory Dump")
            print("  [0] Exit")

            choice = input("\n  Choice: ").strip()
            if choice == "0":
                break
            elif choice == "1":
                self._show_plugins()
            elif choice == "2":
                self._show_acquisition()
            elif choice == "3":
                self._show_methodology()
            elif choice == "4":
                self._show_indicators()
            elif choice == "5":
                self._show_yara()
            elif choice == "6":
                self._analyze_dump(confirm)

    def _show_plugins(self):
        print("\n[Volatility 3 Plugin Reference]")
        for category, plugins in self.VOLATILITY3_PLUGINS.items():
            print(f"\n  --- {category} ({len(plugins)} plugins) ---")
            for p in plugins:
                print(f"\n  {p['plugin']}")
                print(f"    Command:  {p['cmd']}")
                print(f"    Reveals:  {p['reveals']}")
                print(f"    Look for: {p['look_for']}")
                print(f"    MITRE:    {p['mitre']}")

    def _show_acquisition(self):
        print("\n[Memory Acquisition Tools]")
        for platform, tools in self.ACQUISITION_TOOLS.items():
            print(f"\n  --- {platform} ---")
            for t in tools:
                print(f"\n  {t['tool']} ({t['type']})")
                print(f"    {t['desc']}")
                print(f"    Command: {t['cmd']}")
                print(f"    Format:  {t['format']}")
                print(f"    Notes:   {t['notes']}")

    def _show_methodology(self):
        print("\n[Memory Analysis Methodology]")
        for i, phase in enumerate(self.ANALYSIS_METHODOLOGY, 1):
            print(f"\n  Phase {i}: {phase['phase']}")
            for step in phase['steps']:
                print(f"    - {step}")

    def _show_indicators(self):
        print("\n[Malware Indicators in Memory]")
        for category, indicators in self.MALWARE_INDICATORS.items():
            print(f"\n  --- {category} ---")
            for ind in indicators:
                print(f"\n  {ind['pattern']} [{ind['mitre']}]")
                print(f"    Indicator: {ind['indicator']}")
                print(f"    Detection: {ind['detection']}")

    def _show_yara(self):
        print("\n[YARA Rules for Memory Scanning]")
        for rule in self.YARA_MEMORY_RULES:
            print(f"\n  --- {rule['name']} ---")
            print(f"  {rule['rule']}")

    def _analyze_dump(self, confirm):
        dump_path = input("\n  Memory dump path: ").strip()
        if not dump_path or not os.path.isfile(dump_path):
            print("  [!] File not found")
            return

        file_size = os.path.getsize(dump_path)
        print(f"\n  File: {dump_path}")
        print(f"  Size: {file_size / (1024*1024*1024):.2f} GB")

        if confirm("Calculate file hashes?"):
            print("  Calculating hashes (this may take a while)...")
            md5 = hashlib.md5()
            sha256 = hashlib.sha256()
            with open(dump_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    md5.update(chunk)
                    sha256.update(chunk)
            print(f"  MD5:    {md5.hexdigest()}")
            print(f"  SHA256: {sha256.hexdigest()}")
            self.findings.append({"severity": "info", "title": "Memory dump hashed", "detail": f"MD5: {md5.hexdigest()}, SHA256: {sha256.hexdigest()}"})

        vol_available = False
        try:
            subprocess.run(["vol", "--help"], capture_output=True, timeout=5)
            vol_available = True
        except Exception:
            pass

        if vol_available and confirm("Run Volatility 3 pslist on this dump?"):
            cmd = f"vol -f {dump_path} windows.pslist"
            print(f"  Running: {cmd}")
            try:
                result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=120)
                print(result.stdout[:3000] if result.stdout else result.stderr[:1000])
            except Exception as e:
                print(f"  [!] Error: {e}")
        elif not vol_available:
            print("  [!] Volatility 3 not installed. Install with: pip3 install volatility3")
            print("  Showing recommended commands instead:")
            print(f"    vol -f {dump_path} windows.pslist")
            print(f"    vol -f {dump_path} windows.pstree")
            print(f"    vol -f {dump_path} windows.netscan")
            print(f"    vol -f {dump_path} windows.malfind")
            print(f"    vol -f {dump_path} windows.cmdline")

    def get_findings(self):
        return self.findings

if __name__ == "__main__":
    m = MemoryForensics()
    m.run()
