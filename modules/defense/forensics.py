#!/usr/bin/env python3
"""AEGIS Digital Forensics Toolkit — file analysis, hashing, strings, entropy, and reference."""
import sys, os, hashlib, math, struct

FILE_SIGNATURES = {
    b"\x4d\x5a": "PE (Windows executable)",
    b"\x7fELF": "ELF (Linux executable)",
    b"\xfe\xed\xfa": "Mach-O (macOS executable)",
    b"\xcf\xfa\xed\xfe": "Mach-O 64-bit (macOS)",
    b"\x50\x4b\x03\x04": "ZIP archive (or DOCX/XLSX/APK/JAR)",
    b"\x50\x4b\x05\x06": "ZIP archive (empty)",
    b"\x89PNG": "PNG image",
    b"\xff\xd8\xff": "JPEG image",
    b"GIF87a": "GIF image (87a)",
    b"GIF89a": "GIF image (89a)",
    b"\x25\x50\x44\x46": "PDF document",
    b"\xd0\xcf\x11\xe0": "Microsoft Office (OLE2 - DOC/XLS/PPT)",
    b"Rar!\x1a\x07": "RAR archive",
    b"\x1f\x8b": "GZIP compressed",
    b"BZh": "BZIP2 compressed",
    b"\xfd\x37\x7a\x58\x5a": "XZ compressed",
    b"\x37\x7a\xbc\xaf": "7-Zip archive",
    b"\x00\x61\x73\x6d": "WebAssembly (WASM)",
    b"\xca\xfe\xba\xbe": "Java class file",
    b"dex\n": "Android DEX",
    b"\x53\x51\x4c\x69\x74\x65": "SQLite database",
    b"RIFF": "RIFF (AVI/WAV)",
    b"\x00\x00\x01\x00": "ICO icon",
    b"\x00\x00\x00\x1c\x66\x74\x79\x70": "MP4 video",
    b"OggS": "OGG audio/video",
    b"fLaC": "FLAC audio",
    b"ID3": "MP3 audio (ID3 tag)",
}

VOLATILITY_PLUGINS = [
    {"name": "imageinfo", "vol2": "vol.py -f DUMP imageinfo", "vol3": "vol -f DUMP windows.info", "desc": "Identify OS profile and architecture", "look_for": "Suggested Profile, KDBG address"},
    {"name": "pslist", "vol2": "vol.py -f DUMP --profile=PROFILE pslist", "vol3": "vol -f DUMP windows.pslist", "desc": "List running processes", "look_for": "Unusual processes, processes with no parent, processes running from temp dirs"},
    {"name": "pstree", "vol2": "vol.py -f DUMP --profile=PROFILE pstree", "vol3": "vol -f DUMP windows.pstree", "desc": "Process tree view", "look_for": "cmd.exe/powershell.exe spawned by unusual parents (word, excel, outlook)"},
    {"name": "psscan", "vol2": "vol.py -f DUMP --profile=PROFILE psscan", "vol3": "vol -f DUMP windows.psscan", "desc": "Scan for hidden/terminated processes", "look_for": "Processes not in pslist (hidden by rootkit)"},
    {"name": "netscan", "vol2": "vol.py -f DUMP --profile=PROFILE netscan", "vol3": "vol -f DUMP windows.netscan", "desc": "Network connections", "look_for": "Connections to external IPs, unusual ports, C2 indicators"},
    {"name": "malfind", "vol2": "vol.py -f DUMP --profile=PROFILE malfind", "vol3": "vol -f DUMP windows.malfind", "desc": "Find injected code", "look_for": "MZ headers in non-image regions, RWX memory sections"},
    {"name": "dlllist", "vol2": "vol.py -f DUMP --profile=PROFILE dlllist -p PID", "vol3": "vol -f DUMP windows.dlllist --pid PID", "desc": "Loaded DLLs per process", "look_for": "DLLs loaded from unusual paths (temp, user dirs)"},
    {"name": "handles", "vol2": "vol.py -f DUMP --profile=PROFILE handles -p PID", "vol3": "vol -f DUMP windows.handles --pid PID", "desc": "Open handles (files, registry, mutexes)", "look_for": "Mutexes (malware markers), open file handles to sensitive files"},
    {"name": "filescan", "vol2": "vol.py -f DUMP --profile=PROFILE filescan", "vol3": "vol -f DUMP windows.filescan", "desc": "Scan for file objects", "look_for": "Files in temp dirs, recently created executables"},
    {"name": "dumpfiles", "vol2": "vol.py -f DUMP --profile=PROFILE dumpfiles -Q OFFSET -D output/", "vol3": "vol -f DUMP windows.dumpfiles --virtaddr ADDR", "desc": "Extract files from memory", "look_for": "Extract suspicious files for analysis"},
    {"name": "hivelist", "vol2": "vol.py -f DUMP --profile=PROFILE hivelist", "vol3": "vol -f DUMP windows.registry.hivelist", "desc": "List registry hives in memory", "look_for": "SAM, SYSTEM, SOFTWARE hive addresses"},
    {"name": "hashdump", "vol2": "vol.py -f DUMP --profile=PROFILE hashdump", "vol3": "vol -f DUMP windows.hashdump", "desc": "Extract password hashes from SAM", "look_for": "NTLM hashes for offline cracking"},
    {"name": "timeliner", "vol2": "vol.py -f DUMP --profile=PROFILE timeliner", "vol3": "vol -f DUMP timeliner", "desc": "Create timeline of activity", "look_for": "Chronological sequence of events"},
    {"name": "cmdline", "vol2": "vol.py -f DUMP --profile=PROFILE cmdline", "vol3": "vol -f DUMP windows.cmdline", "desc": "Process command line arguments", "look_for": "Encoded PowerShell, suspicious arguments"},
    {"name": "consoles", "vol2": "vol.py -f DUMP --profile=PROFILE consoles", "vol3": "vol -f DUMP windows.consoles", "desc": "Console command history", "look_for": "Commands typed by attacker"},
    {"name": "svcscan", "vol2": "vol.py -f DUMP --profile=PROFILE svcscan", "vol3": "vol -f DUMP windows.svcscan", "desc": "Scan for Windows services", "look_for": "Services with unusual binary paths, new services"},
    {"name": "modules", "vol2": "vol.py -f DUMP --profile=PROFILE modules", "vol3": "vol -f DUMP windows.modules", "desc": "Loaded kernel modules/drivers", "look_for": "Unsigned drivers, rootkit drivers"},
    {"name": "ssdt", "vol2": "vol.py -f DUMP --profile=PROFILE ssdt", "vol3": "vol -f DUMP windows.ssdt", "desc": "System Service Descriptor Table", "look_for": "Hooked entries pointing outside ntoskrnl (rootkit)"},
    {"name": "callbacks", "vol2": "vol.py -f DUMP --profile=PROFILE callbacks", "vol3": "vol -f DUMP windows.callbacks", "desc": "Kernel callbacks", "look_for": "Callbacks registered by unknown modules"},
    {"name": "mutantscan", "vol2": "vol.py -f DUMP --profile=PROFILE mutantscan", "vol3": "vol -f DUMP windows.mutantscan", "desc": "Scan for mutex objects", "look_for": "Known malware mutexes"},
]

TSHARK_ONELINERS = [
    {"desc": "Extract HTTP requests", "cmd": "tshark -r capture.pcap -Y http.request -T fields -e ip.src -e http.host -e http.request.uri"},
    {"desc": "Extract DNS queries", "cmd": "tshark -r capture.pcap -Y dns.qr==0 -T fields -e ip.src -e dns.qry.name"},
    {"desc": "Extract credentials (HTTP Basic)", "cmd": "tshark -r capture.pcap -Y 'http.authbasic' -T fields -e ip.src -e http.authbasic"},
    {"desc": "Extract FTP credentials", "cmd": "tshark -r capture.pcap -Y 'ftp.request.command==USER || ftp.request.command==PASS' -T fields -e ip.src -e ftp.request.arg"},
    {"desc": "Follow TCP stream", "cmd": "tshark -r capture.pcap -z follow,tcp,ascii,STREAM_NUM"},
    {"desc": "Protocol hierarchy", "cmd": "tshark -r capture.pcap -z io,phs"},
    {"desc": "Top talkers", "cmd": "tshark -r capture.pcap -z endpoints,ip -q"},
    {"desc": "Extract TLS server names (SNI)", "cmd": "tshark -r capture.pcap -Y tls.handshake.extensions_server_name -T fields -e ip.dst -e tls.handshake.extensions_server_name"},
    {"desc": "Find beaconing (regular intervals)", "cmd": "tshark -r capture.pcap -Y 'ip.dst==C2_IP' -T fields -e frame.time_delta_displayed | sort -n | uniq -c"},
    {"desc": "Extract files from HTTP", "cmd": "tshark -r capture.pcap --export-objects http,exported_files/"},
]


class ForensicsToolkit:
    """Digital forensics analysis toolkit."""

    def identify_file(self, filepath):
        try:
            with open(filepath, "rb") as f:
                header = f.read(16)
            for sig, filetype in FILE_SIGNATURES.items():
                if header[:len(sig)] == sig:
                    return filetype
            return "Unknown file type"
        except Exception as e:
            return f"Error: {e}"

    def hash_file(self, filepath):
        try:
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()
            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
            return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}
        except Exception as e:
            return {"error": str(e)}

    def extract_strings(self, filepath, min_len=4):
        try:
            strings = []
            with open(filepath, "rb") as f:
                data = f.read()
            current = []
            for byte in data:
                if 32 <= byte < 127:
                    current.append(chr(byte))
                else:
                    if len(current) >= min_len:
                        strings.append("".join(current))
                    current = []
            if len(current) >= min_len:
                strings.append("".join(current))
            return strings
        except Exception as e:
            return [f"Error: {e}"]

    def entropy(self, filepath, chunk_size=256):
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            if not data:
                return {"overall": 0, "chunks": []}
            freq = [0] * 256
            for b in data:
                freq[b] += 1
            total = len(data)
            overall = -sum((c / total) * math.log2(c / total) for c in freq if c > 0)
            chunks = []
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i + chunk_size]
                cf = [0] * 256
                for b in chunk:
                    cf[b] += 1
                ct = len(chunk)
                ce = -sum((c / ct) * math.log2(c / ct) for c in cf if c > 0)
                chunks.append({"offset": i, "entropy": round(ce, 2)})
            return {"overall": round(overall, 4), "size": total, "chunks": chunks, "packed": overall > 7.0}
        except Exception as e:
            return {"error": str(e)}

    def volatility_reference(self):
        return VOLATILITY_PLUGINS

    def tshark_reference(self):
        return TSHARK_ONELINERS

    def run(self, confirm_fn=None):
        print("\n=== AEGIS Digital Forensics Toolkit ===")
        print("Commands: analyze <file>, hash <file>, strings <file>, entropy <file>, volatility, tshark, quit\n")
        while True:
            cmd = input("[forensics] > ").strip()
            if cmd.lower() in ("quit", "exit", "q"):
                break
            if cmd.lower().startswith("analyze "):
                filepath = cmd[8:].strip()
                filetype = self.identify_file(filepath)
                hashes = self.hash_file(filepath)
                ent = self.entropy(filepath)
                size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
                print(f"\n  File: {filepath}")
                print(f"  Size: {size:,} bytes")
                print(f"  Type: {filetype}")
                print(f"  MD5:    {hashes.get('md5', 'N/A')}")
                print(f"  SHA1:   {hashes.get('sha1', 'N/A')}")
                print(f"  SHA256: {hashes.get('sha256', 'N/A')}")
                print(f"  Entropy: {ent.get('overall', 'N/A')} {'(PACKED/ENCRYPTED)' if ent.get('packed') else '(normal)'}")
            elif cmd.lower().startswith("hash "):
                hashes = self.hash_file(cmd[5:].strip())
                for algo, val in hashes.items():
                    print(f"  {algo.upper()}: {val}")
            elif cmd.lower().startswith("strings "):
                strings = self.extract_strings(cmd[8:].strip())
                print(f"  Found {len(strings)} strings:")
                for s in strings[:50]:
                    print(f"    {s}")
                if len(strings) > 50:
                    print(f"    ... and {len(strings) - 50} more")
            elif cmd.lower().startswith("entropy "):
                ent = self.entropy(cmd[8:].strip())
                print(f"  Overall entropy: {ent.get('overall', 'N/A')}")
                print(f"  File size: {ent.get('size', 0):,} bytes")
                if ent.get("packed"):
                    print("  WARNING: High entropy suggests file is packed or encrypted")
            elif cmd.lower() == "volatility":
                print("\n  === Volatility Plugin Reference ===\n")
                for p in VOLATILITY_PLUGINS:
                    print(f"  [{p['name']}]")
                    print(f"    Vol2: {p['vol2']}")
                    print(f"    Vol3: {p['vol3']}")
                    print(f"    Desc: {p['desc']}")
                    print(f"    Look for: {p['look_for']}\n")
            elif cmd.lower() == "tshark":
                print("\n  === tshark One-Liners ===\n")
                for t in TSHARK_ONELINERS:
                    print(f"  {t['desc']}:")
                    print(f"    {t['cmd']}\n")
            else:
                print("  Commands: analyze, hash, strings, entropy, volatility, tshark, quit")


if __name__ == "__main__":
    ForensicsToolkit().run()
