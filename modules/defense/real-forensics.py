#!/usr/bin/env python3
"""AEGIS Real Digital Forensics Module
Wraps volatility3, binwalk, foremost, exiftool, yara, and VirusTotal
for memory analysis, disk imaging, metadata extraction, and evidence chain.
All operations require explicit user authorization.
"""
import subprocess
import shutil
import sys
import os
import json
import hashlib
import tempfile
import re
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from core.db import MissionDB

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.tree import Tree
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

LEGAL_DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════════╗
║                    AEGIS FORENSICS — LEGAL NOTICE                  ║
║                                                                    ║
║  This module performs REAL digital forensic analysis using system   ║
║  tools. You MUST have legal authorization to analyze the provided  ║
║  evidence. Unauthorized analysis of computer systems, memory       ║
║  dumps, or disk images may violate federal and state laws          ║
║  including the CFAA (18 U.S.C. § 1030).                           ║
║                                                                    ║
║  By proceeding you confirm:                                        ║
║   • You own or have written authorization to analyze the evidence  ║
║   • Analysis is for lawful security research or incident response  ║
║   • You accept full responsibility for all actions taken           ║
║   • Evidence chain-of-custody requirements are understood          ║
╚══════════════════════════════════════════════════════════════════════╝
"""

DB_PATH = os.path.expanduser("~/.aegis/missions.db")


def _run(cmd, timeout=300):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", 1
    except Exception as e:
        return "", str(e), 1


def _has(tool):
    return shutil.which(tool) is not None


def _file_hash(filepath, algo="sha256"):
    h = hashlib.new(algo)
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class AegisForensics:
    name = "Real Digital Forensics"
    description = "Memory analysis, disk forensics, metadata extraction, and evidence chain management"
    category = "defense"
    mitre = ["T1005", "T1039", "T1074", "T1119", "T1560"]

    TOOL_MAP = {
        "vol3": ["vol", "vol3", "volatility3", "python3 -m volatility3"],
        "binwalk": ["binwalk"],
        "foremost": ["foremost"],
        "fdisk": ["fdisk"],
        "exiftool": ["exiftool"],
        "yara": ["yara"],
    }

    def __init__(self, mission_id=None):
        self.mission_id = mission_id or f"forensics-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
        self.console = Console() if HAS_RICH else None
        self.db = MissionDB(DB_PATH)
        self.findings = []
        self.evidence_chain = []
        self.available_tools = {}
        self._check_tools()
        existing = self.db.get_mission(self.mission_id)
        if not existing:
            self.db.create_mission(
                self.mission_id,
                f"Forensic Analysis {self.mission_id}",
                "evidence",
                scope="digital forensics",
                classification="CONFIDENTIAL"
            )

    def _check_tools(self):
        for tool_name, candidates in self.TOOL_MAP.items():
            for candidate in candidates:
                binary = candidate.split()[0]
                if _has(binary):
                    self.available_tools[tool_name] = candidate
                    break
        if self.console:
            available = [f"[green]✓ {t}[/]" for t in self.available_tools]
            missing = [f"[red]✗ {t}[/]" for t in self.TOOL_MAP if t not in self.available_tools]
            self.console.print(Panel(
                "  ".join(available + missing),
                title="[bold]Forensic Tool Availability[/]",
                border_style="cyan"
            ))

    def _require_tool(self, tool_name):
        if tool_name not in self.available_tools:
            msg = f"Required tool '{tool_name}' not found. Install it to proceed."
            if self.console:
                self.console.print(f"[bold red]ERROR:[/] {msg}")
            return False
        return True

    def _authorize(self, action_desc):
        if self.console:
            self.console.print(LEGAL_DISCLAIMER, style="bold yellow")
            self.console.print(f"\n[bold cyan]Action:[/] {action_desc}\n")
        else:
            print(LEGAL_DISCLAIMER)
            print(f"\nAction: {action_desc}\n")
        response = input("Do you have legal authorization to proceed? (yes/no): ").strip().lower()
        if response not in ("yes", "y"):
            if self.console:
                self.console.print("[bold red]Operation cancelled — authorization not confirmed.[/]")
            else:
                print("Operation cancelled — authorization not confirmed.")
            return False
        return True

    def _add_finding(self, severity, title, detail, evidence_hash="", mitre=""):
        finding = {
            "severity": severity, "title": title, "detail": detail,
            "evidence_hash": evidence_hash, "mitre": mitre,
            "timestamp": datetime.utcnow().isoformat(), "module": self.name
        }
        self.findings.append(finding)
        self.db.add_finding(
            self.mission_id, severity, title, detail,
            module=self.name, mitre=mitre, evidence_hash=evidence_hash
        )
        return finding

    def _log_action(self, command, output="", result=""):
        self.db.add_action(
            self.mission_id, command, output=output[:4000],
            result=result, module=self.name
        )

    def _add_to_chain(self, description, filepath="", file_hash=""):
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "description": description,
            "filepath": filepath,
            "sha256": file_hash,
            "analyst": os.getenv("USER", "unknown")
        }
        self.evidence_chain.append(entry)
        if filepath and file_hash:
            self.db.add_evidence(
                self.mission_id, os.path.basename(filepath),
                file_hash, description=description, source_module=self.name
            )

    # ─── Memory Analysis ──────────────────────────────────────────────

    def analyze_memory(self, dump_path):
        if not os.path.isfile(dump_path):
            if self.console:
                self.console.print(f"[bold red]File not found:[/] {dump_path}")
            return None
        if not self._require_tool("vol3"):
            return None
        if not self._authorize(f"Analyze memory dump: {dump_path}"):
            return None

        vol_cmd = self.available_tools["vol3"]
        dump_hash = _file_hash(dump_path)
        self._add_to_chain(f"Memory dump submitted for analysis", dump_path, dump_hash)

        results = {"dump": dump_path, "sha256": dump_hash, "os_type": None, "plugins": {}}

        os_type = self._detect_dump_os(vol_cmd, dump_path)
        results["os_type"] = os_type

        if self.console:
            self.console.print(f"\n[bold cyan]Detected OS type:[/] {os_type or 'Unknown (defaulting to windows)'}")

        prefix = os_type if os_type in ("windows", "linux", "mac") else "windows"

        plugins = {
            "pslist": f"{prefix}.pslist.PsList",
            "netscan": f"{prefix}.netscan.NetScan" if prefix == "windows" else f"{prefix}.sockstat.Sockstat",
            "cmdline": f"{prefix}.cmdline.CmdLine",
            "filescan": f"{prefix}.filescan.FileScan" if prefix == "windows" else None,
            "hashdump": f"{prefix}.hashdump.Hashdump" if prefix == "windows" else None,
        }

        if self.console:
            progress = Progress(
                SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                BarColumn(), TimeElapsedColumn(), console=self.console
            )
            with progress:
                task = progress.add_task("Running volatility plugins...", total=len(plugins))
                for name, plugin in plugins.items():
                    if plugin is None:
                        progress.advance(task)
                        continue
                    progress.update(task, description=f"Running {name}...")
                    cmd = f"{vol_cmd} -f {dump_path} {plugin}"
                    stdout, stderr, rc = _run(cmd, timeout=600)
                    results["plugins"][name] = {
                        "command": cmd, "output": stdout, "error": stderr, "rc": rc
                    }
                    self._log_action(cmd, output=stdout, result="success" if rc == 0 else "failed")
                    if rc == 0 and stdout:
                        self._add_finding(
                            "INFO", f"Memory analysis: {name}",
                            f"Plugin {plugin} returned {len(stdout.splitlines())} lines",
                            evidence_hash=dump_hash, mitre="T1005"
                        )
                    progress.advance(task)
        else:
            for name, plugin in plugins.items():
                if plugin is None:
                    continue
                print(f"  Running {name}...")
                cmd = f"{vol_cmd} -f {dump_path} {plugin}"
                stdout, stderr, rc = _run(cmd, timeout=600)
                results["plugins"][name] = {
                    "command": cmd, "output": stdout, "error": stderr, "rc": rc
                }
                self._log_action(cmd, output=stdout, result="success" if rc == 0 else "failed")

        self._display_memory_results(results)
        return results

    def _detect_dump_os(self, vol_cmd, dump_path):
        cmd = f"{vol_cmd} -f {dump_path} banners.Banners 2>/dev/null"
        stdout, _, rc = _run(cmd, timeout=120)
        if rc == 0 and stdout:
            lower = stdout.lower()
            if "linux" in lower:
                return "linux"
            if "windows" in lower or "ntoskrnl" in lower:
                return "windows"
            if "darwin" in lower or "mac" in lower:
                return "mac"
        cmd2 = f"{vol_cmd} -f {dump_path} windows.info.Info 2>/dev/null"
        stdout2, _, rc2 = _run(cmd2, timeout=120)
        if rc2 == 0 and stdout2 and "NTBuildLab" in stdout2:
            return "windows"
        return "windows"

    def _display_memory_results(self, results):
        if not self.console:
            for name, data in results.get("plugins", {}).items():
                print(f"\n=== {name.upper()} ===")
                if data["rc"] == 0:
                    print(data["output"][:2000])
                else:
                    print(f"  Error: {data['error'][:500]}")
            return

        for name, data in results.get("plugins", {}).items():
            if data["rc"] != 0:
                self.console.print(f"[red]✗ {name}:[/] {data['error'][:200]}")
                continue
            lines = data["output"].splitlines()
            if len(lines) < 2:
                self.console.print(f"[yellow]⚠ {name}:[/] No data returned")
                continue
            table = Table(title=f"Memory Analysis: {name}", border_style="cyan", show_lines=False)
            headers = lines[0].split()
            for h in headers[:8]:
                table.add_column(h, style="white")
            for line in lines[1:51]:
                cols = line.split(None, len(headers) - 1)
                if len(cols) >= len(headers[:8]):
                    table.add_row(*[str(c) for c in cols[:8]])
            self.console.print(table)
            if len(lines) > 51:
                self.console.print(f"  [dim]... and {len(lines) - 51} more rows[/]")

    # ─── Disk Image Analysis ──────────────────────────────────────────

    def analyze_disk_image(self, image_path):
        if not os.path.isfile(image_path):
            if self.console:
                self.console.print(f"[bold red]File not found:[/] {image_path}")
            return None
        if not self._authorize(f"Analyze disk image: {image_path}"):
            return None

        img_hash = _file_hash(image_path)
        self._add_to_chain("Disk image submitted for analysis", image_path, img_hash)
        results = {"image": image_path, "sha256": img_hash, "partitions": None, "binwalk": None, "carved": None}

        if self.console:
            self.console.print("\n[bold cyan]═══ Disk Image Analysis ═══[/]\n")

        # Partition table
        if _has("fdisk"):
            if self.console:
                self.console.print("[cyan]▸ Analyzing partition table...[/]")
            cmd = f"fdisk -l {image_path} 2>/dev/null"
            stdout, stderr, rc = _run(cmd, timeout=60)
            results["partitions"] = stdout
            self._log_action(cmd, output=stdout, result="success" if rc == 0 else "failed")
            if self.console and stdout:
                self.console.print(Panel(stdout, title="Partition Table", border_style="green"))
            if rc == 0 and stdout:
                self._add_finding("INFO", "Partition table recovered",
                                  stdout[:1000], evidence_hash=img_hash, mitre="T1005")

        # Binwalk — embedded file detection
        if self._require_tool("binwalk"):
            if self.console:
                self.console.print("[cyan]▸ Scanning for embedded files with binwalk...[/]")
            cmd = f"binwalk --quiet {image_path}"
            stdout, stderr, rc = _run(cmd, timeout=300)
            results["binwalk"] = stdout
            self._log_action(cmd, output=stdout, result="success" if rc == 0 else "failed")
            if stdout:
                entries = [l for l in stdout.splitlines() if l.strip()]
                if self.console:
                    table = Table(title="Binwalk: Embedded Files", border_style="magenta")
                    table.add_column("Offset", style="cyan")
                    table.add_column("Type", style="white")
                    table.add_column("Description", style="green")
                    for line in entries[:50]:
                        parts = line.split(None, 2)
                        if len(parts) >= 3:
                            table.add_row(parts[0], parts[1], parts[2])
                        elif len(parts) == 2:
                            table.add_row(parts[0], parts[1], "")
                    self.console.print(table)
                self._add_finding("MEDIUM", "Embedded files detected in disk image",
                                  f"{len(entries)} embedded objects found",
                                  evidence_hash=img_hash, mitre="T1074")

        # Foremost — file carving
        if self._require_tool("foremost"):
            carve_dir = tempfile.mkdtemp(prefix="aegis_carve_")
            if self.console:
                self.console.print(f"[cyan]▸ Carving files with foremost → {carve_dir}[/]")
            cmd = f"foremost -i {image_path} -o {carve_dir}/output -T"
            stdout, stderr, rc = _run(cmd, timeout=600)
            self._log_action(cmd, output=stdout, result="success" if rc == 0 else "failed")
            carved_files = []
            output_dir = os.path.join(carve_dir, "output")
            if os.path.isdir(output_dir):
                for dirpath, dirnames, filenames in os.walk(output_dir):
                    for fn in filenames:
                        fp = os.path.join(dirpath, fn)
                        if os.path.getsize(fp) > 0:
                            carved_files.append({
                                "path": fp,
                                "size": os.path.getsize(fp),
                                "type": os.path.splitext(fn)[1]
                            })
            results["carved"] = carved_files
            if carved_files:
                self._add_finding("HIGH", "Files carved from disk image",
                                  f"{len(carved_files)} files recovered by foremost",
                                  evidence_hash=img_hash, mitre="T1005")
                if self.console:
                    table = Table(title=f"Carved Files ({len(carved_files)} recovered)", border_style="green")
                    table.add_column("File", style="white")
                    table.add_column("Size", style="cyan", justify="right")
                    table.add_column("Type", style="yellow")
                    for cf in carved_files[:40]:
                        size_str = f"{cf['size']:,}" if cf["size"] < 1048576 else f"{cf['size']/1048576:.1f}MB"
                        table.add_row(os.path.basename(cf["path"]), size_str, cf["type"])
                    self.console.print(table)
                    if len(carved_files) > 40:
                        self.console.print(f"  [dim]... and {len(carved_files) - 40} more files[/]")

        return results

    # ─── Metadata Extraction ─────────────────────────────────────────

    def extract_metadata(self, file_path):
        if not os.path.isfile(file_path):
            if self.console:
                self.console.print(f"[bold red]File not found:[/] {file_path}")
            return None
        if not self._require_tool("exiftool"):
            return None
        if not self._authorize(f"Extract metadata from: {file_path}"):
            return None

        fhash = _file_hash(file_path)
        self._add_to_chain("File submitted for metadata extraction", file_path, fhash)

        cmd = f"exiftool -json {file_path}"
        stdout, stderr, rc = _run(cmd, timeout=60)
        self._log_action(cmd, output=stdout, result="success" if rc == 0 else "failed")

        if rc != 0 or not stdout:
            if self.console:
                self.console.print(f"[red]exiftool failed:[/] {stderr}")
            return None

        try:
            metadata = json.loads(stdout)
            if isinstance(metadata, list) and metadata:
                metadata = metadata[0]
        except json.JSONDecodeError:
            metadata = {"raw": stdout}

        interesting_keys = [
            "Author", "Creator", "Producer", "CreateDate", "ModifyDate",
            "GPSLatitude", "GPSLongitude", "GPSPosition",
            "Software", "Make", "Model", "CameraModelName",
            "Artist", "Copyright", "Comment", "UserComment",
            "XPAuthor", "LastModifiedBy", "Company", "Manager",
            "MachineName", "HostComputer", "SerialNumber"
        ]

        sensitive = {}
        for key in interesting_keys:
            if key in metadata and metadata[key]:
                sensitive[key] = metadata[key]

        if sensitive:
            self._add_finding(
                "MEDIUM", "Sensitive metadata found in file",
                json.dumps(sensitive, indent=2),
                evidence_hash=fhash, mitre="T1005"
            )

        if self.console:
            table = Table(title=f"Metadata: {os.path.basename(file_path)}", border_style="cyan")
            table.add_column("Field", style="yellow")
            table.add_column("Value", style="white")
            for k, v in metadata.items():
                style = "bold red" if k in sensitive else "white"
                table.add_row(k, str(v)[:120], style=style)
            self.console.print(table)

        return metadata

    # ─── File Hashing & VirusTotal ────────────────────────────────────

    def hash_file(self, file_path):
        if not os.path.isfile(file_path):
            if self.console:
                self.console.print(f"[bold red]File not found:[/] {file_path}")
            return None
        if not self._authorize(f"Hash and check file: {file_path}"):
            return None

        hashes = {
            "md5": _file_hash(file_path, "md5"),
            "sha1": _file_hash(file_path, "sha1"),
            "sha256": _file_hash(file_path, "sha256"),
        }
        self._add_to_chain("File hashed for integrity verification", file_path, hashes["sha256"])

        if self.console:
            table = Table(title=f"File Hashes: {os.path.basename(file_path)}", border_style="cyan")
            table.add_column("Algorithm", style="yellow")
            table.add_column("Hash", style="green")
            for algo, digest in hashes.items():
                table.add_row(algo.upper(), digest)
            self.console.print(table)

        vt_result = self._check_virustotal(hashes["sha256"])
        hashes["virustotal"] = vt_result

        if vt_result and vt_result.get("positives", 0) > 0:
            self._add_finding(
                "CRITICAL",
                f"VirusTotal: {vt_result['positives']}/{vt_result.get('total', '?')} detections",
                json.dumps(vt_result.get("scans_summary", {}), indent=2),
                evidence_hash=hashes["sha256"], mitre="T1204"
            )
        elif vt_result and vt_result.get("positives", 0) == 0:
            self._add_finding(
                "INFO", "VirusTotal: clean",
                "No detections reported by VirusTotal",
                evidence_hash=hashes["sha256"]
            )

        self._log_action(
            f"hash_file {file_path}",
            output=json.dumps(hashes, indent=2),
            result="success"
        )
        return hashes

    def _check_virustotal(self, sha256):
        api_key = os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")
        if not api_key:
            if self.console:
                self.console.print("[yellow]⚠ No VirusTotal API key set (VT_API_KEY). Skipping VT check.[/]")
            return None

        cmd = (
            f'curl -s --max-time 30 '
            f'-H "x-apikey: {api_key}" '
            f'"https://www.virustotal.com/api/v3/files/{sha256}"'
        )
        stdout, stderr, rc = _run(cmd, timeout=45)
        if rc != 0 or not stdout:
            return None
        try:
            data = json.loads(stdout)
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0
            scans = attrs.get("last_analysis_results", {})
            flagged = {eng: info.get("result", "") for eng, info in scans.items()
                       if info.get("category") in ("malicious", "suspicious")}
            return {
                "positives": positives,
                "total": total,
                "scans_summary": dict(list(flagged.items())[:10]),
                "sha256": sha256
            }
        except (json.JSONDecodeError, KeyError):
            return None

    # ─── Filesystem Timeline ──────────────────────────────────────────

    def timeline_fs(self, mount_point):
        if not os.path.isdir(mount_point):
            if self.console:
                self.console.print(f"[bold red]Directory not found:[/] {mount_point}")
            return None
        if not self._authorize(f"Generate MAC timeline from: {mount_point}"):
            return None

        if self.console:
            self.console.print(f"[cyan]▸ Generating MAC timeline for {mount_point}...[/]")

        cmd = (
            f"find {mount_point} -xdev -type f "
            f"-printf '%T+ %A+ %C+ %s %p\\n' 2>/dev/null "
            f"| sort -r | head -5000"
        )
        stdout, stderr, rc = _run(cmd, timeout=300)
        self._log_action(cmd, output=stdout[:4000], result="success" if rc == 0 else "failed")

        if rc != 0 or not stdout:
            fallback = (
                f"find {mount_point} -xdev -type f -exec stat --format='%y %x %z %s %n' {{}} \\; "
                f"2>/dev/null | sort -r | head -5000"
            )
            stdout, stderr, rc = _run(fallback, timeout=300)
            self._log_action(fallback, output=stdout[:4000], result="success" if rc == 0 else "failed")

        if not stdout:
            if self.console:
                self.console.print("[red]Timeline generation failed — no output returned.[/]")
            return None

        timeline = []
        for line in stdout.splitlines():
            parts = line.split(None, 4)
            if len(parts) >= 5:
                timeline.append({
                    "modified": parts[0],
                    "accessed": parts[1],
                    "changed": parts[2],
                    "size": parts[3],
                    "path": parts[4]
                })
            elif len(parts) >= 2:
                timeline.append({"raw": line})

        tl_path = os.path.join(tempfile.gettempdir(), f"aegis_timeline_{self.mission_id}.json")
        with open(tl_path, "w") as f:
            json.dump(timeline, f, indent=2)

        tl_hash = _file_hash(tl_path)
        self._add_to_chain("MAC timeline generated", tl_path, tl_hash)
        self._add_finding(
            "INFO", f"Filesystem timeline: {len(timeline)} entries",
            f"Timeline saved to {tl_path}",
            evidence_hash=tl_hash, mitre="T1083"
        )

        if self.console:
            table = Table(title=f"MAC Timeline (latest {min(30, len(timeline))} entries)", border_style="cyan")
            table.add_column("Modified", style="yellow")
            table.add_column("Accessed", style="green")
            table.add_column("Size", style="cyan", justify="right")
            table.add_column("Path", style="white")
            for entry in timeline[:30]:
                mod = entry.get("modified", "?")[:19]
                acc = entry.get("accessed", "?")[:19]
                sz = entry.get("size", "?")
                path = entry.get("path", entry.get("raw", "?"))
                table.add_row(mod, acc, sz, path)
            self.console.print(table)
            self.console.print(f"\n[dim]Full timeline ({len(timeline)} entries) saved: {tl_path}[/]")

        return {"entries": len(timeline), "output_path": tl_path, "timeline": timeline[:100]}

    # ─── YARA Scanning ────────────────────────────────────────────────

    def yara_scan(self, scan_path, rules_dir):
        if not os.path.exists(scan_path):
            if self.console:
                self.console.print(f"[bold red]Scan target not found:[/] {scan_path}")
            return None
        if not os.path.isdir(rules_dir):
            if self.console:
                self.console.print(f"[bold red]Rules directory not found:[/] {rules_dir}")
            return None
        if not self._require_tool("yara"):
            return None
        if not self._authorize(f"YARA scan {scan_path} with rules from {rules_dir}"):
            return None

        if self.console:
            self.console.print(f"[cyan]▸ Loading YARA rules from {rules_dir}...[/]")

        rule_files = list(Path(rules_dir).rglob("*.yar")) + list(Path(rules_dir).rglob("*.yara"))
        if not rule_files:
            if self.console:
                self.console.print("[yellow]⚠ No .yar/.yara rule files found in rules directory.[/]")
            return None

        all_matches = []
        recursive = "-r" if os.path.isdir(scan_path) else ""

        if self.console:
            progress = Progress(
                SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                BarColumn(), TimeElapsedColumn(), console=self.console
            )
            with progress:
                task = progress.add_task("Scanning with YARA rules...", total=len(rule_files))
                for rule_file in rule_files:
                    progress.update(task, description=f"Rule: {rule_file.name}")
                    cmd = f"yara {recursive} {rule_file} {scan_path} 2>/dev/null"
                    stdout, stderr, rc = _run(cmd, timeout=300)
                    self._log_action(cmd, output=stdout, result="success" if rc == 0 else "failed")
                    if rc == 0 and stdout:
                        for line in stdout.splitlines():
                            parts = line.split(None, 1)
                            if len(parts) == 2:
                                all_matches.append({
                                    "rule": parts[0],
                                    "file": parts[1],
                                    "rule_source": str(rule_file)
                                })
                    progress.advance(task)
        else:
            for rule_file in rule_files:
                cmd = f"yara {recursive} {rule_file} {scan_path} 2>/dev/null"
                stdout, _, rc = _run(cmd, timeout=300)
                self._log_action(cmd, output=stdout, result="success" if rc == 0 else "failed")
                if rc == 0 and stdout:
                    for line in stdout.splitlines():
                        parts = line.split(None, 1)
                        if len(parts) == 2:
                            all_matches.append({
                                "rule": parts[0],
                                "file": parts[1],
                                "rule_source": str(rule_file)
                            })

        if all_matches:
            severity = "CRITICAL" if len(all_matches) > 10 else "HIGH"
            self._add_finding(
                severity, f"YARA: {len(all_matches)} matches found",
                json.dumps(all_matches[:50], indent=2),
                mitre="T1204"
            )
            for match in all_matches:
                self.db.add_ioc(
                    self.mission_id, "yara_match", match["rule"],
                    context=f"File: {match['file']}", confidence="high", source=self.name
                )

        if self.console:
            if all_matches:
                table = Table(title=f"YARA Matches ({len(all_matches)} hits)", border_style="red")
                table.add_column("Rule", style="bold red")
                table.add_column("Matched File", style="white")
                table.add_column("Rule Source", style="dim")
                for m in all_matches[:40]:
                    table.add_row(m["rule"], m["file"], os.path.basename(m["rule_source"]))
                self.console.print(table)
            else:
                self.console.print("[green]✓ No YARA matches — scan clean.[/]")

        return all_matches

    # ─── Evidence Chain ───────────────────────────────────────────────

    def collect_evidence(self, description=""):
        if not self.evidence_chain and not self.findings:
            if self.console:
                self.console.print("[yellow]No evidence collected yet.[/]")
            return None

        report = {
            "mission_id": self.mission_id,
            "collected_at": datetime.utcnow().isoformat(),
            "description": description or "AEGIS Forensic Evidence Package",
            "analyst": os.getenv("USER", "unknown"),
            "evidence_chain": self.evidence_chain,
            "findings_count": len(self.findings),
            "findings": self.findings,
            "stats": self.db.get_stats(self.mission_id)
        }

        report_path = os.path.join(
            tempfile.gettempdir(),
            f"aegis_evidence_{self.mission_id}.json"
        )
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        report_hash = _file_hash(report_path)
        self._add_to_chain("Evidence package compiled", report_path, report_hash)

        if self.console:
            self.console.print(Panel(
                f"[bold]Mission:[/] {self.mission_id}\n"
                f"[bold]Evidence Items:[/] {len(self.evidence_chain)}\n"
                f"[bold]Findings:[/] {len(self.findings)}\n"
                f"[bold]Package Hash:[/] {report_hash}\n"
                f"[bold]Saved To:[/] {report_path}",
                title="[bold green]Evidence Package[/]",
                border_style="green"
            ))

            if self.evidence_chain:
                tree = Tree("[bold cyan]Evidence Chain of Custody[/]")
                for item in self.evidence_chain:
                    node_label = (
                        f"[yellow]{item['timestamp']}[/] — "
                        f"{item['description']}"
                    )
                    node = tree.add(node_label)
                    if item.get("filepath"):
                        node.add(f"[dim]File: {item['filepath']}[/]")
                    if item.get("sha256"):
                        node.add(f"[dim]SHA256: {item['sha256'][:32]}...[/]")
                self.console.print(tree)

            stats = report["stats"]
            sev_table = Table(title="Finding Summary", border_style="cyan")
            sev_table.add_column("Severity", style="bold")
            sev_table.add_column("Count", justify="right")
            sev_colors = {"critical": "red", "high": "bright_red", "medium": "yellow", "low": "green", "info": "blue"}
            for sev in ("critical", "high", "medium", "low", "info"):
                count = stats.get(sev, 0)
                color = sev_colors.get(sev, "white")
                sev_table.add_row(f"[{color}]{sev.upper()}[/]", str(count))
            self.console.print(sev_table)

        return report

    def close(self):
        self.db.close()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="AEGIS Real Digital Forensics",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  %(prog)s memory /path/to/dump.raw\n"
               "  %(prog)s disk /path/to/image.dd\n"
               "  %(prog)s metadata /path/to/file.docx\n"
               "  %(prog)s hash /path/to/suspicious.exe\n"
               "  %(prog)s timeline /mnt/evidence\n"
               "  %(prog)s yara /mnt/evidence /path/to/yara-rules\n"
    )
    parser.add_argument("action", choices=["memory", "disk", "metadata", "hash", "timeline", "yara"],
                        help="Forensic action to perform")
    parser.add_argument("target", help="Target file, dump, image, or directory")
    parser.add_argument("extra", nargs="?", default=None,
                        help="Extra argument (rules dir for yara)")
    parser.add_argument("--mission", "-m", default=None, help="Mission ID")

    args = parser.parse_args()
    forensics = AegisForensics(mission_id=args.mission)

    try:
        if args.action == "memory":
            forensics.analyze_memory(args.target)
        elif args.action == "disk":
            forensics.analyze_disk_image(args.target)
        elif args.action == "metadata":
            forensics.extract_metadata(args.target)
        elif args.action == "hash":
            forensics.hash_file(args.target)
        elif args.action == "timeline":
            forensics.timeline_fs(args.target)
        elif args.action == "yara":
            if not args.extra:
                print("ERROR: yara action requires a rules directory as extra argument")
                sys.exit(1)
            forensics.yara_scan(args.target, args.extra)

        forensics.collect_evidence(f"CLI forensic analysis: {args.action} on {args.target}")
    finally:
        forensics.close()
