#!/usr/bin/env python3
"""AEGIS Real Password Cracking & Crypto Operations Module
Wraps hashcat, john, fcrackzip, aircrack-ng for real hash cracking,
archive cracking, WiFi capture cracking, and wordlist generation.
All operations require explicit user authorization.
"""
import subprocess
import shutil
import sys
import os
import re
import math
import string
import tempfile
import itertools
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from core.db import MissionDB

LEGAL_DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════════╗
║  AEGIS PASSWORD CRACKING MODULE — LEGAL DISCLAIMER                 ║
║                                                                    ║
║  This module performs real password cracking and crypto operations. ║
║  Use ONLY on systems and data you own or have written permission   ║
║  to test. Unauthorized password cracking is illegal under the      ║
║  Computer Fraud and Abuse Act (18 U.S.C. § 1030) and equivalent   ║
║  laws worldwide. You assume all liability for your actions.        ║
╚══════════════════════════════════════════════════════════════════════╝
"""

DB_PATH = os.path.expanduser("~/.aegis/missions.db")

HASH_TYPES = {
    "md5":         {"hashcat": 0,    "john": "Raw-MD5",       "regex": r"^[a-f0-9]{32}$"},
    "ntlm":        {"hashcat": 1000, "john": "NT",            "regex": r"^[A-F0-9]{32}$"},
    "sha1":        {"hashcat": 100,  "john": "Raw-SHA1",      "regex": r"^[a-f0-9]{40}$"},
    "sha256":      {"hashcat": 1400, "john": "Raw-SHA256",    "regex": r"^[a-f0-9]{64}$"},
    "sha512":      {"hashcat": 1700, "john": "Raw-SHA512",    "regex": r"^[a-f0-9]{128}$"},
    "bcrypt":      {"hashcat": 3200, "john": "bcrypt",        "regex": r"^\$2[aby]?\$\d{2}\$.{53}$"},
    "sha512crypt": {"hashcat": 1800, "john": "sha512crypt",   "regex": r"^\$6\$"},
    "sha256crypt": {"hashcat": 7400, "john": "sha256crypt",   "regex": r"^\$5\$"},
    "md5crypt":    {"hashcat": 500,  "john": "md5crypt",      "regex": r"^\$1\$"},
    "descrypt":    {"hashcat": 1500, "john": "descrypt",      "regex": r"^[a-zA-Z0-9./]{13}$"},
    "mysql323":    {"hashcat": 200,  "john": "mysql",         "regex": r"^[a-f0-9]{16}$"},
    "mysql41":     {"hashcat": 300,  "john": "mysql-sha1",    "regex": r"^\*[A-F0-9]{40}$"},
    "lm":          {"hashcat": 3000, "john": "LM",            "regex": r"^[A-F0-9]{32}$"},
    "mscash2":     {"hashcat": 2100, "john": "mscash2",       "regex": r"^\$DCC2\$"},
    "kerberos_tgs":{"hashcat": 13100,"john": "krb5tgs",       "regex": r"^\$krb5tgs\$"},
    "kerberos_as": {"hashcat": 18200,"john": "krb5asrep",     "regex": r"^\$krb5asrep\$"},
}

LEET_MAP = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7", "l": "1", "g": "9"}

COMMON_PASSWORDS = [
    "password", "123456", "qwerty", "letmein", "admin", "welcome",
    "monkey", "dragon", "master", "login", "abc123", "shadow",
    "sunshine", "princess", "trustno1", "iloveyou", "batman",
]

COMMON_PATTERNS = [
    (r"^[a-z]+$", "lowercase only"),
    (r"^[A-Z]+$", "uppercase only"),
    (r"^[0-9]+$", "digits only"),
    (r"^(.)\1+$", "repeated character"),
    (r"^(012|123|234|345|456|567|678|789|890)+", "sequential digits"),
    (r"^(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)+", "sequential letters"),
    (r"(19|20)\d{2}$", "ends with year"),
    (r"^[a-zA-Z]+\d{1,4}$", "word + short number"),
]


def _run(cmd, timeout=600):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "Operation timed out", 1
    except Exception as e:
        return "", str(e), 1


def _has(tool):
    return shutil.which(tool) is not None


def _confirm(prompt_text):
    try:
        from rich.console import Console
        console = Console()
        console.print(f"\n[bold yellow][?][/] {prompt_text}")
        resp = input("    Confirm (y/N): ").strip().lower()
    except ImportError:
        print(f"\n[?] {prompt_text}")
        resp = input("    Confirm (y/N): ").strip().lower()
    return resp in ("y", "yes")


class AegisCracker:
    name = "Real Password Cracking"
    description = "Hash identification, cracking with hashcat/john, archive & WiFi cracking, wordlist generation"
    category = "crypto"
    mitre = ["T1110.002", "T1110.004", "T1558"]

    def __init__(self, mission_id=None):
        self.mission_id = mission_id
        self.db = MissionDB(DB_PATH) if mission_id else None
        self.has_hashcat = _has("hashcat")
        self.has_john = _has("john")
        self.has_fcrackzip = _has("fcrackzip")
        self.has_zip2john = _has("zip2john")
        self.has_aircrack = _has("aircrack-ng")
        self.results = []
        try:
            from rich.console import Console
            from rich.table import Table
            from rich.panel import Panel
            from rich.progress import Progress
            self.console = Console()
            self._rich = True
        except ImportError:
            self._rich = False
            self.console = None

    def _log(self, msg, style="bold white"):
        if self._rich:
            self.console.print(f"  {msg}", style=style)
        else:
            print(f"  {msg}")

    def _log_action(self, command, output="", result=""):
        if self.db and self.mission_id:
            self.db.add_action(self.mission_id, command, output=output, result=result, module=self.name)

    def _log_finding(self, severity, title, detail=""):
        if self.db and self.mission_id:
            self.db.add_finding(self.mission_id, severity, title, detail=detail, module=self.name)

    def _log_credential(self, service, username, cred_type, value, host=""):
        if self.db and self.mission_id:
            self.db.add_credential(self.mission_id, service, username, cred_type, value, host=host, source=self.name)

    # ── Hash Identification ──────────────────────────────────────────
    def identify_hash(self, hash_string):
        hash_string = hash_string.strip()
        self._log(f"[*] Analyzing hash: {hash_string[:40]}{'...' if len(hash_string) > 40 else ''}")
        matches = []
        for name, info in HASH_TYPES.items():
            if re.match(info["regex"], hash_string, re.IGNORECASE):
                matches.append({
                    "type": name,
                    "hashcat_mode": info["hashcat"],
                    "john_format": info["john"],
                    "hash_preview": hash_string[:32] + ("..." if len(hash_string) > 32 else ""),
                })
        if not matches:
            self._log("[!] Unknown hash format", style="bold red")
            return []

        if self._rich:
            from rich.table import Table
            table = Table(title="Hash Identification Results")
            table.add_column("Type", style="cyan")
            table.add_column("Hashcat Mode", style="green")
            table.add_column("John Format", style="yellow")
            for m in matches:
                table.add_row(m["type"], str(m["hashcat_mode"]), m["john_format"])
            self.console.print(table)
        else:
            for m in matches:
                print(f"  Type: {m['type']}  Hashcat: {m['hashcat_mode']}  John: {m['john_format']}")

        self._log_action(f"identify_hash({hash_string[:32]}...)", result=str(matches))
        self.results.append({"action": "identify_hash", "matches": matches})
        return matches

    # ── Hash Cracking ────────────────────────────────────────────────
    def crack_hash(self, hash_string, wordlist, hash_type=None):
        if not os.path.isfile(wordlist):
            self._log(f"[!] Wordlist not found: {wordlist}", style="bold red")
            return None

        if hash_type is None:
            matches = self.identify_hash(hash_string)
            if not matches:
                self._log("[!] Could not auto-detect hash type. Specify hash_type.", style="bold red")
                return None
            hash_type = matches[0]["type"]

        if hash_type not in HASH_TYPES:
            self._log(f"[!] Unknown hash type: {hash_type}", style="bold red")
            return None

        info = HASH_TYPES[hash_type]
        print(LEGAL_DISCLAIMER)
        if not _confirm(f"Crack {hash_type.upper()} hash using wordlist '{os.path.basename(wordlist)}'?"):
            self._log("[!] Operation cancelled by user", style="bold yellow")
            return None

        tmpdir = tempfile.mkdtemp(prefix="aegis_crack_")
        hash_file = os.path.join(tmpdir, "hash.txt")
        with open(hash_file, "w") as f:
            f.write(hash_string.strip() + "\n")

        cracked = None
        if self.has_hashcat:
            cracked = self._crack_hashcat(hash_file, wordlist, info["hashcat"], tmpdir)
        if cracked is None and self.has_john:
            cracked = self._crack_john(hash_file, wordlist, info["john"], tmpdir)

        if cracked is None and not self.has_hashcat and not self.has_john:
            self._log("[!] Neither hashcat nor john is installed", style="bold red")
            return None

        if cracked:
            self._log(f"[+] CRACKED: {cracked}", style="bold green")
            self._log_finding("HIGH", f"Hash cracked ({hash_type})", f"Hash: {hash_string[:32]}... => {cracked}")
            self._log_credential("hash_crack", hash_type, "password", cracked)
            self.results.append({"action": "crack_hash", "type": hash_type, "result": cracked})
        else:
            self._log("[!] Hash not cracked with provided wordlist", style="bold yellow")
            self.results.append({"action": "crack_hash", "type": hash_type, "result": None})

        try:
            import shutil as _sh
            _sh.rmtree(tmpdir, ignore_errors=True)
        except:
            pass
        return cracked

    def _crack_hashcat(self, hash_file, wordlist, mode, tmpdir):
        self._log(f"[*] Running hashcat -m {mode} ...", style="bold cyan")
        potfile = os.path.join(tmpdir, "hashcat.pot")
        cmd = f"hashcat -m {mode} '{hash_file}' '{wordlist}' --force --potfile-path='{potfile}' --quiet -o '{tmpdir}/cracked.txt' 2>/dev/null"
        self._log_action(cmd)

        if self._rich:
            from rich.progress import Progress, SpinnerColumn, TextColumn
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=self.console) as progress:
                task = progress.add_task("Hashcat running...", total=None)
                stdout, stderr, rc = _run(cmd, timeout=600)
                progress.update(task, description="Hashcat finished")
        else:
            stdout, stderr, rc = _run(cmd, timeout=600)

        cracked_file = os.path.join(tmpdir, "cracked.txt")
        if os.path.isfile(cracked_file):
            with open(cracked_file) as f:
                for line in f:
                    if ":" in line:
                        return line.strip().split(":", 1)[1]

        show_out, _, _ = _run(f"hashcat -m {mode} '{hash_file}' --show --potfile-path='{potfile}' --quiet 2>/dev/null")
        if show_out and ":" in show_out:
            return show_out.strip().split(":", 1)[1]
        return None

    def _crack_john(self, hash_file, wordlist, fmt, tmpdir):
        self._log(f"[*] Running john --format={fmt} ...", style="bold cyan")
        session = os.path.join(tmpdir, "aegis_john")
        cmd = f"john --format='{fmt}' --wordlist='{wordlist}' --session='{session}' '{hash_file}' 2>/dev/null"
        self._log_action(cmd)

        if self._rich:
            from rich.progress import Progress, SpinnerColumn, TextColumn
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=self.console) as progress:
                task = progress.add_task("John running...", total=None)
                stdout, stderr, rc = _run(cmd, timeout=600)
                progress.update(task, description="John finished")
        else:
            stdout, stderr, rc = _run(cmd, timeout=600)

        show_out, _, _ = _run(f"john --show '{hash_file}' 2>/dev/null")
        if show_out:
            for line in show_out.splitlines():
                if ":" in line and "password hash" not in line.lower():
                    parts = line.strip().split(":")
                    if len(parts) >= 2 and parts[1]:
                        return parts[1]
        return None

    # ── ZIP Cracking ─────────────────────────────────────────────────
    def crack_zip(self, zip_path, wordlist):
        if not os.path.isfile(zip_path):
            self._log(f"[!] ZIP file not found: {zip_path}", style="bold red")
            return None
        if not os.path.isfile(wordlist):
            self._log(f"[!] Wordlist not found: {wordlist}", style="bold red")
            return None

        print(LEGAL_DISCLAIMER)
        if not _confirm(f"Crack ZIP archive '{os.path.basename(zip_path)}'?"):
            self._log("[!] Operation cancelled by user", style="bold yellow")
            return None

        cracked = None
        if self.has_fcrackzip:
            cracked = self._crack_zip_fcrackzip(zip_path, wordlist)

        if cracked is None and self.has_zip2john and self.has_john:
            cracked = self._crack_zip_john(zip_path, wordlist)

        if cracked is None and not self.has_fcrackzip and not (self.has_zip2john and self.has_john):
            self._log("[!] Neither fcrackzip nor zip2john+john installed", style="bold red")
            return None

        if cracked:
            self._log(f"[+] ZIP CRACKED: {cracked}", style="bold green")
            self._log_finding("MEDIUM", "ZIP password cracked", f"Archive: {zip_path} => {cracked}")
            self._log_credential("zip_archive", os.path.basename(zip_path), "password", cracked)
        else:
            self._log("[!] ZIP not cracked with provided wordlist", style="bold yellow")
        return cracked

    def _crack_zip_fcrackzip(self, zip_path, wordlist):
        self._log("[*] Running fcrackzip ...", style="bold cyan")
        cmd = f"fcrackzip -D -p '{wordlist}' -u '{zip_path}' 2>/dev/null"
        self._log_action(cmd)
        stdout, stderr, rc = _run(cmd, timeout=600)
        if stdout:
            match = re.search(r"PASSWORD FOUND.*?:\s*(.+)", stdout, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None

    def _crack_zip_john(self, zip_path, wordlist):
        self._log("[*] Running zip2john + john ...", style="bold cyan")
        tmpdir = tempfile.mkdtemp(prefix="aegis_zip_")
        hash_file = os.path.join(tmpdir, "zip_hash.txt")
        cmd_extract = f"zip2john '{zip_path}' > '{hash_file}' 2>/dev/null"
        self._log_action(cmd_extract)
        _run(cmd_extract)
        if not os.path.isfile(hash_file) or os.path.getsize(hash_file) == 0:
            return None
        session = os.path.join(tmpdir, "aegis_zip_john")
        cmd = f"john --wordlist='{wordlist}' --session='{session}' '{hash_file}' 2>/dev/null"
        self._log_action(cmd)
        _run(cmd, timeout=600)
        show_out, _, _ = _run(f"john --show '{hash_file}' 2>/dev/null")
        if show_out:
            for line in show_out.splitlines():
                if ":" in line and "password hash" not in line.lower():
                    parts = line.split(":")
                    if len(parts) >= 2 and parts[1]:
                        return parts[1]
        try:
            import shutil as _sh
            _sh.rmtree(tmpdir, ignore_errors=True)
        except:
            pass
        return None

    # ── WiFi Capture Cracking ────────────────────────────────────────
    def crack_wifi(self, capture_path, wordlist):
        if not os.path.isfile(capture_path):
            self._log(f"[!] Capture file not found: {capture_path}", style="bold red")
            return None
        if not os.path.isfile(wordlist):
            self._log(f"[!] Wordlist not found: {wordlist}", style="bold red")
            return None
        if not self.has_aircrack:
            self._log("[!] aircrack-ng is not installed", style="bold red")
            return None

        print(LEGAL_DISCLAIMER)
        if not _confirm(f"Crack WiFi capture '{os.path.basename(capture_path)}'?"):
            self._log("[!] Operation cancelled by user", style="bold yellow")
            return None

        self._log("[*] Running aircrack-ng ...", style="bold cyan")
        cmd = f"aircrack-ng -w '{wordlist}' -q '{capture_path}' 2>/dev/null"
        self._log_action(cmd)

        if self._rich:
            from rich.progress import Progress, SpinnerColumn, TextColumn
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=self.console) as progress:
                task = progress.add_task("Aircrack-ng running...", total=None)
                stdout, stderr, rc = _run(cmd, timeout=1200)
                progress.update(task, description="Aircrack-ng finished")
        else:
            stdout, stderr, rc = _run(cmd, timeout=1200)

        match = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", stdout)
        if match:
            key = match.group(1)
            self._log(f"[+] WIFI KEY CRACKED: {key}", style="bold green")
            self._log_finding("HIGH", "WiFi key cracked", f"Capture: {capture_path} => {key}")
            self._log_credential("wifi", os.path.basename(capture_path), "wpa_key", key)
            return key
        else:
            self._log("[!] WiFi key not cracked with provided wordlist", style="bold yellow")
            return None

    # ── Wordlist Generation ──────────────────────────────────────────
    def generate_wordlist(self, base_words, rules=None, output_path=None):
        if rules is None:
            rules = ["leet", "case", "numbers", "special"]

        if output_path is None:
            output_path = os.path.join(tempfile.gettempdir(), "aegis_wordlist.txt")

        self._log(f"[*] Generating wordlist from {len(base_words)} base words, rules: {rules}", style="bold cyan")
        mutations = set()
        for word in base_words:
            mutations.add(word)
            if "case" in rules:
                mutations.add(word.lower())
                mutations.add(word.upper())
                mutations.add(word.capitalize())
                mutations.add(word.swapcase())
            if "leet" in rules:
                leet = word.lower()
                for orig, repl in LEET_MAP.items():
                    leet = leet.replace(orig, repl)
                mutations.add(leet)
                mutations.add(leet.upper())
            if "numbers" in rules:
                for n in ["0", "1", "12", "123", "1234", "!", "69", "007", "99", "01"]:
                    mutations.add(word + n)
                    mutations.add(n + word)
                for year in range(1990, 2027):
                    mutations.add(word + str(year))
            if "special" in rules:
                for ch in ["!", "@", "#", "$", ".", "*", "!!", "!@#"]:
                    mutations.add(word + ch)
                    mutations.add(ch + word)
            if "reverse" in rules:
                mutations.add(word[::-1])
            if "double" in rules:
                mutations.add(word + word)
                mutations.add(word + word.capitalize())

        sorted_words = sorted(mutations)
        with open(output_path, "w") as f:
            for w in sorted_words:
                f.write(w + "\n")

        self._log(f"[+] Generated {len(sorted_words)} candidates -> {output_path}", style="bold green")
        self._log_action(f"generate_wordlist(base={len(base_words)}, rules={rules})", result=f"{len(sorted_words)} candidates")
        return output_path

    # ── Password Strength Check ──────────────────────────────────────
    def check_password_strength(self, password):
        self._log(f"[*] Analyzing password strength ({len(password)} chars)", style="bold cyan")
        feedback = []
        score = 0

        length = len(password)
        if length >= 16:
            score += 30
        elif length >= 12:
            score += 25
        elif length >= 8:
            score += 15
        elif length >= 6:
            score += 5
        else:
            feedback.append("Password is too short (< 6 chars)")

        charset = 0
        if re.search(r"[a-z]", password):
            charset += 26
        if re.search(r"[A-Z]", password):
            charset += 26
        if re.search(r"[0-9]", password):
            charset += 10
        if re.search(r"[^a-zA-Z0-9]", password):
            charset += 33

        if charset >= 85:
            score += 20
            feedback.append("Good character diversity")
        elif charset >= 36:
            score += 10
        else:
            feedback.append("Low character diversity")

        if charset > 0 and length > 0:
            entropy = length * math.log2(charset)
            if entropy >= 60:
                score += 20
            elif entropy >= 40:
                score += 10
            elif entropy >= 28:
                score += 5
            else:
                feedback.append(f"Low entropy ({entropy:.1f} bits)")
        else:
            entropy = 0

        if password.lower() in COMMON_PASSWORDS:
            score = max(score - 40, 0)
            feedback.append("Password is in common password list")

        for pattern, desc in COMMON_PATTERNS:
            if re.search(pattern, password, re.IGNORECASE):
                score = max(score - 10, 0)
                feedback.append(f"Weak pattern detected: {desc}")

        if len(set(password)) <= 3:
            score = max(score - 15, 0)
            feedback.append("Very few unique characters")

        score += min(15, len(set(password)))

        score = max(0, min(100, score))

        if score >= 80:
            rating = "STRONG"
            color = "bold green"
        elif score >= 60:
            rating = "GOOD"
            color = "bold blue"
        elif score >= 40:
            rating = "FAIR"
            color = "bold yellow"
        elif score >= 20:
            rating = "WEAK"
            color = "bold red"
        else:
            rating = "VERY WEAK"
            color = "bold red"

        result = {
            "score": score,
            "rating": rating,
            "length": length,
            "charset_size": charset,
            "entropy_bits": round(entropy, 1),
            "feedback": feedback,
        }

        if self._rich:
            from rich.panel import Panel
            from rich.table import Table
            table = Table(show_header=False, box=None)
            table.add_column("Key", style="cyan")
            table.add_column("Value")
            table.add_row("Score", f"[{color}]{score}/100 ({rating})[/]")
            table.add_row("Length", str(length))
            table.add_row("Charset Size", str(charset))
            table.add_row("Entropy", f"{entropy:.1f} bits")
            if feedback:
                table.add_row("Feedback", "\n".join(f"• {f}" for f in feedback))
            self.console.print(Panel(table, title="Password Strength Analysis", border_style=color))
        else:
            print(f"  Score: {score}/100 ({rating})")
            print(f"  Entropy: {entropy:.1f} bits")
            for f in feedback:
                print(f"    - {f}")

        self.results.append({"action": "check_password_strength", "result": result})
        return result


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="AEGIS Real Password Cracking Module")
    sub = parser.add_subparsers(dest="command")

    p_id = sub.add_parser("identify", help="Identify a hash type")
    p_id.add_argument("hash", help="Hash string to identify")

    p_crack = sub.add_parser("crack", help="Crack a hash")
    p_crack.add_argument("hash", help="Hash string to crack")
    p_crack.add_argument("-w", "--wordlist", default="/usr/share/wordlists/rockyou.txt", help="Wordlist path")
    p_crack.add_argument("-t", "--type", dest="hash_type", default=None, help="Hash type (md5, sha1, ntlm, ...)")
    p_crack.add_argument("-m", "--mission", default=None, help="Mission ID for DB logging")

    p_zip = sub.add_parser("zip", help="Crack a ZIP archive")
    p_zip.add_argument("zipfile", help="ZIP file path")
    p_zip.add_argument("-w", "--wordlist", default="/usr/share/wordlists/rockyou.txt", help="Wordlist path")
    p_zip.add_argument("-m", "--mission", default=None, help="Mission ID")

    p_wifi = sub.add_parser("wifi", help="Crack a WiFi capture")
    p_wifi.add_argument("capture", help="Capture file (.cap/.pcap)")
    p_wifi.add_argument("-w", "--wordlist", default="/usr/share/wordlists/rockyou.txt", help="Wordlist path")
    p_wifi.add_argument("-m", "--mission", default=None, help="Mission ID")

    p_wl = sub.add_parser("wordlist", help="Generate a custom wordlist")
    p_wl.add_argument("words", nargs="+", help="Base words")
    p_wl.add_argument("-o", "--output", default=None, help="Output file path")
    p_wl.add_argument("-r", "--rules", nargs="+", default=["leet", "case", "numbers", "special"],
                       help="Mutation rules: leet case numbers special reverse double")

    p_pw = sub.add_parser("strength", help="Check password strength")
    p_pw.add_argument("password", help="Password to check")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    cracker = AegisCracker(mission_id=getattr(args, "mission", None))

    if args.command == "identify":
        cracker.identify_hash(args.hash)
    elif args.command == "crack":
        cracker.crack_hash(args.hash, args.wordlist, hash_type=args.hash_type)
    elif args.command == "zip":
        cracker.crack_zip(args.zipfile, args.wordlist)
    elif args.command == "wifi":
        cracker.crack_wifi(args.capture, args.wordlist)
    elif args.command == "wordlist":
        cracker.generate_wordlist(args.words, rules=args.rules, output_path=args.output)
    elif args.command == "strength":
        cracker.check_password_strength(args.password)
