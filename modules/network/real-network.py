#!/usr/bin/env python3
"""AEGIS Real Network Operations Module
Packet capture, traffic analysis, ARP discovery, traceroute, bandwidth
monitoring, and WiFi reconnaissance using real system tools.
All operations require explicit user authorization.
"""
import subprocess
import shutil
import sys
import os
import re
import time
import json
import tempfile
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from core.db import MissionDB

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.live import Live
    from rich.text import Text
    from rich.columns import Columns
except ImportError:
    print("[!] rich library required: pip install rich")
    sys.exit(1)

console = Console()

LEGAL_DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════════╗
║                    AEGIS — LEGAL DISCLAIMER                        ║
║                                                                    ║
║  This tool performs REAL network operations including packet        ║
║  capture, traffic analysis, and host discovery.                    ║
║                                                                    ║
║  You MUST have explicit written authorization from the network     ║
║  owner before running any of these operations.                     ║
║                                                                    ║
║  Unauthorized network interception or scanning is illegal under    ║
║  the Computer Fraud and Abuse Act (18 U.S.C. § 1030), the         ║
║  Wiretap Act (18 U.S.C. § 2511), and equivalent laws worldwide.   ║
║                                                                    ║
║  The operator assumes ALL legal responsibility.                    ║
╚══════════════════════════════════════════════════════════════════════╝
"""

DB_PATH = os.path.expanduser("~/.aegis/missions.db")
OUTPUT_DIR = os.path.expanduser("~/.aegis/captures")


def _run(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 1
    except Exception as e:
        return "", str(e), 1


def _has(tool):
    return shutil.which(tool) is not None


def _confirm(action_desc):
    console.print(f"\n[bold yellow][?] Proposed action:[/] {action_desc}")
    try:
        resp = input("    Authorize this operation? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return resp in ("y", "yes")


class AegisNetwork:
    name = "Real Network Operations"
    description = "Packet capture, traffic analysis, host discovery, and WiFi recon using real tools"
    category = "network"
    mitre = ["T1040", "T1046", "T1016", "T1018"]

    def __init__(self, mission_id=None):
        self.mission_id = mission_id or f"net-{int(time.time())}"
        self.db = MissionDB(DB_PATH)
        self.findings = []
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        self.has_tshark = _has("tshark")
        self.has_tcpdump = _has("tcpdump")
        self.has_arpscan = _has("arp-scan")
        self.has_nmap = _has("nmap")
        self.has_traceroute = _has("traceroute")
        self.has_ifstat = _has("ifstat")
        self.has_iwlist = _has("iwlist")
        self.has_airmon = _has("airmon-ng")

    def _tool_check(self, primary, fallback=None):
        if _has(primary):
            return primary
        if fallback and _has(fallback):
            return fallback
        return None

    def _log_action(self, command, output="", result=""):
        self.db.add_action(
            self.mission_id, command, output=output[:4000],
            result=result, module=self.name
        )

    def _add_finding(self, severity, title, detail="", host="", port=0):
        self.findings.append({
            "severity": severity, "title": title, "detail": detail,
            "host": host, "port": port
        })
        self.db.add_finding(
            self.mission_id, severity, title, detail=detail,
            module=self.name, host=host, port=port
        )

    # ── 1. Packet Capture ────────────────────────────────────────────

    def packet_capture(self, interface="eth0", duration=30, bpf_filter="",
                       output_file=None):
        console.print(Panel(LEGAL_DISCLAIMER, style="red"))
        desc = (f"Capture packets on interface '{interface}' for {duration}s"
                + (f" with filter '{bpf_filter}'" if bpf_filter else ""))
        if not _confirm(desc):
            console.print("[yellow][-] Capture cancelled by operator[/]")
            return None

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        outfile = output_file or os.path.join(OUTPUT_DIR, f"capture_{ts}.pcap")

        tool = self._tool_check("tshark", "tcpdump")
        if not tool:
            console.print("[red][!] Neither tshark nor tcpdump found[/]")
            return None

        if tool == "tshark":
            cmd = f"tshark -i {interface} -a duration:{duration} -w {outfile}"
            if bpf_filter:
                cmd += f" -f \"{bpf_filter}\""
        else:
            cmd = f"tcpdump -i {interface} -G {duration} -W 1 -w {outfile}"
            if bpf_filter:
                cmd += f" \"{bpf_filter}\""

        console.print(f"[cyan][*] Running:[/] {cmd}")
        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), TimeElapsedColumn(), console=console
        ) as progress:
            task = progress.add_task(f"Capturing on {interface}...", total=duration)
            stdout, stderr, rc = _run(cmd, timeout=duration + 30)
            progress.update(task, completed=duration)

        self._log_action(cmd, output=stdout or stderr, result="OK" if rc == 0 else "FAIL")

        if rc == 0 and os.path.exists(outfile):
            size = os.path.getsize(outfile)
            console.print(f"[green][+] Capture saved: {outfile} ({size:,} bytes)[/]")
            self._add_finding("INFO", "Packet capture completed",
                              f"Interface: {interface}, Duration: {duration}s, "
                              f"File: {outfile}, Size: {size} bytes")
            return outfile
        else:
            console.print(f"[red][!] Capture failed: {stderr}[/]")
            return None

    # ── 2. Analyze Capture ───────────────────────────────────────────

    def analyze_capture(self, pcap_path):
        if not os.path.isfile(pcap_path):
            console.print(f"[red][!] File not found: {pcap_path}[/]")
            return None
        if not self.has_tshark:
            console.print("[red][!] tshark required for PCAP analysis[/]")
            return None

        console.print(Panel(f"[bold]Analyzing capture:[/] {pcap_path}", style="cyan"))
        results = {}

        analyses = [
            ("Protocol Hierarchy", f'tshark -r "{pcap_path}" -q -z io,phs'),
            ("TCP Conversations", f'tshark -r "{pcap_path}" -q -z conv,tcp'),
            ("HTTP Requests", f'tshark -r "{pcap_path}" -Y "http.request" -T fields '
                              f'-e http.host -e http.request.uri -e http.request.method'),
            ("DNS Queries", f'tshark -r "{pcap_path}" -Y "dns.qry.type == 1" -T fields '
                            f'-e dns.qry.name'),
            ("TLS Handshakes", f'tshark -r "{pcap_path}" -Y "tls.handshake.type == 1" '
                               f'-T fields -e tls.handshake.extensions_server_name'),
        ]

        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                       console=console) as progress:
            for label, cmd in analyses:
                task = progress.add_task(f"Extracting {label}...", total=1)
                stdout, stderr, rc = _run(cmd, timeout=60)
                results[label] = stdout if rc == 0 else f"Error: {stderr}"
                progress.update(task, completed=1)
                self._log_action(cmd, output=stdout[:2000], result=label)

        # Protocol hierarchy
        if results.get("Protocol Hierarchy"):
            table = Table(title="Protocol Hierarchy", show_lines=True)
            table.add_column("Protocol Tree", style="cyan")
            for line in results["Protocol Hierarchy"].splitlines():
                if line.strip():
                    table.add_row(line.rstrip())
            console.print(table)

        # TCP conversations
        if results.get("TCP Conversations"):
            table = Table(title="TCP Conversations", show_lines=True)
            table.add_column("Conversation", style="green")
            for line in results["TCP Conversations"].splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("="):
                    table.add_row(stripped)
            console.print(table)

        # HTTP requests
        if results.get("HTTP Requests"):
            table = Table(title="HTTP Requests")
            table.add_column("Host", style="yellow")
            table.add_column("URI", style="white")
            table.add_column("Method", style="magenta")
            for line in results["HTTP Requests"].splitlines():
                parts = line.split("\t")
                if len(parts) >= 2:
                    host = parts[0]
                    uri = parts[1] if len(parts) > 1 else ""
                    method = parts[2] if len(parts) > 2 else "GET"
                    table.add_row(host, uri, method)
            console.print(table)

        # DNS queries
        if results.get("DNS Queries"):
            domains = [d.strip() for d in results["DNS Queries"].splitlines() if d.strip()]
            unique = sorted(set(domains))
            table = Table(title=f"DNS Queries ({len(unique)} unique domains)")
            table.add_column("Domain", style="cyan")
            table.add_column("Count", style="yellow", justify="right")
            for domain in unique[:50]:
                table.add_row(domain, str(domains.count(domain)))
            console.print(table)

        # TLS SNI
        if results.get("TLS Handshakes"):
            snis = [s.strip() for s in results["TLS Handshakes"].splitlines() if s.strip()]
            unique_sni = sorted(set(snis))
            table = Table(title=f"TLS Server Names ({len(unique_sni)} unique)")
            table.add_column("SNI", style="green")
            table.add_column("Count", style="yellow", justify="right")
            for sni in unique_sni[:50]:
                table.add_row(sni, str(snis.count(sni)))
            console.print(table)

        self._add_finding("INFO", "PCAP analysis completed", f"File: {pcap_path}")
        return results

    # ── 3. ARP Scan ──────────────────────────────────────────────────

    def arp_scan(self, interface="eth0"):
        console.print(Panel(LEGAL_DISCLAIMER, style="red"))
        if not _confirm(f"ARP scan on interface '{interface}' to discover local hosts"):
            console.print("[yellow][-] ARP scan cancelled[/]")
            return []

        hosts = []

        if self.has_arpscan:
            cmd = f"arp-scan --interface={interface} --localnet"
            console.print(f"[cyan][*] Running:[/] {cmd}")
            stdout, stderr, rc = _run(cmd, timeout=30)
            self._log_action(cmd, output=stdout, result="OK" if rc == 0 else "FAIL")
            if rc == 0:
                for line in stdout.splitlines():
                    match = re.match(
                        r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]+)\s+(.*)', line
                    )
                    if match:
                        hosts.append({
                            "ip": match.group(1),
                            "mac": match.group(2),
                            "vendor": match.group(3).strip()
                        })
        elif self.has_nmap:
            cmd = f"nmap -sn -e {interface} --send-eth 192.168.1.0/24"
            # try to detect local subnet
            ip_out, _, _ = _run(f"ip -4 addr show {interface} | grep inet")
            subnet_match = re.search(r'inet (\d+\.\d+\.\d+)\.\d+/(\d+)', ip_out)
            if subnet_match:
                net = f"{subnet_match.group(1)}.0/{subnet_match.group(2)}"
                cmd = f"nmap -sn {net}"

            console.print(f"[cyan][*] Running:[/] {cmd}")
            stdout, stderr, rc = _run(cmd, timeout=60)
            self._log_action(cmd, output=stdout, result="OK" if rc == 0 else "FAIL")
            if rc == 0:
                current_ip = None
                for line in stdout.splitlines():
                    ip_match = re.search(r'Nmap scan report for .*?(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        current_ip = ip_match.group(1)
                    mac_match = re.search(r'MAC Address: ([0-9A-F:]+)\s*(.*)', line)
                    if mac_match and current_ip:
                        hosts.append({
                            "ip": current_ip,
                            "mac": mac_match.group(1),
                            "vendor": mac_match.group(2).strip("() ")
                        })
                        current_ip = None
        else:
            console.print("[red][!] Neither arp-scan nor nmap found[/]")
            return []

        table = Table(title=f"ARP Scan Results — {len(hosts)} hosts discovered")
        table.add_column("#", style="dim", justify="right")
        table.add_column("IP Address", style="green")
        table.add_column("MAC Address", style="cyan")
        table.add_column("Vendor", style="yellow")
        for i, h in enumerate(hosts, 1):
            table.add_row(str(i), h["ip"], h["mac"], h["vendor"])
        console.print(table)

        for h in hosts:
            self.db.add_ioc(self.mission_id, "ip", h["ip"],
                            context=f"MAC={h['mac']} Vendor={h['vendor']}",
                            source="arp_scan")
        self._add_finding("INFO", f"ARP scan: {len(hosts)} hosts on {interface}",
                          json.dumps(hosts, indent=2))
        return hosts

    # ── 4. Traceroute ────────────────────────────────────────────────

    def traceroute(self, target):
        console.print(Panel(LEGAL_DISCLAIMER, style="red"))
        if not _confirm(f"Traceroute to '{target}'"):
            console.print("[yellow][-] Traceroute cancelled[/]")
            return []

        tool = self._tool_check("traceroute", "mtr")
        if not tool:
            console.print("[red][!] Neither traceroute nor mtr found[/]")
            return []

        if tool == "traceroute":
            cmd = f"traceroute -m 30 -w 2 {target}"
        else:
            cmd = f"mtr -r -c 3 -n {target}"

        console.print(f"[cyan][*] Running:[/] {cmd}")
        with Progress(SpinnerColumn(), TextColumn("Tracing route..."),
                       console=console) as progress:
            task = progress.add_task("traceroute", total=1)
            stdout, stderr, rc = _run(cmd, timeout=120)
            progress.update(task, completed=1)

        self._log_action(cmd, output=stdout, result="OK" if rc == 0 else "FAIL")

        hops = []
        if rc == 0 and stdout:
            table = Table(title=f"Traceroute to {target}")
            table.add_column("Hop", style="dim", justify="right")
            table.add_column("IP Address", style="green")
            table.add_column("Hostname / Info", style="cyan")
            table.add_column("RTT", style="yellow", justify="right")

            for line in stdout.splitlines()[1:]:
                hop_match = re.match(
                    r'\s*(\d+)\s+(\S+)\s+\(?([\d.]+)\)?\s+([\d.]+\s*ms.*)', line
                )
                if hop_match:
                    hop_num = hop_match.group(1)
                    hostname = hop_match.group(2)
                    ip = hop_match.group(3)
                    rtt = hop_match.group(4).strip()
                    table.add_row(hop_num, ip, hostname, rtt)
                    hops.append({"hop": int(hop_num), "ip": ip,
                                 "hostname": hostname, "rtt": rtt})
                elif re.match(r'\s*(\d+)\s+\*\s+\*\s+\*', line):
                    num = re.match(r'\s*(\d+)', line).group(1)
                    table.add_row(num, "*", "* * *", "timeout")
                    hops.append({"hop": int(num), "ip": "*",
                                 "hostname": "*", "rtt": "timeout"})

            console.print(table)

        # Attempt ASN lookup for discovered IPs
        asn_ips = [h["ip"] for h in hops if h["ip"] != "*"]
        if asn_ips and _has("whois"):
            console.print("\n[cyan][*] Looking up ASN info for hops...[/]")
            asn_table = Table(title="ASN Information")
            asn_table.add_column("IP", style="green")
            asn_table.add_column("ASN", style="yellow")
            asn_table.add_column("Organization", style="cyan")
            for ip in asn_ips[:15]:
                out, _, _ = _run(f"whois -h whois.cymru.com \" -v {ip}\"", timeout=10)
                for wline in out.splitlines()[1:]:
                    parts = [p.strip() for p in wline.split("|")]
                    if len(parts) >= 3:
                        asn_table.add_row(ip, parts[0], parts[-1])
                        break
            console.print(asn_table)

        self._add_finding("INFO", f"Traceroute to {target}: {len(hops)} hops",
                          json.dumps(hops, indent=2), host=target)
        return hops

    # ── 5. Bandwidth Monitor ────────────────────────────────────────

    def bandwidth_monitor(self, interface="eth0", duration=10):
        console.print(Panel(LEGAL_DISCLAIMER, style="red"))
        if not _confirm(f"Monitor bandwidth on '{interface}' for {duration}s"):
            console.print("[yellow][-] Bandwidth monitor cancelled[/]")
            return []

        samples = []
        proc_path = f"/proc/net/dev"

        def _read_bytes(iface):
            try:
                with open(proc_path) as f:
                    for line in f:
                        if iface in line:
                            parts = line.split()
                            rx = int(parts[1])
                            tx = int(parts[9])
                            return rx, tx
            except (IOError, IndexError, ValueError):
                pass
            return None, None

        if self.has_ifstat:
            cmd = f"ifstat -i {interface} -t 1 {duration}"
            console.print(f"[cyan][*] Running:[/] {cmd}")
            stdout, stderr, rc = _run(cmd, timeout=duration + 10)
            self._log_action(cmd, output=stdout, result="OK" if rc == 0 else "FAIL")
            if rc == 0:
                for line in stdout.splitlines()[2:]:
                    parts = line.split()
                    if len(parts) >= 3:
                        samples.append({
                            "time": parts[0],
                            "rx_kbps": float(parts[1]),
                            "tx_kbps": float(parts[2])
                        })
        elif os.path.exists(proc_path):
            console.print(f"[cyan][*] Polling /proc/net/dev for {duration}s...[/]")
            prev_rx, prev_tx = _read_bytes(interface)
            if prev_rx is None:
                console.print(f"[red][!] Interface '{interface}' not found in /proc/net/dev[/]")
                return []

            table = Table(title=f"Bandwidth Monitor — {interface}")
            table.add_column("Time", style="dim")
            table.add_column("RX KB/s", style="green", justify="right")
            table.add_column("TX KB/s", style="cyan", justify="right")
            table.add_column("RX Total", style="yellow", justify="right")
            table.add_column("TX Total", style="yellow", justify="right")

            total_rx = 0
            total_tx = 0

            with Live(table, console=console, refresh_per_second=1) as live:
                for i in range(duration):
                    time.sleep(1)
                    cur_rx, cur_tx = _read_bytes(interface)
                    if cur_rx is None:
                        break
                    d_rx = (cur_rx - prev_rx) / 1024.0
                    d_tx = (cur_tx - prev_tx) / 1024.0
                    total_rx += d_rx
                    total_tx += d_tx
                    ts = datetime.now().strftime("%H:%M:%S")
                    table.add_row(
                        ts,
                        f"{d_rx:.1f}",
                        f"{d_tx:.1f}",
                        f"{total_rx:.0f} KB",
                        f"{total_tx:.0f} KB"
                    )
                    samples.append({"time": ts, "rx_kbps": round(d_rx, 1),
                                    "tx_kbps": round(d_tx, 1)})
                    prev_rx, prev_tx = cur_rx, cur_tx
                    live.refresh()

            self._log_action(
                f"bandwidth_monitor({interface}, {duration}s)",
                output=json.dumps(samples[:10]),
                result=f"total_rx={total_rx:.0f}KB total_tx={total_tx:.0f}KB"
            )
        else:
            console.print("[red][!] Neither ifstat nor /proc/net/dev available[/]")
            return []

        if samples:
            avg_rx = sum(s["rx_kbps"] for s in samples) / len(samples)
            avg_tx = sum(s["tx_kbps"] for s in samples) / len(samples)
            peak_rx = max(s["rx_kbps"] for s in samples)
            peak_tx = max(s["tx_kbps"] for s in samples)
            console.print(Panel(
                f"[green]Avg RX:[/] {avg_rx:.1f} KB/s  |  "
                f"[cyan]Avg TX:[/] {avg_tx:.1f} KB/s\n"
                f"[green]Peak RX:[/] {peak_rx:.1f} KB/s  |  "
                f"[cyan]Peak TX:[/] {peak_tx:.1f} KB/s",
                title="Bandwidth Summary"
            ))
            self._add_finding("INFO", f"Bandwidth monitor on {interface}",
                              f"Avg RX: {avg_rx:.1f} KB/s, Avg TX: {avg_tx:.1f} KB/s, "
                              f"Peak RX: {peak_rx:.1f} KB/s, Peak TX: {peak_tx:.1f} KB/s")
        return samples

    # ── 6. WiFi Scan ─────────────────────────────────────────────────

    def wifi_scan(self):
        console.print(Panel(LEGAL_DISCLAIMER, style="red"))
        if not _confirm("Scan for WiFi networks (requires wireless interface)"):
            console.print("[yellow][-] WiFi scan cancelled[/]")
            return []

        # Detect wireless interfaces
        ifaces = []
        iw_out, _, rc = _run("iw dev 2>/dev/null || iwconfig 2>/dev/null")
        if rc == 0:
            for match in re.finditer(r'Interface\s+(\S+)', iw_out):
                ifaces.append(match.group(1))
            if not ifaces:
                for match in re.finditer(r'^(\S+)\s+IEEE', iw_out, re.MULTILINE):
                    ifaces.append(match.group(1))

        if not ifaces:
            # Fallback: check /sys/class/net
            try:
                for name in os.listdir("/sys/class/net"):
                    wireless_path = f"/sys/class/net/{name}/wireless"
                    if os.path.exists(wireless_path):
                        ifaces.append(name)
            except OSError:
                pass

        if not ifaces:
            console.print("[red][!] No wireless interfaces detected[/]")
            return []

        iface = ifaces[0]
        console.print(f"[cyan][*] Using wireless interface: {iface}[/]")
        networks = []

        if self.has_iwlist:
            cmd = f"iwlist {iface} scan"
            console.print(f"[cyan][*] Running:[/] {cmd}")
            stdout, stderr, rc = _run(cmd, timeout=30)
            self._log_action(cmd, output=stdout[:3000], result="OK" if rc == 0 else "FAIL")

            if rc == 0:
                current = {}
                for line in stdout.splitlines():
                    line = line.strip()
                    if "Cell" in line and "Address:" in line:
                        if current:
                            networks.append(current)
                        bssid = re.search(r'Address:\s*(\S+)', line)
                        current = {"bssid": bssid.group(1) if bssid else "",
                                   "essid": "", "channel": "", "signal": "",
                                   "encryption": "Open"}
                    elif "ESSID:" in line:
                        essid = re.search(r'ESSID:"([^"]*)"', line)
                        if essid:
                            current["essid"] = essid.group(1)
                    elif "Channel:" in line:
                        ch = re.search(r'Channel:(\d+)', line)
                        if ch:
                            current["channel"] = ch.group(1)
                    elif "Signal level" in line:
                        sig = re.search(r'Signal level[=:](-?\d+)', line)
                        if sig:
                            current["signal"] = f"{sig.group(1)} dBm"
                    elif "Encryption key:on" in line:
                        current["encryption"] = "Encrypted"
                    elif "WPA2" in line:
                        current["encryption"] = "WPA2"
                    elif "WPA" in line and current.get("encryption") != "WPA2":
                        current["encryption"] = "WPA"
                    elif "WEP" in line:
                        current["encryption"] = "WEP"
                if current:
                    networks.append(current)

        elif _has("nmcli"):
            cmd = "nmcli -t -f SSID,BSSID,CHAN,SIGNAL,SECURITY dev wifi list"
            console.print(f"[cyan][*] Running:[/] {cmd}")
            stdout, stderr, rc = _run(cmd, timeout=15)
            self._log_action(cmd, output=stdout, result="OK" if rc == 0 else "FAIL")
            if rc == 0:
                for line in stdout.splitlines():
                    parts = line.split(":")
                    if len(parts) >= 5:
                        networks.append({
                            "essid": parts[0],
                            "bssid": ":".join(parts[1:7]) if len(parts) > 6 else parts[1],
                            "channel": parts[-3] if len(parts) > 4 else "",
                            "signal": f"{parts[-2]}%" if len(parts) > 4 else "",
                            "encryption": parts[-1] if len(parts) > 4 else ""
                        })
        else:
            console.print("[red][!] Neither iwlist nor nmcli available[/]")
            return []

        table = Table(title=f"WiFi Networks — {len(networks)} found")
        table.add_column("#", style="dim", justify="right")
        table.add_column("ESSID", style="green")
        table.add_column("BSSID", style="cyan")
        table.add_column("Channel", style="yellow", justify="right")
        table.add_column("Signal", style="magenta", justify="right")
        table.add_column("Security", style="red")
        for i, net in enumerate(networks, 1):
            sec_style = "red bold" if net["encryption"] in ("Open", "WEP") else "green"
            table.add_row(
                str(i), net.get("essid", ""), net.get("bssid", ""),
                net.get("channel", ""), net.get("signal", ""),
                Text(net.get("encryption", ""), style=sec_style)
            )
        console.print(table)

        open_nets = [n for n in networks if n.get("encryption") == "Open"]
        wep_nets = [n for n in networks if n.get("encryption") == "WEP"]
        if open_nets:
            self._add_finding("HIGH", f"{len(open_nets)} open WiFi networks detected",
                              json.dumps(open_nets, indent=2))
        if wep_nets:
            self._add_finding("MEDIUM", f"{len(wep_nets)} WEP-encrypted networks (weak)",
                              json.dumps(wep_nets, indent=2))
        self._add_finding("INFO", f"WiFi scan: {len(networks)} networks on {iface}",
                          json.dumps(networks, indent=2))
        return networks

    # ── Summary ──────────────────────────────────────────────────────

    def summary(self):
        table = Table(title="AEGIS Network Operations Summary")
        table.add_column("Check", style="cyan")
        table.add_column("Status", style="green")
        tools = {
            "tshark": self.has_tshark, "tcpdump": self.has_tcpdump,
            "arp-scan": self.has_arpscan, "nmap": self.has_nmap,
            "traceroute": self.has_traceroute, "ifstat": self.has_ifstat,
            "iwlist": self.has_iwlist, "airmon-ng": self.has_airmon
        }
        for t, avail in tools.items():
            status = "[green]Available[/]" if avail else "[red]Missing[/]"
            table.add_row(t, status)
        table.add_row("Findings", str(len(self.findings)))
        table.add_row("Mission ID", self.mission_id)
        console.print(table)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="AEGIS Real Network Operations")
    parser.add_argument("--mission", default=None, help="Mission ID")
    sub = parser.add_subparsers(dest="command")

    cap = sub.add_parser("capture", help="Capture packets")
    cap.add_argument("-i", "--interface", default="eth0")
    cap.add_argument("-d", "--duration", type=int, default=30)
    cap.add_argument("-f", "--filter", default="")
    cap.add_argument("-o", "--output", default=None)

    ana = sub.add_parser("analyze", help="Analyze PCAP")
    ana.add_argument("pcap", help="Path to PCAP file")

    arp = sub.add_parser("arp", help="ARP scan")
    arp.add_argument("-i", "--interface", default="eth0")

    tr = sub.add_parser("trace", help="Traceroute")
    tr.add_argument("target", help="Target host")

    bw = sub.add_parser("bandwidth", help="Bandwidth monitor")
    bw.add_argument("-i", "--interface", default="eth0")
    bw.add_argument("-d", "--duration", type=int, default=10)

    wifi = sub.add_parser("wifi", help="WiFi scan")

    args = parser.parse_args()
    net = AegisNetwork(mission_id=args.mission)

    if args.command == "capture":
        net.packet_capture(args.interface, args.duration, args.filter, args.output)
    elif args.command == "analyze":
        net.analyze_capture(args.pcap)
    elif args.command == "arp":
        net.arp_scan(args.interface)
    elif args.command == "trace":
        net.traceroute(args.target)
    elif args.command == "bandwidth":
        net.bandwidth_monitor(args.interface, args.duration)
    elif args.command == "wifi":
        net.wifi_scan()
    else:
        net.summary()
        parser.print_help()
