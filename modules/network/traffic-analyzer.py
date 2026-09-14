#!/usr/bin/env python3
"""
AEGIS Network Traffic Analyzer
================================
PCAP analysis simulation, protocol statistics, flow analysis,
DNS analysis, TLS inspection, beacon detection, and rule generation.

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
except ImportError:
    print("[!] rich library required: pip install rich")
    sys.exit(1)

console = Console()

# ─── Protocol Database ─────────────────────────────────────────────────
PROTOCOL_HIERARCHY = {
    "Ethernet": {
        "percentage": 100.0,
        "children": {
            "IPv4": {
                "percentage": 92.5,
                "children": {
                    "TCP": {
                        "percentage": 78.3,
                        "children": {
                            "HTTP": {"percentage": 12.1, "children": {}},
                            "HTTPS/TLS": {"percentage": 45.2, "children": {}},
                            "SMB": {"percentage": 8.7, "children": {}},
                            "SSH": {"percentage": 3.4, "children": {}},
                            "FTP": {"percentage": 0.8, "children": {}},
                            "SMTP": {"percentage": 2.1, "children": {}},
                            "RDP": {"percentage": 1.5, "children": {}},
                            "MySQL": {"percentage": 0.9, "children": {}},
                            "Other TCP": {"percentage": 3.6, "children": {}},
                        },
                    },
                    "UDP": {
                        "percentage": 13.8,
                        "children": {
                            "DNS": {"percentage": 8.2, "children": {}},
                            "DHCP": {"percentage": 1.1, "children": {}},
                            "NTP": {"percentage": 0.9, "children": {}},
                            "SNMP": {"percentage": 0.4, "children": {}},
                            "SSDP": {"percentage": 0.6, "children": {}},
                            "Other UDP": {"percentage": 2.6, "children": {}},
                        },
                    },
                    "ICMP": {"percentage": 0.4, "children": {}},
                },
            },
            "IPv6": {
                "percentage": 6.2,
                "children": {
                    "TCP6": {"percentage": 4.8, "children": {}},
                    "UDP6": {"percentage": 1.2, "children": {}},
                    "ICMPv6": {"percentage": 0.2, "children": {}},
                },
            },
            "ARP": {"percentage": 1.3, "children": {}},
        },
    },
}

# ─── Known C2 Beacon Patterns ──────────────────────────────────────────
C2_BEACON_PATTERNS = {
    "Cobalt Strike": {
        "default_sleep": 60,
        "jitter": 0.1,
        "uri_patterns": ["/ca", "/dpixel", "/__utm.gif", "/pixel.gif", "/submit.php"],
        "user_agents": [
            "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        ],
        "http_methods": ["GET", "POST"],
        "port_range": [80, 443, 8080, 8443],
        "indicators": ["Cookie: SESSIONID=", "Content-Type: application/octet-stream"],
    },
    "Metasploit Meterpreter": {
        "default_sleep": 5,
        "jitter": 0.0,
        "uri_patterns": ["/", "/conn", "/met"],
        "user_agents": ["Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)"],
        "http_methods": ["GET", "POST"],
        "port_range": [4444, 443, 80, 8080],
        "indicators": ["Large POST bodies", "Binary content in responses"],
    },
    "Empire/Starkiller": {
        "default_sleep": 5,
        "jitter": 0.2,
        "uri_patterns": ["/login/process.php", "/admin/get.php", "/news.php"],
        "user_agents": ["Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0)"],
        "http_methods": ["GET", "POST"],
        "port_range": [80, 443],
        "indicators": ["Base64-encoded POST data", "Predictable URI patterns"],
    },
    "Sliver": {
        "default_sleep": 60,
        "jitter": 0.3,
        "uri_patterns": ["/static/", "/assets/", "/api/"],
        "user_agents": ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"],
        "http_methods": ["GET", "POST"],
        "port_range": [443, 8443, 31337],
        "indicators": ["mTLS connections", "WireGuard tunnels", "DNS over HTTPS"],
    },
}

# ─── DGA Detection Patterns ───────────────────────────────────────────
DGA_CHARACTERISTICS = {
    "high_entropy": {
        "description": "Domain labels with unusually high character entropy",
        "threshold": 3.5,
        "example": "xk8mq2p9rn3.example.com",
    },
    "unusual_length": {
        "description": "Domain labels significantly longer than typical",
        "threshold": 20,
        "example": "asdfjkl234890uqweiopzxc.net",
    },
    "consonant_ratio": {
        "description": "Abnormally high ratio of consonants to vowels",
        "threshold": 0.8,
        "example": "bkprnmxcvzqw.org",
    },
    "numeric_ratio": {
        "description": "High proportion of digits in domain label",
        "threshold": 0.4,
        "example": "abc123def456ghi789.com",
    },
    "dictionary_words": {
        "description": "Domains composed of random dictionary words",
        "threshold": 0,
        "example": "blue-horse-staple-battery.com",
    },
}


class NetworkFlow:
    """Represents a network flow/session."""

    def __init__(self, src_ip, src_port, dst_ip, dst_port, protocol,
                 packets=0, bytes_total=0, duration=0):
        self.flow_id = str(uuid.uuid4())[:8]
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        self.packets = packets
        self.bytes_total = bytes_total
        self.duration = duration
        self.start_time = datetime.datetime.now() - datetime.timedelta(seconds=duration)
        self.end_time = datetime.datetime.now()
        self.flags = set()
        self.anomaly_score = 0.0
        self.tags = []

    def to_dict(self):
        return {
            "flow_id": self.flow_id,
            "src": f"{self.src_ip}:{self.src_port}",
            "dst": f"{self.dst_ip}:{self.dst_port}",
            "protocol": self.protocol,
            "packets": self.packets,
            "bytes": self.bytes_total,
            "duration": self.duration,
            "anomaly_score": self.anomaly_score,
            "tags": self.tags,
        }


class DNSQuery:
    """Represents a DNS query for analysis."""

    def __init__(self, query_name, query_type, src_ip, response_ip=None):
        self.timestamp = datetime.datetime.now()
        self.query_name = query_name
        self.query_type = query_type
        self.src_ip = src_ip
        self.response_ip = response_ip
        self.response_code = "NOERROR"
        self.is_dga = False
        self.is_tunneling = False
        self.entropy = 0.0

    def to_dict(self):
        return {
            "timestamp": self.timestamp.isoformat(),
            "query": self.query_name,
            "type": self.query_type,
            "src_ip": self.src_ip,
            "response_ip": self.response_ip,
            "response_code": self.response_code,
            "is_dga": self.is_dga,
            "is_tunneling": self.is_tunneling,
            "entropy": self.entropy,
        }


class NetworkTrafficAnalyzer:
    """
    Network Traffic Analyzer

    Simulates PCAP analysis with protocol statistics, flow analysis,
    DNS inspection, TLS analysis, beacon detection, and rule generation.

    Usage:
        analyzer = NetworkTrafficAnalyzer()
        analyzer.run()
    """

    HELP_TEXT = """
AEGIS Network Traffic Analyzer
================================
Network traffic analysis and threat detection (simulated).

Commands:
  analyze <pcap>        Analyze PCAP file (simulated)
  protocols             Show protocol hierarchy statistics
  flows                 Display network flow analysis
  dns                   DNS query analysis (DGA, tunneling)
  tls                   TLS certificate inspection
  beacons               Detect C2 beacon patterns
  anomalies             Network anomaly detection
  rules                 Generate detection rules from findings
  help                  Show this help message

Options:
  --pcap <file>         PCAP file to analyze (simulated)
  --duration <minutes>  Analysis time window
  --output <file>       Export results to JSON
"""

    def __init__(self):
        """Initialize the Network Traffic Analyzer."""
        self.flows = []
        self.dns_queries = []
        self.tls_certs = []
        self.anomalies = []
        self.beacon_detections = []
        self._verify_authorization()

    def _verify_authorization(self):
        """Verify operator authorization."""
        console.print(Panel(
            "[bold yellow]AUTHORIZATION CHECK[/bold yellow]\n\n"
            "This module simulates network traffic analysis for [bold]educational purposes[/bold].\n"
            "All network flows, DNS queries, and detections are simulated data.\n"
            "No actual packet capture or network interception is performed.",
            title="AEGIS Traffic Analyzer",
            border_style="yellow"
        ))

    def _gen_internal_ip(self):
        return f"10.0.{random.randint(0, 10)}.{random.randint(1, 254)}"

    def _gen_external_ip(self):
        return f"{random.randint(45, 200)}.{random.randint(10, 250)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

    def analyze_pcap(self, pcap_file="capture.pcap"):
        """Simulate PCAP file analysis."""
        total_packets = random.randint(500000, 5000000)
        total_bytes = random.randint(500_000_000, 5_000_000_000)
        duration_sec = random.randint(300, 86400)

        console.print(Panel(
            f"[bold cyan]PCAP ANALYSIS[/bold cyan]\n\n"
            f"File:          {pcap_file}\n"
            f"Total Packets: {total_packets:,}\n"
            f"Total Bytes:   {total_bytes / (1024**2):.1f} MB\n"
            f"Duration:      {duration_sec / 60:.1f} minutes\n"
            f"Avg Pkt Rate:  {total_packets / duration_sec:.0f} pkt/sec\n"
            f"Avg Bandwidth: {(total_bytes * 8) / duration_sec / 1_000_000:.1f} Mbps",
            title="PCAP Summary",
            border_style="cyan",
        ))

        # Generate simulated flows
        self._generate_flows(50)

        # Run all analysis components
        self.show_protocol_hierarchy()
        console.print("\n")
        self.analyze_flows()
        console.print("\n")
        self.analyze_dns()
        console.print("\n")
        self.inspect_tls()
        console.print("\n")
        self.detect_beacons()
        console.print("\n")
        self.detect_anomalies()

    def _generate_flows(self, count=50):
        """Generate simulated network flows."""
        protocols_ports = [
            ("HTTP", 80), ("HTTPS", 443), ("SSH", 22), ("SMB", 445),
            ("DNS", 53), ("RDP", 3389), ("SMTP", 25), ("FTP", 21),
            ("MySQL", 3306), ("LDAP", 389),
        ]

        for _ in range(count):
            proto, port = random.choice(protocols_ports)
            src_ip = self._gen_internal_ip()
            dst_ip = random.choice([self._gen_internal_ip(), self._gen_external_ip()])
            flow = NetworkFlow(
                src_ip=src_ip,
                src_port=random.randint(1024, 65535),
                dst_ip=dst_ip,
                dst_port=port,
                protocol=proto,
                packets=random.randint(10, 50000),
                bytes_total=random.randint(1000, 100_000_000),
                duration=random.randint(1, 3600),
            )

            # Add anomaly scores to some flows
            if random.random() < 0.15:
                flow.anomaly_score = random.uniform(0.7, 1.0)
                flow.tags.append("suspicious")
                if port in [80, 443]:
                    flow.tags.append("potential-c2")
                elif port == 53:
                    flow.tags.append("dns-anomaly")

            self.flows.append(flow)

    def show_protocol_hierarchy(self):
        """Display protocol hierarchy statistics."""
        def build_tree(node, parent_tree, indent=0):
            for proto, info in node.items():
                pct = info.get("percentage", 0)
                branch = parent_tree.add(
                    f"[cyan]{proto}[/cyan] [dim]({pct:.1f}%)[/dim]"
                )
                if info.get("children"):
                    build_tree(info["children"], branch, indent + 1)

        tree = Tree("[bold]Protocol Hierarchy[/bold]")
        build_tree(PROTOCOL_HIERARCHY, tree)
        console.print(tree)

    def analyze_flows(self):
        """Analyze network flows for suspicious patterns."""
        console.print(Panel(
            "[bold cyan]FLOW ANALYSIS[/bold cyan]\n\n"
            f"Analyzing {len(self.flows)} network flows...",
            title="Flow Analysis",
            border_style="cyan",
        ))

        # Top talkers
        table = Table(title="Top Network Flows (by bytes)")
        table.add_column("Source", style="cyan", width=20)
        table.add_column("Destination", style="yellow", width=20)
        table.add_column("Protocol", style="green", width=8)
        table.add_column("Packets", justify="right")
        table.add_column("Bytes", justify="right")
        table.add_column("Duration", justify="right")
        table.add_column("Score", justify="right")
        table.add_column("Tags", style="dim")

        sorted_flows = sorted(self.flows, key=lambda f: f.bytes_total, reverse=True)
        for flow in sorted_flows[:15]:
            bytes_str = f"{flow.bytes_total / (1024**2):.1f} MB" if flow.bytes_total > 1024**2 else f"{flow.bytes_total / 1024:.0f} KB"
            dur_str = f"{flow.duration}s" if flow.duration < 60 else f"{flow.duration / 60:.1f}m"
            score_style = "red bold" if flow.anomaly_score >= 0.7 else "yellow" if flow.anomaly_score >= 0.4 else "green"

            table.add_row(
                f"{flow.src_ip}:{flow.src_port}",
                f"{flow.dst_ip}:{flow.dst_port}",
                flow.protocol,
                f"{flow.packets:,}",
                bytes_str,
                dur_str,
                Text(f"{flow.anomaly_score:.2f}", style=score_style) if flow.anomaly_score > 0 else Text("-", style="dim"),
                ", ".join(flow.tags) if flow.tags else "-",
            )
        console.print(table)

        # Session reconstruction summary
        suspicious = [f for f in self.flows if f.anomaly_score >= 0.7]
        if suspicious:
            console.print(f"\n[red bold]Alert: {len(suspicious)} suspicious flows detected[/red bold]")

    def analyze_dns(self):
        """Analyze DNS queries for DGA and tunneling detection."""
        console.print(Panel(
            "[bold cyan]DNS ANALYSIS[/bold cyan]\n\n"
            "Analyzing DNS queries for DGA patterns and tunneling indicators...",
            title="DNS Analysis",
            border_style="cyan",
        ))

        # Generate sample DNS queries
        normal_domains = [
            "www.google.com", "api.github.com", "mail.office365.com",
            "cdn.cloudflare.com", "s3.amazonaws.com", "login.microsoftonline.com",
            "updates.windows.com", "fonts.googleapis.com",
        ]
        suspicious_domains = [
            "xk8mq2p9rn3bvz7.example.com",
            "aabbccddeeff0011.malware-c2.example.net",
            "AAAAAAAAAAAAAAAA.BBBBBBBBBBBBB.evil.example.org",
            f"{hashlib.md5(b'dga1').hexdigest()[:20]}.example.xyz",
            f"{hashlib.md5(b'dga2').hexdigest()[:18]}.example.top",
        ]
        tunneling_domains = [
            f"{'a'*60}.{'b'*60}.tunnel.example.com",
            f"{'base64encoded'*3}.dns-exfil.example.net",
        ]

        queries = []
        for domain in normal_domains:
            q = DNSQuery(domain, "A", self._gen_internal_ip(),
                         self._gen_external_ip())
            queries.append(q)

        for domain in suspicious_domains:
            q = DNSQuery(domain, "A", self._gen_internal_ip())
            q.is_dga = True
            q.entropy = random.uniform(3.5, 4.5)
            q.response_code = random.choice(["NXDOMAIN", "NOERROR", "NXDOMAIN"])
            queries.append(q)

        for domain in tunneling_domains:
            q = DNSQuery(domain, "TXT", self._gen_internal_ip())
            q.is_tunneling = True
            q.entropy = random.uniform(4.0, 5.0)
            queries.append(q)

        self.dns_queries = queries

        # Display results
        table = Table(title="DNS Query Analysis")
        table.add_column("Source", style="cyan", width=14)
        table.add_column("Query", style="white", width=40)
        table.add_column("Type", style="yellow", width=5)
        table.add_column("Response", style="green", width=12)
        table.add_column("Entropy", justify="right", width=7)
        table.add_column("Flags", width=15)

        for q in queries:
            flags = []
            flag_style = "green"
            if q.is_dga:
                flags.append("[red]DGA[/red]")
                flag_style = "red"
            if q.is_tunneling:
                flags.append("[red]TUNNEL[/red]")
                flag_style = "red"
            if not flags:
                flags.append("[green]Clean[/green]")

            query_style = "red" if q.is_dga or q.is_tunneling else "white"
            entropy_style = "red bold" if q.entropy > 3.5 else "white"

            table.add_row(
                q.src_ip,
                Text(q.query_name[:40], style=query_style),
                q.query_type,
                q.response_code or "-",
                Text(f"{q.entropy:.2f}", style=entropy_style) if q.entropy > 0 else Text("-", style="dim"),
                " ".join(flags),
            )
        console.print(table)

        dga_count = sum(1 for q in queries if q.is_dga)
        tunnel_count = sum(1 for q in queries if q.is_tunneling)
        if dga_count or tunnel_count:
            console.print(Panel(
                f"[bold red]DNS ALERTS[/bold red]\n\n"
                f"DGA Domains Detected:      {dga_count}\n"
                f"Tunneling Detected:        {tunnel_count}\n"
                f"Unique Suspicious Sources:  {len(set(q.src_ip for q in queries if q.is_dga or q.is_tunneling))}",
                title="DNS Threat Summary",
                border_style="red",
            ))

    def inspect_tls(self):
        """Inspect TLS certificates in network traffic."""
        console.print(Panel(
            "[bold cyan]TLS CERTIFICATE INSPECTION[/bold cyan]\n\n"
            "Inspecting TLS certificates in captured traffic...",
            title="TLS Analysis",
            border_style="cyan",
        ))

        certs = [
            {"sni": "www.google.com", "issuer": "GTS CA 1C3", "root": "GlobalSign",
             "valid_from": "2024-07-01", "valid_until": "2025-01-01",
             "key_size": 2048, "sig_alg": "SHA256-RSA", "san_count": 45,
             "suspicious": False, "issue": None},
            {"sni": "api.github.com", "issuer": "DigiCert SHA2 High Assurance",
             "root": "DigiCert", "valid_from": "2024-03-15", "valid_until": "2025-03-15",
             "key_size": 2048, "sig_alg": "SHA256-RSA", "san_count": 12,
             "suspicious": False, "issue": None},
            {"sni": "update-service.example.com", "issuer": "Self-Signed",
             "root": "Self-Signed", "valid_from": "2024-09-01", "valid_until": "2025-09-01",
             "key_size": 1024, "sig_alg": "SHA1-RSA", "san_count": 1,
             "suspicious": True, "issue": "Self-signed, weak key, SHA1"},
            {"sni": "cdn-delivery.example.net", "issuer": "Let's Encrypt R3",
             "root": "ISRG Root X1", "valid_from": "2024-09-10", "valid_until": "2024-12-09",
             "key_size": 2048, "sig_alg": "SHA256-RSA", "san_count": 1,
             "suspicious": True, "issue": "Recently issued, single SAN, C2 indicator"},
            {"sni": "internal-app.company.local", "issuer": "Company Internal CA",
             "root": "Company Root CA", "valid_from": "2024-01-01", "valid_until": "2026-01-01",
             "key_size": 4096, "sig_alg": "SHA384-RSA", "san_count": 5,
             "suspicious": False, "issue": None},
        ]

        table = Table(title="TLS Certificate Inventory")
        table.add_column("SNI", style="cyan", width=30)
        table.add_column("Issuer", style="yellow", width=25)
        table.add_column("Valid Until", style="white")
        table.add_column("Key", justify="right")
        table.add_column("Sig Alg", style="green")
        table.add_column("Status", width=12)
        table.add_column("Issue", style="dim", width=25)

        for cert in certs:
            status = "[red bold]ALERT[/red bold]" if cert["suspicious"] else "[green]Valid[/green]"
            key_style = "red" if cert["key_size"] < 2048 else "white"
            sig_style = "red" if "SHA1" in cert["sig_alg"] else "green"

            table.add_row(
                cert["sni"],
                cert["issuer"],
                cert["valid_until"],
                Text(str(cert["key_size"]), style=key_style),
                Text(cert["sig_alg"], style=sig_style),
                status,
                cert["issue"] or "-",
            )
        console.print(table)

        self.tls_certs = certs

    def detect_beacons(self):
        """Detect C2 beacon patterns in network traffic."""
        console.print(Panel(
            "[bold cyan]C2 BEACON DETECTION[/bold cyan]\n\n"
            "Analyzing traffic patterns for C2 beacon characteristics...",
            title="Beacon Detection",
            border_style="cyan",
        ))

        detections = []
        for c2_name, pattern in C2_BEACON_PATTERNS.items():
            if random.random() < 0.3:  # 30% chance of detecting each C2 type
                detection = {
                    "c2_framework": c2_name,
                    "src_ip": self._gen_internal_ip(),
                    "dst_ip": self._gen_external_ip(),
                    "dst_port": random.choice(pattern["port_range"]),
                    "sleep_interval": pattern["default_sleep"],
                    "jitter": pattern["jitter"],
                    "uri_pattern": random.choice(pattern["uri_patterns"]),
                    "beacon_count": random.randint(50, 500),
                    "confidence": random.uniform(0.7, 0.99),
                    "first_seen": (datetime.datetime.now() -
                                   datetime.timedelta(hours=random.randint(1, 72))).isoformat(),
                }
                detections.append(detection)

        if detections:
            table = Table(title="C2 Beacon Detections")
            table.add_column("Framework", style="red bold")
            table.add_column("Source", style="cyan")
            table.add_column("Destination", style="yellow")
            table.add_column("Port", justify="right")
            table.add_column("Sleep", justify="right")
            table.add_column("Beacons", justify="right")
            table.add_column("Confidence", justify="right")

            for d in detections:
                conf_style = "red bold" if d["confidence"] >= 0.9 else "yellow" if d["confidence"] >= 0.7 else "green"
                table.add_row(
                    d["c2_framework"],
                    d["src_ip"],
                    d["dst_ip"],
                    str(d["dst_port"]),
                    f"{d['sleep_interval']}s",
                    str(d["beacon_count"]),
                    Text(f"{d['confidence']:.0%}", style=conf_style),
                )
            console.print(table)
        else:
            console.print("[green]No C2 beacon patterns detected[/green]")

        self.beacon_detections = detections

    def detect_anomalies(self):
        """Detect network anomalies using statistical analysis."""
        console.print(Panel(
            "[bold cyan]NETWORK ANOMALY DETECTION[/bold cyan]\n\n"
            "Analyzing network traffic for statistical anomalies...",
            title="Anomaly Detection",
            border_style="cyan",
        ))

        anomalies = [
            {"type": "Unusual Port", "src": self._gen_internal_ip(), "dst": self._gen_external_ip(),
             "detail": "Outbound connection on port 4444 (common Meterpreter port)",
             "severity": "HIGH", "score": random.uniform(0.8, 1.0)},
            {"type": "Data Volume", "src": self._gen_internal_ip(), "dst": self._gen_external_ip(),
             "detail": f"Outbound transfer of {random.randint(500, 5000)} MB to external IP in 2 hours",
             "severity": "HIGH", "score": random.uniform(0.7, 0.95)},
            {"type": "Protocol Anomaly", "src": self._gen_internal_ip(), "dst": self._gen_internal_ip(),
             "detail": "DNS over HTTPS (DoH) traffic to non-standard resolver",
             "severity": "MEDIUM", "score": random.uniform(0.5, 0.75)},
            {"type": "Timing Pattern", "src": self._gen_internal_ip(), "dst": self._gen_external_ip(),
             "detail": "Regular 60-second interval connections (beacon pattern)",
             "severity": "HIGH", "score": random.uniform(0.8, 0.99)},
            {"type": "Geo Anomaly", "src": self._gen_internal_ip(), "dst": "203.0.113.42",
             "detail": "Connection to IP geolocated to country not in baseline",
             "severity": "MEDIUM", "score": random.uniform(0.5, 0.7)},
            {"type": "Protocol Violation", "src": self._gen_internal_ip(), "dst": self._gen_external_ip(),
             "detail": "Non-DNS traffic on port 53 (potential tunneling)",
             "severity": "HIGH", "score": random.uniform(0.75, 0.95)},
        ]

        table = Table(title="Network Anomalies")
        table.add_column("Type", style="cyan")
        table.add_column("Source", style="white")
        table.add_column("Destination", style="white")
        table.add_column("Severity", width=8)
        table.add_column("Score", justify="right")
        table.add_column("Detail", style="dim", width=40)

        for a in anomalies:
            sev_style = {"HIGH": "red bold", "MEDIUM": "yellow", "LOW": "green"}.get(a["severity"], "white")
            score_style = "red bold" if a["score"] >= 0.8 else "yellow" if a["score"] >= 0.5 else "green"
            table.add_row(
                a["type"],
                a["src"],
                a["dst"],
                Text(a["severity"], style=sev_style),
                Text(f"{a['score']:.2f}", style=score_style),
                a["detail"][:40],
            )
        console.print(table)

        self.anomalies = anomalies

    def generate_rules(self):
        """Generate detection rules from analysis findings."""
        console.print(Panel(
            "[bold cyan]DETECTION RULE GENERATION[/bold cyan]\n\n"
            "Generating Suricata/Zeek rules from analysis findings...",
            title="Rule Generation",
            border_style="cyan",
        ))

        rules = [
            {
                "type": "Suricata",
                "rule": 'alert tcp $HOME_NET any -> $EXTERNAL_NET 4444 (msg:"AEGIS - Potential Meterpreter C2"; flow:established,to_server; content:"|00|"; offset:0; depth:1; classtype:trojan-activity; sid:1000001; rev:1;)',
                "description": "Detects connections to common Meterpreter port",
            },
            {
                "type": "Suricata",
                "rule": 'alert dns $HOME_NET any -> any any (msg:"AEGIS - DGA Domain Detected"; dns.query; pcre:"/^[a-z0-9]{20,}\\./"; classtype:bad-unknown; sid:1000002; rev:1;)',
                "description": "Detects domains with DGA characteristics",
            },
            {
                "type": "Suricata",
                "rule": 'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"AEGIS - Cobalt Strike Beacon URI"; flow:established,to_server; content:"/dpixel"; http.uri; classtype:trojan-activity; sid:1000003; rev:1;)',
                "description": "Detects default Cobalt Strike beacon URI",
            },
            {
                "type": "Zeek",
                "rule": '@load base/frameworks/notice\nevent dns_request(c: connection, msg: string, query: string, qtype: count, qclass: count) {\n  if (|query| > 50) {\n    NOTICE([$note=DNS::Tunneling_Suspicion, $msg=fmt("Long DNS query: %s", query), $conn=c]);\n  }\n}',
                "description": "Detects unusually long DNS queries (tunneling indicator)",
            },
            {
                "type": "Zeek",
                "rule": '@load base/protocols/ssl\nevent ssl_established(c: connection) {\n  if (c$ssl?$cert_chain && |c$ssl$cert_chain| > 0) {\n    local cert = c$ssl$cert_chain[0];\n    if (cert$issuer == cert$subject) {\n      NOTICE([$note=SSL::Self_Signed_Cert, $msg="Self-signed certificate", $conn=c]);\n    }\n  }\n}',
                "description": "Alerts on self-signed TLS certificates",
            },
        ]

        for rule in rules:
            console.print(Panel(
                f"[bold]{rule['type']} Rule[/bold]\n\n"
                f"[dim]{rule['description']}[/dim]\n\n"
                f"[yellow]{rule['rule']}[/yellow]",
                border_style="green",
            ))

    def run(self):
        """Main execution entry point."""
        self.analyze_pcap()
        console.print("\n")
        self.generate_rules()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="AEGIS Network Traffic Analyzer -- Educational Use Only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("command", nargs="?", default="analyze",
                        choices=["analyze", "protocols", "flows", "dns", "tls",
                                 "beacons", "anomalies", "rules", "help"],
                        help="Command to execute")
    parser.add_argument("--pcap", "-p", default="capture.pcap",
                        help="PCAP file to analyze (simulated)")
    parser.add_argument("--output", "-o", default=None,
                        help="Export results to JSON file")

    args = parser.parse_args()
    analyzer = NetworkTrafficAnalyzer()

    if args.command == "help":
        console.print(analyzer.HELP_TEXT)
    elif args.command == "analyze":
        analyzer.analyze_pcap(args.pcap)
    elif args.command == "protocols":
        analyzer.show_protocol_hierarchy()
    elif args.command == "flows":
        analyzer._generate_flows(50)
        analyzer.analyze_flows()
    elif args.command == "dns":
        analyzer.analyze_dns()
    elif args.command == "tls":
        analyzer.inspect_tls()
    elif args.command == "beacons":
        analyzer._generate_flows(30)
        analyzer.detect_beacons()
    elif args.command == "anomalies":
        analyzer.detect_anomalies()
    elif args.command == "rules":
        analyzer.generate_rules()
    else:
        analyzer.run()

    if args.output:
        data = {
            "flows": [f.to_dict() for f in analyzer.flows],
            "dns_queries": [q.to_dict() for q in analyzer.dns_queries],
            "anomalies": analyzer.anomalies,
            "beacon_detections": analyzer.beacon_detections,
        }
        with open(args.output, "w") as f:
            json.dump(data, f, indent=2)
        console.print(f"[green]Results exported to {args.output}[/green]")


if __name__ == "__main__":
    main()
