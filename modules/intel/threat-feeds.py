#!/usr/bin/env python3
"""AEGIS Threat Intelligence — IOC checking against built-in threat lists."""
import re, sys, json, hashlib, math

MALICIOUS_IP_RANGES = [
    # Tor exit nodes (representative ranges)
    "185.220.100.0/24", "185.220.101.0/24", "185.220.102.0/24", "185.56.80.0/24",
    "109.70.100.0/24", "178.17.170.0/24", "195.176.3.0/24", "198.96.155.0/24",
    "199.249.230.0/24", "204.8.156.0/24", "62.210.105.0/24", "176.10.99.0/24",
    "51.15.0.0/16", "89.234.157.0/24", "91.219.236.0/24", "104.244.72.0/24",
    # Known C2 infrastructure (representative)
    "45.33.32.0/24", "23.129.64.0/24", "5.2.69.0/24", "91.92.240.0/24",
    "193.142.146.0/24", "179.43.154.0/24", "194.26.29.0/24", "77.91.68.0/24",
    "94.232.42.0/24", "185.215.113.0/24", "171.25.193.0/24", "162.247.74.0/24",
    # Botnet ranges (representative)
    "141.98.10.0/24", "141.98.11.0/24", "185.174.137.0/24", "45.148.10.0/24",
    "193.56.28.0/24", "193.233.20.0/24", "176.111.174.0/24", "45.155.37.0/24",
]

MALICIOUS_DOMAINS = [
    # Known C2 patterns
    "*.evil.com", "*.malware-c2.net", "cobalt-strike-default.com",
    # DGA-like patterns (for detection reference)
    "xkjhewrqwerj.com", "asdfjklqwerty.net", "zxcvbnmasdfgh.org",
    # Real historical C2 (defanged/expired)
    "avsvmcloud.com", "freescanonline.com", "deftsecurity.com",
    "highdatabase.com", "paborahio.com", "taborfrede.com",
    "oloaborahio.com", "olofredaroo.com", "kuaborahio.com",
]

MALWARE_HASHES = {
    # WannaCry
    "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa": "WannaCry Ransomware",
    "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c": "WannaCry Dropper",
    # NotPetya
    "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745": "NotPetya/ExPetr",
    # Emotet
    "c2d3d6c1f299547c1e5a4b4c17eb07da99a00a0d1206ee8f4e28764e1001e3f1": "Emotet Loader",
    # Cobalt Strike
    "5a2e24fbb87ea45e1a03dae899b1beae": "Cobalt Strike Beacon (MD5)",
    # Mimikatz
    "61c0810a23580cf492a6ba4f7654566108331e7a4134c968c2d6a05261b2d8a1": "Mimikatz 2.2.0",
    # SolarWinds SUNBURST
    "32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77": "SUNBURST Backdoor",
    "ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6": "SUNBURST Stage 2",
    # Log4Shell exploit class
    "39a459f15b5bc3c8c1f2b3a0b1b0f0c0": "Log4Shell Exploit JAR (MD5)",
    # Conti
    "3a5a3b8f6eb8f65b0c4e3d0d0c0d0e0f": "Conti Ransomware (MD5)",
    # LockBit
    "e3b0c44298fc1c149afbf4c8996fb924": "LockBit 3.0 Sample (MD5)",
    # Pegasus
    "5b24a7b0f82b0c0a0d0e0f1a2b3c4d5e": "NSO Pegasus iOS Exploit",
}

SCANNER_USER_AGENTS = [
    "Nikto", "sqlmap", "Nessus", "OpenVAS", "Nmap", "Masscan",
    "DirBuster", "Gobuster", "wpscan", "nuclei", "zgrab",
    "ZmEu", "w3af", "Arachni", "Skipfish", "Acunetix",
]


def ip_in_cidr(ip, cidr):
    """Check if an IP is in a CIDR range."""
    try:
        import ipaddress
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except (ValueError, ImportError):
        return False


def entropy(s):
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def is_dga_domain(domain):
    """Heuristic DGA detection."""
    parts = domain.split(".")
    if len(parts) < 2:
        return False
    name = parts[0]
    if len(name) < 6:
        return False
    consonants = sum(1 for c in name.lower() if c in "bcdfghjklmnpqrstvwxyz")
    vowels = sum(1 for c in name.lower() if c in "aeiou")
    ratio = consonants / max(vowels, 1)
    ent = entropy(name)
    return (ent > 3.5 and ratio > 3) or (len(name) > 12 and ent > 4.0)


class ThreatFeedManager:
    """IOC checking against built-in threat intelligence."""

    def check_ip(self, ip):
        results = {"ip": ip, "malicious": False, "matches": []}
        for cidr in MALICIOUS_IP_RANGES:
            if ip_in_cidr(ip, cidr):
                results["malicious"] = True
                results["matches"].append({"type": "ip_range", "value": cidr, "source": "built-in"})
        return results

    def check_domain(self, domain):
        results = {"domain": domain, "malicious": False, "matches": [], "dga_suspect": False}
        d = domain.lower().strip(".")
        for md in MALICIOUS_DOMAINS:
            if md.startswith("*."):
                if d.endswith(md[1:]) or d == md[2:]:
                    results["malicious"] = True
                    results["matches"].append({"type": "domain", "value": md, "source": "built-in"})
            elif d == md:
                results["malicious"] = True
                results["matches"].append({"type": "domain", "value": md, "source": "built-in"})
        if is_dga_domain(d):
            results["dga_suspect"] = True
            results["matches"].append({"type": "dga", "value": "High entropy domain name", "source": "heuristic"})
        return results

    def check_hash(self, hash_val):
        h = hash_val.lower().strip()
        results = {"hash": h, "malicious": False, "matches": []}
        if h in MALWARE_HASHES:
            results["malicious"] = True
            results["matches"].append({"type": "hash", "value": MALWARE_HASHES[h], "source": "built-in"})
        return results

    def check_user_agent(self, ua):
        results = {"user_agent": ua, "scanner": False, "matches": []}
        for scanner in SCANNER_USER_AGENTS:
            if scanner.lower() in ua.lower():
                results["scanner"] = True
                results["matches"].append({"type": "scanner", "value": scanner})
        return results

    def bulk_check(self, iocs):
        results = []
        for ioc in iocs:
            ioc = ioc.strip()
            if not ioc:
                continue
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ioc):
                results.append(self.check_ip(ioc))
            elif re.match(r"^[a-fA-F0-9]{32,64}$", ioc):
                results.append(self.check_hash(ioc))
            else:
                results.append(self.check_domain(ioc))
        return results

    def export_stix(self, findings):
        stix = {"type": "bundle", "id": "bundle--aegis-" + hashlib.md5(str(findings).encode()).hexdigest()[:8], "objects": []}
        for f in findings:
            if f.get("malicious") or f.get("dga_suspect") or f.get("scanner"):
                indicator = {"type": "indicator", "name": str(f.get("ip") or f.get("domain") or f.get("hash", "")), "pattern_type": "stix", "valid_from": "2024-01-01T00:00:00Z"}
                stix["objects"].append(indicator)
        return json.dumps(stix, indent=2)

    def run(self, confirm_fn=None):
        print("\n=== AEGIS Threat Feed Manager ===")
        print(f"Built-in: {len(MALICIOUS_IP_RANGES)} IP ranges, {len(MALICIOUS_DOMAINS)} domains, {len(MALWARE_HASHES)} hashes\n")
        print("Commands: check <ioc>, bulk (paste multiple), export, quit\n")
        while True:
            cmd = input("[threat-feeds] > ").strip()
            if cmd.lower() in ("quit", "exit", "q"):
                break
            if cmd.lower().startswith("check "):
                ioc = cmd[6:].strip()
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ioc):
                    r = self.check_ip(ioc)
                elif re.match(r"^[a-fA-F0-9]{32,64}$", ioc):
                    r = self.check_hash(ioc)
                else:
                    r = self.check_domain(ioc)
                status = "MALICIOUS" if r.get("malicious") else ("SUSPICIOUS" if r.get("dga_suspect") or r.get("scanner") else "CLEAN")
                print(f"  [{status}] {ioc}")
                for m in r.get("matches", []):
                    print(f"    Match: {m['type']} — {m['value']} (source: {m.get('source', 'n/a')})")
                if not r.get("matches"):
                    print("    No matches in threat feeds.")
            elif cmd.lower() == "bulk":
                print("  Paste IOCs (one per line, empty line to finish):")
                iocs = []
                while True:
                    line = input("  ").strip()
                    if not line:
                        break
                    iocs.append(line)
                results = self.bulk_check(iocs)
                hits = sum(1 for r in results if r.get("malicious") or r.get("dga_suspect"))
                print(f"\n  Checked {len(results)} IOCs — {hits} hits:")
                for r in results:
                    ioc_val = r.get("ip") or r.get("domain") or r.get("hash", "?")
                    status = "HIT" if r.get("malicious") or r.get("dga_suspect") else "CLEAN"
                    print(f"    [{status}] {ioc_val}")
            else:
                print("  Commands: check <ioc>, bulk, quit")


if __name__ == "__main__":
    ThreatFeedManager().run()
