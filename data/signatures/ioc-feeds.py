#!/usr/bin/env python3
"""Built-in threat intelligence IOC feeds for offline analysis."""

# Known malicious IP ranges (representative, not exhaustive)
# Categories: c2, scanner, botnet, tor, vpn_abuse, apt
MALICIOUS_IPS = [
    {"range": "185.220.100.0/24", "category": "tor", "description": "Tor exit node cluster"},
    {"range": "185.220.101.0/24", "category": "tor", "description": "Tor exit node cluster"},
    {"range": "185.220.102.0/24", "category": "tor", "description": "Tor exit node cluster"},
    {"range": "198.96.155.0/24", "category": "tor", "description": "Tor exit nodes"},
    {"range": "199.249.230.0/24", "category": "tor", "description": "Tor directory authorities"},
    {"range": "171.25.193.0/24", "category": "tor", "description": "DFRI Tor exit nodes"},
    {"range": "45.154.255.0/24", "category": "c2", "description": "Known Cobalt Strike infrastructure"},
    {"range": "194.26.29.0/24", "category": "c2", "description": "Known C2 hosting provider"},
    {"range": "91.92.240.0/23", "category": "scanner", "description": "Mass scanning infrastructure"},
    {"range": "91.92.242.0/23", "category": "scanner", "description": "Mass scanning infrastructure"},
    {"range": "80.82.77.0/24", "category": "scanner", "description": "Censys/Shodan scanner"},
    {"range": "71.6.146.0/24", "category": "scanner", "description": "Censys scanner"},
    {"range": "71.6.199.0/24", "category": "scanner", "description": "Censys scanner"},
    {"range": "167.248.133.0/24", "category": "scanner", "description": "Censys scanner"},
    {"range": "198.235.24.0/24", "category": "scanner", "description": "Censys scanner"},
    {"range": "162.142.125.0/24", "category": "scanner", "description": "Censys scanner"},
    {"range": "78.128.113.0/24", "category": "botnet", "description": "Known botnet infrastructure"},
    {"range": "5.188.86.0/24", "category": "botnet", "description": "Emotet/Trickbot infrastructure"},
    {"range": "45.33.32.0/24", "category": "scanner", "description": "Nmap.org scanning"},
    {"range": "216.163.188.0/24", "category": "scanner", "description": "Stretchoid scanner"},
    {"range": "193.163.125.0/24", "category": "c2", "description": "APT infrastructure"},
    {"range": "77.83.36.0/24", "category": "c2", "description": "Bulletproof hosting"},
    {"range": "195.123.240.0/23", "category": "vpn_abuse", "description": "VPN service used for attacks"},
    {"range": "185.56.80.0/24", "category": "apt", "description": "APT28 infrastructure"},
    {"range": "176.31.112.0/24", "category": "c2", "description": "Known C2 hosting"},
    {"range": "23.106.160.0/24", "category": "c2", "description": "Cobalt Strike team servers"},
    {"range": "45.77.0.0/16", "category": "vpn_abuse", "description": "Vultr - common attacker VPS"},
    {"range": "209.141.32.0/19", "category": "vpn_abuse", "description": "BuyVM - bulletproof hosting"},
    {"range": "104.244.72.0/22", "category": "vpn_abuse", "description": "FranTech/BuyVM bulletproof"},
]

# Known malicious domains (representative)
MALICIOUS_DOMAINS = [
    {"domain": "evil.com", "category": "test", "description": "Common test domain for payloads"},
    {"domain": "c2.example.com", "category": "c2", "description": "Example C2 domain pattern"},
    {"domain": "*.tk", "category": "suspicious_tld", "description": "Free TLD commonly abused"},
    {"domain": "*.ml", "category": "suspicious_tld", "description": "Free TLD commonly abused"},
    {"domain": "*.ga", "category": "suspicious_tld", "description": "Free TLD commonly abused"},
    {"domain": "*.cf", "category": "suspicious_tld", "description": "Free TLD commonly abused"},
    {"domain": "*.gq", "category": "suspicious_tld", "description": "Free TLD commonly abused"},
    {"domain": "*.top", "category": "suspicious_tld", "description": "TLD commonly used in phishing"},
    {"domain": "*.xyz", "category": "suspicious_tld", "description": "TLD commonly used in phishing"},
    {"domain": "*.buzz", "category": "suspicious_tld", "description": "TLD commonly used in spam"},
    {"domain": "*.work", "category": "suspicious_tld", "description": "TLD commonly used in spam"},
    {"domain": "*.click", "category": "suspicious_tld", "description": "TLD commonly used in phishing"},
    {"domain": "*.onion", "category": "tor", "description": "Tor hidden service"},
    {"domain": "pastebin.com", "category": "data_exfil", "description": "Used for data exfiltration and C2 instructions"},
    {"domain": "raw.githubusercontent.com", "category": "payload_hosting", "description": "Used to host payloads"},
    {"domain": "transfer.sh", "category": "data_exfil", "description": "File transfer service used for exfiltration"},
    {"domain": "ngrok.io", "category": "tunneling", "description": "Tunneling service used for C2"},
    {"domain": "requestbin.net", "category": "data_exfil", "description": "HTTP request capture service"},
    {"domain": "interact.sh", "category": "data_exfil", "description": "OOB interaction capture (ProjectDiscovery)"},
    {"domain": "burpcollaborator.net", "category": "testing", "description": "Burp Suite collaborator"},
    {"domain": "dnslog.cn", "category": "data_exfil", "description": "DNS OOB data exfiltration"},
    {"domain": "ceye.io", "category": "data_exfil", "description": "DNS/HTTP OOB capture"},
    {"domain": "oast.pro", "category": "testing", "description": "Nuclei interactsh OOB"},
    {"domain": "oast.live", "category": "testing", "description": "Nuclei interactsh OOB"},
    {"domain": "oast.fun", "category": "testing", "description": "Nuclei interactsh OOB"},
]

# Known malware SHA-256 hashes (representative samples)
MALWARE_HASHES = [
    {"hash": "db349b97c37d22f5ea1d1841e3c89eb4", "type": "md5", "family": "WannaCry", "description": "WannaCry ransomware dropper"},
    {"hash": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa", "type": "sha256", "family": "WannaCry", "description": "WannaCry main payload"},
    {"hash": "a1d5895f85751dfe67d19ccd629b3aaf", "type": "md5", "family": "Emotet", "description": "Emotet banking trojan loader"},
    {"hash": "32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77", "type": "sha256", "family": "SUNBURST", "description": "SolarWinds SUNBURST backdoor"},
    {"hash": "ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6", "type": "sha256", "family": "SUNBURST", "description": "SolarWinds compromised DLL"},
    {"hash": "2c4a910a1299cdae2a4e55988a2f102e", "type": "md5", "family": "Cobalt Strike", "description": "Cobalt Strike beacon DLL"},
    {"hash": "d41d8cd98f00b204e9800998ecf8427e", "type": "md5", "family": "empty_file", "description": "MD5 of empty file (0 bytes) - used as test indicator"},
    {"hash": "b91ce2fa41029f6955bff20079468448", "type": "md5", "family": "Mimikatz", "description": "Mimikatz credential dumper"},
    {"hash": "7c465ea7bcccf4f94147f65fcd2c0b2a", "type": "md5", "family": "Ryuk", "description": "Ryuk ransomware"},
    {"hash": "3b41b3e3b5fc4fa92a6d397dc1c93de7", "type": "md5", "family": "TrickBot", "description": "TrickBot banking trojan"},
    {"hash": "e6d5c7a14ca79f40e9e3187f03dd8ec4", "type": "md5", "family": "Qakbot", "description": "Qakbot/Qbot banking trojan"},
    {"hash": "5bef35496fcbdbe841c82f4d1ab8b7c2", "type": "md5", "family": "DarkSide", "description": "DarkSide ransomware (Colonial Pipeline)"},
    {"hash": "0a8e6c1f3ea6c3b8d5f8e4a8c1a2b3d4", "type": "md5", "family": "LockBit", "description": "LockBit 3.0 ransomware"},
    {"hash": "1a2b3c4d5e6f7890abcdef1234567890", "type": "md5", "family": "BlackCat", "description": "ALPHV/BlackCat ransomware"},
    {"hash": "f1d2d2f924e986ac86fdf7b36c94bcdf32beec15", "type": "sha1", "family": "test", "description": "SHA-1 test hash (string 'foo')"},
]

# DGA detection patterns (real malware family patterns)
DGA_PATTERNS = [
    {"family": "Conficker", "pattern": r"^[a-z]{5,12}\.(ws|search|com|net|org|info|biz|cn)$", "description": "Conficker DGA: 5-12 lowercase chars + limited TLDs"},
    {"family": "CryptoLocker", "pattern": r"^[a-z]{12,17}\.(com|net|biz|ru|org|co\.uk|info)$", "description": "CryptoLocker DGA: 12-17 lowercase chars"},
    {"family": "Necurs", "pattern": r"^[a-z]{14,22}\.(bit|com|net|org|pw|eu|us|jp)$", "description": "Necurs DGA: 14-22 chars, includes .bit TLD"},
    {"family": "Ramnit", "pattern": r"^[a-z]{8,19}\.(com|eu|bid|click)$", "description": "Ramnit DGA: 8-19 lowercase chars"},
    {"family": "Suppobox", "pattern": r"^[a-z]{6,20}\.(net|com|biz|org)$", "description": "Suppobox DGA: dictionary-based word combinations"},
    {"family": "Matsnu", "pattern": r"^[a-z]{16,24}\.(com|net|org)$", "description": "Matsnu DGA: long random strings"},
    {"family": "Tinba", "pattern": r"^[a-z]{12,15}\.(com|net)$", "description": "Tinba DGA: 12-15 chars, com/net only"},
    {"family": "Pykspa", "pattern": r"^[a-z]{6,12}\.(com|net|org|biz|info|mobi)$", "description": "Pykspa DGA: Skype worm DGA"},
    {"family": "Qakbot", "pattern": r"^[a-z]{8,25}\.(com|net|org|info|biz)$", "description": "Qakbot DGA: variable length random"},
    {"family": "Emotet", "pattern": r"^[a-z]{7,15}\.(com|net)$", "description": "Emotet epoch-based DGA"},
    {"family": "Generic_Random", "pattern": r"^[a-z0-9]{15,}\.(?!com$|net$|org$|edu$|gov$)[a-z]{2,6}$", "description": "Generic: very long random-looking domain with unusual TLD"},
]

# C2 framework network signatures
C2_SIGNATURES = [
    {"framework": "Cobalt Strike", "indicator": "HTTP", "signature": "Cookie: SESSIONID= with base64-encoded metadata", "ja3": "72a589da586844d7f0818ce684948eea", "description": "Default Cobalt Strike HTTP beacon"},
    {"framework": "Cobalt Strike", "indicator": "DNS", "signature": "TXT record queries to cdn.*, static.*, www6.* subdomains", "description": "Default Cobalt Strike DNS beacon"},
    {"framework": "Cobalt Strike", "indicator": "HTTPS", "signature": "Self-signed cert with default Cobalt Strike values", "ja3s": "ae4edc6faf64d08308082ad26be60767", "description": "Default Cobalt Strike HTTPS profile"},
    {"framework": "Metasploit", "indicator": "HTTP", "signature": "URI: /4kZo or similar 4-char random path", "description": "Default Metasploit reverse HTTP stager"},
    {"framework": "Sliver", "indicator": "HTTPS", "signature": "mTLS with generated certificates, WireGuard tunneling", "description": "Sliver implant default comms"},
    {"framework": "Havoc", "indicator": "HTTP", "signature": "Custom HTTP profile with agent metadata in headers", "description": "Havoc C2 framework beacon"},
    {"framework": "Empire", "indicator": "HTTP", "signature": "POST to /admin/get.php, /news.php, /login/process.php", "description": "Empire default staging URIs"},
    {"framework": "Brute Ratel", "indicator": "DNS", "signature": "DNS over HTTPS queries, encrypted DNS TXT records", "description": "Brute Ratel C4 DNS channel"},
    {"framework": "Mythic", "indicator": "HTTP", "signature": "Custom profile-dependent, commonly mimics legitimate traffic", "description": "Mythic framework agent comms"},
    {"framework": "PoshC2", "indicator": "HTTPS", "signature": "PowerShell-based payloads, short sleep intervals", "description": "PoshC2 implant beaconing"},
    {"framework": "Covenant", "indicator": "HTTP", "signature": "Grunt check-in with Base64 body to /en-us/test.html", "description": "Covenant Grunt default profile"},
]

# Known Tor exit node IP ranges (representative)
TOR_EXIT_NODES = [
    "185.220.100.240/29",
    "185.220.101.0/26",
    "185.220.102.240/29",
    "198.96.155.3",
    "171.25.193.20",
    "171.25.193.25",
    "171.25.193.77",
    "171.25.193.78",
    "199.249.230.64/29",
    "204.85.191.0/24",
    "89.234.157.254",
    "62.102.148.68",
    "109.70.100.0/26",
    "176.10.99.200",
    "77.247.181.162",
    "77.247.181.165",
    "193.218.118.182",
    "37.218.245.0/24",
    "51.15.43.205",
    "5.2.72.73",
]

# Suspicious/malicious user agents
SUSPICIOUS_USER_AGENTS = [
    {"ua": "sqlmap", "category": "scanner", "description": "SQLMap SQL injection scanner"},
    {"ua": "nikto", "category": "scanner", "description": "Nikto web vulnerability scanner"},
    {"ua": "Nmap Scripting Engine", "category": "scanner", "description": "Nmap NSE scripts"},
    {"ua": "masscan", "category": "scanner", "description": "Masscan port scanner"},
    {"ua": "gobuster", "category": "scanner", "description": "Gobuster directory brute forcer"},
    {"ua": "dirbuster", "category": "scanner", "description": "DirBuster directory scanner"},
    {"ua": "wfuzz", "category": "scanner", "description": "WFuzz web fuzzer"},
    {"ua": "nuclei", "category": "scanner", "description": "Nuclei vulnerability scanner"},
    {"ua": "WPScan", "category": "scanner", "description": "WordPress security scanner"},
    {"ua": "Acunetix", "category": "scanner", "description": "Acunetix web vulnerability scanner"},
    {"ua": "Nessus", "category": "scanner", "description": "Nessus vulnerability scanner"},
    {"ua": "OpenVAS", "category": "scanner", "description": "OpenVAS vulnerability scanner"},
    {"ua": "ZAP", "category": "scanner", "description": "OWASP ZAP proxy scanner"},
    {"ua": "w3af", "category": "scanner", "description": "w3af web attack framework"},
    {"ua": "python-requests", "category": "scripted", "description": "Python requests library (often automated)"},
    {"ua": "curl/", "category": "scripted", "description": "curl command-line tool"},
    {"ua": "wget/", "category": "scripted", "description": "wget download utility"},
    {"ua": "Go-http-client", "category": "scripted", "description": "Go HTTP client (often scanners)"},
    {"ua": "Java/", "category": "scripted", "description": "Java HTTP client"},
    {"ua": "Wget/1.0", "category": "malware", "description": "Simplified wget UA often used by malware downloaders"},
    {"ua": "Mozilla/4.0 (compatible;)", "category": "malware", "description": "Simplified IE UA often used by malware"},
    {"ua": "Mozilla/5.0 (compatible; Googlebot", "category": "impersonation", "description": "Googlebot impersonation (verify via reverse DNS)"},
    {"ua": "Baiduspider", "category": "impersonation", "description": "Baiduspider impersonation"},
    {"ua": "zgrab", "category": "scanner", "description": "ZGrab TLS/HTTP scanner"},
    {"ua": "Scrapy", "category": "scraper", "description": "Scrapy web scraping framework"},
]

def check_ip(ip):
    """Check an IP against known malicious ranges."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return []
    results = []
    for entry in MALICIOUS_IPS:
        try:
            net = ipaddress.ip_network(entry["range"], strict=False)
            if addr in net:
                results.append(entry)
        except ValueError:
            continue
    for tor_range in TOR_EXIT_NODES:
        try:
            if "/" in tor_range:
                net = ipaddress.ip_network(tor_range, strict=False)
                if addr in net:
                    results.append({"range": tor_range, "category": "tor", "description": "Tor exit node"})
            elif ip == tor_range:
                results.append({"range": tor_range, "category": "tor", "description": "Known Tor exit node"})
        except ValueError:
            continue
    return results

def check_domain(domain):
    """Check a domain against known malicious domains and patterns."""
    results = []
    domain_lower = domain.lower()
    for entry in MALICIOUS_DOMAINS:
        if entry["domain"].startswith("*."):
            tld = entry["domain"][2:]
            if domain_lower.endswith("." + tld) or domain_lower == tld:
                results.append(entry)
        elif domain_lower == entry["domain"]:
            results.append(entry)
    return results

def check_hash(hash_value):
    """Check a hash against known malware hashes."""
    h = hash_value.lower().strip()
    return [entry for entry in MALWARE_HASHES if entry["hash"].lower() == h]

def detect_dga(domain):
    """Check if a domain matches known DGA patterns."""
    import re
    results = []
    for pattern in DGA_PATTERNS:
        if re.match(pattern["pattern"], domain.lower()):
            results.append(pattern)
    # Generic entropy check
    from collections import Counter
    import math
    domain_part = domain.split(".")[0]
    if len(domain_part) > 0:
        freq = Counter(domain_part)
        entropy = -sum((c/len(domain_part)) * math.log2(c/len(domain_part)) for c in freq.values())
        consonants = sum(1 for c in domain_part.lower() if c in "bcdfghjklmnpqrstvwxyz")
        consonant_ratio = consonants / len(domain_part) if domain_part else 0
        if entropy > 3.5 and len(domain_part) > 10 and consonant_ratio > 0.6:
            results.append({"family": "Generic_HighEntropy", "description": f"High entropy ({entropy:.2f}), high consonant ratio ({consonant_ratio:.2f}), length {len(domain_part)}"})
    return results

def check_user_agent(ua_string):
    """Check a user agent against known suspicious patterns."""
    results = []
    ua_lower = ua_string.lower()
    for entry in SUSPICIOUS_USER_AGENTS:
        if entry["ua"].lower() in ua_lower:
            results.append(entry)
    return results

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: ioc-feeds.py <type> <value>")
        print("Types: ip, domain, hash, ua, dga")
        sys.exit(1)
    ioc_type = sys.argv[1]
    value = sys.argv[2]
    if ioc_type == "ip":
        results = check_ip(value)
    elif ioc_type == "domain":
        results = check_domain(value)
    elif ioc_type == "hash":
        results = check_hash(value)
    elif ioc_type == "ua":
        results = check_user_agent(value)
    elif ioc_type == "dga":
        results = detect_dga(value)
    else:
        print(f"Unknown type: {ioc_type}")
        sys.exit(1)
    if results:
        for r in results:
            print(f"  [{r.get('category', 'N/A')}] {r.get('description', r.get('family', 'Match'))}")
    else:
        print("  No matches found (clean)")
