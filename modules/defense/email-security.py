#!/usr/bin/env python3
"""Email security operations — header analysis, phishing detection, authentication"""
import re, hashlib, json, sys
from datetime import datetime

# ============================================================================
# HOMOGLYPH MAP
# ============================================================================
HOMOGLYPHS = {
    'a': ['а', 'ɑ', 'α', 'а'],  'b': ['Ь', 'ƅ'],  'c': ['с', 'ϲ', 'ᴄ'],
    'd': ['ԁ', 'ɗ'],  'e': ['е', 'ё', 'ε'],  'f': ['ƒ'],
    'g': ['ɡ', 'ğ'],  'h': ['һ', 'ℎ'],  'i': ['і', 'ı', 'ɪ'],
    'j': ['ϳ', 'ј'],  'k': ['κ', 'ⲕ'],  'l': ['ⅼ', 'ӏ', '|', 'ɭ'],
    'm': ['ⅿ', 'ṁ'],  'n': ['ո', 'ɳ'],  'o': ['о', '0', 'ο', 'ᴏ'],
    'p': ['р', 'ρ'],  'q': ['ԛ'],  'r': ['г', 'ᴦ'],
    's': ['ѕ', 'ꜱ'],  't': ['τ', 'ᴛ'],  'u': ['υ', 'ᴜ', 'ü'],
    'v': ['ν', 'ᴠ'],  'w': ['ω', 'ᴡ'],  'x': ['х', 'ⅹ'],
    'y': ['у', 'ý'],  'z': ['ᴢ', 'ζ'],
}

# ============================================================================
# BRAND TARGETS FOR IMPERSONATION DETECTION
# ============================================================================
BRANDS = [
    "apple", "google", "microsoft", "amazon", "facebook", "meta", "netflix",
    "paypal", "chase", "wellsfargo", "bankofamerica", "citibank", "usbank",
    "capitalone", "amex", "americanexpress", "visa", "mastercard", "discover",
    "dropbox", "docusign", "adobe", "salesforce", "slack", "zoom", "teams",
    "linkedin", "twitter", "instagram", "whatsapp", "telegram", "signal",
    "coinbase", "binance", "kraken", "fedex", "ups", "usps", "dhl",
    "walmart", "target", "bestbuy", "ebay", "etsy", "shopify",
    "github", "gitlab", "bitbucket", "atlassian", "jira", "confluence",
    "office365", "outlook", "hotmail", "yahoo", "aol", "protonmail",
]

URGENCY_PHRASES = [
    "act now", "immediate action required", "urgent", "account suspended",
    "verify your account", "confirm your identity", "unusual activity",
    "unauthorized access", "security alert", "your account will be closed",
    "within 24 hours", "within 48 hours", "limited time", "expires today",
    "failure to respond", "final warning", "last chance", "action required",
    "click here immediately", "do not ignore", "important update",
    "suspicious activity detected", "password expired", "verify now",
]

DANGEROUS_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".psd1",
    ".msi", ".msp", ".mst", ".cpl", ".hta", ".inf", ".ins",
    ".reg", ".rgs", ".sct", ".shb", ".shs", ".ws",
    ".iso", ".img", ".vhd", ".vhdx",
    ".lnk", ".url", ".xll", ".xlam",
    ".docm", ".xlsm", ".pptm", ".dotm",
    ".jar", ".py", ".rb", ".pl", ".sh",
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc",
    "rb.gy", "qr.ae", "adf.ly", "bc.vc", "v.gd", "x.co",
]


class EmailSecurity:
    name = "Email Security Operations"
    description = "Email header analysis, phishing detection, and authentication auditing"
    category = "defense"
    mitre = ["T1566", "T1566.001", "T1566.002", "T1534"]

    def __init__(self, target=None, options=None):
        self.target = target
        self.options = options or {}
        self.findings = []

    def run(self, confirm_fn=None):
        print("\n=== AEGIS Email Security ===\n")
        print("Modes:")
        print("  1. Analyze email headers (paste raw headers)")
        print("  2. Phishing detection (paste email content)")
        print("  3. SPF record builder")
        print("  4. DKIM record reference")
        print("  5. DMARC record builder")
        print("  6. Email authentication scoring")
        print("  7. Extract IOCs from email")
        print("  8. Best practices checklist")
        print()
        mode = input("Select mode (1-8): ").strip()
        if mode == "1": self._analyze_headers()
        elif mode == "2": self._detect_phishing()
        elif mode == "3": self._build_spf()
        elif mode == "4": self._dkim_reference()
        elif mode == "5": self._build_dmarc()
        elif mode == "6": self._auth_scoring()
        elif mode == "7": self._extract_iocs()
        elif mode == "8": self._best_practices()

    def _analyze_headers(self):
        print("\nPaste raw email headers (end with empty line):")
        lines = []
        while True:
            line = input()
            if not line.strip():
                break
            lines.append(line)
        raw = "\n".join(lines)
        self._parse_headers(raw)

    def _parse_headers(self, raw):
        headers = {}
        current_key = None
        for line in raw.split("\n"):
            if re.match(r'^[A-Za-z][\w-]*:', line):
                key, _, val = line.partition(":")
                current_key = key.strip()
                headers.setdefault(current_key, []).append(val.strip())
            elif current_key and line.startswith((" ", "\t")):
                headers[current_key][-1] += " " + line.strip()

        print("\n=== Header Analysis ===\n")
        for field in ["From", "To", "Subject", "Date", "Message-ID", "Return-Path", "Reply-To", "X-Mailer", "X-Originating-IP"]:
            vals = headers.get(field, [])
            if vals:
                print("  " + field + ": " + vals[0])

        # Received chain
        received = headers.get("Received", [])
        if received:
            print("\n  Received Chain (" + str(len(received)) + " hops):")
            for i, r in enumerate(received):
                ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', r)
                from_match = re.search(r'from\s+(\S+)', r)
                by_match = re.search(r'by\s+(\S+)', r)
                ip = ip_match.group(1) if ip_match else "?"
                fr = from_match.group(1) if from_match else "?"
                by = by_match.group(1) if by_match else "?"
                print("    Hop " + str(i+1) + ": " + fr + " -> " + by + " [" + ip + "]")

        # Authentication results
        auth = headers.get("Authentication-Results", [])
        if auth:
            print("\n  Authentication Results:")
            for a in auth:
                spf = re.search(r'spf=(\w+)', a)
                dkim = re.search(r'dkim=(\w+)', a)
                dmarc = re.search(r'dmarc=(\w+)', a)
                if spf: print("    SPF:   " + spf.group(1).upper())
                if dkim: print("    DKIM:  " + dkim.group(1).upper())
                if dmarc: print("    DMARC: " + dmarc.group(1).upper())

        # Red flags
        flags = []
        from_val = headers.get("From", [""])[0]
        reply_to = headers.get("Reply-To", [""])[0]
        return_path = headers.get("Return-Path", [""])[0]

        from_email = re.search(r'<(.+?)>', from_val)
        reply_email = re.search(r'<(.+?)>', reply_to) if reply_to else None
        if from_email and reply_email and from_email.group(1).lower() != reply_email.group(1).lower():
            flags.append("From/Reply-To mismatch: " + from_email.group(1) + " vs " + reply_email.group(1))

        from_domain = from_email.group(1).split("@")[1] if from_email and "@" in from_email.group(1) else ""
        rp_domain = return_path.strip("<>").split("@")[1] if "@" in return_path else ""
        if from_domain and rp_domain and from_domain.lower() != rp_domain.lower():
            flags.append("From/Return-Path domain mismatch: " + from_domain + " vs " + rp_domain)

        if auth:
            for a in auth:
                if "spf=fail" in a.lower() or "spf=softfail" in a.lower():
                    flags.append("SPF validation failed")
                if "dkim=fail" in a.lower():
                    flags.append("DKIM validation failed")
                if "dmarc=fail" in a.lower():
                    flags.append("DMARC validation failed")

        if flags:
            print("\n  \033[91mRed Flags:\033[0m")
            for f in flags:
                print("    [!] " + f)
                self.findings.append({"severity": "high", "title": f, "mitre": "T1566"})

    def _detect_phishing(self):
        print("\nPaste email body/content (end with empty line):")
        lines = []
        while True:
            line = input()
            if not line.strip():
                break
            lines.append(line)
        content = "\n".join(lines).lower()
        flags = []

        # Urgency
        for phrase in URGENCY_PHRASES:
            if phrase in content:
                flags.append(("medium", "Urgency language: '" + phrase + "'"))

        # URLs
        urls = re.findall(r'https?://[^\s<>"\']+', content)
        for url in urls:
            domain = re.search(r'https?://([^/]+)', url)
            if domain:
                d = domain.group(1).lower()
                if re.match(r'\d+\.\d+\.\d+\.\d+', d):
                    flags.append(("high", "IP-based URL: " + url))
                for s in URL_SHORTENERS:
                    if s in d:
                        flags.append(("medium", "URL shortener: " + url))
                        break
                if "%" in d or "xn--" in d:
                    flags.append(("high", "Encoded/IDN domain: " + d))
                for brand in BRANDS:
                    if brand in d and not d.endswith("." + brand + ".com") and d != brand + ".com":
                        flags.append(("high", "Brand impersonation in URL: " + brand + " in " + d))
                        break

        # Attachments mentioned
        for ext in DANGEROUS_EXTENSIONS:
            if ext in content:
                flags.append(("high", "Dangerous attachment type referenced: " + ext))

        # Brand impersonation in text
        for brand in BRANDS:
            if brand in content:
                flags.append(("low", "Brand mentioned: " + brand))
                break

        print("\n=== Phishing Analysis ===\n")
        if flags:
            for severity, msg in flags:
                color = {"critical": "\033[91m", "high": "\033[93m", "medium": "\033[33m", "low": "\033[0m"}.get(severity, "")
                print("  " + color + "[" + severity.upper() + "] " + msg + "\033[0m")
                self.findings.append({"severity": severity, "title": msg, "mitre": "T1566"})
            score = sum(3 if s == "high" else 2 if s == "medium" else 1 for s, _ in flags)
            verdict = "LIKELY PHISHING" if score >= 6 else "SUSPICIOUS" if score >= 3 else "LOW RISK"
            color = "\033[91m" if score >= 6 else "\033[93m" if score >= 3 else "\033[92m"
            print("\n  " + color + "Verdict: " + verdict + " (score: " + str(score) + ")\033[0m")
        else:
            print("  \033[92mNo obvious phishing indicators found.\033[0m")

    def _build_spf(self):
        print("\n=== SPF Record Builder ===\n")
        print("  SPF (Sender Policy Framework) defines which servers can send email for your domain.\n")
        domain = input("  Domain: ").strip() or "example.com"
        mechanisms = []
        if input("  Include MX servers? (y/n): ").strip().lower() == "y":
            mechanisms.append("mx")
        if input("  Include A record? (y/n): ").strip().lower() == "y":
            mechanisms.append("a")
        ips = input("  Additional IPs (comma-separated, or blank): ").strip()
        if ips:
            for ip in ips.split(","):
                ip = ip.strip()
                if "/" in ip:
                    mechanisms.append("ip4:" + ip)
                elif ":" in ip:
                    mechanisms.append("ip6:" + ip)
                else:
                    mechanisms.append("ip4:" + ip)
        includes = input("  Include third-party senders (e.g. _spf.google.com, comma-sep): ").strip()
        if includes:
            for inc in includes.split(","):
                mechanisms.append("include:" + inc.strip())
        policy = input("  Default policy (fail/-all, softfail/~all, neutral/?all): ").strip()
        qualifier = "-all" if "fail" in policy.lower() and "soft" not in policy.lower() else "~all" if "soft" in policy.lower() else "?all"
        record = "v=spf1 " + " ".join(mechanisms) + " " + qualifier
        print("\n  DNS TXT Record for " + domain + ":")
        print("  " + record)
        print("\n  Lookup count: " + str(len([m for m in mechanisms if m.startswith("include:") or m in ("mx", "a")])) + "/10 (max 10 DNS lookups)")

    def _dkim_reference(self):
        print("\n=== DKIM Reference ===\n")
        print("  DKIM (DomainKeys Identified Mail) adds a digital signature to outgoing emails.\n")
        print("  DNS Record Format:")
        print("    selector._domainkey.example.com  TXT  \"v=DKIM1; k=rsa; p=<public_key>\"\n")
        print("  Tags:")
        print("    v=DKIM1     Version (required)")
        print("    k=rsa       Key type (rsa or ed25519)")
        print("    p=...       Public key (base64)")
        print("    t=y         Testing mode")
        print("    t=s         Strict alignment (domain must match exactly)")
        print("    s=email     Service type")
        print("    h=sha256    Hash algorithm\n")
        print("  Key Generation:")
        print("    openssl genrsa -out dkim_private.pem 2048")
        print("    openssl rsa -in dkim_private.pem -pubout -outform der | base64 -w0")

    def _build_dmarc(self):
        print("\n=== DMARC Record Builder ===\n")
        domain = input("  Domain: ").strip() or "example.com"
        policy = input("  Policy (none/quarantine/reject): ").strip() or "none"
        rua = input("  Aggregate report email (rua): ").strip() or "dmarc@" + domain
        ruf = input("  Forensic report email (ruf, blank to skip): ").strip()
        pct = input("  Percentage to apply policy (1-100, default 100): ").strip() or "100"
        aspf = input("  SPF alignment (strict/relaxed, default relaxed): ").strip()
        adkim = input("  DKIM alignment (strict/relaxed, default relaxed): ").strip()
        record = "v=DMARC1; p=" + policy + "; rua=mailto:" + rua
        if ruf:
            record += "; ruf=mailto:" + ruf
        record += "; pct=" + pct
        if aspf.startswith("s"):
            record += "; aspf=s"
        if adkim.startswith("s"):
            record += "; adkim=s"
        print("\n  DNS TXT Record for _dmarc." + domain + ":")
        print("  " + record)

    def _auth_scoring(self):
        print("\n=== Email Authentication Scoring ===\n")
        domain = input("  Domain to check: ").strip()
        if not domain:
            print("  No domain provided.")
            return
        checks = [
            ("SPF record exists", "dig +short TXT " + domain + " | grep spf"),
            ("SPF uses -all (hard fail)", "dig +short TXT " + domain + " | grep '\\-all'"),
            ("DKIM selector exists", "dig +short TXT default._domainkey." + domain),
            ("DMARC record exists", "dig +short TXT _dmarc." + domain),
            ("DMARC policy is reject", "dig +short TXT _dmarc." + domain + " | grep 'p=reject'"),
            ("MTA-STS record exists", "dig +short TXT _mta-sts." + domain),
            ("BIMI record exists", "dig +short TXT default._bimi." + domain),
        ]
        print("  Manual checks (run these commands):\n")
        for desc, cmd in checks:
            print("  [ ] " + desc)
            print("      $ " + cmd)
        print("\n  Scoring:")
        print("    A: SPF -all + DKIM + DMARC reject + MTA-STS + BIMI")
        print("    B: SPF -all + DKIM + DMARC quarantine")
        print("    C: SPF ~all + DKIM + DMARC none")
        print("    D: SPF only, no DKIM or DMARC")
        print("    F: No email authentication records")

    def _extract_iocs(self):
        print("\nPaste email content for IOC extraction (end with empty line):")
        lines = []
        while True:
            line = input()
            if not line.strip():
                break
            lines.append(line)
        content = "\n".join(lines)
        ips = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content)))
        urls = list(set(re.findall(r'https?://[^\s<>"\']+', content)))
        domains = list(set(re.findall(r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}\b', content)))
        emails = list(set(re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', content)))
        hashes_md5 = list(set(re.findall(r'\b[a-fA-F0-9]{32}\b', content)))
        hashes_sha1 = list(set(re.findall(r'\b[a-fA-F0-9]{40}\b', content)))
        hashes_sha256 = list(set(re.findall(r'\b[a-fA-F0-9]{64}\b', content)))
        print("\n=== Extracted IOCs ===\n")
        if ips: print("  IPs (" + str(len(ips)) + "): " + ", ".join(ips))
        if urls: print("  URLs (" + str(len(urls)) + "):\n" + "\n".join("    " + u for u in urls))
        if domains: print("  Domains (" + str(len(domains)) + "): " + ", ".join(domains[:20]))
        if emails: print("  Emails (" + str(len(emails)) + "): " + ", ".join(emails))
        if hashes_md5: print("  MD5 (" + str(len(hashes_md5)) + "): " + ", ".join(hashes_md5))
        if hashes_sha1: print("  SHA1 (" + str(len(hashes_sha1)) + "): " + ", ".join(hashes_sha1))
        if hashes_sha256: print("  SHA256 (" + str(len(hashes_sha256)) + "): " + ", ".join(hashes_sha256))
        # Defanged output
        print("\n  Defanged IOCs:")
        for ip in ips:
            print("    " + ip.replace(".", "[.]"))
        for u in urls:
            print("    " + u.replace("http", "hxxp").replace(".", "[.]", 1))

    def _best_practices(self):
        print("\n=== Email Security Best Practices ===\n")
        checklist = [
            ("SPF", "Publish SPF record with -all (hard fail)"),
            ("DKIM", "Sign all outgoing email with DKIM (2048-bit RSA or Ed25519)"),
            ("DMARC", "Set DMARC to p=reject with aggregate reporting"),
            ("MTA-STS", "Enforce TLS for incoming mail with MTA-STS policy"),
            ("TLS-RPT", "Enable TLS reporting to detect delivery failures"),
            ("BIMI", "Add BIMI record for brand logo in email clients"),
            ("DANE/TLSA", "Publish TLSA records for mail server certificates"),
            ("Anti-spoofing", "Block emails where From domain is your own but fails SPF/DKIM"),
            ("Attachment filtering", "Block dangerous attachment types at the gateway"),
            ("URL rewriting", "Rewrite URLs in incoming email for click-time analysis"),
            ("Sandboxing", "Detonate attachments in sandbox before delivery"),
            ("Anti-phishing training", "Regular phishing simulation exercises for employees"),
            ("External email banner", "Mark external emails with a visible warning banner"),
            ("Mail flow rules", "Alert on auto-forwarding rules to external domains"),
            ("Reporting", "Provide easy 'Report Phishing' button in email client"),
            ("MFA", "Enable MFA on all email accounts"),
            ("Legacy auth", "Disable legacy authentication protocols (POP3, IMAP basic auth)"),
            ("Conditional access", "Restrict email access by device compliance and location"),
            ("DLP", "Enable Data Loss Prevention policies for sensitive data"),
            ("Encryption", "Enable S/MIME or PGP for sensitive communications"),
            ("Audit logging", "Enable mailbox audit logging for all accounts"),
            ("Admin alerts", "Alert on new mail forwarding rules and delegate access"),
            ("Impersonation protection", "Configure anti-impersonation for executives"),
            ("Safe links", "Enable URL protection/safe links for all recipients"),
            ("Safe attachments", "Enable attachment protection with detonation"),
        ]
        for i, (cat, desc) in enumerate(checklist):
            print("  [ ] " + str(i+1) + ". [" + cat + "] " + desc)

    def get_findings(self):
        return self.findings


if __name__ == "__main__":
    e = EmailSecurity()
    e.run()
