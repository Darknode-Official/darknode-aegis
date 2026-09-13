#!/usr/bin/env python3
"""AEGIS Dark Web Monitor — educational reference for dark web monitoring methodology."""
import sys

MARKETPLACE_TAXONOMY = {
    "Credentials": {"types": ["email:password combos", "RDP access", "VPN credentials", "SSH keys", "API keys", "database dumps", "session tokens", "cloud account access"], "price_range": "$0.50 - $500 per account", "volume": "Billions of records available"},
    "PII": {"types": ["SSN + DOB + address (fullz)", "driver's license scans", "passport scans", "medical records (PHI)", "tax returns", "credit reports"], "price_range": "$1 - $100 per record", "volume": "Hundreds of millions of records"},
    "Financial": {"types": ["credit card numbers (CVV)", "bank account logins", "PayPal accounts", "crypto wallet keys", "wire transfer access", "cloned cards"], "price_range": "$5 - $500 per item", "volume": "Tens of millions of cards"},
    "Access": {"types": ["corporate network access", "webshell access", "admin panels", "cPanel/WHM access", "email server access", "database access"], "price_range": "$50 - $10,000+ per access", "volume": "Thousands of listings"},
    "Exploits": {"types": ["zero-day exploits", "exploit kits", "RAT builders", "ransomware-as-a-service", "botnet rental", "DDoS-for-hire"], "price_range": "$100 - $2,500,000", "volume": "Selective, high-value"},
    "Services": {"types": ["money laundering", "SIM swapping", "social engineering calls", "document forgery", "DDoS attacks", "spam/phishing campaigns"], "price_range": "$20 - $50,000+", "volume": "Widely available"},
}

MONITORING_METHODOLOGY = [
    "1. Define monitoring scope: organization name, domains, key employee names, IP ranges, product names",
    "2. Set up automated keyword alerts on known paste sites and forum aggregators",
    "3. Monitor Certificate Transparency logs for lookalike domains (typosquatting)",
    "4. Check breach notification services (Have I Been Pwned, SpyCloud, Identity Guard)",
    "5. Monitor dark web marketplace listings via threat intel platforms (Recorded Future, Flashpoint, DarkOwl)",
    "6. Track brand mentions on social media and underground forums",
    "7. Set up domain monitoring for newly registered lookalike domains",
    "8. Establish a process for triaging and responding to discovered exposures",
    "9. Maintain a log of all discovered mentions with timestamps and context",
    "10. Generate regular reports for stakeholders on dark web exposure status",
]

TOR_REFERENCE = {
    "setup": "sudo apt install tor torbrowser-launcher && torbrowser-launcher",
    "socks_proxy": "Configure applications to use SOCKS5 proxy at 127.0.0.1:9050",
    "search_engines": ["Ahmia.fi (clearnet gateway)", "Torch", "DuckDuckGo .onion", "Haystak"],
    "safety": ["Use Tails OS or Whonix for anonymity", "Never use personal credentials", "Disable JavaScript in Tor Browser", "Never download files from untrusted .onion sites", "Use a dedicated machine or VM", "Do not interact with illegal content"],
}

BREACH_NOTIFICATION_WORKFLOW = [
    "1. Verify the breach: confirm data is real and belongs to your organization",
    "2. Determine scope: what data types, how many records, date range",
    "3. Preserve evidence: screenshot/archive the listing with timestamps",
    "4. Engage legal counsel: determine notification obligations",
    "5. Notify law enforcement: FBI IC3, local CERT, CISA",
    "6. Internal notification: CISO, executive team, board (if material)",
    "7. Affected individual notification: within regulatory timeframes",
    "8. Regulatory notification: GDPR (72hr), HIPAA (60 days), state AG",
    "9. Public disclosure: if required or if media coverage is likely",
    "10. Remediation: reset compromised credentials, revoke tokens, patch vuln",
    "11. Post-incident: update security controls, conduct lessons learned",
]


class DarkWebReference:
    """Dark web monitoring educational reference."""

    def get_reference(self, topic):
        topic = topic.lower()
        if "market" in topic or "taxonomy" in topic:
            return MARKETPLACE_TAXONOMY
        if "method" in topic or "monitor" in topic:
            return MONITORING_METHODOLOGY
        if "tor" in topic or "setup" in topic:
            return TOR_REFERENCE
        if "breach" in topic or "notif" in topic:
            return BREACH_NOTIFICATION_WORKFLOW
        return None

    def price_lookup(self, data_type):
        dt = data_type.lower()
        for category, info in MARKETPLACE_TAXONOMY.items():
            if dt in category.lower() or any(dt in t.lower() for t in info["types"]):
                return {"category": category, "types": info["types"], "price_range": info["price_range"], "volume": info["volume"]}
        return None

    def run(self, confirm_fn=None):
        print("\n=== AEGIS Dark Web Monitor (Educational Reference) ===")
        print("NOTE: This module provides reference information only. It does NOT access the dark web.\n")
        print("Topics: marketplace, monitoring, tor, breach, prices, quit\n")
        while True:
            cmd = input("[darkweb] > ").strip().lower()
            if cmd in ("quit", "exit", "q"):
                break
            if cmd == "marketplace":
                for cat, info in MARKETPLACE_TAXONOMY.items():
                    print(f"\n  [{cat}] ({info['price_range']})")
                    for t in info["types"]:
                        print(f"    - {t}")
                    print(f"    Volume: {info['volume']}")
            elif cmd == "monitoring":
                print("\n  Dark Web Monitoring Methodology:")
                for step in MONITORING_METHODOLOGY:
                    print(f"  {step}")
            elif cmd == "tor":
                print("\n  Tor Setup Reference:")
                print(f"  Install: {TOR_REFERENCE['setup']}")
                print(f"  Proxy: {TOR_REFERENCE['socks_proxy']}")
                print("  Search engines: " + ", ".join(TOR_REFERENCE["search_engines"]))
                print("  Safety guidelines:")
                for s in TOR_REFERENCE["safety"]:
                    print(f"    - {s}")
            elif cmd == "breach":
                print("\n  Breach Notification Workflow:")
                for step in BREACH_NOTIFICATION_WORKFLOW:
                    print(f"  {step}")
            elif cmd.startswith("price"):
                query = cmd.replace("prices", "").replace("price", "").strip()
                if not query:
                    for cat, info in MARKETPLACE_TAXONOMY.items():
                        print(f"  {cat:15s} {info['price_range']}")
                else:
                    result = self.price_lookup(query)
                    if result:
                        print(f"  {result['category']}: {result['price_range']}")
                    else:
                        print("  Data type not found.")
            else:
                print("  Topics: marketplace, monitoring, tor, breach, prices, quit")


if __name__ == "__main__":
    DarkWebReference().run()
