#!/usr/bin/env python3
"""AEGIS Honeypot Deployer — honeypot templates, honeytoken generators, and tripwires."""
import sys, secrets, string, hashlib
from datetime import datetime

HONEYPOT_TEMPLATES = {
    "ssh": {
        "name": "SSH Honeypot (Cowrie)",
        "tool": "Cowrie",
        "docker_compose": """version: '3'
services:
  cowrie:
    image: cowrie/cowrie:latest
    ports:
      - "2222:2222"
    volumes:
      - ./cowrie-logs:/cowrie/cowrie-git/var/log/cowrie
      - ./cowrie-dl:/cowrie/cowrie-git/var/lib/cowrie/downloads
    environment:
      - COWRIE_TELNET_ENABLED=no
    restart: unless-stopped""",
        "redirect": "iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222",
        "behavior": "Emulates SSH server, records login attempts, captures commands and uploaded files",
        "log_format": "JSON — username, password, source IP, commands executed, files downloaded",
        "detection_rule": 'alert tcp any any -> $HONEYPOT_IP 2222 (msg:"AEGIS: SSH honeypot triggered"; sid:200001; rev:1;)',
    },
    "web": {
        "name": "Web Application Honeypot (SNARE/TANNER)",
        "tool": "SNARE + TANNER",
        "docker_compose": """version: '3'
services:
  tanner:
    image: mushorg/tanner:latest
    ports:
      - "8090:8090"
    restart: unless-stopped
  snare:
    image: mushorg/snare:latest
    ports:
      - "8080:80"
    command: --tanner tanner --page-dir /opt/snare/pages
    depends_on:
      - tanner
    restart: unless-stopped""",
        "behavior": "Clones real websites, captures web attacks (SQLi, XSS, RFI), logs all requests",
        "log_format": "JSON — source IP, path, parameters, attack type, payload",
        "detection_rule": 'alert tcp any any -> $HONEYPOT_IP 8080 (msg:"AEGIS: Web honeypot triggered"; sid:200002; rev:1;)',
    },
    "database": {
        "name": "Database Honeypot (fake MySQL/Redis)",
        "tool": "Custom script",
        "docker_compose": """version: '3'
services:
  fake-mysql:
    image: python:3.11-slim
    ports:
      - "3306:3306"
    volumes:
      - ./fake_mysql.py:/app/fake_mysql.py
    command: python3 /app/fake_mysql.py
    restart: unless-stopped
  fake-redis:
    image: python:3.11-slim
    ports:
      - "6379:6379"
    volumes:
      - ./fake_redis.py:/app/fake_redis.py
    command: python3 /app/fake_redis.py
    restart: unless-stopped""",
        "behavior": "Accepts connections, logs authentication attempts, returns fake data on queries",
        "log_format": "JSON — source IP, credentials tried, queries attempted",
        "detection_rule": 'alert tcp any any -> $HONEYPOT_IP 3306 (msg:"AEGIS: MySQL honeypot triggered"; sid:200003; rev:1;)',
    },
    "smb": {
        "name": "SMB File Share Honeypot",
        "tool": "Impacket smbserver / HoneyDrive",
        "docker_compose": """version: '3'
services:
  fake-smb:
    image: python:3.11-slim
    ports:
      - "445:445"
    volumes:
      - ./fake_share:/share
      - ./smb_honeypot.py:/app/smb_honeypot.py
    command: python3 /app/smb_honeypot.py
    restart: unless-stopped""",
        "behavior": "Shares decoy files (fake credentials, configs), logs all access and enumeration",
        "log_format": "JSON — source IP, shares accessed, files read/written",
        "detection_rule": 'alert tcp any any -> $HONEYPOT_IP 445 (msg:"AEGIS: SMB honeypot triggered"; sid:200004; rev:1;)',
    },
    "rdp": {
        "name": "RDP Honeypot (RDPY)",
        "tool": "RDPY / PyRDP",
        "docker_compose": """version: '3'
services:
  fake-rdp:
    image: gosecure/pyrdp:latest
    ports:
      - "3389:3389"
    volumes:
      - ./rdp-logs:/var/log/pyrdp
    restart: unless-stopped""",
        "behavior": "Emulates RDP login screen, captures credentials and session activity",
        "log_format": "JSON + session recordings — credentials, keystrokes, screenshots",
        "detection_rule": 'alert tcp any any -> $HONEYPOT_IP 3389 (msg:"AEGIS: RDP honeypot triggered"; sid:200005; rev:1;)',
    },
}


def generate_fake_aws_key():
    """Generate a realistic-looking (but fake) AWS access key pair."""
    key_id = "AKIA" + "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))
    secret = "".join(secrets.choice(string.ascii_letters + string.digits + "+/") for _ in range(40))
    return {"access_key_id": key_id, "secret_access_key": secret, "note": "FAKE CANARY TOKEN — do not use for real AWS access", "alert_on": "Any AWS API call using this key triggers an alert"}


def generate_fake_db_creds():
    """Generate fake database connection strings."""
    password = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
    return {
        "mysql": f"mysql://admin:{password}@db-prod-01.internal:3306/customers",
        "postgresql": f"postgresql://dbadmin:{password}@pg-primary.internal:5432/production",
        "mongodb": f"mongodb://root:{password}@mongo-rs0.internal:27017/admin",
        "note": "FAKE CANARY — place in .env files, config files, or code repos",
        "alert_on": "Any connection attempt using these credentials",
    }


def generate_breadcrumb(breadcrumb_type):
    """Generate decoy file content."""
    if breadcrumb_type == "env":
        aws = generate_fake_aws_key()
        return f"""# Production environment - DO NOT SHARE
AWS_ACCESS_KEY_ID={aws['access_key_id']}
AWS_SECRET_ACCESS_KEY={aws['secret_access_key']}
DATABASE_URL=mysql://root:Pr0d_P@ssw0rd!@db-primary.internal:3306/production
STRIPE_SECRET_KEY=sk_live_{''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(24))}
ADMIN_PASSWORD=Sup3r$ecr3t2024!
"""
    elif breadcrumb_type == "passwords":
        return """=== IT Admin Passwords (CONFIDENTIAL) ===
Last updated: 2024-01-15

Domain Admin: admin / P@ssw0rd2024!
VPN: vpnadmin / Vpn$ecure123
Jenkins: admin / Jenkins#2024
Grafana: admin / Monitor!ng99
Database (prod): dbadmin / Db@Pr0d2024
SSH root: R00t$hell!2024
"""
    elif breadcrumb_type == "backup_sql":
        return """-- MySQL dump - customers database
-- CONFIDENTIAL - contains PII

CREATE TABLE customers (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100),
  email VARCHAR(100),
  ssn VARCHAR(11),
  credit_card VARCHAR(19),
  cvv VARCHAR(4)
);

INSERT INTO customers VALUES
(1, 'CANARY_TOKEN', 'alert@canary.internal', '000-00-0000', '0000-0000-0000-0000', '000');
"""
    return "Unknown breadcrumb type"


def generate_dns_canary(base_domain):
    """Generate a DNS canary subdomain."""
    token = secrets.token_hex(8)
    return {
        "subdomain": f"canary-{token}.{base_domain}",
        "usage": f"Place this domain in fake config files. Any DNS resolution attempt triggers an alert.",
        "monitor": f"Watch DNS logs for queries to canary-{token}.{base_domain}",
    }


PLACEMENT_RECOMMENDATIONS = [
    {"location": "Same subnet as production database", "type": "Database honeypot", "reason": "Detect lateral movement toward database servers"},
    {"location": "DMZ adjacent to web servers", "type": "Web honeypot", "reason": "Detect attackers who breach the DMZ"},
    {"location": "Server VLAN", "type": "SSH honeypot", "reason": "Detect credential reuse and brute force in server segment"},
    {"location": "Unused IP addresses in active subnets", "type": "Port listener", "reason": "Any traffic to unused IPs is suspicious by definition"},
    {"location": "Active Directory", "type": "Honeytoken credentials", "reason": "Detect Kerberoasting and credential theft"},
    {"location": "Network shares", "type": "Canary documents", "reason": "Detect data access and exfiltration attempts"},
    {"location": "Code repositories", "type": "Fake .env files", "reason": "Detect secret scanning and repo compromise"},
    {"location": "Cloud console", "type": "Unused IAM key", "reason": "Detect credential theft and cloud compromise"},
]


class HoneypotDeployer:
    """Honeypot deployment and honeytoken management."""

    def get_template(self, honeypot_type):
        return HONEYPOT_TEMPLATES.get(honeypot_type)

    def list_templates(self):
        return list(HONEYPOT_TEMPLATES.keys())

    def generate_honeytoken(self, token_type):
        if token_type == "aws":
            return generate_fake_aws_key()
        elif token_type == "db":
            return generate_fake_db_creds()
        elif token_type in ("env", "passwords", "backup_sql"):
            return generate_breadcrumb(token_type)
        elif token_type == "dns":
            domain = input("  Base domain: ").strip() or "example.com"
            return generate_dns_canary(domain)
        return None

    def run(self, confirm_fn=None):
        print("\n=== AEGIS Honeypot Deployer ===")
        print(f"Honeypot templates: {', '.join(self.list_templates())}")
        print("Commands: template <type>, token <aws|db|env|passwords|backup_sql|dns>, placement, quit\n")
        while True:
            cmd = input("[honeypot] > ").strip()
            if cmd.lower() in ("quit", "exit", "q"):
                break
            if cmd.lower().startswith("template "):
                t = self.get_template(cmd[9:].strip())
                if t:
                    print(f"\n  === {t['name']} ===")
                    print(f"  Tool: {t['tool']}")
                    print(f"  Behavior: {t['behavior']}")
                    print(f"  Log format: {t['log_format']}")
                    print(f"\n  Docker Compose:\n{t['docker_compose']}")
                    if t.get("redirect"):
                        print(f"\n  Port redirect: {t['redirect']}")
                    print(f"\n  Detection rule: {t['detection_rule']}")
                else:
                    print(f"  Unknown type. Available: {', '.join(self.list_templates())}")
            elif cmd.lower().startswith("token "):
                token_type = cmd[6:].strip()
                result = self.generate_honeytoken(token_type)
                if result:
                    if isinstance(result, dict):
                        for k, v in result.items():
                            print(f"  {k}: {v}")
                    else:
                        print(result)
                else:
                    print("  Unknown token type. Try: aws, db, env, passwords, backup_sql, dns")
            elif cmd.lower() == "placement":
                print("\n  === Honeypot Placement Recommendations ===\n")
                for r in PLACEMENT_RECOMMENDATIONS:
                    print(f"  Location: {r['location']}")
                    print(f"  Type: {r['type']}")
                    print(f"  Reason: {r['reason']}\n")
            else:
                print("  Commands: template, token, placement, quit")


if __name__ == "__main__":
    HoneypotDeployer().run()
