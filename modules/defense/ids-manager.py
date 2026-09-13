#!/usr/bin/env python3
"""AEGIS IDS Manager — Snort, Sigma, and YARA rule generation and management."""
import sys

BUILTIN_SNORT_RULES = [
    {"sid": 100001, "msg": "Port scan detected", "rule": 'alert tcp any any -> $HOME_NET any (msg:"AEGIS: Port scan detected"; flags:S; threshold:type threshold, track by_src, count 20, seconds 60; sid:100001; rev:1;)'},
    {"sid": 100002, "msg": "SSH brute force", "rule": 'alert tcp any any -> $HOME_NET 22 (msg:"AEGIS: SSH brute force attempt"; flow:to_server; threshold:type threshold, track by_src, count 5, seconds 120; sid:100002; rev:1;)'},
    {"sid": 100003, "msg": "SQL injection attempt", "rule": 'alert tcp any any -> $HOME_NET $HTTP_PORTS (msg:"AEGIS: SQL injection attempt"; content:"UNION"; nocase; content:"SELECT"; nocase; sid:100003; rev:1;)'},
    {"sid": 100004, "msg": "XSS attempt", "rule": 'alert tcp any any -> $HOME_NET $HTTP_PORTS (msg:"AEGIS: XSS attempt"; content:"<script"; nocase; sid:100004; rev:1;)'},
    {"sid": 100005, "msg": "Command injection", "rule": 'alert tcp any any -> $HOME_NET $HTTP_PORTS (msg:"AEGIS: Command injection attempt"; content:"|3b|"; content:"wget"; nocase; sid:100005; rev:1;)'},
    {"sid": 100006, "msg": "Reverse shell detected", "rule": 'alert tcp $HOME_NET any -> any any (msg:"AEGIS: Reverse shell connection"; flow:established; content:"/bin/sh"; sid:100006; rev:1;)'},
    {"sid": 100007, "msg": "Mimikatz detected", "rule": 'alert tcp $HOME_NET any -> any any (msg:"AEGIS: Mimikatz activity"; content:"sekurlsa"; nocase; sid:100007; rev:1;)'},
    {"sid": 100008, "msg": "EternalBlue exploit", "rule": 'alert tcp any any -> $HOME_NET 445 (msg:"AEGIS: EternalBlue exploit attempt"; content:"|ff|SMB"; content:"|57 00 69 00 6e 00 64 00 6f 00 77 00 73|"; sid:100008; rev:1;)'},
    {"sid": 100009, "msg": "DNS tunneling", "rule": 'alert udp any any -> any 53 (msg:"AEGIS: Possible DNS tunneling"; dsize:>512; sid:100009; rev:1;)'},
    {"sid": 100010, "msg": "C2 beacon pattern", "rule": 'alert tcp $HOME_NET any -> any any (msg:"AEGIS: Possible C2 beacon - regular intervals"; flow:established,to_server; threshold:type both, track by_src, count 10, seconds 300; sid:100010; rev:1;)'},
    {"sid": 100011, "msg": "Web shell access", "rule": 'alert tcp any any -> $HOME_NET $HTTP_PORTS (msg:"AEGIS: Web shell access attempt"; content:"cmd="; nocase; pcre:"/cmd=(whoami|id|cat|ls|dir|net\x20user)/i"; sid:100011; rev:1;)'},
    {"sid": 100012, "msg": "SMB lateral movement", "rule": 'alert tcp $HOME_NET any -> $HOME_NET 445 (msg:"AEGIS: Internal SMB lateral movement"; flow:established; content:"|ff|SMB"; sid:100012; rev:1;)'},
    {"sid": 100013, "msg": "Data exfiltration", "rule": 'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"AEGIS: Large outbound transfer - possible exfiltration"; dsize:>10000; threshold:type threshold, track by_src, count 100, seconds 60; sid:100013; rev:1;)'},
    {"sid": 100014, "msg": "Log4Shell exploit", "rule": 'alert tcp any any -> $HOME_NET any (msg:"AEGIS: Log4Shell JNDI injection"; content:"${jndi:"; nocase; sid:100014; rev:1;)'},
    {"sid": 100015, "msg": "LDAP enumeration", "rule": 'alert tcp any any -> $HOME_NET 389 (msg:"AEGIS: LDAP enumeration"; content:"objectClass=*"; sid:100015; rev:1;)'},
    {"sid": 100016, "msg": "RDP brute force", "rule": 'alert tcp any any -> $HOME_NET 3389 (msg:"AEGIS: RDP brute force attempt"; threshold:type threshold, track by_src, count 5, seconds 120; sid:100016; rev:1;)'},
    {"sid": 100017, "msg": "Kerberoasting", "rule": 'alert tcp $HOME_NET any -> $HOME_NET 88 (msg:"AEGIS: Kerberoasting - TGS request with RC4"; content:"|a0 03 02 01 17|"; sid:100017; rev:1;)'},
    {"sid": 100018, "msg": "Pass-the-Hash", "rule": 'alert tcp $HOME_NET any -> $HOME_NET 445 (msg:"AEGIS: Pass-the-Hash lateral movement"; content:"NTLMSSP"; sid:100018; rev:1;)'},
    {"sid": 100019, "msg": "FTP anonymous login", "rule": 'alert tcp any any -> $HOME_NET 21 (msg:"AEGIS: FTP anonymous login"; content:"USER anonymous"; nocase; sid:100019; rev:1;)'},
    {"sid": 100020, "msg": "ICMP tunnel", "rule": 'alert icmp any any -> any any (msg:"AEGIS: ICMP tunnel - oversized payload"; dsize:>100; sid:100020; rev:1;)'},
]


def generate_snort_rule(proto, src, src_port, dst, dst_port, msg, content, sid, rev=1, flow="", extra=""):
    parts = [f'alert {proto} {src} {src_port} -> {dst} {dst_port} (msg:"{msg}";']
    if flow:
        parts.append(f' flow:{flow};')
    if content:
        parts.append(f' content:"{content}"; nocase;')
    if extra:
        parts.append(f' {extra};')
    parts.append(f' sid:{sid}; rev:{rev};)')
    return "".join(parts)


def generate_sigma_rule(title, status, description, logsource_product, logsource_service, detection_selection, condition, level, mitre_tags):
    lines = [
        f"title: {title}",
        f"status: {status}",
        f"description: {description}",
        "logsource:",
        f"    product: {logsource_product}",
        f"    service: {logsource_service}",
        "detection:",
        "    selection:",
    ]
    for k, v in detection_selection.items():
        lines.append(f"        {k}: '{v}'")
    lines.append(f"    condition: {condition}")
    lines.append(f"level: {level}")
    lines.append("tags:")
    for tag in mitre_tags:
        lines.append(f"    - {tag}")
    return "\n".join(lines)


def generate_yara_rule(name, description, strings_dict, condition="any of them", mitre=""):
    lines = [
        f"rule {name} {{",
        "    meta:",
        f'        description = "{description}"',
    ]
    if mitre:
        lines.append(f'        mitre = "{mitre}"')
    lines.append("    strings:")
    for var, val in strings_dict.items():
        lines.append(f'        {var} = "{val}"')
    lines.append(f"    condition:")
    lines.append(f"        {condition}")
    lines.append("}")
    return "\n".join(lines)


class IDSManager:
    """IDS/IPS rule generation and management."""

    def __init__(self):
        self.rules = list(BUILTIN_SNORT_RULES)

    def get_builtin_rules(self):
        return self.rules

    def rules_for_attack(self, attack_type):
        at = attack_type.lower()
        return [r for r in self.rules if at in r["msg"].lower()]

    def export_snort(self, rules=None):
        return "\n".join(r["rule"] for r in (rules or self.rules))

    def run(self, confirm_fn=None):
        print(f"\n=== AEGIS IDS Manager === ({len(self.rules)} built-in rules)")
        print("Commands: list, search <keyword>, snort <proto> <src> <dst> <port> <msg> <content>, sigma, yara, export, quit\n")
        while True:
            cmd = input("[ids] > ").strip()
            if cmd.lower() in ("quit", "exit", "q"):
                break
            if cmd.lower() == "list":
                for r in self.rules:
                    print(f"  [SID:{r['sid']}] {r['msg']}")
            elif cmd.lower().startswith("search "):
                results = self.rules_for_attack(cmd[7:])
                for r in results:
                    print(f"  [SID:{r['sid']}] {r['msg']}")
                    print(f"    {r['rule'][:120]}...")
            elif cmd.lower() == "export":
                print(self.export_snort())
            elif cmd.lower().startswith("snort"):
                print("  Enter rule parameters:")
                proto = input("    Protocol (tcp/udp/icmp): ").strip() or "tcp"
                src = input("    Source ($EXTERNAL_NET): ").strip() or "$EXTERNAL_NET"
                dst = input("    Destination ($HOME_NET): ").strip() or "$HOME_NET"
                port = input("    Port: ").strip() or "any"
                msg = input("    Message: ").strip()
                content = input("    Content match: ").strip()
                sid = input("    SID: ").strip() or str(100100 + len(self.rules))
                rule = generate_snort_rule(proto, src, "any", dst, port, msg, content, sid)
                print(f"\n  Generated rule:\n  {rule}")
            elif cmd.lower() == "sigma":
                print("  Enter Sigma rule parameters:")
                title = input("    Title: ").strip()
                desc = input("    Description: ").strip()
                product = input("    Log product (windows/linux): ").strip() or "windows"
                service = input("    Log service (sysmon/security): ").strip() or "sysmon"
                field = input("    Detection field: ").strip() or "EventID"
                value = input("    Detection value: ").strip()
                level = input("    Level (low/medium/high/critical): ").strip() or "medium"
                mitre = input("    MITRE technique (e.g. T1059): ").strip()
                rule = generate_sigma_rule(title, "experimental", desc, product, service, {field: value}, "selection", level, [f"attack.{mitre}"] if mitre else [])
                print(f"\n{rule}")
            elif cmd.lower() == "yara":
                print("  Enter YARA rule parameters:")
                name = input("    Rule name: ").strip() or "custom_rule"
                desc = input("    Description: ").strip()
                num = int(input("    Number of strings: ").strip() or "1")
                strings = {}
                for i in range(num):
                    val = input(f"    String {i+1}: ").strip()
                    strings[f"$s{i+1}"] = val
                rule = generate_yara_rule(name, desc, strings)
                print(f"\n{rule}")
            else:
                print("  Commands: list, search, snort, sigma, yara, export, quit")


if __name__ == "__main__":
    IDSManager().run()
