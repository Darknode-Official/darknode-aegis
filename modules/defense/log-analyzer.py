#!/usr/bin/env python3
"""AEGIS Log Analyzer — multi-format log parsing and threat detection."""
import re, sys, json
from datetime import datetime
from collections import Counter

SCANNER_UAS = ["nikto", "sqlmap", "nessus", "nmap", "masscan", "gobuster", "dirbuster", "wpscan", "nuclei", "acunetix", "burp", "zaproxy", "arachni", "w3af", "skipfish", "openvas", "qualys", "zgrab"]

SQLI_PATTERNS = [r"union\s+select", r"or\s+1\s*=\s*1", r"'\s*or\s*'", r";\s*drop\s+table", r"'\s*;\s*--", r"waitfor\s+delay", r"benchmark\(", r"extractvalue\(", r"updatexml\(", r"load_file\("]
XSS_PATTERNS = [r"<script", r"javascript:", r"onerror\s*=", r"onload\s*=", r"onfocus\s*=", r"onclick\s*=", r"eval\(", r"document\.cookie", r"alert\(", r"prompt\("]
CMDI_PATTERNS = [r";\s*(ls|cat|id|whoami|wget|curl|nc|bash|sh|python)", r"\|\s*(ls|cat|id|whoami)", r"`.*`", r"\$\(.*\)"]


def parse_apache_log(line):
    m = re.match(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) (\S+)(?: "([^"]*)" "([^"]*)")?', line)
    if not m:
        return None
    return {"src_ip": m.group(1), "timestamp": m.group(2), "method": m.group(3), "path": m.group(4), "status": int(m.group(5)), "size": int(m.group(6)) if m.group(6) != "-" else 0, "referer": m.group(7) or "", "user_agent": m.group(8) or "", "type": "apache"}


def parse_syslog(line):
    m = re.match(r'^(\S+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)', line)
    if not m:
        return None
    return {"timestamp": m.group(1), "host": m.group(2), "process": m.group(3), "pid": m.group(4) or "", "message": m.group(5), "src_ip": "", "type": "syslog"}


def parse_authlog(line):
    event = parse_syslog(line)
    if not event:
        return None
    event["type"] = "auth"
    msg = event["message"]
    ip_m = re.search(r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', msg)
    if ip_m:
        event["src_ip"] = ip_m.group(1)
    user_m = re.search(r'for\s+(?:invalid\s+user\s+)?(\S+)', msg)
    if user_m:
        event["user"] = user_m.group(1)
    if "Failed password" in msg:
        event["action"] = "failed_login"
    elif "Accepted" in msg:
        event["action"] = "successful_login"
    elif "sudo" in msg:
        event["action"] = "sudo"
    return event


def parse_json_log(line):
    try:
        data = json.loads(line)
        return {**data, "type": "json"}
    except (json.JSONDecodeError, TypeError):
        return None


def auto_detect_and_parse(line):
    line = line.strip()
    if not line:
        return None
    if line.startswith("{"):
        return parse_json_log(line)
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s', line):
        return parse_apache_log(line)
    if "sshd" in line or "sudo" in line or "Failed password" in line or "Accepted" in line:
        return parse_authlog(line)
    return parse_syslog(line)


class LogAnalyzer:
    """Multi-format log analysis engine."""

    def parse(self, log_text):
        events = []
        for line in log_text.strip().split("\n"):
            event = auto_detect_and_parse(line)
            if event:
                events.append(event)
        return events

    def detect_brute_force(self, events, threshold=5, window_minutes=5):
        failed = [e for e in events if e.get("action") == "failed_login" or (e.get("status") and e["status"] == 401)]
        ip_counts = Counter(e.get("src_ip", "") for e in failed if e.get("src_ip"))
        alerts = []
        for ip, count in ip_counts.most_common():
            if count >= threshold:
                alerts.append({"type": "brute_force", "severity": "HIGH", "src_ip": ip, "count": count, "desc": f"{count} failed login attempts from {ip}", "mitre": "T1110"})
        return alerts

    def detect_sqli(self, events):
        alerts = []
        for e in events:
            path = e.get("path", "")
            for pattern in SQLI_PATTERNS:
                if re.search(pattern, path, re.IGNORECASE):
                    alerts.append({"type": "sqli", "severity": "CRITICAL", "src_ip": e.get("src_ip", ""), "path": path, "desc": f"SQL injection attempt from {e.get('src_ip', '?')}", "mitre": "T1190"})
                    break
        return alerts

    def detect_xss(self, events):
        alerts = []
        for e in events:
            path = e.get("path", "")
            for pattern in XSS_PATTERNS:
                if re.search(pattern, path, re.IGNORECASE):
                    alerts.append({"type": "xss", "severity": "HIGH", "src_ip": e.get("src_ip", ""), "path": path, "desc": f"XSS attempt from {e.get('src_ip', '?')}", "mitre": "T1189"})
                    break
        return alerts

    def detect_scanners(self, events):
        alerts = []
        seen = set()
        for e in events:
            ua = e.get("user_agent", "").lower()
            for scanner in SCANNER_UAS:
                if scanner in ua and e.get("src_ip") not in seen:
                    seen.add(e.get("src_ip"))
                    alerts.append({"type": "scanner", "severity": "MEDIUM", "src_ip": e.get("src_ip", ""), "scanner": scanner, "desc": f"Scanner ({scanner}) detected from {e.get('src_ip', '?')}", "mitre": "T1595"})
        return alerts

    def detect_cmdi(self, events):
        alerts = []
        for e in events:
            path = e.get("path", "")
            for pattern in CMDI_PATTERNS:
                if re.search(pattern, path, re.IGNORECASE):
                    alerts.append({"type": "command_injection", "severity": "CRITICAL", "src_ip": e.get("src_ip", ""), "path": path, "desc": f"Command injection attempt from {e.get('src_ip', '?')}", "mitre": "T1059"})
                    break
        return alerts

    def detect_exfiltration(self, events, threshold_bytes=100_000_000):
        ip_bytes = Counter()
        for e in events:
            if e.get("size") and e.get("src_ip"):
                ip_bytes[e["src_ip"]] += e["size"]
        alerts = []
        for ip, total in ip_bytes.most_common():
            if total >= threshold_bytes:
                alerts.append({"type": "exfiltration", "severity": "HIGH", "src_ip": ip, "bytes": total, "desc": f"Large data transfer to {ip}: {total / 1_000_000:.1f} MB", "mitre": "T1048"})
        return alerts

    def extract_iocs(self, events):
        ips = set()
        paths = set()
        user_agents = set()
        for e in events:
            if e.get("src_ip"):
                ips.add(e["src_ip"])
            if e.get("path"):
                paths.add(e["path"])
            if e.get("user_agent"):
                user_agents.add(e["user_agent"])
        return {"ips": sorted(ips), "unique_paths": len(paths), "unique_user_agents": len(user_agents)}

    def statistics(self, events):
        ip_counts = Counter(e.get("src_ip", "") for e in events if e.get("src_ip"))
        status_counts = Counter(e.get("status") for e in events if e.get("status"))
        method_counts = Counter(e.get("method") for e in events if e.get("method"))
        return {"total_events": len(events), "unique_ips": len(ip_counts), "top_ips": ip_counts.most_common(10), "status_codes": status_counts.most_common(10), "methods": method_counts.most_common(5)}

    def run_all_detections(self, events):
        all_alerts = []
        all_alerts.extend(self.detect_brute_force(events))
        all_alerts.extend(self.detect_sqli(events))
        all_alerts.extend(self.detect_xss(events))
        all_alerts.extend(self.detect_cmdi(events))
        all_alerts.extend(self.detect_scanners(events))
        all_alerts.extend(self.detect_exfiltration(events))
        return sorted(all_alerts, key=lambda a: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(a.get("severity", "LOW"), 4))

    def run(self, confirm_fn=None):
        print("\n=== AEGIS Log Analyzer ===")
        print("Paste log entries (empty line to finish):\n")
        lines = []
        while True:
            line = input()
            if not line.strip():
                break
            lines.append(line)
        if not lines:
            print("  No logs provided.")
            return
        log_text = "\n".join(lines)
        events = self.parse(log_text)
        print(f"\n  Parsed {len(events)} events")
        stats = self.statistics(events)
        print(f"  Unique IPs: {stats['unique_ips']}")
        print(f"  Top IPs: {', '.join(f'{ip}({c})' for ip, c in stats['top_ips'][:5])}")
        if stats["status_codes"]:
            print(f"  Status codes: {', '.join(f'{s}({c})' for s, c in stats['status_codes'][:5])}")
        alerts = self.run_all_detections(events)
        if alerts:
            print(f"\n  {len(alerts)} ALERT(S) DETECTED:\n")
            for a in alerts:
                print(f"  [{a['severity']:8s}] [{a['type']}] {a['desc']} (MITRE: {a.get('mitre', 'N/A')})")
        else:
            print("\n  No threats detected.")


if __name__ == "__main__":
    LogAnalyzer().run()
