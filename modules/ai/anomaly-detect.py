#!/usr/bin/env python3
"""AEGIS Anomaly Detection Engine — statistical and behavioral anomaly detection on log data."""
import os, sys, re, math, json, csv
from datetime import datetime, timedelta
from collections import Counter, defaultdict

class AnomalyDetector:
    name = "Anomaly Detection Engine"
    description = "Statistical anomaly detection on logs: z-score, time-series, frequency, user behavior analytics"
    category = "ai"
    mitre = ["T1078", "T1110", "T1048"]

    def __init__(self, target=None, options=None):
        self.target = target
        self.options = options or {}
        self.findings = []
        self.actions = []
        self.baseline = {}

    def _log(self, msg):
        self.actions.append({"time": datetime.now().isoformat(), "action": msg})
        print(f"  [ANOMALY] {msg}")

    def _parse_log_line(self, line):
        patterns = [
            (r'(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[\d+\])?\s*:\s*(.*)', 'syslog'),
            (r'(\S+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"(\w+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+)', 'apache'),
            (r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\s]*)\s+(.*)', 'timestamp'),
        ]
        for pattern, fmt in patterns:
            m = re.match(pattern, line)
            if m:
                return {'format': fmt, 'groups': m.groups(), 'raw': line}
        return {'format': 'unknown', 'raw': line}

    def _extract_ips(self, text):
        return re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)

    def _mean(self, values):
        return sum(values) / len(values) if values else 0

    def _stddev(self, values):
        if len(values) < 2:
            return 0
        m = self._mean(values)
        return math.sqrt(sum((x - m) ** 2 for x in values) / (len(values) - 1))

    def z_score_analysis(self, values, labels=None, threshold=2.5):
        if len(values) < 3:
            return []
        mean = self._mean(values)
        std = self._stddev(values)
        if std == 0:
            return []
        anomalies = []
        for i, v in enumerate(values):
            z = (v - mean) / std
            if abs(z) > threshold:
                anomalies.append({
                    'index': i,
                    'label': labels[i] if labels else str(i),
                    'value': v,
                    'z_score': round(z, 2),
                    'mean': round(mean, 2),
                    'stddev': round(std, 2),
                    'direction': 'above' if z > 0 else 'below',
                })
        return anomalies

    def frequency_analysis(self, log_lines):
        ip_counts = Counter()
        user_counts = Counter()
        path_counts = Counter()
        hourly = defaultdict(int)
        status_counts = Counter()
        for line in log_lines:
            ips = self._extract_ips(line)
            for ip in ips:
                ip_counts[ip] += 1
            users = re.findall(r'(?:user|username|login)[=:\s]+(\S+)', line, re.I)
            for u in users:
                user_counts[u] += 1
            time_match = re.search(r'(\d{2}):(\d{2}):\d{2}', line)
            if time_match:
                hourly[int(time_match.group(1))] += 1
            status_match = re.search(r'\b([1-5]\d{2})\b', line)
            if status_match:
                status_counts[status_match.group(1)] += 1
        results = {
            'top_ips': dict(ip_counts.most_common(20)),
            'top_users': dict(user_counts.most_common(20)),
            'hourly_distribution': dict(sorted(hourly.items())),
            'status_codes': dict(status_counts.most_common(20)),
            'total_lines': len(log_lines),
        }
        ip_values = list(ip_counts.values())
        ip_labels = list(ip_counts.keys())
        ip_anomalies = self.z_score_analysis(ip_values, ip_labels)
        if ip_anomalies:
            for a in ip_anomalies:
                self.findings.append({
                    'severity': 'high',
                    'title': f"Anomalous IP activity: {a['label']}",
                    'detail': f"Count: {a['value']} (mean: {a['mean']}, z-score: {a['z_score']})",
                    'mitre': 'T1110'
                })
        results['ip_anomalies'] = ip_anomalies
        off_hours = sum(hourly.get(h, 0) for h in [0,1,2,3,4,5,22,23])
        total = sum(hourly.values())
        if total > 0 and off_hours / total > 0.3:
            self.findings.append({
                'severity': 'medium',
                'title': 'Significant off-hours activity',
                'detail': f"{off_hours}/{total} events ({off_hours/total*100:.0f}%) occurred outside business hours",
                'mitre': 'T1078'
            })
            results['off_hours_ratio'] = round(off_hours / total, 3)
        self._log(f"Frequency analysis: {len(log_lines)} lines, {len(ip_counts)} unique IPs")
        return results

    def brute_force_detection(self, log_lines, threshold=10, window_seconds=300):
        failed_logins = defaultdict(list)
        patterns = [
            r'Failed password for (\S+) from (\S+)',
            r'authentication failure.*rhost=(\S+)',
            r'Invalid user (\S+) from (\S+)',
            r'(\S+).*(?:401|403).*from (\S+)',
        ]
        for line in log_lines:
            for pat in patterns:
                m = re.search(pat, line, re.I)
                if m:
                    groups = m.groups()
                    ip = groups[-1] if len(groups) > 1 else groups[0]
                    time_match = re.search(r'(\w{3}\s+\d+\s+\d+:\d+:\d+|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})', line)
                    ts = time_match.group(1) if time_match else ''
                    failed_logins[ip].append({'time': ts, 'line': line.strip()[:200]})
        brute_force = []
        for ip, attempts in failed_logins.items():
            if len(attempts) >= threshold:
                brute_force.append({
                    'ip': ip,
                    'attempts': len(attempts),
                    'first_seen': attempts[0]['time'],
                    'last_seen': attempts[-1]['time'],
                })
                self.findings.append({
                    'severity': 'critical',
                    'title': f"Brute force detected from {ip}",
                    'detail': f"{len(attempts)} failed login attempts",
                    'mitre': 'T1110'
                })
        self._log(f"Brute force check: {len(brute_force)} attackers, {sum(len(a) for a in failed_logins.values())} total failed logins")
        return brute_force

    def privilege_escalation_detection(self, log_lines):
        indicators = []
        priv_patterns = [
            (r'sudo:\s+(\S+)\s+:', 'sudo usage', 'medium'),
            (r'su\[\d+\]:\s.*session opened for user root', 'su to root', 'high'),
            (r'COMMAND=.*(\/bin\/sh|\/bin\/bash|passwd|shadow|sudoers)', 'sensitive command via sudo', 'high'),
            (r'usermod.*-aG.*(sudo|wheel|admin|root)', 'user added to privileged group', 'critical'),
            (r'chmod\s+[47]\d{2}\s+\/(?:usr|etc|bin)', 'permission change on system file', 'high'),
            (r'setuid|setgid|capability', 'capability/setuid modification', 'high'),
        ]
        for line in log_lines:
            for pat, desc, sev in priv_patterns:
                if re.search(pat, line, re.I):
                    indicators.append({'description': desc, 'severity': sev, 'line': line.strip()[:200]})
                    self.findings.append({'severity': sev, 'title': f"Privilege escalation indicator: {desc}", 'detail': line.strip()[:200], 'mitre': 'T1548'})
        self._log(f"Privilege escalation check: {len(indicators)} indicators")
        return indicators

    def data_exfil_detection(self, log_lines, size_threshold=10485760):
        large_transfers = []
        size_patterns = [
            r'(\d+)\s+bytes?\s+(?:sent|transferred|uploaded)',
            r'Content-Length:\s+(\d+)',
            r'\b(\d{7,})\b.*(?:POST|PUT|upload)',
        ]
        for line in log_lines:
            for pat in size_patterns:
                m = re.search(pat, line, re.I)
                if m:
                    size = int(m.group(1))
                    if size > size_threshold:
                        large_transfers.append({'size_bytes': size, 'size_mb': round(size/1048576, 2), 'line': line.strip()[:200]})
                        self.findings.append({
                            'severity': 'high',
                            'title': f"Large data transfer: {size/1048576:.1f} MB",
                            'detail': line.strip()[:200],
                            'mitre': 'T1048'
                        })
        self._log(f"Exfiltration check: {len(large_transfers)} large transfers detected")
        return large_transfers

    def full_analysis(self, log_path, confirm_fn=None):
        if confirm_fn and not confirm_fn(f"Analyze log file {log_path} for anomalies?"):
            return {"status": "cancelled"}
        if not os.path.isfile(log_path):
            return {"error": f"File not found: {log_path}"}
        with open(log_path, 'r', errors='ignore') as f:
            lines = f.readlines()
        self._log(f"Loaded {len(lines)} lines from {log_path}")
        results = {
            'file': log_path,
            'total_lines': len(lines),
            'frequency': self.frequency_analysis(lines),
            'brute_force': self.brute_force_detection(lines),
            'privilege_escalation': self.privilege_escalation_detection(lines),
            'data_exfiltration': self.data_exfil_detection(lines),
            'findings': self.findings,
        }
        return results

    def run(self, confirm_fn=None):
        if not self.target:
            return {"error": "Provide log file path as target"}
        return self.full_analysis(self.target, confirm_fn)

    def get_findings(self):
        return self.findings

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: anomaly-detect.py <log_file>")
        sys.exit(1)
    ad = AnomalyDetector(sys.argv[1])
    result = ad.run()
    print(f"\n  Total findings: {len(result.get('findings', []))}")
    for f in result.get('findings', []):
        print(f"  [{f['severity'].upper()}] {f['title']}")
