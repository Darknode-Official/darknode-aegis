#!/usr/bin/env python3
"""AEGIS Network Traffic Analysis — PCAP analysis, beaconing detection, protocol stats."""
import os, sys, subprocess, re, math, json
from datetime import datetime
from collections import Counter, defaultdict

class TrafficAnalysis:
    name = "Network Traffic Analysis"
    description = "PCAP analysis, protocol statistics, beaconing detection, DNS tunneling detection, suspicious traffic patterns"
    category = "network"
    mitre = ["T1040", "T1071", "T1572"]

    SUSPICIOUS_PORTS = {4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 12345, 54321}
    KNOWN_BAD_UA = ['sqlmap', 'nikto', 'nmap', 'masscan', 'gobuster', 'dirbuster', 'wfuzz', 'ffuf',
                    'nuclei', 'burp', 'zap', 'acunetix', 'nessus', 'openvas', 'qualys']
    C2_INDICATORS = ['beacon', 'callback', 'shell', 'meterpreter', 'cobalt', 'empire', 'covenant', 'sliver']

    def __init__(self, target=None, options=None):
        self.target = target
        self.options = options or {}
        self.findings = []
        self.actions = []

    def _log(self, msg):
        self.actions.append({"time": datetime.now().isoformat(), "action": msg})
        print(f"  [TRAFFIC] {msg}")

    def _run_tshark(self, pcap, args, timeout=60):
        cmd = f"tshark -r {pcap} {args}"
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout)
            return result.stdout.decode(errors='replace').strip()
        except subprocess.TimeoutExpired:
            return "Analysis timed out"
        except FileNotFoundError:
            return "tshark not found — install wireshark-cli"

    def protocol_stats(self, pcap_path):
        if not os.path.isfile(pcap_path):
            return {"error": f"File not found: {pcap_path}"}
        output = self._run_tshark(pcap_path, "-q -z io,phs")
        self._log(f"Protocol hierarchy: {pcap_path}")
        return {"protocol_hierarchy": output}

    def top_talkers(self, pcap_path, top_n=20):
        output = self._run_tshark(pcap_path, f"-q -z endpoints,ip")
        self._log(f"Top talkers from {pcap_path}")
        return {"endpoints": output}

    def conversations(self, pcap_path, proto='tcp'):
        output = self._run_tshark(pcap_path, f"-q -z conv,{proto}")
        self._log(f"{proto.upper()} conversations from {pcap_path}")
        return {f"{proto}_conversations": output}

    def dns_analysis(self, pcap_path):
        results = {}
        queries = self._run_tshark(pcap_path, "-Y 'dns.flags.response==0' -T fields -e dns.qry.name -e dns.qry.type")
        results["queries"] = queries[:3000]
        query_list = [l.split('\t')[0] for l in queries.split('\n') if l.strip()]
        results["total_queries"] = len(query_list)
        domain_counts = Counter()
        for q in query_list:
            parts = q.split('.')
            if len(parts) >= 2:
                domain_counts['.'.join(parts[-2:])] += 1
        results["top_domains"] = dict(domain_counts.most_common(20))
        long_queries = [q for q in query_list if len(q) > 50]
        if long_queries:
            results["long_queries"] = long_queries[:20]
            self.findings.append({
                "severity": "medium",
                "title": f"Long DNS queries detected ({len(long_queries)})",
                "detail": "DNS queries longer than 50 characters may indicate DNS tunneling",
                "mitre": "T1071.004"
            })
        high_entropy = []
        for q in query_list:
            label = q.split('.')[0]
            if len(label) > 10:
                freq = Counter(label.lower())
                ent = -sum((c/len(label)) * math.log2(c/len(label)) for c in freq.values() if c > 0)
                if ent > 3.5:
                    high_entropy.append({"query": q, "entropy": round(ent, 2)})
        if high_entropy:
            results["high_entropy_queries"] = high_entropy[:10]
            self.findings.append({
                "severity": "high",
                "title": f"High-entropy DNS queries ({len(high_entropy)})",
                "detail": "High entropy in DNS labels strongly indicates DNS tunneling or encoded data exfiltration",
                "mitre": "T1048.003"
            })
        self._log(f"DNS analysis: {len(query_list)} queries, {len(long_queries)} long, {len(high_entropy)} high-entropy")
        return results

    def http_analysis(self, pcap_path):
        results = {}
        requests = self._run_tshark(pcap_path, "-Y http.request -T fields -e http.request.method -e http.host -e http.request.uri -e http.user_agent -e ip.src")
        results["requests"] = requests[:3000]
        lines = [l for l in requests.split('\n') if l.strip()]
        results["total_requests"] = len(lines)
        for line in lines:
            parts = line.split('\t')
            if len(parts) >= 4:
                ua = parts[3].lower() if len(parts) > 3 else ''
                for scanner in self.KNOWN_BAD_UA:
                    if scanner in ua:
                        self.findings.append({
                            "severity": "high",
                            "title": f"Security scanner detected: {scanner}",
                            "detail": f"User-Agent matches known scanner: {parts[3][:100]}",
                            "mitre": "T1595.002"
                        })
                        break
                uri = parts[2] if len(parts) > 2 else ''
                sqli_patterns = ["union+select", "' or ", "1=1", "@@version", "information_schema"]
                for pattern in sqli_patterns:
                    if pattern.lower() in uri.lower():
                        self.findings.append({
                            "severity": "critical",
                            "title": "SQL injection attempt detected",
                            "detail": f"URI contains SQLi pattern: {uri[:200]}",
                            "mitre": "T1190"
                        })
                        break
        self._log(f"HTTP analysis: {len(lines)} requests")
        return results

    def detect_beaconing(self, pcap_path, min_connections=10, jitter_threshold=0.15):
        timestamps_raw = self._run_tshark(pcap_path, "-Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport")
        connections = defaultdict(list)
        for line in timestamps_raw.split('\n'):
            parts = line.strip().split('\t')
            if len(parts) >= 4:
                try:
                    ts = float(parts[0])
                    key = f"{parts[1]}->{parts[2]}:{parts[3]}"
                    connections[key].append(ts)
                except ValueError:
                    continue
        beacons = []
        for key, times in connections.items():
            if len(times) < min_connections:
                continue
            times.sort()
            intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
            if not intervals:
                continue
            mean_interval = sum(intervals) / len(intervals)
            if mean_interval < 1:
                continue
            variance = sum((i - mean_interval)**2 for i in intervals) / len(intervals)
            std_dev = variance ** 0.5
            jitter = std_dev / mean_interval if mean_interval > 0 else 1
            if jitter < jitter_threshold:
                beacons.append({
                    "connection": key,
                    "count": len(times),
                    "mean_interval_sec": round(mean_interval, 2),
                    "jitter": round(jitter, 4),
                    "duration_min": round((times[-1] - times[0]) / 60, 1),
                })
                self.findings.append({
                    "severity": "critical",
                    "title": f"C2 beaconing detected: {key}",
                    "detail": f"Regular interval: {mean_interval:.1f}s, jitter: {jitter:.4f}, connections: {len(times)}",
                    "mitre": "T1071"
                })
        self._log(f"Beaconing analysis: {len(beacons)} potential beacons found")
        return {"beacons": beacons, "total_flows_analyzed": len(connections)}

    def detect_data_exfil(self, pcap_path, threshold_mb=100):
        output = self._run_tshark(pcap_path, "-q -z conv,tcp")
        large_transfers = []
        for line in output.split('\n'):
            parts = line.split()
            if len(parts) >= 10:
                try:
                    bytes_ab = int(parts[4]) if parts[4].isdigit() else 0
                    bytes_ba = int(parts[7]) if len(parts) > 7 and parts[7].isdigit() else 0
                    total_mb = (bytes_ab + bytes_ba) / (1024 * 1024)
                    if total_mb > threshold_mb:
                        large_transfers.append({
                            "flow": f"{parts[0]} <-> {parts[2]}",
                            "size_mb": round(total_mb, 2),
                        })
                except (ValueError, IndexError):
                    continue
        if large_transfers:
            for t in large_transfers:
                self.findings.append({
                    "severity": "high",
                    "title": f"Large data transfer: {t['size_mb']} MB",
                    "detail": f"Flow: {t['flow']}",
                    "mitre": "T1048"
                })
        self._log(f"Exfiltration check: {len(large_transfers)} large transfers (>{threshold_mb} MB)")
        return {"large_transfers": large_transfers}

    def tls_analysis(self, pcap_path):
        output = self._run_tshark(pcap_path, "-Y 'tls.handshake.type==1' -T fields -e ip.src -e ip.dst -e tls.handshake.extensions_server_name -e tls.handshake.version")
        results = {"tls_connections": output[:3000]}
        ja3_output = self._run_tshark(pcap_path, "-Y 'tls.handshake.type==1' -T fields -e tls.handshake.ja3")
        if ja3_output.strip():
            results["ja3_hashes"] = list(set(ja3_output.strip().split('\n')))[:20]
        self._log(f"TLS analysis complete")
        return results

    def full_analysis(self, pcap_path, confirm_fn=None):
        if confirm_fn and not confirm_fn(f"Run full traffic analysis on {pcap_path}?"):
            return {"status": "cancelled"}
        if not os.path.isfile(pcap_path):
            return {"error": f"File not found: {pcap_path}"}
        results = {}
        results["protocols"] = self.protocol_stats(pcap_path)
        results["dns"] = self.dns_analysis(pcap_path)
        results["http"] = self.http_analysis(pcap_path)
        results["beaconing"] = self.detect_beaconing(pcap_path)
        results["exfiltration"] = self.detect_data_exfil(pcap_path)
        results["tls"] = self.tls_analysis(pcap_path)
        results["findings"] = self.findings
        return results

    def run(self, confirm_fn=None):
        if not self.target:
            return {"error": "Provide PCAP file path as target"}
        return self.full_analysis(self.target, confirm_fn)

    def get_findings(self):
        return self.findings

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: traffic-analysis.py <pcap_file> [--beaconing] [--dns] [--http]")
        sys.exit(1)
    ta = TrafficAnalysis(sys.argv[1])
    if '--beaconing' in sys.argv:
        r = ta.detect_beaconing(sys.argv[1])
    elif '--dns' in sys.argv:
        r = ta.dns_analysis(sys.argv[1])
    elif '--http' in sys.argv:
        r = ta.http_analysis(sys.argv[1])
    else:
        r = ta.full_analysis(sys.argv[1])
    print(json.dumps(r, indent=2, default=str)[:5000])
