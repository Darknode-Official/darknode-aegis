#!/usr/bin/env python3
"""AEGIS Active Reconnaissance Module
Directly probes target systems to discover open ports, services, and OS.
Every action requires explicit user confirmation.
"""
import subprocess, json, os, sys, re, socket, struct
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

def _run(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", 1
    except Exception as e:
        return "", str(e), 1

def _has(tool):
    return subprocess.run(["which", tool], capture_output=True).returncode == 0

TOP_100_PORTS = [7,20,21,22,23,25,43,53,67,68,69,79,80,88,110,111,113,119,123,135,137,138,139,143,161,162,179,194,201,264,389,443,445,464,500,512,513,514,515,543,544,548,554,587,631,636,873,902,993,995,1025,1080,1194,1433,1434,1521,1723,1883,2049,2082,2083,2086,2087,2096,2181,2222,3000,3128,3268,3269,3306,3389,3690,4443,4444,4567,4848,5000,5060,5432,5631,5632,5800,5900,5984,5985,5986,6000,6379,6443,6667,7001,7002,7070,7443,8000,8008,8080,8081,8443,8888]

TOP_20_UDP = [53,67,68,69,111,123,135,137,138,161,162,445,500,514,520,631,1434,1900,4500,5353]

class ActiveRecon:
    name = "Active Reconnaissance"
    description = "Port scanning, service detection, and OS fingerprinting via direct probing"
    category = "recon"
    mitre = ["T1046", "T1595.001", "T1595.002"]

    def __init__(self, target, options=None):
        self.target = target
        self.options = options or {}
        self.findings = []
        self.actions = []
        self.open_ports = []
        self.services = []
        self.os_info = ""
        self.has_nmap = _has("nmap")
        self.has_masscan = _has("masscan")

    def _add(self, severity, title, detail, evidence="", mitre=""):
        self.findings.append({
            "severity": severity, "title": title, "detail": detail,
            "evidence": evidence, "mitre": mitre,
            "timestamp": datetime.utcnow().isoformat(), "module": self.name
        })

    def _confirm(self, action, confirm_fn):
        self.actions.append(action)
        if confirm_fn:
            return confirm_fn(action)
        return True

    def _resolve(self):
        try:
            ip = socket.gethostbyname(self.target)
            return ip
        except socket.gaierror:
            return None

    def _python_scan(self, ip, ports, timeout=1.5):
        """Fallback TCP connect scan using Python sockets"""
        open_ports = []
        def check(port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                result = s.connect_ex((ip, port))
                s.close()
                if result == 0:
                    return port
            except:
                pass
            return None
        with ThreadPoolExecutor(max_workers=50) as pool:
            futures = {pool.submit(check, p): p for p in ports}
            for f in as_completed(futures):
                r = f.result()
                if r is not None:
                    open_ports.append(r)
        return sorted(open_ports)

    def _banner_grab(self, ip, port, timeout=3):
        """Grab service banner from an open port"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            probes = {
                80: b"HEAD / HTTP/1.0\r\nHost: " + self.target.encode() + b"\r\n\r\n",
                443: b"",
                8080: b"HEAD / HTTP/1.0\r\nHost: " + self.target.encode() + b"\r\n\r\n",
                8443: b"HEAD / HTTP/1.0\r\nHost: " + self.target.encode() + b"\r\n\r\n",
            }
            probe = probes.get(port, b"")
            if probe:
                s.send(probe)
            else:
                s.send(b"\r\n")
            banner = s.recv(1024).decode("utf-8", errors="replace").strip()
            s.close()
            return banner[:500]
        except:
            return ""

    def _guess_service(self, port):
        """Map port number to common service name"""
        port_map = {
            7: "echo", 20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
            25: "smtp", 43: "whois", 53: "dns", 67: "dhcp", 68: "dhcp",
            69: "tftp", 79: "finger", 80: "http", 88: "kerberos",
            110: "pop3", 111: "rpcbind", 119: "nntp", 123: "ntp",
            135: "msrpc", 137: "netbios-ns", 139: "netbios-ssn",
            143: "imap", 161: "snmp", 179: "bgp", 389: "ldap",
            443: "https", 445: "smb", 464: "kpasswd", 500: "isakmp",
            512: "rexec", 513: "rlogin", 514: "syslog", 543: "klogin",
            548: "afp", 554: "rtsp", 587: "submission", 631: "ipp",
            636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s",
            1080: "socks", 1194: "openvpn", 1433: "mssql", 1521: "oracle",
            1723: "pptp", 1883: "mqtt", 2049: "nfs", 2181: "zookeeper",
            2222: "ssh-alt", 3000: "grafana", 3128: "squid",
            3268: "ldap-gc", 3306: "mysql", 3389: "rdp", 3690: "svn",
            4443: "https-alt", 4848: "glassfish", 5000: "flask",
            5060: "sip", 5432: "postgresql", 5631: "pcanywhere",
            5800: "vnc-http", 5900: "vnc", 5984: "couchdb",
            5985: "winrm-http", 5986: "winrm-https", 6000: "x11",
            6379: "redis", 6443: "k8s-api", 6667: "irc",
            7001: "weblogic", 7070: "realserver", 7443: "https-alt",
            8000: "http-alt", 8008: "http-alt", 8080: "http-proxy",
            8081: "http-alt", 8443: "https-alt", 8888: "http-alt",
            9090: "prometheus", 9200: "elasticsearch", 9300: "es-transport",
            9418: "git", 9999: "abyss", 10000: "webmin",
            11211: "memcached", 27017: "mongodb", 27018: "mongodb",
            44818: "ethernet-ip", 47808: "bacnet", 50000: "sap",
        }
        return port_map.get(port, f"unknown-{port}")

    def nmap_scan(self, scan_type="standard", confirm_fn=None):
        if not self.has_nmap:
            self._add("info", "nmap not installed", "Install with: sudo apt install nmap\nFalling back to Python socket scan")
            return self.python_scan(scan_type, confirm_fn)

        port_arg = {
            "quick": "--top-ports 100",
            "standard": "--top-ports 1000",
            "full": "-p-",
            "custom": f"-p {self.options.get('ports', '1-1000')}",
        }.get(scan_type, "--top-ports 1000")

        cmd = f"nmap -sV -sC -T4 {port_arg} -oX - {self.target}"
        if not self._confirm(f"Run nmap scan: {cmd}", confirm_fn):
            return

        timeout = 600 if scan_type == "full" else 120
        out, err, rc = _run(cmd, timeout=timeout)
        if rc != 0 or not out:
            self._add("medium", "nmap scan failed", err or "No output")
            return

        self._parse_nmap_xml(out)
        self._add("info", f"nmap {scan_type} scan complete", f"Found {len(self.open_ports)} open ports on {self.target}", out[:3000], "T1046")

    def _parse_nmap_xml(self, xml):
        port_pattern = re.findall(r'<port protocol="(\w+)" portid="(\d+)">(.*?)</port>', xml, re.DOTALL)
        for proto, portid, content in port_pattern:
            port = int(portid)
            state_m = re.search(r'state="(\w+)"', content)
            if not state_m or state_m.group(1) != "open":
                continue
            service_m = re.search(r'<service name="([^"]*)"', content)
            product_m = re.search(r'product="([^"]*)"', content)
            version_m = re.search(r'version="([^"]*)"', content)
            svc_name = service_m.group(1) if service_m else self._guess_service(port)
            product = product_m.group(1) if product_m else ""
            version = version_m.group(1) if version_m else ""
            svc = {"port": port, "protocol": proto, "service": svc_name, "product": product, "version": version}
            self.open_ports.append(port)
            self.services.append(svc)
            banner = f"{product} {version}".strip()
            self._add("info", f"Port {port}/{proto} open: {svc_name}", f"Product: {product or 'unknown'}, Version: {version or 'unknown'}", banner, "T1046")

        os_m = re.search(r'<osmatch name="([^"]*)" accuracy="(\d+)"', xml)
        if os_m:
            self.os_info = f"{os_m.group(1)} (accuracy: {os_m.group(2)}%)"
            self._add("info", f"OS detected: {self.os_info}", "", "", "T1046")

    def python_scan(self, scan_type="standard", confirm_fn=None):
        ip = self._resolve()
        if not ip:
            self._add("high", f"Cannot resolve {self.target}", "DNS resolution failed")
            return

        ports = {
            "quick": TOP_100_PORTS,
            "standard": TOP_100_PORTS + list(range(1, 1001)),
            "full": list(range(1, 65536)),
            "custom": [int(p) for p in self.options.get("ports", "80,443").split(",") if p.strip().isdigit()],
        }.get(scan_type, TOP_100_PORTS)
        ports = sorted(set(ports))

        action = f"Python TCP connect scan on {ip} ({len(ports)} ports)"
        if not self._confirm(action, confirm_fn):
            return

        print(f"  Scanning {len(ports)} ports on {ip}...")
        open_ports = self._python_scan(ip, ports)
        self.open_ports = open_ports

        for port in open_ports:
            svc = self._guess_service(port)
            banner = self._banner_grab(ip, port)
            self.services.append({"port": port, "protocol": "tcp", "service": svc, "product": "", "version": "", "banner": banner})
            self._add("info", f"Port {port}/tcp open: {svc}", f"Banner: {banner[:200]}" if banner else "No banner", banner, "T1046")

        self._add("info", f"TCP scan complete: {len(open_ports)} open ports", f"Target: {self.target} ({ip})\nOpen: {', '.join(str(p) for p in open_ports)}", "", "T1046")

    def os_detection(self, confirm_fn=None):
        if not self.has_nmap:
            return
        cmd = f"sudo nmap -O --osscan-guess {self.target}"
        if not self._confirm(f"OS detection (requires root): {cmd}", confirm_fn):
            return
        out, err, rc = _run(cmd, timeout=60)
        if rc == 0 and out:
            os_lines = [l for l in out.splitlines() if "OS details:" in l or "Running:" in l or "OS CPE:" in l]
            if os_lines:
                self.os_info = "\n".join(os_lines)
                self._add("info", "OS fingerprint", self.os_info, "", "T1046")

    def udp_scan(self, confirm_fn=None):
        if not self.has_nmap:
            self._add("info", "UDP scan requires nmap", "Install with: sudo apt install nmap")
            return
        ports = ",".join(str(p) for p in TOP_20_UDP)
        cmd = f"sudo nmap -sU -T4 -p {ports} {self.target}"
        if not self._confirm(f"UDP scan (requires root): {cmd}", confirm_fn):
            return
        out, err, rc = _run(cmd, timeout=120)
        if rc == 0 and out:
            udp_open = re.findall(r'(\d+)/udp\s+open\s+(\S+)', out)
            for port, svc in udp_open:
                self._add("info", f"Port {port}/udp open: {svc}", "", "", "T1046")

    def traceroute(self, confirm_fn=None):
        tool = "traceroute" if _has("traceroute") else "tracepath" if _has("tracepath") else None
        if not tool:
            return
        cmd = f"{tool} -m 20 {self.target}"
        if not self._confirm(f"Traceroute: {cmd}", confirm_fn):
            return
        out, _, rc = _run(cmd, timeout=30)
        if rc == 0 and out:
            hops = len([l for l in out.splitlines() if re.match(r'\s*\d+\s', l)])
            self._add("info", f"Traceroute: {hops} hops to {self.target}", out[:2000], "", "T1046")

    def run(self, confirm_fn=None):
        print(f"\n[AEGIS] Active Reconnaissance: {self.target}")
        print("=" * 60)
        scan_type = self.options.get("scan_type", "standard")
        self.nmap_scan(scan_type, confirm_fn)
        if self.options.get("os_detect"):
            self.os_detection(confirm_fn)
        if self.options.get("udp"):
            self.udp_scan(confirm_fn)
        if self.options.get("traceroute"):
            self.traceroute(confirm_fn)
        print(f"\n[AEGIS] Active recon complete: {len(self.findings)} findings, {len(self.open_ports)} open ports")
        return self.findings

    def get_findings(self):
        return self.findings

    def get_services(self):
        return self.services

    def get_open_ports(self):
        return self.open_ports


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 active-recon.py <target> [quick|standard|full]")
        sys.exit(1)
    target = sys.argv[1]
    scan_type = sys.argv[2] if len(sys.argv) > 2 else "standard"
    def confirm(action):
        resp = input(f"\n[?] {action}\n    Execute? [y/n]: ").strip().lower()
        return resp in ("y", "yes")
    mod = ActiveRecon(target, {"scan_type": scan_type, "traceroute": True})
    findings = mod.run(confirm_fn=confirm)
    print(f"\n{'='*60}")
    print(f"FINDINGS: {len(findings)} | OPEN PORTS: {len(mod.get_open_ports())}")
    print(f"{'='*60}")
    for f in findings:
        sev = f["severity"].upper()
        color = {"critical": "\033[91m", "high": "\033[91m", "medium": "\033[93m", "low": "\033[94m", "info": "\033[90m"}.get(f["severity"], "")
        print(f"  {color}[{sev:8s}]\033[0m {f['title']}")
