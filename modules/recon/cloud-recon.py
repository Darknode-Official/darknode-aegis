#!/usr/bin/env python3
"""AEGIS Cloud Asset Discovery Module
Discovers cloud-hosted assets: S3 buckets, Azure blobs, GCP buckets,
cloud provider identification, CDN detection.
"""
import subprocess, json, os, sys, re
from datetime import datetime

def _run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except:
        return "", "", 1

class CloudRecon:
    name = "Cloud Asset Discovery"
    description = "Discover cloud-hosted assets, S3 buckets, Azure blobs, GCP buckets, CDN, and cloud provider identification"
    category = "recon"
    mitre = ["T1580", "T1538", "T1526"]

    BUCKET_SUFFIXES = [
        "", "-dev", "-staging", "-prod", "-production", "-test", "-backup", "-backups",
        "-assets", "-static", "-media", "-uploads", "-data", "-logs", "-archive",
        "-public", "-private", "-internal", "-www", "-web", "-api", "-cdn",
        "-images", "-img", "-files", "-docs", "-documents", "-config",
        "-db", "-database", "-dump", "-export", "-import", "-temp", "-tmp",
        "-deploy", "-releases", "-artifacts", "-packages", "-dist",
        ".dev", ".staging", ".prod", ".backup", ".assets", ".static",
    ]

    CLOUD_IP_RANGES = {
        "AWS": [
            ("3.0.0.0", "3.255.255.255"), ("13.0.0.0", "13.255.255.255"),
            ("18.0.0.0", "18.255.255.255"), ("34.0.0.0", "34.255.255.255"),
            ("35.0.0.0", "35.255.255.255"), ("44.192.0.0", "44.255.255.255"),
            ("52.0.0.0", "52.255.255.255"), ("54.0.0.0", "54.255.255.255"),
        ],
        "Azure": [
            ("13.64.0.0", "13.107.255.255"), ("20.0.0.0", "20.255.255.255"),
            ("40.64.0.0", "40.127.255.255"), ("51.0.0.0", "51.255.255.255"),
            ("52.96.0.0", "52.191.255.255"), ("104.40.0.0", "104.47.255.255"),
        ],
        "GCP": [
            ("34.64.0.0", "34.127.255.255"), ("35.184.0.0", "35.239.255.255"),
        ],
        "DigitalOcean": [
            ("64.225.0.0", "64.225.127.255"), ("134.209.0.0", "134.209.255.255"),
            ("157.230.0.0", "157.230.255.255"), ("167.71.0.0", "167.71.255.255"),
        ],
    }

    CDN_HEADERS = {
        "cloudfront": {"via": "cloudfront", "x-amz-cf-id": True, "x-amz-cf-pop": True},
        "cloudflare": {"cf-ray": True, "cf-cache-status": True, "server": "cloudflare"},
        "akamai": {"x-akamai-transformed": True, "server": "akamaighost"},
        "fastly": {"x-served-by": True, "x-cache": True, "x-fastly-request-id": True, "via": "varnish"},
        "stackpath": {"x-hw": True},
        "sucuri": {"x-sucuri-id": True},
        "incapsula": {"x-cdn": "incapsula", "x-iinfo": True},
    }

    def __init__(self, target, options=None):
        self.target = target.replace("https://", "").replace("http://", "").split("/")[0]
        self.options = options or {}
        self.findings = []
        self.actions = []

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

    def _ip_to_int(self, ip):
        parts = ip.split(".")
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])

    def cloud_provider_check(self, confirm_fn=None):
        cmd = f"dig +short {self.target} A"
        if not self._confirm(f"Resolve IP for cloud provider check: {cmd}", confirm_fn):
            return
        out, _, rc = _run(cmd)
        if rc != 0 or not out:
            return
        ip = out.splitlines()[0].strip()
        if not re.match(r'\d+\.\d+\.\d+\.\d+', ip):
            return
        ip_int = self._ip_to_int(ip)
        for provider, ranges in self.CLOUD_IP_RANGES.items():
            for start, end in ranges:
                if self._ip_to_int(start) <= ip_int <= self._ip_to_int(end):
                    self._add("info", f"Cloud provider: {provider}", f"IP {ip} falls within {provider} range ({start}-{end})", ip, "T1580")
                    return
        cname_out, _, _ = _run(f"dig +short {self.target} CNAME")
        if cname_out:
            cname = cname_out.strip().lower()
            if "amazonaws.com" in cname or "aws" in cname:
                self._add("info", "Cloud provider: AWS", f"CNAME points to {cname}", cname, "T1580")
            elif "azure" in cname or "microsoft" in cname or "cloudapp" in cname:
                self._add("info", "Cloud provider: Azure", f"CNAME points to {cname}", cname, "T1580")
            elif "googleapis" in cname or "google" in cname:
                self._add("info", "Cloud provider: GCP", f"CNAME points to {cname}", cname, "T1580")

    def s3_enumeration(self, confirm_fn=None):
        base = self.target.split(".")[0]
        action = f"Check {len(self.BUCKET_SUFFIXES)} S3 bucket naming patterns for '{base}'"
        if not self._confirm(action, confirm_fn):
            return
        found = []
        for suffix in self.BUCKET_SUFFIXES:
            bucket = base + suffix
            cmd = f'curl -sS -o /dev/null -w "%{{http_code}}" --max-time 5 "https://{bucket}.s3.amazonaws.com"'
            out, _, rc = _run(cmd, timeout=8)
            if rc == 0 and out in ("200", "403"):
                status = "PUBLIC" if out == "200" else "EXISTS (access denied)"
                severity = "high" if out == "200" else "info"
                found.append({"name": bucket, "status": status, "code": out})
                self._add(severity, f"S3 bucket found: {bucket} [{status}]", f"https://{bucket}.s3.amazonaws.com", "", "T1530")
        if found:
            self._add("info", f"S3 enumeration: {len(found)} buckets found", "\n".join(f"  {f['name']} [{f['status']}]" for f in found), "", "T1530")

    def azure_blob_enumeration(self, confirm_fn=None):
        base = self.target.split(".")[0]
        action = f"Check Azure blob storage patterns for '{base}'"
        if not self._confirm(action, confirm_fn):
            return
        suffixes = ["", "dev", "staging", "prod", "backup", "data", "assets", "public"]
        for suffix in suffixes:
            name = base + suffix if suffix else base
            cmd = f'curl -sS -o /dev/null -w "%{{http_code}}" --max-time 5 "https://{name}.blob.core.windows.net/?comp=list"'
            out, _, rc = _run(cmd, timeout=8)
            if rc == 0 and out in ("200", "403"):
                status = "PUBLIC" if out == "200" else "EXISTS"
                severity = "high" if out == "200" else "info"
                self._add(severity, f"Azure blob: {name} [{status}]", f"https://{name}.blob.core.windows.net", "", "T1530")

    def gcp_bucket_enumeration(self, confirm_fn=None):
        base = self.target.split(".")[0]
        action = f"Check GCP bucket patterns for '{base}'"
        if not self._confirm(action, confirm_fn):
            return
        suffixes = ["", "-dev", "-staging", "-prod", "-backup", "-data"]
        for suffix in suffixes:
            name = base + suffix
            cmd = f'curl -sS -o /dev/null -w "%{{http_code}}" --max-time 5 "https://storage.googleapis.com/{name}"'
            out, _, rc = _run(cmd, timeout=8)
            if rc == 0 and out in ("200", "403"):
                status = "PUBLIC" if out == "200" else "EXISTS"
                severity = "high" if out == "200" else "info"
                self._add(severity, f"GCP bucket: {name} [{status}]", f"https://storage.googleapis.com/{name}", "", "T1530")

    def cdn_detection(self, confirm_fn=None):
        cmd = f'curl -sS -D- --max-time 10 "https://{self.target}" -o /dev/null'
        if not self._confirm(f"Check CDN headers: {cmd}", confirm_fn):
            return
        out, _, rc = _run(cmd, timeout=15)
        if rc != 0 or not out:
            return
        headers = {}
        for line in out.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip().lower()
        for cdn, sigs in self.CDN_HEADERS.items():
            for key, val in sigs.items():
                if key in headers:
                    if val is True or (isinstance(val, str) and val in headers[key]):
                        self._add("info", f"CDN detected: {cdn}", f"Via header: {key}: {headers[key]}", "", "T1590.002")
                        return

    def cloud_api_discovery(self, confirm_fn=None):
        apis = [
            f"https://api.{self.target}", f"https://{self.target}/api",
            f"https://{self.target}/api/v1", f"https://{self.target}/api/v2",
            f"https://{self.target}/graphql", f"https://{self.target}/swagger.json",
            f"https://{self.target}/openapi.json", f"https://{self.target}/.well-known/openid-configuration",
        ]
        action = f"Check {len(apis)} API endpoints"
        if not self._confirm(action, confirm_fn):
            return
        for url in apis:
            cmd = f'curl -sS -o /dev/null -w "%{{http_code}}" --max-time 5 "{url}"'
            out, _, rc = _run(cmd, timeout=8)
            if rc == 0 and out in ("200", "301", "302", "401"):
                self._add("info" if out == "401" else "medium", f"API endpoint: {url} [{out}]", "", "", "T1595.002")

    def run(self, confirm_fn=None):
        print(f"\n[AEGIS] Cloud Asset Discovery: {self.target}")
        print("=" * 60)
        self.cloud_provider_check(confirm_fn)
        self.cdn_detection(confirm_fn)
        self.s3_enumeration(confirm_fn)
        self.azure_blob_enumeration(confirm_fn)
        self.gcp_bucket_enumeration(confirm_fn)
        self.cloud_api_discovery(confirm_fn)
        print(f"\n[AEGIS] Cloud recon complete: {len(self.findings)} findings")
        return self.findings

    def get_findings(self):
        return self.findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 cloud-recon.py <domain>")
        sys.exit(1)
    def confirm(action):
        resp = input(f"\n[?] {action}\n    Execute? [y/n]: ").strip().lower()
        return resp in ("y", "yes")
    mod = CloudRecon(sys.argv[1])
    mod.run(confirm_fn=confirm)
    for f in mod.get_findings():
        sev = f["severity"].upper()
        print(f"  [{sev:8s}] {f['title']}")
