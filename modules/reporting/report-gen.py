#!/usr/bin/env python3
"""AEGIS Professional Report Generator — pentest reports in Markdown with classification banners."""
import os, sys, json
from datetime import datetime

class ReportGenerator:
    name = "Report Generator"
    description = "Generate professional penetration test reports in Markdown with findings, risk matrix, and remediation"
    category = "reporting"
    mitre = []

    SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

    def __init__(self, target=None, options=None):
        self.target = target
        self.options = options or {}
        self.actions = []

    def _log(self, msg):
        self.actions.append({"time": datetime.now().isoformat(), "action": msg})

    def generate(self, mission_data):
        name = mission_data.get('name', 'Security Assessment')
        target = mission_data.get('target', 'Unknown')
        scope = mission_data.get('scope', 'As defined in the rules of engagement')
        classification = mission_data.get('classification', 'UNCLASSIFIED')
        operator = mission_data.get('operator', 'AEGIS Operator')
        findings = mission_data.get('findings', [])
        actions = mission_data.get('actions', [])
        iocs = mission_data.get('iocs', [])
        now = datetime.now()
        banner = f"**{classification}**" if classification != 'UNCLASSIFIED' else ''
        report = []
        report.append(f"# {name}")
        report.append(f"## Penetration Test Report")
        if banner:
            report.append(f"\n> {banner}\n")
        report.append(f"| Field | Value |")
        report.append(f"|-------|-------|")
        report.append(f"| **Target** | {target} |")
        report.append(f"| **Date** | {now.strftime('%Y-%m-%d')} |")
        report.append(f"| **Operator** | {operator} |")
        report.append(f"| **Classification** | {classification} |")
        report.append(f"| **Report ID** | AEGIS-{now.strftime('%Y%m%d')}-001 |")
        report.append("")
        report.append("---")
        report.append("")
        report.append("## Table of Contents")
        report.append("1. Executive Summary")
        report.append("2. Scope and Methodology")
        report.append("3. Findings Summary")
        report.append("4. Detailed Findings")
        report.append("5. Risk Rating Matrix")
        report.append("6. Remediation Roadmap")
        report.append("7. Appendices")
        report.append("")
        sev_counts = {}
        for s in self.SEVERITY_ORDER:
            sev_counts[s] = len([f for f in findings if f.get('severity', '').lower() == s])
        total = len(findings)
        compromised = len(set(f.get('host', '') for f in findings if f.get('severity', '') in ('critical', 'high')))
        report.append("## 1. Executive Summary")
        report.append("")
        report.append(f"AEGIS conducted a security assessment of **{target}** on {now.strftime('%B %d, %Y')}. ")
        report.append(f"The assessment identified **{total} findings**: "
                      f"**{sev_counts.get('critical',0)} critical**, **{sev_counts.get('high',0)} high**, "
                      f"**{sev_counts.get('medium',0)} medium**, and **{sev_counts.get('low',0)} low** severity issues.")
        report.append("")
        if sev_counts.get('critical', 0) > 0:
            report.append("**Overall Risk Rating: CRITICAL** - Immediate remediation required for critical findings. "
                         "The assessed environment has exploitable vulnerabilities that could lead to full compromise.")
        elif sev_counts.get('high', 0) > 0:
            report.append("**Overall Risk Rating: HIGH** - Significant vulnerabilities exist that should be addressed "
                         "within the next sprint cycle.")
        else:
            report.append("**Overall Risk Rating: MODERATE** - No critical vulnerabilities were identified, but "
                         "several medium-severity issues require attention.")
        report.append("")
        report.append("### Key Findings at a Glance")
        report.append("")
        report.append("| Severity | Count |")
        report.append("|----------|-------|")
        for s in self.SEVERITY_ORDER:
            if sev_counts.get(s, 0) > 0:
                report.append(f"| {s.upper()} | {sev_counts[s]} |")
        report.append("")
        report.append("## 2. Scope and Methodology")
        report.append("")
        report.append(f"**Scope:** {scope}")
        report.append("")
        report.append("**Methodology:** The assessment followed industry-standard methodology (PTES/OWASP/NIST) "
                     "with the AEGIS automated assessment platform. Testing phases included:")
        report.append("- Passive and active reconnaissance")
        report.append("- Vulnerability identification and verification")
        report.append("- Exploitation (with authorization)")
        report.append("- Post-exploitation and lateral movement assessment")
        report.append("- Reporting and remediation guidance")
        report.append("")
        report.append("**Tools Used:** AEGIS Platform, Nmap, Nikto, Gobuster, SQLMap, SSLScan, custom scripts")
        report.append("")
        report.append("**Limitations:**")
        report.append("- Testing was limited to the defined scope and rules of engagement")
        report.append("- Social engineering and physical security testing were not in scope")
        report.append("- Some vulnerabilities may not be discoverable through automated scanning alone")
        report.append("")
        report.append("## 3. Findings Summary")
        report.append("")
        report.append("| # | Severity | Title | Host | CVSS | MITRE |")
        report.append("|---|----------|-------|------|------|-------|")
        sorted_findings = sorted(findings, key=lambda f: self.SEVERITY_ORDER.index(f.get('severity', 'info').lower()) if f.get('severity', 'info').lower() in self.SEVERITY_ORDER else 99)
        for i, f in enumerate(sorted_findings, 1):
            sev = f.get('severity', 'info').upper()
            title = f.get('title', 'Untitled')[:60]
            host = f.get('host', '-')
            cvss = f.get('cvss', '-')
            mitre = f.get('mitre', '-')
            report.append(f"| {i} | {sev} | {title} | {host} | {cvss} | {mitre} |")
        report.append("")
        report.append("## 4. Detailed Findings")
        report.append("")
        for i, f in enumerate(sorted_findings, 1):
            sev = f.get('severity', 'info').upper()
            report.append(f"### Finding {i}: {f.get('title', 'Untitled')}")
            report.append("")
            report.append(f"| Field | Value |")
            report.append(f"|-------|-------|")
            report.append(f"| **Severity** | {sev} |")
            report.append(f"| **CVSS** | {f.get('cvss', 'N/A')} |")
            report.append(f"| **Host** | {f.get('host', 'N/A')} |")
            report.append(f"| **MITRE ATT&CK** | {f.get('mitre', 'N/A')} |")
            report.append(f"| **Module** | {f.get('module', 'N/A')} |")
            report.append("")
            report.append(f"**Description:** {f.get('detail', 'No details available.')}")
            report.append("")
            if f.get('evidence'):
                report.append(f"**Evidence:**")
                report.append(f"```")
                report.append(f"{f['evidence'][:500]}")
                report.append(f"```")
                report.append("")
            report.append(f"**Impact:** {f.get('impact', 'Could allow unauthorized access to the system or sensitive data.')}")
            report.append("")
            report.append(f"**Remediation:** {f.get('remediation', 'Apply vendor patches, harden configuration, follow least-privilege principles.')}")
            report.append("")
            report.append("---")
            report.append("")
        report.append("## 5. Risk Rating Matrix")
        report.append("")
        report.append("```")
        report.append("Impact      |  Critical  |   High   |  Medium  |   Low    |")
        report.append("------------|------------|----------|----------|----------|")
        report.append("Very High   |  CRITICAL  | CRITICAL |   HIGH   |  MEDIUM  |")
        report.append("High        |  CRITICAL  |   HIGH   |   HIGH   |  MEDIUM  |")
        report.append("Medium      |    HIGH    |   HIGH   |  MEDIUM  |   LOW    |")
        report.append("Low         |   MEDIUM   |  MEDIUM  |   LOW    |   LOW    |")
        report.append("Very Low    |   MEDIUM   |   LOW    |   LOW    |   INFO   |")
        report.append("```")
        report.append("")
        report.append("## 6. Remediation Roadmap")
        report.append("")
        report.append("### Immediate (0-48 hours)")
        for f in sorted_findings:
            if f.get('severity', '').lower() == 'critical':
                report.append(f"- [ ] **{f.get('title', '')}** on {f.get('host', 'N/A')}")
        report.append("")
        report.append("### Short-term (1-2 weeks)")
        for f in sorted_findings:
            if f.get('severity', '').lower() == 'high':
                report.append(f"- [ ] **{f.get('title', '')}** on {f.get('host', 'N/A')}")
        report.append("")
        report.append("### Medium-term (1-3 months)")
        for f in sorted_findings:
            if f.get('severity', '').lower() == 'medium':
                report.append(f"- [ ] {f.get('title', '')} on {f.get('host', 'N/A')}")
        report.append("")
        report.append("### Long-term (3-6 months)")
        for f in sorted_findings:
            if f.get('severity', '').lower() == 'low':
                report.append(f"- [ ] {f.get('title', '')} on {f.get('host', 'N/A')}")
        report.append("")
        if iocs:
            report.append("## 7. Appendix A: Indicators of Compromise")
            report.append("")
            report.append("| Type | Value | Context |")
            report.append("|------|-------|---------|")
            for ioc in iocs:
                report.append(f"| {ioc.get('type', '-')} | `{ioc.get('value', '-')}` | {ioc.get('context', '-')} |")
            report.append("")
        if actions:
            report.append("## Appendix B: Actions Taken")
            report.append("")
            report.append("| Time | Command | Result |")
            report.append("|------|---------|--------|")
            for a in actions[:50]:
                report.append(f"| {a.get('time', '-')} | `{a.get('command', '-')[:80]}` | {a.get('result', '-')[:40]} |")
            report.append("")
        report.append("---")
        report.append(f"*Report generated by AEGIS v1.0 on {now.isoformat()}*")
        if banner:
            report.append(f"\n> {banner}")
        final = '\n'.join(report)
        self._log(f"Generated report: {len(findings)} findings, {len(final)} chars")
        return final

    def save(self, report_text, output_path):
        with open(output_path, 'w') as f:
            f.write(report_text)
        self._log(f"Report saved to {output_path}")
        return {"status": "success", "path": output_path, "size": len(report_text)}

    def run(self, confirm_fn=None):
        return {"info": "Use generate(mission_data) to create a report, save(text, path) to write it."}

    def get_findings(self):
        return []

if __name__ == "__main__":
    rg = ReportGenerator()
    sample = {
        "name": "Sample Assessment",
        "target": "10.0.0.0/24",
        "scope": "Internal network penetration test",
        "classification": "CONFIDENTIAL",
        "operator": "AEGIS Operator",
        "findings": [
            {"severity": "critical", "title": "EternalBlue (CVE-2017-0144)", "host": "10.0.0.20", "cvss": "9.8", "mitre": "T1210", "detail": "SMBv1 buffer overflow allowing unauthenticated RCE", "remediation": "Disable SMBv1, apply MS17-010 patch"},
            {"severity": "high", "title": "Default MySQL Credentials", "host": "10.0.0.40", "cvss": "7.5", "mitre": "T1078", "detail": "MySQL root account has empty password", "remediation": "Set strong password for MySQL root"},
            {"severity": "medium", "title": "Missing HSTS Header", "host": "10.0.0.20", "cvss": "4.0", "mitre": "T1557", "detail": "Web server does not enforce HSTS", "remediation": "Add Strict-Transport-Security header"},
        ],
        "iocs": [{"type": "ip", "value": "10.0.0.20", "context": "Compromised host"}],
    }
    report = rg.generate(sample)
    print(report)
