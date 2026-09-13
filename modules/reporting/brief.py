#!/usr/bin/env python3
"""AEGIS Executive Briefing Generator — one-page security posture summary for leadership."""
import os, sys, json
from datetime import datetime

class ExecutiveBrief:
    name = "Executive Briefing"
    description = "One-page security posture summary for board/leadership: grade, top findings, budget recommendations"
    category = "reporting"

    INDUSTRY_BENCHMARKS = {
        "healthcare": {"avg_score": 62, "avg_findings": 47, "avg_critical": 8, "security_spend_pct": 6.0},
        "finance": {"avg_score": 74, "avg_findings": 38, "avg_critical": 5, "security_spend_pct": 10.0},
        "technology": {"avg_score": 71, "avg_findings": 42, "avg_critical": 6, "security_spend_pct": 8.0},
        "government": {"avg_score": 58, "avg_findings": 55, "avg_critical": 12, "security_spend_pct": 7.0},
        "education": {"avg_score": 52, "avg_findings": 61, "avg_critical": 15, "security_spend_pct": 4.0},
        "retail": {"avg_score": 60, "avg_findings": 44, "avg_critical": 9, "security_spend_pct": 5.0},
        "manufacturing": {"avg_score": 55, "avg_findings": 50, "avg_critical": 11, "security_spend_pct": 4.5},
    }

    def __init__(self, target=None, options=None):
        self.options = options or {}
        self.actions = []

    def _log(self, msg):
        self.actions.append({"time": datetime.now().isoformat(), "action": msg})

    def calculate_score(self, findings):
        if not findings:
            return 100
        score = 100
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev == "critical":
                score -= 15
            elif sev == "high":
                score -= 8
            elif sev == "medium":
                score -= 3
            elif sev == "low":
                score -= 1
        return max(0, min(100, score))

    def score_to_grade(self, score):
        if score >= 90: return "A"
        if score >= 80: return "B"
        if score >= 70: return "C"
        if score >= 60: return "D"
        return "F"

    def generate(self, mission_data):
        name = mission_data.get("name", "Security Assessment")
        target = mission_data.get("target", "Unknown")
        industry = mission_data.get("industry", "technology")
        findings = mission_data.get("findings", [])
        classification = mission_data.get("classification", "UNCLASSIFIED")
        now = datetime.now()
        score = self.calculate_score(findings)
        grade = self.score_to_grade(score)
        benchmark = self.INDUSTRY_BENCHMARKS.get(industry, self.INDUSTRY_BENCHMARKS["technology"])
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            s = f.get("severity", "info").lower()
            sev_counts[s] = sev_counts.get(s, 0) + 1
        top_5 = sorted(findings, key=lambda f: ["critical", "high", "medium", "low", "info"].index(f.get("severity", "info").lower()))[:5]
        brief = []
        brief.append(f"# EXECUTIVE SECURITY BRIEFING")
        if classification != "UNCLASSIFIED":
            brief.append(f"> **{classification}**")
        brief.append("")
        brief.append(f"**Assessment:** {name}")
        brief.append(f"**Target:** {target}")
        brief.append(f"**Date:** {now.strftime('%B %d, %Y')}")
        brief.append(f"**Industry:** {industry.title()}")
        brief.append("")
        brief.append("---")
        brief.append("")
        brief.append("## Security Posture Grade")
        brief.append("")
        brief.append(f"# {grade}")
        brief.append(f"**Score: {score}/100**")
        brief.append("")
        vs = "above" if score > benchmark["avg_score"] else "below"
        brief.append(f"Your score is **{abs(score - benchmark['avg_score'])} points {vs}** the {industry} industry average ({benchmark['avg_score']}/100).")
        brief.append("")
        brief.append("## Key Numbers")
        brief.append("")
        brief.append(f"| Metric | Your Result | Industry Avg |")
        brief.append(f"|--------|------------|-------------|")
        brief.append(f"| Total Findings | {len(findings)} | {benchmark['avg_findings']} |")
        brief.append(f"| Critical Issues | {sev_counts['critical']} | {benchmark['avg_critical']} |")
        brief.append(f"| High Issues | {sev_counts['high']} | - |")
        brief.append(f"| Security Grade | {grade} | {self.score_to_grade(benchmark['avg_score'])} |")
        brief.append("")
        brief.append("## Top 5 Critical Findings")
        brief.append("")
        for i, f in enumerate(top_5, 1):
            sev = f.get("severity", "info").upper()
            brief.append(f"{i}. **[{sev}]** {f.get('title', 'Untitled')}")
            brief.append(f"   - Host: {f.get('host', 'N/A')}")
            brief.append(f"   - Business Impact: {f.get('impact', 'Could lead to unauthorized access or data breach')}")
            brief.append("")
        brief.append("## Recommended Actions")
        brief.append("")
        if sev_counts["critical"] > 0:
            brief.append(f"1. **IMMEDIATE:** Address {sev_counts['critical']} critical vulnerabilities within 48 hours")
        if sev_counts["high"] > 0:
            brief.append(f"2. **URGENT:** Remediate {sev_counts['high']} high-severity issues within 2 weeks")
        brief.append("3. **SHORT-TERM:** Implement multi-factor authentication on all external-facing services")
        brief.append("4. **MEDIUM-TERM:** Deploy endpoint detection and response (EDR) across all systems")
        brief.append("5. **ONGOING:** Establish vulnerability management program with regular scanning cadence")
        brief.append("")
        brief.append("## Budget Recommendation")
        brief.append("")
        if score < 50:
            brief.append("Current security posture is **significantly below acceptable levels**. Recommend increasing security budget to at least **8-12% of IT spend** to address critical gaps.")
        elif score < 70:
            brief.append("Security posture has **notable gaps**. Recommend allocating **6-8% of IT spend** to security improvements, focusing on the critical and high findings above.")
        else:
            brief.append(f"Security posture is **{'strong' if score >= 80 else 'adequate'}**. Recommend maintaining current security investment at **{benchmark['security_spend_pct']:.0f}%+ of IT spend** with focus on continuous improvement.")
        brief.append("")
        brief.append("---")
        brief.append(f"*Prepared by AEGIS Platform | {now.strftime('%B %d, %Y')}*")
        text = "\n".join(brief)
        self._log(f"Generated executive brief: grade {grade}, score {score}")
        return text

    def run(self, confirm_fn=None):
        return {"info": "Use generate(mission_data) to create an executive brief"}

    def get_findings(self):
        return []

if __name__ == "__main__":
    eb = ExecutiveBrief()
    sample = {
        "name": "Q3 2024 Security Assessment",
        "target": "Corporate Infrastructure",
        "industry": "finance",
        "classification": "CONFIDENTIAL",
        "findings": [
            {"severity": "critical", "title": "Domain Admin via Kerberoasting", "host": "DC01", "impact": "Complete domain compromise possible"},
            {"severity": "critical", "title": "Unpatched Exchange (ProxyLogon)", "host": "MAIL01", "impact": "Pre-auth RCE on email server"},
            {"severity": "high", "title": "Default credentials on MySQL", "host": "DB01", "impact": "Customer database accessible"},
            {"severity": "high", "title": "No network segmentation", "host": "Network", "impact": "Lateral movement unrestricted"},
            {"severity": "medium", "title": "Missing HSTS header", "host": "WEB01"},
            {"severity": "medium", "title": "Weak SSH ciphers", "host": "APP01"},
            {"severity": "low", "title": "Server version disclosure", "host": "WEB01"},
        ],
    }
    print(eb.generate(sample))
