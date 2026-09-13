#!/usr/bin/env python3
"""Executive-level security dashboard and posture scoring"""
import json, os, sys, math
from datetime import datetime
from collections import defaultdict

# =============================================================================
# INDUSTRY BENCHMARKS (Verizon DBIR / IBM Cost of Breach 2024)
# =============================================================================
INDUSTRY_BENCHMARKS = {
    "healthcare": {"avg_score": 42, "breach_cost": 10930000, "mttd_days": 213, "mttr_days": 80, "breach_rate": 0.33},
    "financial": {"avg_score": 58, "breach_cost": 5900000, "mttd_days": 177, "mttr_days": 56, "breach_rate": 0.27},
    "technology": {"avg_score": 55, "breach_cost": 4970000, "mttd_days": 185, "mttr_days": 65, "breach_rate": 0.25},
    "government": {"avg_score": 45, "breach_cost": 4640000, "mttd_days": 233, "mttr_days": 92, "breach_rate": 0.29},
    "retail": {"avg_score": 40, "breach_cost": 3280000, "mttd_days": 205, "mttr_days": 78, "breach_rate": 0.24},
    "education": {"avg_score": 38, "breach_cost": 3650000, "mttd_days": 240, "mttr_days": 95, "breach_rate": 0.30},
    "manufacturing": {"avg_score": 35, "breach_cost": 4730000, "mttd_days": 220, "mttr_days": 85, "breach_rate": 0.22},
    "energy": {"avg_score": 43, "breach_cost": 4780000, "mttd_days": 195, "mttr_days": 75, "breach_rate": 0.28},
    "general": {"avg_score": 45, "breach_cost": 4450000, "mttd_days": 204, "mttr_days": 73, "breach_rate": 0.26},
}

SECURITY_KPIS = [
    {"name": "Vulnerability Density", "unit": "vulns/host", "target": "< 2.0", "weight": 15, "category": "vulnerability"},
    {"name": "Critical Vuln Patch Time", "unit": "days", "target": "< 7", "weight": 15, "category": "vulnerability"},
    {"name": "High Vuln Patch Time", "unit": "days", "target": "< 30", "weight": 10, "category": "vulnerability"},
    {"name": "EDR Coverage", "unit": "%", "target": "> 95%", "weight": 10, "category": "detection"},
    {"name": "SIEM Coverage", "unit": "%", "target": "> 90%", "weight": 8, "category": "detection"},
    {"name": "MFA Adoption", "unit": "%", "target": "100%", "weight": 10, "category": "identity"},
    {"name": "Privileged Account Ratio", "unit": "%", "target": "< 5%", "weight": 5, "category": "identity"},
    {"name": "Mean Time to Detect", "unit": "hours", "target": "< 24", "weight": 8, "category": "detection"},
    {"name": "Mean Time to Respond", "unit": "hours", "target": "< 4", "weight": 7, "category": "response"},
    {"name": "Security Training Completion", "unit": "%", "target": "> 95%", "weight": 5, "category": "awareness"},
    {"name": "Phishing Click Rate", "unit": "%", "target": "< 3%", "weight": 5, "category": "awareness"},
    {"name": "Backup Success Rate", "unit": "%", "target": "> 99%", "weight": 5, "category": "recovery"},
    {"name": "DR Test Frequency", "unit": "per year", "target": ">= 2", "weight": 3, "category": "recovery"},
    {"name": "Third-Party Risk Assessments", "unit": "% vendors assessed", "target": "> 80%", "weight": 3, "category": "governance"},
    {"name": "Policy Review Currency", "unit": "months since review", "target": "< 12", "weight": 3, "category": "governance"},
]

BUDGET_ALLOCATION = {
    "preventive": {"percentage": 40, "items": ["Patching and vulnerability management", "Security hardening and configuration", "Security awareness training", "Application security testing", "Encryption and data protection"]},
    "detective": {"percentage": 30, "items": ["SIEM and log management", "EDR and endpoint monitoring", "Network detection and response", "Threat intelligence feeds", "Security operations center staffing"]},
    "responsive": {"percentage": 20, "items": ["Incident response team and retainers", "IR playbooks and automation", "Digital forensics capabilities", "Legal and communications (breach response)", "Tabletop exercises and drills"]},
    "recovery": {"percentage": 10, "items": ["Backup and disaster recovery", "Business continuity planning", "Cyber insurance premiums", "Recovery testing and validation"]},
}

COMPLIANCE_FRAMEWORKS = {
    "NIST CSF": {"controls": 108, "categories": ["Identify", "Protect", "Detect", "Respond", "Recover"]},
    "ISO 27001": {"controls": 93, "categories": ["Organizational", "People", "Physical", "Technological"]},
    "PCI DSS 4.0": {"controls": 64, "categories": ["Build Secure Network", "Protect Data", "Manage Vulnerabilities", "Access Control", "Monitor and Test", "Security Policy"]},
    "HIPAA": {"controls": 54, "categories": ["Administrative", "Physical", "Technical", "Organizational"]},
    "SOC 2": {"controls": 64, "categories": ["Security", "Availability", "Processing Integrity", "Confidentiality", "Privacy"]},
    "CIS Controls v8": {"controls": 153, "categories": ["Basic", "Foundational", "Organizational"]},
}

# =============================================================================
# EXECUTIVE DASHBOARD ENGINE
# =============================================================================
class ExecutiveDashboard:
    name = "Executive Dashboard"
    description = "Security posture scoring and executive reporting"
    category = "reporting"
    mitre = []

    def __init__(self):
        self.scores = {}
        self.findings = []
        self.kpi_values = {}
        self.industry = "general"
        self.company_size = "medium"
        self.history = []

    def set_industry(self, industry):
        if industry in INDUSTRY_BENCHMARKS:
            self.industry = industry
        else:
            self.industry = "general"

    def load_findings(self, findings):
        self.findings = findings

    def set_kpi(self, kpi_name, value):
        self.kpi_values[kpi_name] = value

    def calculate_posture_score(self):
        total_weight = 0
        weighted_score = 0
        vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            sev = f.get("severity", "info").lower()
            if sev in vuln_counts:
                vuln_counts[sev] += 1
        vuln_penalty = min(50, vuln_counts["critical"] * 10 + vuln_counts["high"] * 5 + vuln_counts["medium"] * 2 + vuln_counts["low"] * 0.5)
        base_score = max(0, 100 - vuln_penalty)
        control_bonus = 0
        if self.kpi_values.get("EDR Coverage", 0) > 90:
            control_bonus += 5
        if self.kpi_values.get("MFA Adoption", 0) > 90:
            control_bonus += 5
        if self.kpi_values.get("SIEM Coverage", 0) > 80:
            control_bonus += 5
        if self.kpi_values.get("Security Training Completion", 0) > 90:
            control_bonus += 3
        if self.kpi_values.get("Backup Success Rate", 0) > 95:
            control_bonus += 2
        final_score = min(100, max(0, base_score + control_bonus))
        self.scores = {
            "overall": round(final_score),
            "vulnerability": round(max(0, 100 - vuln_penalty)),
            "detection": round(min(100, (self.kpi_values.get("EDR Coverage", 0) + self.kpi_values.get("SIEM Coverage", 0)) / 2)),
            "identity": round(min(100, self.kpi_values.get("MFA Adoption", 50))),
            "response": round(min(100, max(0, 100 - self.kpi_values.get("Mean Time to Respond", 24) * 2))),
            "recovery": round(min(100, self.kpi_values.get("Backup Success Rate", 50))),
            "governance": round(min(100, self.kpi_values.get("Security Training Completion", 50))),
        }
        return self.scores

    def get_grade(self, score=None):
        s = score if score is not None else self.scores.get("overall", 0)
        if s >= 90: return "A"
        if s >= 80: return "B"
        if s >= 70: return "C"
        if s >= 60: return "D"
        return "F"

    def get_risk_level(self, score=None):
        s = score if score is not None else self.scores.get("overall", 0)
        if s >= 80: return "LOW"
        if s >= 60: return "MODERATE"
        if s >= 40: return "HIGH"
        if s >= 20: return "CRITICAL"
        return "SEVERE"

    def compare_to_industry(self):
        bench = INDUSTRY_BENCHMARKS.get(self.industry, INDUSTRY_BENCHMARKS["general"])
        our_score = self.scores.get("overall", 0)
        return {
            "our_score": our_score,
            "industry_avg": bench["avg_score"],
            "difference": our_score - bench["avg_score"],
            "above_average": our_score > bench["avg_score"],
            "avg_breach_cost": bench["breach_cost"],
            "avg_mttd": bench["mttd_days"],
            "avg_mttr": bench["mttr_days"],
            "breach_probability": bench["breach_rate"],
        }

    def estimate_breach_cost(self):
        bench = INDUSTRY_BENCHMARKS.get(self.industry, INDUSTRY_BENCHMARKS["general"])
        base_cost = bench["breach_cost"]
        size_multiplier = {"startup": 0.3, "small": 0.5, "medium": 1.0, "enterprise": 2.0}.get(self.company_size, 1.0)
        score = self.scores.get("overall", 50)
        risk_multiplier = max(0.5, 2.0 - (score / 50))
        estimated = base_cost * size_multiplier * risk_multiplier
        return {
            "estimated_cost": round(estimated),
            "base_industry_cost": base_cost,
            "size_multiplier": size_multiplier,
            "risk_multiplier": round(risk_multiplier, 2),
            "annual_probability": bench["breach_rate"],
            "expected_annual_loss": round(estimated * bench["breach_rate"]),
        }

    def top_risks(self, n=5):
        critical = [f for f in self.findings if f.get("severity", "").lower() == "critical"]
        high = [f for f in self.findings if f.get("severity", "").lower() == "high"]
        risks = (critical + high)[:n]
        result = []
        for f in risks:
            result.append({
                "title": f.get("title", "Unknown"),
                "severity": f.get("severity", "unknown"),
                "cvss": f.get("cvss", 0),
                "business_impact": self._estimate_impact(f),
                "remediation": f.get("remediation", "See detailed finding"),
            })
        return result

    def _estimate_impact(self, finding):
        sev = finding.get("severity", "").lower()
        impacts = {
            "critical": "Potential for full system compromise, data breach, or operational disruption. Immediate business impact.",
            "high": "Significant security gap that could lead to unauthorized access or data exposure. Near-term business risk.",
            "medium": "Security weakness that increases attack surface. Should be addressed in normal maintenance cycle.",
            "low": "Minor security improvement opportunity. Low business impact.",
            "info": "Informational finding for security team awareness.",
        }
        return impacts.get(sev, "Unknown impact")

    def budget_recommendations(self, total_budget=None):
        recs = []
        for category, info in BUDGET_ALLOCATION.items():
            amount = round(total_budget * info["percentage"] / 100) if total_budget else None
            recs.append({
                "category": category.title(),
                "percentage": info["percentage"],
                "amount": amount,
                "items": info["items"],
            })
        return recs

    def compliance_status(self, implemented_controls=None):
        implemented = implemented_controls or {}
        status = {}
        for framework, info in COMPLIANCE_FRAMEWORKS.items():
            impl = implemented.get(framework, 0)
            total = info["controls"]
            status[framework] = {
                "total_controls": total,
                "implemented": impl,
                "percentage": round(impl / total * 100) if total > 0 else 0,
                "gap": total - impl,
            }
        return status

    def generate_board_report(self):
        scores = self.calculate_posture_score() if not self.scores else self.scores
        grade = self.get_grade()
        risk = self.get_risk_level()
        comparison = self.compare_to_industry()
        breach_cost = self.estimate_breach_cost()
        top = self.top_risks()
        vuln_counts = defaultdict(int)
        for f in self.findings:
            vuln_counts[f.get("severity", "info").lower()] += 1
        report = []
        report.append("=" * 60)
        report.append("SECURITY POSTURE EXECUTIVE BRIEF")
        report.append(f"Date: {datetime.now().strftime('%Y-%m-%d')}")
        report.append(f"Classification: CONFIDENTIAL")
        report.append("=" * 60)
        report.append("")
        report.append(f"OVERALL SECURITY GRADE: {grade} ({scores.get('overall', 0)}/100)")
        report.append(f"RISK LEVEL: {risk}")
        report.append("")
        report.append("POSTURE BREAKDOWN:")
        for cat, score in scores.items():
            if cat != "overall":
                bar = "#" * (score // 5) + "." * (20 - score // 5)
                report.append(f"  {cat:15s} [{bar}] {score}/100")
        report.append("")
        report.append("FINDINGS SUMMARY:")
        report.append(f"  Critical: {vuln_counts.get('critical', 0)}")
        report.append(f"  High:     {vuln_counts.get('high', 0)}")
        report.append(f"  Medium:   {vuln_counts.get('medium', 0)}")
        report.append(f"  Low:      {vuln_counts.get('low', 0)}")
        report.append(f"  Info:     {vuln_counts.get('info', 0)}")
        report.append("")
        report.append("INDUSTRY COMPARISON:")
        report.append(f"  Your score: {comparison['our_score']} | Industry average: {comparison['industry_avg']}")
        report.append(f"  {'Above' if comparison['above_average'] else 'Below'} industry average by {abs(comparison['difference'])} points")
        report.append("")
        report.append("FINANCIAL RISK:")
        report.append(f"  Estimated breach cost: ${breach_cost['estimated_cost']:,.0f}")
        report.append(f"  Annual breach probability: {breach_cost['annual_probability']*100:.0f}%")
        report.append(f"  Expected annual loss: ${breach_cost['expected_annual_loss']:,.0f}")
        report.append("")
        if top:
            report.append("TOP RISKS:")
            for i, r in enumerate(top):
                report.append(f"  {i+1}. [{r['severity'].upper()}] {r['title']}")
                report.append(f"     Impact: {r['business_impact'][:80]}")
                report.append("")
        report.append("RECOMMENDED ACTIONS:")
        report.append("  1. Address all critical vulnerabilities within 24 hours")
        report.append("  2. Patch high-severity findings within 7 days")
        report.append("  3. Deploy EDR on all endpoints lacking coverage")
        report.append("  4. Enforce MFA for all privileged and remote access")
        report.append("  5. Conduct incident response tabletop exercise")
        report.append("")
        report.append("=" * 60)
        return "\n".join(report)

    def run(self, confirm_fn=None):
        print("\n" + "=" * 60)
        print(" EXECUTIVE SECURITY DASHBOARD")
        print("=" * 60)
        print("\nIndustries: " + ", ".join(INDUSTRY_BENCHMARKS.keys()))
        ind = input("Select industry [general]: ").strip().lower() or "general"
        self.set_industry(ind)
        print(f"\nIndustry: {self.industry}")
        print("\nEnter current KPI values (press Enter to skip):")
        for kpi in SECURITY_KPIS[:8]:
            val = input(f"  {kpi['name']} ({kpi['unit']}, target: {kpi['target']}): ").strip()
            if val:
                try:
                    self.set_kpi(kpi["name"], float(val))
                except ValueError:
                    pass
        scores = self.calculate_posture_score()
        print(f"\n--- SECURITY POSTURE: {self.get_grade()} ({scores['overall']}/100) ---")
        print(f"Risk Level: {self.get_risk_level()}")
        for cat, score in scores.items():
            if cat != "overall":
                bar = "#" * (score // 5) + "." * (20 - score // 5)
                print(f"  {cat:15s} [{bar}] {score}/100")
        comp = self.compare_to_industry()
        print(f"\nIndustry comparison: {'Above' if comp['above_average'] else 'Below'} average by {abs(comp['difference'])} pts")
        bc = self.estimate_breach_cost()
        print(f"Estimated breach cost: ${bc['estimated_cost']:,.0f}")
        print(f"Expected annual loss: ${bc['expected_annual_loss']:,.0f}")
        print(f"\nFull board report? (y/n): ", end="")
        if input().strip().lower() == "y":
            print("\n" + self.generate_board_report())


if __name__ == "__main__":
    dash = ExecutiveDashboard()
    dash.run()
