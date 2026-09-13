#!/usr/bin/env python3
"""AI-powered threat prediction and risk modeling — attack surface scoring, breach probability, attack path prediction"""
import sys
import math
import json
from datetime import datetime

class ThreatPrediction:
    name = "Threat Prediction Engine"
    description = "AI-powered threat prediction — attack surface scoring, breach probability, attack path generation, ROI modeling"
    category = "ai"
    mitre = ["T1595", "T1190", "T1078"]

    INDUSTRY_THREAT_WEIGHTS = {
        "healthcare": {"ransomware": 0.35, "data_theft": 0.25, "insider": 0.15, "nation_state": 0.05, "hacktivism": 0.05, "supply_chain": 0.10, "credential": 0.05},
        "financial": {"ransomware": 0.15, "data_theft": 0.20, "insider": 0.15, "nation_state": 0.15, "hacktivism": 0.05, "supply_chain": 0.10, "credential": 0.20},
        "government": {"ransomware": 0.10, "data_theft": 0.15, "insider": 0.15, "nation_state": 0.30, "hacktivism": 0.10, "supply_chain": 0.10, "credential": 0.10},
        "technology": {"ransomware": 0.10, "data_theft": 0.25, "insider": 0.15, "nation_state": 0.10, "hacktivism": 0.05, "supply_chain": 0.20, "credential": 0.15},
        "education": {"ransomware": 0.30, "data_theft": 0.20, "insider": 0.15, "nation_state": 0.05, "hacktivism": 0.10, "supply_chain": 0.05, "credential": 0.15},
        "retail": {"ransomware": 0.20, "data_theft": 0.30, "insider": 0.10, "nation_state": 0.05, "hacktivism": 0.05, "supply_chain": 0.10, "credential": 0.20},
        "energy": {"ransomware": 0.20, "data_theft": 0.10, "insider": 0.10, "nation_state": 0.30, "hacktivism": 0.10, "supply_chain": 0.10, "credential": 0.10},
        "manufacturing": {"ransomware": 0.30, "data_theft": 0.15, "insider": 0.10, "nation_state": 0.15, "hacktivism": 0.05, "supply_chain": 0.15, "credential": 0.10},
    }

    BREACH_COSTS_BY_INDUSTRY = {
        "healthcare": {"avg_cost_m": 10.93, "cost_per_record": 614, "avg_records": 17800, "breach_rate": 0.33},
        "financial": {"avg_cost_m": 5.90, "cost_per_record": 239, "avg_records": 24600, "breach_rate": 0.27},
        "technology": {"avg_cost_m": 4.97, "cost_per_record": 194, "avg_records": 25600, "breach_rate": 0.24},
        "energy": {"avg_cost_m": 4.78, "cost_per_record": 213, "avg_records": 22400, "breach_rate": 0.22},
        "education": {"avg_cost_m": 3.86, "cost_per_record": 188, "avg_records": 20500, "breach_rate": 0.30},
        "retail": {"avg_cost_m": 3.48, "cost_per_record": 174, "avg_records": 20000, "breach_rate": 0.25},
        "government": {"avg_cost_m": 2.60, "cost_per_record": 196, "avg_records": 13300, "breach_rate": 0.20},
        "manufacturing": {"avg_cost_m": 4.47, "cost_per_record": 199, "avg_records": 22500, "breach_rate": 0.23},
    }

    CONTROL_EFFECTIVENESS = {
        "mfa": {"credential": 0.80, "data_theft": 0.30, "ransomware": 0.20, "nation_state": 0.40, "insider": 0.20},
        "edr": {"ransomware": 0.60, "data_theft": 0.40, "nation_state": 0.30, "credential": 0.20, "supply_chain": 0.30},
        "siem": {"ransomware": 0.30, "data_theft": 0.50, "insider": 0.50, "nation_state": 0.40, "credential": 0.30},
        "waf": {"data_theft": 0.50, "credential": 0.30, "hacktivism": 0.40, "ransomware": 0.10},
        "dlp": {"data_theft": 0.60, "insider": 0.50, "credential": 0.20},
        "network_segmentation": {"ransomware": 0.50, "data_theft": 0.40, "nation_state": 0.30, "credential": 0.20},
        "backup": {"ransomware": 0.70, "data_theft": 0.10},
        "patching": {"ransomware": 0.40, "data_theft": 0.30, "nation_state": 0.30, "supply_chain": 0.20, "credential": 0.20},
        "awareness_training": {"credential": 0.40, "ransomware": 0.30, "insider": 0.20, "hacktivism": 0.10},
        "encryption": {"data_theft": 0.50, "insider": 0.30},
        "pam": {"credential": 0.50, "insider": 0.40, "nation_state": 0.30, "data_theft": 0.20},
        "zero_trust": {"credential": 0.60, "data_theft": 0.50, "ransomware": 0.40, "nation_state": 0.40, "insider": 0.30},
    }

    ATTACK_PATH_TEMPLATES = [
        {"name": "Phishing to Domain Admin", "initial": "phishing", "steps": [
            {"phase": "Initial Access", "technique": "Spearphishing attachment", "mitre": "T1566.001", "probability": 0.30, "detection_difficulty": 0.4},
            {"phase": "Execution", "technique": "Macro execution in Office doc", "mitre": "T1204.002", "probability": 0.70, "detection_difficulty": 0.5},
            {"phase": "Persistence", "technique": "Registry Run key", "mitre": "T1547.001", "probability": 0.80, "detection_difficulty": 0.6},
            {"phase": "Credential Access", "technique": "Mimikatz LSASS dump", "mitre": "T1003.001", "probability": 0.60, "detection_difficulty": 0.3},
            {"phase": "Lateral Movement", "technique": "Pass-the-Hash via PsExec", "mitre": "T1550.002", "probability": 0.70, "detection_difficulty": 0.4},
            {"phase": "Privilege Escalation", "technique": "Kerberoasting to Domain Admin", "mitre": "T1558.003", "probability": 0.50, "detection_difficulty": 0.5},
        ]},
        {"name": "Web App to Data Exfil", "initial": "web_exploit", "steps": [
            {"phase": "Initial Access", "technique": "SQL Injection", "mitre": "T1190", "probability": 0.25, "detection_difficulty": 0.5},
            {"phase": "Execution", "technique": "OS command via SQLi", "mitre": "T1059", "probability": 0.40, "detection_difficulty": 0.4},
            {"phase": "Discovery", "technique": "Internal network scanning", "mitre": "T1046", "probability": 0.80, "detection_difficulty": 0.6},
            {"phase": "Lateral Movement", "technique": "SSH with discovered keys", "mitre": "T1021.004", "probability": 0.50, "detection_difficulty": 0.7},
            {"phase": "Collection", "technique": "Database dump", "mitre": "T1005", "probability": 0.70, "detection_difficulty": 0.5},
            {"phase": "Exfiltration", "technique": "HTTPS POST to external server", "mitre": "T1048.002", "probability": 0.80, "detection_difficulty": 0.6},
        ]},
        {"name": "VPN Exploit to Ransomware", "initial": "vpn_exploit", "steps": [
            {"phase": "Initial Access", "technique": "Exploit public-facing VPN", "mitre": "T1190", "probability": 0.40, "detection_difficulty": 0.3},
            {"phase": "Execution", "technique": "PowerShell download cradle", "mitre": "T1059.001", "probability": 0.70, "detection_difficulty": 0.4},
            {"phase": "Defense Evasion", "technique": "Disable AV via Safe Mode", "mitre": "T1562.001", "probability": 0.50, "detection_difficulty": 0.3},
            {"phase": "Credential Access", "technique": "DCSync", "mitre": "T1003.006", "probability": 0.60, "detection_difficulty": 0.4},
            {"phase": "Lateral Movement", "technique": "GPO deployment", "mitre": "T1484.001", "probability": 0.70, "detection_difficulty": 0.5},
            {"phase": "Impact", "technique": "Ransomware encryption via GPO", "mitre": "T1486", "probability": 0.80, "detection_difficulty": 0.2},
        ]},
        {"name": "Supply Chain Compromise", "initial": "supply_chain", "steps": [
            {"phase": "Initial Access", "technique": "Trojanized software update", "mitre": "T1195.002", "probability": 0.10, "detection_difficulty": 0.8},
            {"phase": "Execution", "technique": "Backdoor in trusted software", "mitre": "T1059", "probability": 0.90, "detection_difficulty": 0.9},
            {"phase": "Persistence", "technique": "Legitimate service modification", "mitre": "T1543.003", "probability": 0.80, "detection_difficulty": 0.8},
            {"phase": "Collection", "technique": "Targeted data collection", "mitre": "T1119", "probability": 0.60, "detection_difficulty": 0.7},
            {"phase": "Exfiltration", "technique": "Exfil via legitimate update channel", "mitre": "T1041", "probability": 0.70, "detection_difficulty": 0.9},
        ]},
        {"name": "Insider Threat", "initial": "insider", "steps": [
            {"phase": "Initial Access", "technique": "Legitimate credentials", "mitre": "T1078", "probability": 1.0, "detection_difficulty": 0.9},
            {"phase": "Collection", "technique": "Access sensitive file shares", "mitre": "T1039", "probability": 0.70, "detection_difficulty": 0.7},
            {"phase": "Collection", "technique": "Email forwarding rule", "mitre": "T1114.003", "probability": 0.50, "detection_difficulty": 0.5},
            {"phase": "Exfiltration", "technique": "USB or personal cloud", "mitre": "T1052", "probability": 0.60, "detection_difficulty": 0.6},
        ]},
        {"name": "Cloud Account Takeover", "initial": "cloud_attack", "steps": [
            {"phase": "Initial Access", "technique": "Credential stuffing / MFA fatigue", "mitre": "T1110", "probability": 0.25, "detection_difficulty": 0.5},
            {"phase": "Persistence", "technique": "OAuth app registration", "mitre": "T1098.003", "probability": 0.60, "detection_difficulty": 0.6},
            {"phase": "Discovery", "technique": "Cloud API enumeration", "mitre": "T1580", "probability": 0.80, "detection_difficulty": 0.7},
            {"phase": "Privilege Escalation", "technique": "IAM policy modification", "mitre": "T1484", "probability": 0.40, "detection_difficulty": 0.5},
            {"phase": "Impact", "technique": "Resource hijacking (cryptomining)", "mitre": "T1496", "probability": 0.50, "detection_difficulty": 0.4},
        ]},
    ]

    def __init__(self, target=None, options=None):
        self.target = target
        self.options = options or {}
        self.findings = []

    def run(self, confirm_fn=None):
        print(f"\n[THREAT-PREDICTION] Threat Prediction Engine")
        print("=" * 60)
        mode = self.options.get("mode", "full")
        if mode in ("score", "full"):
            self.calculate_attack_surface_score()
        if mode in ("paths", "full"):
            self.predict_attack_paths()
        if mode in ("breach", "full"):
            self.calculate_breach_probability()
        if mode in ("roi", "full"):
            self.calculate_security_roi()
        return self.findings

    def calculate_attack_surface_score(self):
        print("\n[*] Attack Surface Score Calculation")
        print("-" * 40)
        external = self.options.get("external_services", 5)
        vulns = self.options.get("vulnerability_count", 20)
        cred_hygiene = self.options.get("credential_hygiene", 50)
        segmentation = self.options.get("segmentation_score", 40)
        control_coverage = self.options.get("control_coverage", 50)
        patch_currency = self.options.get("patch_currency", 60)

        exposure_score = min(100, external * 8)
        vuln_density = min(100, vulns * 3)
        cred_risk = 100 - cred_hygiene
        seg_risk = 100 - segmentation
        control_gap = 100 - control_coverage
        patch_risk = 100 - patch_currency

        weights = {"exposure": 0.20, "vulns": 0.25, "creds": 0.15, "segmentation": 0.15, "controls": 0.15, "patching": 0.10}
        overall = (
            exposure_score * weights["exposure"] +
            vuln_density * weights["vulns"] +
            cred_risk * weights["creds"] +
            seg_risk * weights["segmentation"] +
            control_gap * weights["controls"] +
            patch_risk * weights["patching"]
        )

        print(f"  External Service Exposure:  {exposure_score:.0f}/100 (weight: {weights['exposure']:.0%})")
        print(f"  Vulnerability Density:      {vuln_density:.0f}/100 (weight: {weights['vulns']:.0%})")
        print(f"  Credential Hygiene Risk:    {cred_risk:.0f}/100 (weight: {weights['creds']:.0%})")
        print(f"  Segmentation Gap:           {seg_risk:.0f}/100 (weight: {weights['segmentation']:.0%})")
        print(f"  Control Coverage Gap:       {control_gap:.0f}/100 (weight: {weights['controls']:.0%})")
        print(f"  Patch Currency Risk:        {patch_risk:.0f}/100 (weight: {weights['patching']:.0%})")
        print(f"\n  OVERALL ATTACK SURFACE RISK: {overall:.0f}/100", end="")
        if overall >= 70:
            print(" [CRITICAL]")
        elif overall >= 50:
            print(" [HIGH]")
        elif overall >= 30:
            print(" [MEDIUM]")
        else:
            print(" [LOW]")
        return overall

    def predict_attack_paths(self):
        industry = self.options.get("industry", "technology")
        controls = self.options.get("controls", [])
        print(f"\n[*] Predicted Attack Paths for {industry.upper()}")
        print("-" * 40)
        threat_weights = self.INDUSTRY_THREAT_WEIGHTS.get(industry, self.INDUSTRY_THREAT_WEIGHTS["technology"])
        for path in self.ATTACK_PATH_TEMPLATES:
            initial_type = path["initial"]
            relevance = threat_weights.get(initial_type, threat_weights.get("data_theft", 0.15))
            control_reduction = 0
            for ctrl in controls:
                ctrl_effects = self.CONTROL_EFFECTIVENESS.get(ctrl, {})
                control_reduction += ctrl_effects.get(initial_type, 0) * 0.1
            adjusted_probability = max(0.01, relevance - control_reduction)
            chain_probability = adjusted_probability
            for step in path["steps"]:
                chain_probability *= step["probability"]
            avg_detection = sum(s["detection_difficulty"] for s in path["steps"]) / len(path["steps"])
            print(f"\n  {path['name']}")
            print(f"    Overall probability: {chain_probability:.1%}")
            print(f"    Detection difficulty: {avg_detection:.1%}")
            print(f"    Kill chain:")
            for step in path["steps"]:
                print(f"      -> {step['phase']}: {step['technique']} ({step['mitre']}) [P={step['probability']:.0%}]")
            blocked_by = []
            for ctrl in ["mfa", "edr", "siem", "waf", "network_segmentation", "patching"]:
                if ctrl not in controls:
                    effects = self.CONTROL_EFFECTIVENESS.get(ctrl, {})
                    if effects.get(initial_type, 0) > 0.2:
                        blocked_by.append(f"{ctrl} (reduces {initial_type} by {effects[initial_type]:.0%})")
            if blocked_by:
                print(f"    Mitigations not in place:")
                for m in blocked_by[:3]:
                    print(f"      - {m}")

    def calculate_breach_probability(self):
        industry = self.options.get("industry", "technology")
        controls = self.options.get("controls", [])
        employees = self.options.get("employees", 500)
        print(f"\n[*] Breach Probability Calculator")
        print("-" * 40)
        data = self.BREACH_COSTS_BY_INDUSTRY.get(industry, self.BREACH_COSTS_BY_INDUSTRY["technology"])
        base_rate = data["breach_rate"]
        control_factor = 1.0
        for ctrl in controls:
            if ctrl == "mfa":
                control_factor *= 0.60
            elif ctrl == "edr":
                control_factor *= 0.70
            elif ctrl == "siem":
                control_factor *= 0.75
            elif ctrl == "zero_trust":
                control_factor *= 0.50
            elif ctrl == "awareness_training":
                control_factor *= 0.80
            elif ctrl == "encryption":
                control_factor *= 0.85
            elif ctrl == "patching":
                control_factor *= 0.75
        size_factor = 1.0
        if employees > 5000:
            size_factor = 1.3
        elif employees > 1000:
            size_factor = 1.15
        elif employees < 100:
            size_factor = 0.8
        annual_probability = min(0.95, base_rate * control_factor * size_factor)
        three_year = 1 - (1 - annual_probability) ** 3
        expected_cost = data["avg_cost_m"] * 1_000_000
        expected_annual_loss = annual_probability * expected_cost

        print(f"  Industry:                {industry}")
        print(f"  Base breach rate:        {base_rate:.0%} per year")
        print(f"  Controls in place:       {', '.join(controls) if controls else 'none'}")
        print(f"  Control reduction:       {(1-control_factor):.0%}")
        print(f"  Size factor:             {size_factor:.2f}x ({employees} employees)")
        print(f"\n  ADJUSTED ANNUAL PROBABILITY: {annual_probability:.1%}")
        print(f"  3-YEAR CUMULATIVE:           {three_year:.1%}")
        print(f"\n  Average breach cost ({industry}): ${data['avg_cost_m']:.2f}M")
        print(f"  Cost per record:              ${data['cost_per_record']}")
        print(f"  Expected annual loss (ALE):   ${expected_annual_loss:,.0f}")
        return {"annual_probability": annual_probability, "three_year": three_year, "ale": expected_annual_loss}

    def calculate_security_roi(self):
        industry = self.options.get("industry", "technology")
        current_controls = self.options.get("controls", [])
        print(f"\n[*] Security Investment ROI Calculator")
        print("-" * 40)
        investments = [
            {"control": "mfa", "annual_cost": 50000, "description": "Multi-factor authentication for all users"},
            {"control": "edr", "annual_cost": 150000, "description": "Endpoint Detection and Response on all endpoints"},
            {"control": "siem", "annual_cost": 200000, "description": "SIEM with 24/7 monitoring"},
            {"control": "zero_trust", "annual_cost": 500000, "description": "Zero Trust architecture implementation"},
            {"control": "awareness_training", "annual_cost": 30000, "description": "Annual security awareness training"},
            {"control": "patching", "annual_cost": 80000, "description": "Automated patch management"},
            {"control": "backup", "annual_cost": 60000, "description": "Immutable backup solution"},
            {"control": "dlp", "annual_cost": 120000, "description": "Data Loss Prevention"},
        ]
        data = self.BREACH_COSTS_BY_INDUSTRY.get(industry, self.BREACH_COSTS_BY_INDUSTRY["technology"])
        base_ale = data["breach_rate"] * data["avg_cost_m"] * 1_000_000
        print(f"  Current annual loss expectancy (ALE): ${base_ale:,.0f}")
        print(f"\n  Potential investments (not yet deployed):\n")
        for inv in investments:
            if inv["control"] not in current_controls:
                all_controls = current_controls + [inv["control"]]
                reduction = 0
                threat_weights = self.INDUSTRY_THREAT_WEIGHTS.get(industry, self.INDUSTRY_THREAT_WEIGHTS["technology"])
                for threat_type, weight in threat_weights.items():
                    ctrl_effect = self.CONTROL_EFFECTIVENESS.get(inv["control"], {}).get(threat_type, 0)
                    reduction += weight * ctrl_effect
                ale_reduction = base_ale * reduction
                roi = ((ale_reduction - inv["annual_cost"]) / inv["annual_cost"]) * 100 if inv["annual_cost"] > 0 else 0
                roi_label = f"{roi:+.0f}%" if roi != 0 else "N/A"
                print(f"    {inv['description']}")
                print(f"      Cost: ${inv['annual_cost']:,}/yr | Risk reduction: ${ale_reduction:,.0f}/yr | ROI: {roi_label}")
                if roi > 100:
                    print(f"      >> STRONG BUY — pays for itself {roi/100:.1f}x over")
                elif roi > 0:
                    print(f"      >> Positive ROI")
                else:
                    print(f"      >> Negative ROI (but may be required for compliance)")
                print()

    def get_findings(self):
        return self.findings


if __name__ == "__main__":
    opts = {
        "mode": sys.argv[1] if len(sys.argv) > 1 else "full",
        "industry": sys.argv[2] if len(sys.argv) > 2 else "technology",
        "controls": sys.argv[3].split(",") if len(sys.argv) > 3 else ["patching", "awareness_training"],
        "employees": int(sys.argv[4]) if len(sys.argv) > 4 else 500,
        "external_services": 8,
        "vulnerability_count": 25,
        "credential_hygiene": 45,
        "segmentation_score": 35,
        "control_coverage": 50,
        "patch_currency": 55,
    }
    pred = ThreatPrediction(options=opts)
    pred.run()
