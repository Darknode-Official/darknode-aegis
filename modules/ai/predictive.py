#!/usr/bin/env python3
"""AEGIS Predictive Threat Analysis — risk prediction and next-attack forecasting."""
import os, sys, json, math
from datetime import datetime

class PredictiveAnalysis:
    name = "Predictive Threat Analysis"
    description = "Attack likelihood scoring, risk prediction, next-attack forecasting, trend analysis"
    category = "ai"
    mitre = ["T1595", "T1190"]

    INDUSTRY_THREAT_PROFILES = {
        "healthcare": {"top_threats": ["ransomware", "insider_threat", "phishing", "iot_exploitation"],
                       "avg_breach_cost": 10930000, "dwell_time_days": 236, "attack_frequency": "high"},
        "finance": {"top_threats": ["apt", "credential_theft", "web_attacks", "insider_threat"],
                    "avg_breach_cost": 5900000, "dwell_time_days": 168, "attack_frequency": "very_high"},
        "technology": {"top_threats": ["supply_chain", "zero_day", "ip_theft", "cloud_misconfig"],
                       "avg_breach_cost": 4970000, "dwell_time_days": 197, "attack_frequency": "high"},
        "government": {"top_threats": ["apt", "espionage", "ransomware", "insider_threat"],
                       "avg_breach_cost": 2600000, "dwell_time_days": 287, "attack_frequency": "high"},
        "education": {"top_threats": ["ransomware", "phishing", "data_breach", "credential_stuffing"],
                      "avg_breach_cost": 3650000, "dwell_time_days": 212, "attack_frequency": "medium"},
        "retail": {"top_threats": ["pos_malware", "web_skimming", "credential_stuffing", "supply_chain"],
                   "avg_breach_cost": 3280000, "dwell_time_days": 197, "attack_frequency": "medium"},
        "manufacturing": {"top_threats": ["ransomware", "ics_attacks", "ip_theft", "supply_chain"],
                          "avg_breach_cost": 4730000, "dwell_time_days": 220, "attack_frequency": "medium"},
        "energy": {"top_threats": ["apt", "ics_attacks", "ransomware", "espionage"],
                   "avg_breach_cost": 4720000, "dwell_time_days": 254, "attack_frequency": "high"},
    }

    ATTACK_VECTORS = [
        {"name": "Phishing", "base_likelihood": 0.35,
         "factors": {"mfa": -0.15, "awareness_training": -0.10, "email_gateway": -0.08, "dmarc": -0.05}},
        {"name": "Exploit Public App", "base_likelihood": 0.25,
         "factors": {"waf": -0.08, "patching_sla_7d": -0.10, "vuln_scanning": -0.05, "ids": -0.03}},
        {"name": "Credential Stuffing", "base_likelihood": 0.20,
         "factors": {"mfa": -0.15, "rate_limiting": -0.05, "breach_monitoring": -0.03}},
        {"name": "Supply Chain", "base_likelihood": 0.10,
         "factors": {"sbom": -0.03, "vendor_assessment": -0.03, "code_signing": -0.02}},
        {"name": "Insider Threat", "base_likelihood": 0.10,
         "factors": {"dlp": -0.04, "ueba": -0.03, "access_reviews": -0.02, "least_privilege": -0.03}},
        {"name": "Zero-Day", "base_likelihood": 0.05,
         "factors": {"edr": -0.02, "network_segmentation": -0.01, "threat_intel": -0.01}},
        {"name": "Physical Access", "base_likelihood": 0.03,
         "factors": {"badge_access": -0.01, "cctv": -0.01, "visitor_policy": -0.005}},
        {"name": "Cloud Misconfiguration", "base_likelihood": 0.15,
         "factors": {"cspm": -0.06, "iam_reviews": -0.04, "cloud_audit": -0.03}},
    ]

    def __init__(self, target=None, options=None):
        self.target = target
        self.options = options or {}
        self.findings = []
        self.actions = []

    def _log(self, msg):
        self.actions.append({"time": datetime.now().isoformat(), "action": msg})
        print(f"  [PREDICT] {msg}")

    def predict_attack_likelihood(self, industry, controls=None):
        controls = controls or []
        controls_set = set(c.lower() for c in controls)
        profile = self.INDUSTRY_THREAT_PROFILES.get(industry.lower(), self.INDUSTRY_THREAT_PROFILES["technology"])
        predictions = []
        for vector in self.ATTACK_VECTORS:
            likelihood = vector["base_likelihood"]
            mitigations_applied = []
            for control, reduction in vector["factors"].items():
                if control in controls_set:
                    likelihood += reduction
                    mitigations_applied.append(control)
            likelihood = max(0.01, min(0.99, likelihood))
            is_top = vector["name"].lower().replace(" ", "_") in [t.lower() for t in profile["top_threats"]]
            if is_top:
                likelihood = min(0.99, likelihood * 1.3)
            predictions.append({
                "vector": vector["name"],
                "likelihood": round(likelihood, 3),
                "percentage": f"{likelihood*100:.1f}%",
                "industry_elevated": is_top,
                "mitigations_active": mitigations_applied,
                "mitigations_missing": [c for c in vector["factors"] if c not in controls_set],
            })
        predictions.sort(key=lambda x: -x["likelihood"])
        overall_risk = 1.0
        for p in predictions:
            overall_risk *= (1 - p["likelihood"])
        overall_breach_probability = round(1 - overall_risk, 3)
        result = {
            "industry": industry,
            "profile": profile,
            "predictions": predictions,
            "overall_breach_probability": overall_breach_probability,
            "overall_percentage": f"{overall_breach_probability*100:.1f}%",
            "estimated_breach_cost": profile["avg_breach_cost"],
            "expected_dwell_time_days": profile["dwell_time_days"],
            "risk_adjusted_cost": round(profile["avg_breach_cost"] * overall_breach_probability),
        }
        self._log(f"Attack prediction for {industry}: {overall_breach_probability*100:.1f}% breach probability")
        top = predictions[0]
        self.findings.append({
            "severity": "high" if top["likelihood"] > 0.3 else "medium",
            "title": f"Most likely attack vector: {top['vector']} ({top['percentage']})",
            "detail": f"Missing mitigations: {', '.join(top['mitigations_missing'])}",
            "mitre": "T1190"
        })
        return result

    def next_attack_predictor(self, current_findings):
        if not current_findings:
            return {"prediction": "Insufficient data for prediction"}
        phases_seen = set()
        for f in current_findings:
            mitre = f.get('mitre', '')
            if 'T1595' in mitre or 'T1046' in mitre:
                phases_seen.add('recon')
            elif 'T1190' in mitre or 'T1078' in mitre:
                phases_seen.add('initial_access')
            elif 'T1059' in mitre:
                phases_seen.add('execution')
            elif 'T1003' in mitre or 'T1558' in mitre:
                phases_seen.add('credential_access')
            elif 'T1550' in mitre or 'T1021' in mitre:
                phases_seen.add('lateral_movement')
        next_phases = {
            'recon': ('initial_access', 'Exploitation of discovered vulnerabilities', 'T1190'),
            'initial_access': ('execution', 'Malware/script execution on compromised host', 'T1059'),
            'execution': ('credential_access', 'Credential harvesting from compromised system', 'T1003'),
            'credential_access': ('lateral_movement', 'Lateral movement using stolen credentials', 'T1550'),
            'lateral_movement': ('exfiltration', 'Data staging and exfiltration', 'T1048'),
        }
        predictions = []
        for phase in phases_seen:
            if phase in next_phases:
                next_phase, desc, mitre = next_phases[phase]
                if next_phase not in phases_seen:
                    predictions.append({"current_phase": phase, "predicted_next": next_phase,
                                       "description": desc, "mitre": mitre, "urgency": "high"})
        self._log(f"Next attack prediction: {len(predictions)} predicted phases")
        return {"phases_observed": list(phases_seen), "predictions": predictions}

    def risk_score(self, asset_value, vulnerability_score, threat_level, exposure):
        av = min(10, max(1, asset_value))
        vs = min(10, max(0, vulnerability_score))
        tl = min(10, max(1, threat_level))
        ex = min(10, max(1, exposure))
        score = (av * 0.25 + vs * 0.30 + tl * 0.25 + ex * 0.20) * 10
        severity = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 40 else "low"
        return {"risk_score": round(score, 1), "severity": severity,
                "components": {"asset_value": av, "vulnerability": vs, "threat": tl, "exposure": ex}}

    def run(self, confirm_fn=None):
        industry = self.options.get('industry', 'technology')
        controls = self.options.get('controls', [])
        return self.predict_attack_likelihood(industry, controls)

    def get_findings(self):
        return self.findings

if __name__ == "__main__":
    industry = sys.argv[1] if len(sys.argv) > 1 else 'technology'
    controls = sys.argv[2].split(',') if len(sys.argv) > 2 else []
    pa = PredictiveAnalysis(options={'industry': industry, 'controls': controls})
    result = pa.run()
    print(f"\n  Industry: {result['industry']}")
    print(f"  Breach probability: {result['overall_percentage']}")
    print(f"  Estimated breach cost: ${result['estimated_breach_cost']:,}")
    print(f"  Risk-adjusted cost: ${result['risk_adjusted_cost']:,}")
    print(f"\n  Attack vectors (by likelihood):")
    for p in result['predictions']:
        print(f"    {p['percentage']:>6} | {p['vector']:<25} {'[ELEVATED]' if p['industry_elevated'] else ''}")
        if p['mitigations_missing']:
            print(f"           Missing: {', '.join(p['mitigations_missing'])}")
