#!/usr/bin/env python3
"""AEGIS Timeline Builder — reconstruct incident/engagement timelines."""
import os, sys, json
from datetime import datetime

class TimelineBuilder:
    name = "Timeline Builder"
    description = "Build incident/engagement timelines from events, calculate dwell time, export as Markdown"
    category = "reporting"

    def __init__(self, target=None, options=None):
        self.events = []
        self.actions = []

    def add_event(self, timestamp, description, category="general", evidence=None, severity="info"):
        if isinstance(timestamp, str):
            for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%b %d %H:%M:%S', '%Y-%m-%d']:
                try:
                    timestamp = datetime.strptime(timestamp, fmt)
                    break
                except ValueError:
                    continue
        self.events.append({"timestamp": timestamp, "description": description, "category": category,
                           "evidence": evidence, "severity": severity})
        self.events.sort(key=lambda e: e["timestamp"] if isinstance(e["timestamp"], datetime) else datetime.min)

    def from_actions(self, actions):
        for a in actions:
            ts = a.get("time", a.get("timestamp", ""))
            desc = a.get("command", a.get("action", a.get("description", "")))
            cat = a.get("category", a.get("module", "action"))
            self.add_event(ts, desc, cat)

    def dwell_time(self):
        if len(self.events) < 2:
            return None
        phases = {"recon": None, "initial_access": None, "lateral": None, "exfil": None}
        for e in self.events:
            cat = e["category"].lower()
            ts = e["timestamp"]
            if not isinstance(ts, datetime):
                continue
            if "recon" in cat and not phases["recon"]:
                phases["recon"] = ts
            elif any(k in cat for k in ["exploit", "initial", "access"]) and not phases["initial_access"]:
                phases["initial_access"] = ts
            elif any(k in cat for k in ["lateral", "pivot", "movement"]) and not phases["lateral"]:
                phases["lateral"] = ts
            elif any(k in cat for k in ["exfil", "data", "collection"]) and not phases["exfil"]:
                phases["exfil"] = ts
        result = {}
        if phases["recon"] and phases["initial_access"]:
            result["recon_to_access"] = str(phases["initial_access"] - phases["recon"])
        if phases["initial_access"] and phases["lateral"]:
            result["access_to_lateral"] = str(phases["lateral"] - phases["initial_access"])
        if phases["initial_access"] and phases["exfil"]:
            result["total_dwell"] = str(phases["exfil"] - phases["initial_access"])
        first = min(e["timestamp"] for e in self.events if isinstance(e["timestamp"], datetime))
        last = max(e["timestamp"] for e in self.events if isinstance(e["timestamp"], datetime))
        result["total_duration"] = str(last - first)
        return result

    def to_markdown(self):
        lines = ["# Incident Timeline", "", "| Time | Category | Severity | Event |", "|------|----------|----------|-------|"]
        for e in self.events:
            ts = e["timestamp"].strftime("%Y-%m-%d %H:%M:%S") if isinstance(e["timestamp"], datetime) else str(e["timestamp"])
            lines.append(f"| {ts} | {e['category']} | {e['severity'].upper()} | {e['description'][:100]} |")
        dwell = self.dwell_time()
        if dwell:
            lines.extend(["", "## Dwell Time Analysis", ""])
            for k, v in dwell.items():
                lines.append(f"- **{k.replace('_', ' ').title()}:** {v}")
        return "\n".join(lines)

    def to_json(self):
        return json.dumps([{**e, "timestamp": str(e["timestamp"])} for e in self.events], indent=2)

    def run(self, confirm_fn=None):
        return {"events": len(self.events), "timeline": self.to_markdown()}

    def get_findings(self):
        return []

if __name__ == "__main__":
    tb = TimelineBuilder()
    tb.add_event("2024-01-15 09:00:00", "Port scan detected from 10.0.0.5", "recon", severity="medium")
    tb.add_event("2024-01-15 09:15:00", "SQL injection on web application", "exploit", severity="critical")
    tb.add_event("2024-01-15 10:30:00", "Lateral movement to database server", "lateral", severity="high")
    tb.add_event("2024-01-15 11:00:00", "Data exfiltration of customer records", "exfil", severity="critical")
    print(tb.to_markdown())
