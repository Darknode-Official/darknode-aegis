#!/usr/bin/env python3
"""AI-powered security analysis copilot — connects to local Ollama for intelligent analysis"""
import json, os, sys, time, hashlib
from datetime import datetime

try:
    import urllib.request
    import urllib.error
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False

# =============================================================================
# SYSTEM PROMPTS FOR DIFFERENT ANALYSIS MODES
# =============================================================================
SYSTEM_PROMPTS = {
    "log_analysis": (
        "You are an expert SOC analyst reviewing log data. Identify suspicious patterns, "
        "anomalies, and indicators of compromise. For each finding, specify: what you found, "
        "why it's suspicious, the MITRE ATT&CK technique ID, severity (critical/high/medium/low/info), "
        "and recommended next investigation steps. Be specific with timestamps, IPs, and usernames."
    ),
    "vuln_assessment": (
        "You are a senior vulnerability analyst. Given service versions and configurations, "
        "identify known vulnerabilities (CVEs), misconfigurations, and security weaknesses. "
        "For each finding: CVE ID if applicable, CVSS score, exploit availability, "
        "business impact, and specific remediation steps. Prioritize by risk."
    ),
    "incident_investigation": (
        "You are an incident response lead investigating a security incident. "
        "Analyze the provided evidence and determine: what happened, how the attacker got in, "
        "what they did, what data was affected, and the full timeline. Map actions to the "
        "MITRE ATT&CK framework. Recommend containment and eradication steps."
    ),
    "malware_analysis": (
        "You are a malware reverse engineer analyzing extracted artifacts. "
        "Identify: malware family/type, capabilities, persistence mechanisms, "
        "C2 communication patterns, anti-analysis techniques, and IOCs. "
        "Generate YARA rules and detection signatures."
    ),
    "report_writing": (
        "You are a cybersecurity report writer creating professional documentation. "
        "Write clear, concise, and actionable reports suitable for both technical "
        "and executive audiences. Include: executive summary, detailed findings, "
        "risk ratings, and prioritized remediation recommendations."
    ),
    "attack_planning": (
        "You are an authorized penetration tester planning the next phase of an engagement. "
        "Based on current findings, suggest the most promising attack vectors, "
        "tools to use, and techniques to try next. Consider stealth, reliability, "
        "and impact. Map everything to MITRE ATT&CK. Only suggest actions within scope."
    ),
    "defense_recommendations": (
        "You are a security architect recommending defensive improvements. "
        "Based on identified vulnerabilities and attack paths, recommend: "
        "security controls to implement, detection rules to create, "
        "configuration hardening steps, and monitoring improvements. "
        "Prioritize by cost-effectiveness and risk reduction."
    ),
    "compliance_mapping": (
        "You are a compliance specialist mapping security findings to regulatory frameworks. "
        "Map each finding to relevant controls in: NIST CSF, ISO 27001, PCI DSS, HIPAA, "
        "GDPR, SOC 2, CIS Controls. Identify compliance gaps and remediation priorities."
    ),
    "threat_hunting": (
        "You are an advanced threat hunter analyzing data for hidden threats. "
        "Develop hunting hypotheses, suggest data sources to query, write detection "
        "queries (Splunk SPL and ELK KQL), and analyze results for indicators of "
        "advanced persistent threats. Focus on living-off-the-land techniques."
    ),
    "general": (
        "You are an expert cybersecurity analyst. Provide accurate, detailed, "
        "and actionable security analysis. Reference specific CVEs, MITRE ATT&CK "
        "techniques, and industry best practices. Be direct and technical."
    ),
}

AVAILABLE_MODELS = [
    {"name": "llama3.1", "description": "General purpose, good for most tasks", "size": "8B"},
    {"name": "llama3.1:70b", "description": "High quality, slower", "size": "70B"},
    {"name": "codellama", "description": "Code analysis and generation", "size": "7B"},
    {"name": "mistral", "description": "Fast, good for shorter analysis", "size": "7B"},
    {"name": "mixtral", "description": "Mixture of experts, balanced", "size": "8x7B"},
    {"name": "phi3", "description": "Compact, fast responses", "size": "3.8B"},
    {"name": "deepseek-coder", "description": "Code and exploit analysis", "size": "6.7B"},
    {"name": "qwen2", "description": "Multilingual, strong reasoning", "size": "7B"},
]

# =============================================================================
# OFFLINE FALLBACK TEMPLATES
# =============================================================================
OFFLINE_TEMPLATES = {
    "log_analysis": [
        "Log Analysis Summary (Offline Mode)",
        "---",
        "Without AI analysis, review the logs manually for these indicators:",
        "",
        "1. AUTHENTICATION",
        "   - Failed login attempts > 5 from same IP (brute force)",
        "   - Successful login after multiple failures (compromised account)",
        "   - Login from unusual geographic location",
        "   - Login outside business hours",
        "   - Multiple accounts from same source IP (credential stuffing)",
        "",
        "2. NETWORK",
        "   - Connections to known-bad IPs (check threat intel)",
        "   - Unusual outbound data volume (exfiltration)",
        "   - DNS queries with high entropy (tunneling)",
        "   - Regular interval connections (C2 beaconing)",
        "",
        "3. EXECUTION",
        "   - PowerShell with encoded commands (-enc, -e)",
        "   - certutil, mshta, regsvr32, rundll32 (LOLBins)",
        "   - Process creation from unusual parents",
        "",
        "4. PERSISTENCE",
        "   - Registry Run key modifications",
        "   - New scheduled tasks or services",
        "   - Startup folder changes",
    ],
    "vuln_assessment": [
        "Vulnerability Assessment (Offline Mode)",
        "---",
        "Check each discovered service against:",
        "",
        "1. Known CVEs: search https://nvd.nist.gov/ for the service+version",
        "2. Default credentials: test common username/password pairs",
        "3. Security headers: check for CSP, HSTS, X-Frame-Options",
        "4. TLS configuration: check for weak ciphers, old protocols",
        "5. Exposed management interfaces: /admin, /manager, /console",
        "6. Information disclosure: error pages, debug mode, stack traces",
        "",
        "Priority: Critical CVEs with public exploits > Default creds > Misconfigs",
    ],
    "general": [
        "Offline Mode Active",
        "---",
        "AI copilot requires a running Ollama instance.",
        "Start Ollama with: ollama serve",
        "Then pull a model: ollama pull llama3.1",
        "",
        "In the meantime, use AEGIS modules directly for analysis.",
    ],
}

# =============================================================================
# SECURITY COPILOT ENGINE
# =============================================================================
class SecurityCopilot:
    name = "Security Copilot"
    description = "AI-powered security analysis assistant via local Ollama"
    category = "ai"
    mitre = []

    def __init__(self, endpoint="http://localhost:11434", model="llama3.1"):
        self.endpoint = endpoint
        self.model = model
        self.conversation = []
        self.mode = "general"
        self.context = {}
        self.token_usage = {"prompt": 0, "completion": 0}
        self.online = False

    def check_ollama(self):
        if not HAS_URLLIB:
            return False
        try:
            req = urllib.request.Request(f"{self.endpoint}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read())
                models = [m["name"] for m in data.get("models", [])]
                self.online = True
                return models
        except Exception:
            self.online = False
            return False

    def list_models(self):
        models = self.check_ollama()
        if not models:
            print("  Ollama not running. Available model references:")
            for m in AVAILABLE_MODELS:
                print(f"    {m['name']:20s} {m['size']:6s}  {m['description']}")
            return []
        print("  Installed models:")
        for m in models:
            print(f"    {m}")
        return models

    def set_mode(self, mode):
        if mode in SYSTEM_PROMPTS:
            self.mode = mode
            self.conversation = []
            print(f"  Mode set to: {mode}")
            return True
        print(f"  Unknown mode. Available: {', '.join(SYSTEM_PROMPTS.keys())}")
        return False

    def set_context(self, findings=None, iocs=None, target=None, mission=None):
        if findings:
            self.context["findings"] = findings
        if iocs:
            self.context["iocs"] = iocs
        if target:
            self.context["target"] = target
        if mission:
            self.context["mission"] = mission

    def _build_context_string(self):
        parts = []
        if "target" in self.context:
            parts.append(f"Target: {self.context['target']}")
        if "mission" in self.context:
            parts.append(f"Mission: {self.context['mission']}")
        if "findings" in self.context:
            parts.append(f"Current findings ({len(self.context['findings'])} total):")
            for f in self.context["findings"][:10]:
                parts.append(f"  - [{f.get('severity', '?')}] {f.get('title', 'Unknown')}")
        if "iocs" in self.context:
            parts.append(f"Known IOCs ({len(self.context['iocs'])} total):")
            for ioc in self.context["iocs"][:10]:
                parts.append(f"  - {ioc.get('type', '?')}: {ioc.get('value', '?')}")
        return "\n".join(parts) if parts else ""

    def query(self, user_message, include_context=True):
        system_prompt = SYSTEM_PROMPTS.get(self.mode, SYSTEM_PROMPTS["general"])
        ctx = self._build_context_string() if include_context else ""
        if ctx:
            system_prompt += f"\n\nCurrent engagement context:\n{ctx}"
        if not self.online:
            return self._offline_response(user_message)
        messages = [{"role": "system", "content": system_prompt}]
        for msg in self.conversation[-10:]:
            messages.append(msg)
        messages.append({"role": "user", "content": user_message})
        try:
            payload = json.dumps({
                "model": self.model,
                "messages": messages,
                "stream": False,
                "options": {"temperature": 0.3, "num_predict": 2048},
            }).encode("utf-8")
            req = urllib.request.Request(
                f"{self.endpoint}/api/chat",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read())
                response = data.get("message", {}).get("content", "No response")
                self.token_usage["prompt"] += data.get("prompt_eval_count", 0)
                self.token_usage["completion"] += data.get("eval_count", 0)
                self.conversation.append({"role": "user", "content": user_message})
                self.conversation.append({"role": "assistant", "content": response})
                return response
        except urllib.error.URLError as e:
            return f"Connection error: {e}. Is Ollama running?"
        except Exception as e:
            return f"Error: {e}"

    def stream_query(self, user_message, include_context=True):
        system_prompt = SYSTEM_PROMPTS.get(self.mode, SYSTEM_PROMPTS["general"])
        ctx = self._build_context_string() if include_context else ""
        if ctx:
            system_prompt += f"\n\nCurrent engagement context:\n{ctx}"
        if not self.online:
            yield self._offline_response(user_message)
            return
        messages = [{"role": "system", "content": system_prompt}]
        for msg in self.conversation[-10:]:
            messages.append(msg)
        messages.append({"role": "user", "content": user_message})
        try:
            payload = json.dumps({
                "model": self.model,
                "messages": messages,
                "stream": True,
                "options": {"temperature": 0.3, "num_predict": 2048},
            }).encode("utf-8")
            req = urllib.request.Request(
                f"{self.endpoint}/api/chat",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            full_response = ""
            with urllib.request.urlopen(req, timeout=120) as resp:
                for line in resp:
                    try:
                        chunk = json.loads(line)
                        token = chunk.get("message", {}).get("content", "")
                        if token:
                            full_response += token
                            yield token
                        if chunk.get("done"):
                            self.token_usage["prompt"] += chunk.get("prompt_eval_count", 0)
                            self.token_usage["completion"] += chunk.get("eval_count", 0)
                    except json.JSONDecodeError:
                        continue
            self.conversation.append({"role": "user", "content": user_message})
            self.conversation.append({"role": "assistant", "content": full_response})
        except Exception as e:
            yield f"Error: {e}"

    def _offline_response(self, user_message):
        template = OFFLINE_TEMPLATES.get(self.mode, OFFLINE_TEMPLATES["general"])
        return "\n".join(template)

    def analyze_logs(self, log_text):
        self.set_mode("log_analysis")
        prompt = f"Analyze these log entries for suspicious activity:\n\n```\n{log_text[:4000]}\n```"
        return self.query(prompt)

    def assess_services(self, services):
        self.set_mode("vuln_assessment")
        svc_text = "\n".join([f"- {s.get('name', '?')} {s.get('version', '?')} on port {s.get('port', '?')}" for s in services])
        prompt = f"Assess these discovered services for vulnerabilities:\n\n{svc_text}"
        return self.query(prompt)

    def investigate_alert(self, alert_text):
        self.set_mode("incident_investigation")
        prompt = f"Investigate this security alert:\n\n{alert_text}"
        return self.query(prompt)

    def analyze_strings(self, strings_list):
        self.set_mode("malware_analysis")
        strings_text = "\n".join(strings_list[:200])
        prompt = f"Analyze these strings extracted from a suspicious binary:\n\n```\n{strings_text}\n```"
        return self.query(prompt)

    def write_report(self, findings):
        self.set_mode("report_writing")
        findings_text = "\n".join([f"- [{f.get('severity', '?')}] {f.get('title', '?')}: {f.get('description', '')}" for f in findings[:20]])
        prompt = f"Generate a professional penetration test executive summary for these findings:\n\n{findings_text}"
        return self.query(prompt)

    def suggest_next_steps(self, current_state):
        self.set_mode("attack_planning")
        prompt = f"Based on the current state of the engagement, suggest the next steps:\n\n{current_state}"
        return self.query(prompt)

    def recommend_defenses(self, gaps):
        self.set_mode("defense_recommendations")
        prompt = f"Recommend security controls for these identified gaps:\n\n{gaps}"
        return self.query(prompt)

    def map_compliance(self, findings):
        self.set_mode("compliance_mapping")
        findings_text = "\n".join([f"- {f.get('title', '?')}" for f in findings[:20]])
        prompt = f"Map these findings to relevant compliance frameworks (NIST CSF, PCI DSS, HIPAA, ISO 27001):\n\n{findings_text}"
        return self.query(prompt)

    def get_stats(self):
        return {
            "mode": self.mode,
            "model": self.model,
            "online": self.online,
            "conversation_length": len(self.conversation),
            "tokens_used": self.token_usage,
            "context_items": {k: len(v) if isinstance(v, list) else 1 for k, v in self.context.items()},
        }

    def clear_conversation(self):
        self.conversation = []
        print("  Conversation cleared.")

    def run(self, confirm_fn=None):
        print("\n" + "=" * 60)
        print(" AEGIS SECURITY COPILOT")
        print("=" * 60)
        models = self.check_ollama()
        if models:
            print(f"\n  Ollama: ONLINE ({len(models)} models)")
            print(f"  Active model: {self.model}")
            print(f"  Mode: {self.mode}")
        else:
            print("\n  Ollama: OFFLINE (running in template mode)")
            print("  Start Ollama: ollama serve")
            print("  Pull a model: ollama pull llama3.1")
        print("\nCommands:")
        print("  /mode <name>    - Switch analysis mode")
        print("  /modes          - List available modes")
        print("  /model <name>   - Switch model")
        print("  /models         - List installed models")
        print("  /clear          - Clear conversation")
        print("  /stats          - Show usage statistics")
        print("  /logs <text>    - Quick log analysis")
        print("  /quit           - Exit copilot")
        print("")
        while True:
            try:
                user_input = input("COPILOT> ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not user_input:
                continue
            if user_input == "/quit" or user_input == "/exit":
                break
            elif user_input == "/modes":
                print("\n  Available modes:")
                for mode, desc in SYSTEM_PROMPTS.items():
                    print(f"    {mode:25s} {desc[:60]}...")
                print()
            elif user_input.startswith("/mode "):
                self.set_mode(user_input[6:].strip())
            elif user_input == "/models":
                self.list_models()
            elif user_input.startswith("/model "):
                self.model = user_input[7:].strip()
                print(f"  Model set to: {self.model}")
            elif user_input == "/clear":
                self.clear_conversation()
            elif user_input == "/stats":
                stats = self.get_stats()
                for k, v in stats.items():
                    print(f"  {k}: {v}")
            elif user_input.startswith("/logs "):
                print("\n  Analyzing logs...\n")
                response = self.analyze_logs(user_input[6:])
                print(response)
                print()
            else:
                if self.online:
                    sys.stdout.write("\n")
                    for token in self.stream_query(user_input):
                        sys.stdout.write(token)
                        sys.stdout.flush()
                    sys.stdout.write("\n\n")
                else:
                    response = self.query(user_input)
                    print(f"\n{response}\n")


if __name__ == "__main__":
    copilot = SecurityCopilot()
    copilot.run()
