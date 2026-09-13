#!/usr/bin/env python3
"""NLP Log Analyzer — AI-powered log analysis via local Ollama."""
import subprocess, json, os, sys, re
from datetime import datetime

class NLPLogAnalyzer:
    name = "NLP Log Analyzer"
    description = "AI-powered log analysis using local Ollama models"
    category = "ai"
    mitre = ["T1530"]

    def __init__(self, target=None, options=None):
        self.options = options or {}
        self.model = self.options.get("model", "llama3.1")
        self.endpoint = self.options.get("endpoint", "http://localhost:11434")
        self.findings = []
        self.actions = []
        self.chunk_size = 50

    def check_ollama(self):
        try:
            result = subprocess.run(["curl", "-s", f"{self.endpoint}/api/tags"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                data = json.loads(result.stdout)
                models = [m["name"] for m in data.get("models", [])]
                return True, models
        except Exception:
            pass
        return False, []

    def query_ollama(self, prompt, system_prompt=None):
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.1, "num_predict": 2048}
        }
        if system_prompt:
            payload["system"] = system_prompt
        try:
            result = subprocess.run(
                ["curl", "-s", "-X", "POST", f"{self.endpoint}/api/generate",
                 "-d", json.dumps(payload)],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                return data.get("response", "")
        except Exception as e:
            return f"Error: {e}"
        return "Error: No response from Ollama"

    def analyze_logs(self, log_text, query=None):
        system = (
            "You are AEGIS, a cybersecurity log analysis AI. Analyze the following logs for:\n"
            "1. Suspicious activity (brute force, scanning, exploitation attempts)\n"
            "2. Indicators of compromise (malicious IPs, unusual user agents, encoded payloads)\n"
            "3. Anomalies (unusual times, unexpected services, privilege escalation)\n"
            "4. Attack patterns mapped to MITRE ATT&CK techniques\n\n"
            "Be specific: cite line numbers, IPs, timestamps. Rate severity: CRITICAL/HIGH/MEDIUM/LOW/INFO.\n"
            "Format findings as:\n"
            "[SEVERITY] Finding title\n"
            "  Evidence: <specific log line or pattern>\n"
            "  MITRE: <technique ID>\n"
            "  Recommendation: <action to take>\n"
        )
        if query:
            prompt = f"Regarding these logs, answer this question: {query}\n\nLogs:\n{log_text[:8000]}"
        else:
            prompt = f"Analyze these logs for security threats:\n\n{log_text[:8000]}"
        return self.query_ollama(prompt, system)

    def summarize_logs(self, log_text):
        system = "You are a SOC analyst. Summarize these logs concisely: total events, unique source IPs, time range, key events, any anomalies."
        prompt = f"Summarize these logs:\n\n{log_text[:8000]}"
        return self.query_ollama(prompt, system)

    def hunt_threats(self, log_text, hypothesis=None):
        system = (
            "You are an elite threat hunter. Given these logs, actively search for hidden threats.\n"
            "Look for: C2 beaconing (regular intervals), credential abuse, lateral movement,\n"
            "data staging, defense evasion, living-off-the-land techniques.\n"
            "For each finding, provide the hunting hypothesis, evidence, confidence level, and next steps."
        )
        if hypothesis:
            prompt = f"Test this hunting hypothesis against the logs: {hypothesis}\n\nLogs:\n{log_text[:8000]}"
        else:
            prompt = f"Hunt for hidden threats in these logs:\n\n{log_text[:8000]}"
        return self.query_ollama(prompt, system)

    def generate_detection_rules(self, log_text):
        system = (
            "You are a detection engineer. Based on the suspicious patterns in these logs,\n"
            "generate detection rules in these formats:\n"
            "1. Sigma rule (YAML)\n"
            "2. Splunk SPL query\n"
            "3. Elasticsearch KQL query\n"
            "For each rule, explain what it detects and expected false positive rate."
        )
        prompt = f"Generate detection rules for threats found in these logs:\n\n{log_text[:8000]}"
        return self.query_ollama(prompt, system)

    def correlate_events(self, log_text):
        system = (
            "You are an incident analyst. Correlate events across these logs to reconstruct\n"
            "the attack timeline. Connect related events by: source IP, user account, timestamp\n"
            "proximity, and causal relationships (e.g., login followed by file access).\n"
            "Output a chronological timeline of the attack."
        )
        prompt = f"Correlate events and build an attack timeline:\n\n{log_text[:8000]}"
        return self.query_ollama(prompt, system)

    def explain_event(self, event_line):
        system = "You are a security analyst. Explain this log entry: what happened, is it normal or suspicious, and what should be done about it."
        prompt = f"Explain this log entry:\n{event_line}"
        return self.query_ollama(prompt, system)

    def chunk_and_analyze(self, log_lines):
        results = []
        for i in range(0, len(log_lines), self.chunk_size):
            chunk = "\n".join(log_lines[i:i + self.chunk_size])
            result = self.analyze_logs(chunk)
            results.append({"chunk": i // self.chunk_size + 1, "lines": f"{i+1}-{min(i+self.chunk_size, len(log_lines))}", "analysis": result})
        return results

    def run(self, confirm_fn=None):
        available, models = self.check_ollama()
        if not available:
            print("[!] Ollama is not running. Start it with: ollama serve")
            print("[!] Then pull a model: ollama pull llama3.1")
            return
        print(f"[+] Ollama available with models: {', '.join(models)}")
        if self.model not in [m.split(":")[0] for m in models]:
            print(f"[!] Model {self.model} not found. Available: {', '.join(models)}")
            print(f"[!] Pull it with: ollama pull {self.model}")
            return
        log_file = self.options.get("log_file")
        if log_file and os.path.exists(log_file):
            with open(log_file, "r", errors="ignore") as f:
                log_text = f.read()
            print(f"[+] Loaded {len(log_text)} bytes from {log_file}")
        else:
            print("[*] Paste log entries below (Ctrl+D or empty line to finish):")
            lines = []
            try:
                while True:
                    line = input()
                    if not line:
                        break
                    lines.append(line)
            except EOFError:
                pass
            log_text = "\n".join(lines)
        if not log_text.strip():
            print("[!] No log data provided")
            return
        query = self.options.get("query")
        mode = self.options.get("mode", "analyze")
        print(f"\n[*] Running {mode} mode with {self.model}...")
        if mode == "analyze":
            result = self.analyze_logs(log_text, query)
        elif mode == "summarize":
            result = self.summarize_logs(log_text)
        elif mode == "hunt":
            result = self.hunt_threats(log_text, query)
        elif mode == "detect":
            result = self.generate_detection_rules(log_text)
        elif mode == "correlate":
            result = self.correlate_events(log_text)
        else:
            result = self.analyze_logs(log_text, query)
        print(f"\n{'='*60}")
        print(f"AEGIS AI Analysis ({mode})")
        print(f"{'='*60}")
        print(result)
        self.findings.append({"mode": mode, "result": result, "timestamp": datetime.now().isoformat()})

    def get_findings(self):
        return self.findings

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="AEGIS NLP Log Analyzer")
    parser.add_argument("--file", "-f", help="Log file to analyze")
    parser.add_argument("--mode", "-m", choices=["analyze", "summarize", "hunt", "detect", "correlate"], default="analyze")
    parser.add_argument("--query", "-q", help="Specific question about the logs")
    parser.add_argument("--model", default="llama3.1", help="Ollama model to use")
    args = parser.parse_args()
    analyzer = NLPLogAnalyzer(options={"log_file": args.file, "mode": args.mode, "query": args.query, "model": args.model})
    analyzer.run()
