# AEGIS — Autonomous Electronic Governance & Intelligence System

Government-level cyber operations platform for Darknode OS.

## What is AEGIS?

AEGIS is a comprehensive cyber operations command center with 40+ modules across 9 domains. It provides a unified platform for authorized penetration testing, threat intelligence, incident response, digital forensics, and security operations — all from a single terminal interface.

## Quick Start

```bash
# Install
git clone https://github.com/SpartanKing18/darknode-aegis
cd darknode-aegis
bash install.sh

# Launch
aegis                              # Full TUI dashboard
aegis --quick 10.0.0.1            # Quick recon scan
aegis --module recon/passive-recon # Run a specific module
aegis --list                       # List all modules
aegis --mission "Op Sunrise"       # Start a new mission
```

## Requirements

- Python 3.8+
- `rich` library (auto-installed)
- Security tools (optional but recommended): nmap, nikto, gobuster, sqlmap, hydra, john, hashcat, searchsploit, sslscan, dig, whois, tshark

## 9 Operational Domains

| Domain | Modules | Description |
|--------|---------|-------------|
| **Recon** | 6 | Passive OSINT, active scanning, web fingerprinting, cloud discovery, social recon |
| **Vuln** | 6 | CVE matching (200+), OWASP testing, CIS benchmarks, credential audit, crypto audit |
| **Exploit** | 4+ | Exploit database (200+), payload generator (15+ languages), post-exploitation, privesc |
| **Intel** | 4 | Threat feeds, MITRE ATT&CK mapper, APT tracker (50+ groups), dark web monitor |
| **Defense** | 5+ | IDS rules (Snort/Sigma/YARA), log analysis, incident response, forensics, honeypots |
| **Crypto** | 4 | Encrypt/decrypt, steganography, covert channels, key management |
| **Network** | 4+ | Packet crafting, traffic analysis, wireless ops, tunneling |
| **AI** | 4 | Anomaly detection, pattern matching, automated threat hunting, predictive analysis |
| **Reporting** | 4 | Professional reports, timeline builder, evidence chain of custody, executive briefings |

## Key Features

- **Mission-based workflow** — every operation is a mission with its own database, evidence chain, and report
- **Human-in-the-loop** — confirms every action, logs everything for audit trail
- **Offline-first** — built-in CVE database, exploit archive, wordlists, YARA/Sigma rules
- **Rich TUI dashboard** — panels, tables, charts, classification banners
- **AI-powered** — connects to local Ollama for intelligent log analysis and threat prediction
- **Evidence integrity** — SHA-256 hashing, chain of custody, timestamped audit trail
- **Professional reporting** — generates pentest reports with findings, risk matrices, and remediation roadmaps

## Offline Databases

- 300+ critical CVEs (2014-2025) with CVSS, exploits, patches
- 70+ YARA rules (ransomware, RATs, webshells, stealers, cryptominers)
- 40+ Sigma detection rules
- 100+ Snort/Suricata rules
- 50+ APT group profiles
- 1000+ common passwords
- 185+ CIS Benchmark checks (Linux, Docker, K8s, AWS)
- 2000+ subdomain wordlist
- NIST CSF framework reference

## Legal

Use only on systems you own or have explicit written authorization to test. AEGIS is an educational and authorized-testing platform. Unauthorized access to computer systems is illegal.

## License

Copyright (c) 2026 SpartanKing18. All rights reserved.
Source-available for learning only. Redistribution prohibited. See LICENSE.
