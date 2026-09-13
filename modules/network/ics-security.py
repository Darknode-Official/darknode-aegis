#!/usr/bin/env python3
"""ICS/SCADA/OT Security Operations -- protocol analysis, attacks, defense"""
import json, os, sys
from datetime import datetime

# ============================================================================
# ICS PROTOCOL REFERENCE
# ============================================================================
ICS_PROTOCOLS = [
    {
        "name": "Modbus TCP",
        "port": 502,
        "description": "Master/slave protocol for industrial control. No authentication by design. Function codes control read/write operations on registers and coils.",
        "function_codes": [
            {"code": 1, "name": "Read Coils", "description": "Read ON/OFF status of discrete outputs", "risk": "Information disclosure of physical state"},
            {"code": 2, "name": "Read Discrete Inputs", "description": "Read ON/OFF status of discrete inputs", "risk": "Information disclosure"},
            {"code": 3, "name": "Read Holding Registers", "description": "Read analog output values (setpoints, configs)", "risk": "Reveals process configuration"},
            {"code": 4, "name": "Read Input Registers", "description": "Read analog input values (sensor data)", "risk": "Reveals real-time process data"},
            {"code": 5, "name": "Write Single Coil", "description": "Force a single output ON or OFF", "risk": "CRITICAL: Direct physical manipulation"},
            {"code": 6, "name": "Write Single Register", "description": "Write a value to a single register", "risk": "CRITICAL: Modify setpoints/configurations"},
            {"code": 15, "name": "Write Multiple Coils", "description": "Force multiple outputs simultaneously", "risk": "CRITICAL: Mass physical manipulation"},
            {"code": 16, "name": "Write Multiple Registers", "description": "Write to multiple registers at once", "risk": "CRITICAL: Mass configuration change"},
            {"code": 43, "name": "Read Device ID", "description": "Read vendor/product/version information", "risk": "Device fingerprinting"},
        ],
        "attacks": [
            "Unauthorized read: extract process data and configurations",
            "Unauthorized write: manipulate setpoints, force outputs, change configs",
            "Replay attack: capture and replay valid Modbus packets",
            "Man-in-the-middle: intercept and modify Modbus traffic",
            "Denial of service: flood with invalid function codes",
        ],
        "tools": ["mbtget", "modbus-cli", "pymodbus", "Metasploit modbusclient"],
        "defense": ["Network segmentation", "Modbus-aware firewall/IDS", "Encrypted tunnels (VPN/TLS)", "Access control lists", "Monitor for unexpected write operations"],
    },
    {
        "name": "DNP3 (Distributed Network Protocol 3)",
        "port": 20000,
        "description": "Three-layer protocol (data link, transport, application) used in electric utilities and water systems. Supports Secure Authentication (SA) in v5.",
        "function_codes": [
            {"code": "READ", "name": "Read", "description": "Request data from outstation"},
            {"code": "WRITE", "name": "Write", "description": "Write data to outstation"},
            {"code": "DIRECT_OP", "name": "Direct Operate", "description": "Immediately operate a control point (CROB)", "risk": "CRITICAL: Direct physical control"},
            {"code": "SELECT", "name": "Select-Before-Operate", "description": "Two-step control: select, then operate", "risk": "CRITICAL with confirmed operate"},
            {"code": "COLD_RESTART", "name": "Cold Restart", "description": "Full device restart", "risk": "Denial of service"},
            {"code": "WARM_RESTART", "name": "Warm Restart", "description": "Application restart", "risk": "Service disruption"},
            {"code": "DISABLE_UNSOLICITED", "name": "Disable Unsolicited", "description": "Stop autonomous event reporting", "risk": "Blind operators to field events"},
        ],
        "attacks": [
            "Unauthorized control operations (CROB commands)",
            "Disable unsolicited responses (blind the SCADA master)",
            "Cold restart to cause service disruption",
            "Spoof responses to present false process data",
            "Replay captured control sequences",
        ],
        "tools": ["dnp3-master (OpenDNP3)", "Aegis DNP3 module", "Metasploit dnp3 modules"],
        "defense": ["Enable DNP3 Secure Authentication (SA v5)", "Bump-in-the-wire encryption", "DNP3-aware IDS rules", "Network segmentation between SCADA and PLCs"],
    },
    {
        "name": "OPC UA (Unified Architecture)",
        "port": 4840,
        "description": "Modern industrial protocol with built-in security (authentication, encryption, authorization). Successor to OPC DA/HDA/A&E.",
        "security_modes": [
            {"mode": "None", "description": "No security. All traffic in plaintext.", "risk": "CRITICAL in production"},
            {"mode": "Sign", "description": "Messages are signed but not encrypted", "risk": "Integrity but not confidentiality"},
            {"mode": "SignAndEncrypt", "description": "Full security: signed and encrypted", "risk": "Recommended for production"},
        ],
        "attacks": [
            "Connect with SecurityMode=None if server allows it",
            "Certificate theft/reuse for authenticated access",
            "Exploit known OPC UA implementation vulnerabilities",
            "Session hijacking if security mode is weak",
            "Browse the address space to map the entire process",
        ],
        "defense": ["Enforce SignAndEncrypt mode", "Certificate-based authentication", "Application whitelisting", "Audit logging", "Firewall OPC UA ports"],
    },
    {
        "name": "S7comm (Siemens S7 Communication)",
        "port": 102,
        "description": "Proprietary Siemens protocol for S7-300/400/1200/1500 PLCs. Runs over ISO-TSAP (RFC 1006). Limited authentication in older firmware.",
        "attacks": [
            "Read/write PLC memory (DB blocks, inputs, outputs, markers)",
            "Stop/start PLC CPU",
            "Download/upload PLC program",
            "Extract passwords from protection level configurations",
            "Identify PLC model, firmware version, serial number",
        ],
        "tools": ["snap7", "python-snap7", "PLCScan", "Metasploit s7 modules", "Nmap s7-info script"],
        "defense": ["Firmware updates (S7-1500 has better auth)", "Access control lists", "Network segmentation", "S7 communication firewall"],
    },
    {
        "name": "EtherNet/IP (CIP)",
        "port": 44818,
        "description": "Common Industrial Protocol over Ethernet, used by Allen-Bradley/Rockwell PLCs. No inherent authentication.",
        "attacks": [
            "Read tag values (process data)",
            "Write tag values (modify setpoints)",
            "Discover devices via broadcast",
            "Change PLC mode (Run/Program/Test)",
            "Firmware upload/download",
        ],
        "tools": ["pycomm3", "cpppo", "Metasploit EtherNet/IP modules"],
        "defense": ["CIP Security (TLS-based, newer devices)", "Network segmentation", "Access control lists", "CIP-aware IDS"],
    },
    {
        "name": "BACnet (Building Automation)",
        "port": 47808,
        "description": "Protocol for building automation: HVAC, lighting, fire, access control. Typically no authentication.",
        "attacks": [
            "Read/write BACnet objects (setpoints, schedules, alarms)",
            "Discover all devices on the BACnet network",
            "Modify HVAC setpoints (temperature manipulation)",
            "Disable fire/security alarms",
            "Change access control schedules",
        ],
        "defense": ["BACnet Secure Connect (BACnet/SC)", "Network segmentation from IT", "BACnet-aware firewall"],
    },
]

# ============================================================================
# ICS ATTACK TECHNIQUES (mapped to ICS MITRE ATT&CK)
# ============================================================================
ICS_ATTACKS = [
    {
        "name": "PLC Program Manipulation",
        "description": "Upload a modified program to the PLC that alters the physical process while displaying normal values to operators.",
        "mitre_ics": "T0843",
        "impact": "Physical damage, safety hazard, process disruption",
        "examples": ["Stuxnet: modified Siemens S7-315/417 code to vary centrifuge speeds while reporting normal operation"],
        "detection": "PLC program change monitoring, hash comparison of PLC projects, network monitoring for upload commands",
        "prevention": "PLC program access control, version control for PLC projects, change detection systems",
    },
    {
        "name": "HMI Exploitation",
        "description": "Compromise the Human-Machine Interface to gain visibility into and control over the physical process. Many HMIs run outdated Windows with web interfaces.",
        "mitre_ics": "T0823",
        "impact": "Full process visibility and control, operator deception",
        "examples": ["BlackEnergy: compromised Ukrainian power grid HMIs to open breakers remotely"],
        "detection": "Endpoint monitoring on HMI stations, anomalous HMI commands, login anomalies",
        "prevention": "Patch HMI software, restrict remote access, application whitelisting, MFA",
    },
    {
        "name": "Historian Database Attack",
        "description": "Compromise the data historian to manipulate historical process data, hide evidence of attacks, or extract sensitive process information.",
        "mitre_ics": "T0872",
        "impact": "Data integrity loss, compliance violations, attack concealment",
        "detection": "Database access monitoring, integrity checks on historical data, anomalous queries",
        "prevention": "Historian in DMZ (not directly accessible from IT or OT), DB authentication, audit logging",
    },
    {
        "name": "Safety System Manipulation",
        "description": "Target Safety Instrumented Systems (SIS) to disable safety protections, enabling physical damage. TRITON/TRISIS targeted Schneider Triconex SIS.",
        "mitre_ics": "T0880",
        "impact": "CRITICAL: Loss of safety protections, potential for explosion/injury/death",
        "examples": ["TRITON/TRISIS: targeted Triconex SIS at Saudi petrochemical plant to disable safety shutdowns"],
        "detection": "SIS program change monitoring, network monitoring between SIS and DCS, anomalous engineering workstation activity",
        "prevention": "Air-gap SIS from DCS where possible, physical key locks on SIS, hardware write protection",
    },
    {
        "name": "Physical Process Disruption",
        "description": "Directly manipulate physical process parameters (pressure, temperature, speed, flow) to cause damage or disruption.",
        "mitre_ics": "T0831",
        "impact": "Equipment damage, environmental harm, production loss, safety risk",
        "examples": ["Stuxnet: varied centrifuge speeds to cause mechanical failure", "CrashOverride: opened circuit breakers to cause power outage"],
        "detection": "Process anomaly detection, out-of-range value alerts, rate-of-change monitoring",
        "prevention": "Independent safety systems, physical interlocks, alarm management, defense-in-depth",
    },
    {
        "name": "Engineering Workstation Compromise",
        "description": "Target engineering workstations that have PLC programming software. From these stations, an attacker can reprogram any PLC on the network.",
        "mitre_ics": "T0818",
        "impact": "Full control over all PLCs accessible from the workstation",
        "detection": "EDR on engineering workstations, USB monitoring, anomalous program downloads",
        "prevention": "Dedicated, hardened engineering workstations, MFA, no internet access, USB restrictions",
    },
    {
        "name": "Denial of View / Denial of Control",
        "description": "Blind operators by disrupting SCADA displays (denial of view) or prevent them from sending control commands (denial of control).",
        "mitre_ics": "T0815",
        "impact": "Operators cannot see or control the process, enabling covert manipulation",
        "examples": ["BlackEnergy: locked operators out of workstations while opening breakers", "CrashOverride: disabled serial-to-Ethernet converters to prevent remote recovery"],
        "detection": "Communication monitoring between SCADA and RTUs, heartbeat monitoring",
        "prevention": "Redundant communication paths, out-of-band monitoring, manual override capability",
    },
]

# ============================================================================
# NOTABLE ICS INCIDENTS
# ============================================================================
ICS_INCIDENTS = [
    {
        "name": "Stuxnet (2010)",
        "attribution": "USA/Israel (Operation Olympic Games)",
        "target": "Iran Natanz uranium enrichment facility",
        "description": "First known cyber weapon targeting industrial control systems. Modified Siemens S7-315/417 PLC code to vary centrifuge motor speeds (800-1200 Hz) while reporting normal values to operators. Spread via USB, exploited 4 Windows zero-days.",
        "impact": "Destroyed ~1,000 of 5,000 IR-1 centrifuges, delayed Iranian nuclear program by 1-2 years",
        "ttps": ["Zero-day exploitation (MS08-067, MS10-046, MS10-061, MS10-073)", "USB propagation", "PLC rootkit", "Man-in-the-middle between PLC and HMI"],
        "lessons": ["Air gaps can be bridged via USB/supply chain", "PLC integrity monitoring is essential", "Nation-states will invest years in ICS attacks"],
    },
    {
        "name": "BlackEnergy / Ukraine Power Grid (2015)",
        "attribution": "Russia (Sandworm / GRU Unit 74455)",
        "target": "Three Ukrainian power distribution companies",
        "description": "First confirmed cyberattack to cause a power outage. Attackers used spearphishing to compromise corporate networks, pivoted to SCADA systems, opened circuit breakers remotely, deployed KillDisk wiper, and called the power company's call center to tie up phone lines.",
        "impact": "225,000 customers lost power for 1-6 hours in December winter",
        "ttps": ["Spearphishing with BlackEnergy malware", "VPN credential theft for SCADA access", "HMI remote control to open breakers", "KillDisk to delay recovery", "Call center flooding"],
        "lessons": ["IT-OT convergence creates attack paths", "Remote access to SCADA must be heavily protected", "Manual recovery capability is essential"],
    },
    {
        "name": "CrashOverride / Industroyer (2016)",
        "attribution": "Russia (Sandworm)",
        "target": "Ukrainian power transmission station (Ukrenergo)",
        "description": "Purpose-built ICS malware framework with modules for IEC 101, IEC 104, IEC 61850, and OPC DA. Automatically opened circuit breakers and disabled serial-to-Ethernet converters to prevent remote recovery.",
        "impact": "Power outage in Kyiv for approximately 1 hour",
        "ttps": ["Custom ICS protocol implementations", "Automated attack sequence", "Wiper component for recovery prevention", "Targeted serial communication disruption"],
        "lessons": ["Attackers are building reusable ICS attack frameworks", "Protocol-native attacks are hard to detect", "Recovery procedures must account for communication loss"],
    },
    {
        "name": "TRITON / TRISIS (2017)",
        "attribution": "Russia (TEMP.Veles / Central Scientific Research Institute of Chemistry and Mechanics)",
        "target": "Saudi Arabian petrochemical plant (Schneider Triconex SIS)",
        "description": "First malware to target Safety Instrumented Systems. Attempted to reprogram Triconex controllers to disable safety shutdowns, which could have enabled a physical explosion. The attack was discovered only because a bug in the malware caused the SIS to trip (safe shutdown).",
        "impact": "Plant shutdown (safe failure). If successful, could have caused explosion and loss of life.",
        "ttps": ["Engineering workstation compromise", "Custom Triconex protocol implementation", "SIS program modification", "Attempted to maintain persistent access to safety controller"],
        "lessons": ["Safety systems are now targets", "Air-gap or heavily segment SIS from DCS", "Physical key switches on SIS prevent remote reprogramming"],
    },
    {
        "name": "Pipedream / Incontroller (2022)",
        "attribution": "Unknown (possibly Russia)",
        "target": "US energy sector (discovered before deployment)",
        "description": "Modular ICS attack framework targeting Schneider Electric and OMRON PLCs, and OPC UA servers. Capable of scanning, reconnaissance, and manipulation of ICS devices. Discovered by Dragos and government partners before use.",
        "impact": "None (intercepted). Had capability to disrupt liquefied natural gas facilities and electric power.",
        "ttps": ["Modbus, S7comm, OPC UA protocol support", "PLC program upload/download", "Credential brute-forcing", "OPC UA exploitation"],
        "lessons": ["ICS attack toolkits are becoming commoditized", "Proactive threat hunting in OT networks is essential", "Cross-sector threat intelligence sharing works"],
    },
    {
        "name": "Colonial Pipeline (2021)",
        "attribution": "DarkSide ransomware gang (Russia-based)",
        "target": "Colonial Pipeline Company (US East Coast fuel pipeline)",
        "description": "Ransomware attack on IT systems led to precautionary shutdown of OT systems (the pipeline). Attackers gained access via a compromised VPN password (no MFA). The company paid $4.4M ransom (most recovered by FBI).",
        "impact": "6-day pipeline shutdown, fuel shortages across US East Coast, state of emergency declared",
        "ttps": ["VPN credential compromise (no MFA)", "DarkSide ransomware deployment", "Double extortion (encrypt + data leak threat)"],
        "lessons": ["IT/OT convergence means IT ransomware can stop OT operations", "MFA on all remote access is non-negotiable", "Incident response plans must cover OT shutdown decisions"],
    },
]

# ============================================================================
# ICS DEFENSE FRAMEWORKS
# ============================================================================
ICS_DEFENSE = {
    "purdue_model": {
        "name": "Purdue Enterprise Reference Architecture",
        "description": "Hierarchical model for segmenting IT and OT networks into zones with controlled data flows.",
        "levels": [
            {"level": 0, "name": "Physical Process", "description": "Actual physical equipment: pumps, motors, valves, sensors", "examples": "Pumps, valves, actuators, sensors"},
            {"level": 1, "name": "Basic Control", "description": "PLCs, RTUs, IEDs that directly control Level 0 equipment", "examples": "Siemens S7, Allen-Bradley, ABB AC800M"},
            {"level": 2, "name": "Area Supervisory", "description": "HMIs, SCADA servers, engineering workstations", "examples": "Wonderware, FactoryTalk, WinCC"},
            {"level": 3, "name": "Site Operations", "description": "Production management, data historian, patch management", "examples": "OSIsoft PI, batch management, MES"},
            {"level": 3.5, "name": "ICS DMZ", "description": "Demilitarized zone between IT and OT", "examples": "Data diodes, jump servers, file transfer"},
            {"level": 4, "name": "Enterprise IT", "description": "Business systems: ERP, email, file servers", "examples": "SAP, Exchange, Active Directory"},
            {"level": 5, "name": "Enterprise DMZ/Internet", "description": "Internet-facing services", "examples": "Web servers, VPN, cloud services"},
        ],
        "key_rules": [
            "No direct communication between Level 4 (IT) and Level 2 (OT supervisory)",
            "All IT-OT traffic must pass through Level 3.5 (ICS DMZ)",
            "Data diodes for unidirectional flow where possible",
            "Separate Active Directory for OT (or none)",
            "Jump servers in DMZ for remote OT access",
        ],
    },
    "nist_800_82": {
        "name": "NIST SP 800-82 Rev. 3 (Guide to OT Security)",
        "key_recommendations": [
            "Develop and maintain an OT-specific security plan",
            "Implement network architecture with clearly defined boundaries",
            "Apply defense-in-depth strategies",
            "Restrict physical and logical access to OT networks",
            "Manage OT vulnerabilities and patches separately from IT",
            "Implement continuous monitoring for OT environments",
            "Develop OT-specific incident response procedures",
            "Train workforce on OT security awareness",
            "Conduct regular risk assessments of OT systems",
        ],
    },
    "iec_62443": {
        "name": "IEC 62443 (Industrial Automation and Control Systems Security)",
        "security_levels": [
            {"sl": 0, "description": "No specific requirements", "threat": "None"},
            {"sl": 1, "description": "Protection against casual or coincidental violation", "threat": "Unintentional errors"},
            {"sl": 2, "description": "Protection against intentional violation using simple means", "threat": "Script kiddies, disgruntled employees"},
            {"sl": 3, "description": "Protection against sophisticated attack with moderate resources", "threat": "Hacktivists, organized crime"},
            {"sl": 4, "description": "Protection against state-sponsored attack with extensive resources", "threat": "Nation-states, APTs"},
        ],
    },
}


class ICSSecurity:
    name = "ICS/SCADA/OT Security Operations"
    description = "Industrial control system protocol analysis, attacks, and defense"
    category = "network"
    mitre = ["T0831", "T0843", "T0823", "T0880"]

    def __init__(self, target=None, options=None):
        self.target = target
        self.options = options or {}
        self.findings = []
        self.actions = []

    def run(self, confirm_fn=None):
        action = self.options.get("action", "protocols")
        if action == "protocols":
            self._show_protocols()
        elif action == "attacks":
            self._show_attacks()
        elif action == "incidents":
            self._show_incidents()
        elif action == "defense":
            self._show_defense()

    def _show_protocols(self):
        print(f"\n{'='*60}")
        print("ICS/SCADA PROTOCOL REFERENCE")
        print(f"{'='*60}\n")
        for proto in ICS_PROTOCOLS:
            print(f"  {proto['name']} (Port {proto['port']})")
            print(f"  {proto['description']}")
            if "function_codes" in proto:
                print("  Function Codes:")
                for fc in proto["function_codes"]:
                    risk = f" [{fc['risk']}]" if "risk" in fc else ""
                    print(f"    {fc['code']:>3}: {fc['name']} - {fc['description']}{risk}")
            print(f"  Attack vectors: {', '.join(proto['attacks'][:3])}")
            print(f"  Tools: {', '.join(proto.get('tools', ['N/A']))}")
            print()

    def _show_attacks(self):
        print(f"\n{'='*60}")
        print("ICS ATTACK TECHNIQUES")
        print(f"{'='*60}\n")
        for attack in ICS_ATTACKS:
            print(f"  {attack['name']} (ICS ATT&CK: {attack['mitre_ics']})")
            print(f"  {attack['description']}")
            print(f"  Impact: {attack['impact']}")
            if attack.get("examples"):
                print(f"  Example: {attack['examples'][0]}")
            print(f"  Detection: {attack['detection']}")
            print(f"  Prevention: {attack['prevention']}")
            print()

    def _show_incidents(self):
        print(f"\n{'='*60}")
        print("NOTABLE ICS CYBER INCIDENTS")
        print(f"{'='*60}\n")
        for incident in ICS_INCIDENTS:
            print(f"  {incident['name']}")
            print(f"  Attribution: {incident['attribution']}")
            print(f"  Target: {incident['target']}")
            print(f"  {incident['description']}")
            print(f"  Impact: {incident['impact']}")
            print(f"  TTPs: {', '.join(incident['ttps'][:3])}")
            print(f"  Lessons: {incident['lessons'][0]}")
            print()

    def _show_defense(self):
        print(f"\n{'='*60}")
        print("ICS DEFENSE FRAMEWORKS")
        print(f"{'='*60}\n")
        purdue = ICS_DEFENSE["purdue_model"]
        print(f"  {purdue['name']}")
        for level in purdue["levels"]:
            print(f"    Level {level['level']}: {level['name']} - {level['description']}")
        print()
        print("  Key Rules:")
        for rule in purdue["key_rules"]:
            print(f"    - {rule}")

    def get_findings(self):
        return self.findings


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="AEGIS ICS/SCADA Security")
    parser.add_argument("--action", choices=["protocols", "attacks", "incidents", "defense"], default="protocols")
    args = parser.parse_args()
    mod = ICSSecurity(options={"action": args.action})
    mod.run()
