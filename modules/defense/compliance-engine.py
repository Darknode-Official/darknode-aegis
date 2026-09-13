#!/usr/bin/env python3
"""Multi-framework compliance assessment engine"""
import json, os, sys
from datetime import datetime

# ============================================================================
# COMPLIANCE FRAMEWORKS
# ============================================================================
FRAMEWORKS = {
    "pci_dss_4": {
        "name": "PCI DSS v4.0",
        "description": "Payment Card Industry Data Security Standard",
        "requirements": [
            {"id": "1.1", "title": "Install and maintain network security controls", "desc": "Firewall and router configurations to protect cardholder data", "evidence": "Network diagrams, firewall rules, change management records", "test": "Review firewall configurations and network segmentation"},
            {"id": "1.2", "title": "Network security controls configured and maintained", "desc": "Restrict connections between untrusted networks and CDE", "evidence": "Firewall rule sets, DMZ architecture documentation", "test": "Verify inbound/outbound traffic rules, default deny"},
            {"id": "1.3", "title": "Network access to and from CDE is restricted", "desc": "Restrict direct public access to cardholder data environment", "evidence": "Network topology, ACL configurations", "test": "Attempt access from public network to CDE"},
            {"id": "2.1", "title": "Secure configurations applied to all components", "desc": "Change vendor defaults, remove unnecessary services", "evidence": "Hardening standards, configuration audit reports", "test": "Check for default passwords, unnecessary services"},
            {"id": "2.2", "title": "System components configured securely", "desc": "Develop configuration standards for all system components", "evidence": "CIS benchmark compliance reports", "test": "Run CIS benchmark scan against systems in CDE"},
            {"id": "3.1", "title": "Account data storage is minimized", "desc": "Limit storage amount and retention time", "evidence": "Data retention policy, storage inventory", "test": "Search for stored PAN data beyond retention period"},
            {"id": "3.2", "title": "Account data storage has strong cryptography", "desc": "Render PAN unreadable using strong cryptography", "evidence": "Encryption implementation documentation", "test": "Verify PAN is encrypted at rest, check key management"},
            {"id": "4.1", "title": "Strong cryptography protects CHD during transmission", "desc": "Use strong cryptography for PAN transmission over open networks", "evidence": "TLS configuration, cipher suite documentation", "test": "Check TLS version, cipher suites, certificate validity"},
            {"id": "5.1", "title": "Malicious software is prevented or detected", "desc": "Deploy anti-malware on all systems commonly affected", "evidence": "AV deployment records, scan logs", "test": "Verify AV is installed, updated, and actively scanning"},
            {"id": "6.1", "title": "Secure development processes", "desc": "Establish secure SDLC based on industry standards", "evidence": "SDLC documentation, code review records", "test": "Review SDLC policy, check for security in CI/CD"},
            {"id": "6.2", "title": "Custom software developed securely", "desc": "Bespoke and custom software developed securely", "evidence": "Code review results, SAST/DAST reports", "test": "Review recent code changes for OWASP Top 10"},
            {"id": "7.1", "title": "Access to system components restricted", "desc": "Limit access to cardholder data by business need to know", "evidence": "Access control lists, role definitions", "test": "Review user access levels, verify least privilege"},
            {"id": "8.1", "title": "User identification and authentication managed", "desc": "Ensure proper user identification and authentication", "evidence": "Authentication policy, MFA deployment status", "test": "Check MFA enforcement, password policy compliance"},
            {"id": "8.3", "title": "Strong authentication for users and admins", "desc": "MFA for all access into the CDE", "evidence": "MFA configuration, access logs", "test": "Verify MFA is required for all CDE access"},
            {"id": "9.1", "title": "Physical access to CDE restricted", "desc": "Restrict physical access to cardholder data", "evidence": "Physical access control logs, badge records", "test": "Review physical access controls, visitor logs"},
            {"id": "10.1", "title": "Log and monitor all access to system components", "desc": "Audit trails for all access to cardholder data", "evidence": "Log management policy, SIEM configuration", "test": "Verify logging is enabled and retained for 12 months"},
            {"id": "10.2", "title": "Audit logs support detection of anomalies", "desc": "Log actions like failed logins, privilege changes, data access", "evidence": "Log review procedures, alert configurations", "test": "Verify required events are logged and alerted on"},
            {"id": "11.1", "title": "Regular security testing conducted", "desc": "Regularly test security of systems and networks", "evidence": "Vulnerability scan reports, pentest reports", "test": "Review quarterly ASV scans and annual pentest"},
            {"id": "11.3", "title": "External and internal vulnerabilities addressed", "desc": "Vulnerabilities identified and addressed promptly", "evidence": "Vulnerability management records", "test": "Verify critical vulns patched within 30 days"},
            {"id": "12.1", "title": "Information security policy maintained", "desc": "Establish, publish, maintain an information security policy", "evidence": "Security policy document, annual review records", "test": "Verify policy exists, is current, and distributed"},
        ]
    },
    "hipaa": {
        "name": "HIPAA",
        "description": "Health Insurance Portability and Accountability Act",
        "requirements": [
            {"id": "164.308(a)(1)", "title": "Security Management Process", "desc": "Implement policies to prevent, detect, contain security violations", "evidence": "Risk analysis report, risk management plan", "test": "Review risk assessment, verify it covers all ePHI"},
            {"id": "164.308(a)(2)", "title": "Assigned Security Responsibility", "desc": "Identify the security official responsible for HIPAA compliance", "evidence": "Security officer appointment documentation", "test": "Verify security officer is designated and active"},
            {"id": "164.308(a)(3)", "title": "Workforce Security", "desc": "Ensure workforce members have appropriate access to ePHI", "evidence": "Access authorization procedures, termination procedures", "test": "Review access provisioning and de-provisioning"},
            {"id": "164.308(a)(4)", "title": "Information Access Management", "desc": "Implement policies for authorizing access to ePHI", "evidence": "Access control policy, access review logs", "test": "Verify least privilege and regular access reviews"},
            {"id": "164.308(a)(5)", "title": "Security Awareness Training", "desc": "Implement security awareness and training program", "evidence": "Training records, materials, completion rates", "test": "Verify annual training completion for all workforce"},
            {"id": "164.308(a)(6)", "title": "Security Incident Procedures", "desc": "Implement policies for responding to security incidents", "evidence": "Incident response plan, incident logs", "test": "Review IR plan, test with tabletop exercise"},
            {"id": "164.308(a)(7)", "title": "Contingency Plan", "desc": "Establish policies for responding to system emergencies", "evidence": "Contingency plan, backup procedures, DR tests", "test": "Verify backup and recovery procedures are tested"},
            {"id": "164.308(a)(8)", "title": "Evaluation", "desc": "Perform periodic technical and nontechnical evaluation", "evidence": "Evaluation reports, gap analysis", "test": "Verify regular compliance evaluations are conducted"},
            {"id": "164.310(a)(1)", "title": "Facility Access Controls", "desc": "Implement policies to limit physical access to ePHI systems", "evidence": "Physical security policy, access logs", "test": "Review physical access controls for ePHI locations"},
            {"id": "164.310(b)", "title": "Workstation Use", "desc": "Implement policies for proper workstation use", "evidence": "Workstation use policy, clean desk policy", "test": "Verify workstation security configurations"},
            {"id": "164.310(c)", "title": "Workstation Security", "desc": "Implement physical safeguards for workstations", "evidence": "Workstation security standards", "test": "Check screen locks, encryption, physical placement"},
            {"id": "164.310(d)", "title": "Device and Media Controls", "desc": "Implement policies for media movement and disposal", "evidence": "Media disposal records, encryption policy", "test": "Verify secure disposal and data wiping procedures"},
            {"id": "164.312(a)(1)", "title": "Access Control", "desc": "Implement technical policies for electronic access to ePHI", "evidence": "Access control configuration, unique user IDs", "test": "Verify unique IDs, emergency access, auto-logoff"},
            {"id": "164.312(b)", "title": "Audit Controls", "desc": "Implement mechanisms to record and examine ePHI access", "evidence": "Audit logging configuration, log review procedures", "test": "Verify audit logging for all ePHI systems"},
            {"id": "164.312(c)(1)", "title": "Integrity Controls", "desc": "Implement policies to protect ePHI from improper alteration", "evidence": "Integrity monitoring, checksums, digital signatures", "test": "Verify integrity controls on ePHI at rest and transit"},
            {"id": "164.312(d)", "title": "Person or Entity Authentication", "desc": "Implement procedures to verify identity of those seeking ePHI", "evidence": "Authentication configuration, MFA status", "test": "Verify authentication mechanisms (MFA, strong passwords)"},
            {"id": "164.312(e)(1)", "title": "Transmission Security", "desc": "Implement technical measures to guard against unauthorized access during transmission", "evidence": "TLS/encryption configuration for ePHI in transit", "test": "Verify encryption of ePHI during transmission"},
        ]
    },
    "soc2": {
        "name": "SOC 2 Type II",
        "description": "Service Organization Control 2 Trust Services Criteria",
        "requirements": [
            {"id": "CC1.1", "title": "COSO Principle 1 - Integrity and Ethical Values", "desc": "Organization demonstrates commitment to integrity and ethical values", "evidence": "Code of conduct, ethics policy", "test": "Review code of conduct, verify distribution and acknowledgment"},
            {"id": "CC2.1", "title": "Information and Communication", "desc": "Management uses relevant, quality information", "evidence": "Communication policies, reporting procedures", "test": "Review internal communication channels for security"},
            {"id": "CC3.1", "title": "Risk Assessment", "desc": "Entity specifies objectives and identifies risks", "evidence": "Risk assessment report, risk register", "test": "Review risk assessment methodology and currency"},
            {"id": "CC4.1", "title": "Monitoring Activities", "desc": "Entity selects and performs ongoing monitoring", "evidence": "Monitoring procedures, audit reports", "test": "Verify continuous monitoring capabilities"},
            {"id": "CC5.1", "title": "Logical and Physical Access", "desc": "Entity controls logical and physical access", "evidence": "Access control policy, access reviews", "test": "Review access provisioning, verify periodic access reviews"},
            {"id": "CC5.2", "title": "New Users and Auth", "desc": "New user registration and authentication mechanisms", "evidence": "Provisioning procedures, authentication policy", "test": "Test user onboarding flow, verify MFA"},
            {"id": "CC5.3", "title": "Access Removal", "desc": "User access removed when no longer needed", "evidence": "Termination procedures, access removal logs", "test": "Verify timely access removal for terminated users"},
            {"id": "CC6.1", "title": "System Operations", "desc": "Entity manages system changes through change management", "evidence": "Change management policy, change logs", "test": "Review change management process and approval records"},
            {"id": "CC6.2", "title": "Change Management", "desc": "Infrastructure and software changes authorized and tested", "evidence": "Change tickets, test results", "test": "Verify changes go through proper approval and testing"},
            {"id": "CC6.3", "title": "Security Software", "desc": "Entity deploys security software (AV, firewall, IDS)", "evidence": "Security tool inventory, deployment records", "test": "Verify security tools are deployed and updated"},
            {"id": "CC7.1", "title": "System Monitoring", "desc": "Entity monitors system components for anomalies", "evidence": "SIEM configuration, alert procedures", "test": "Review monitoring coverage and alert response"},
            {"id": "CC7.2", "title": "Incident Response", "desc": "Entity detects and responds to security incidents", "evidence": "Incident response plan, incident logs", "test": "Review IR plan, verify recent incident handling"},
            {"id": "CC8.1", "title": "Vulnerability Management", "desc": "Entity identifies and addresses vulnerabilities", "evidence": "Vulnerability scan reports, remediation records", "test": "Review scan frequency, remediation SLAs"},
            {"id": "CC9.1", "title": "Business Continuity", "desc": "Entity implements business continuity and disaster recovery", "evidence": "BCP/DR plans, test results", "test": "Verify DR testing frequency and results"},
            {"id": "A1.1", "title": "Availability Commitments", "desc": "Entity maintains availability commitments", "evidence": "SLA documentation, uptime reports", "test": "Review SLAs, verify uptime monitoring"},
            {"id": "C1.1", "title": "Confidentiality Classification", "desc": "Entity identifies and classifies confidential information", "evidence": "Data classification policy, labeled assets", "test": "Verify data classification scheme and labeling"},
            {"id": "PI1.1", "title": "Processing Integrity", "desc": "Entity processes data completely, accurately, timely", "evidence": "Processing validation procedures, error logs", "test": "Review data processing controls and validation"},
            {"id": "P1.1", "title": "Privacy Notice", "desc": "Entity provides notice about data practices", "evidence": "Privacy policy, consent mechanisms", "test": "Review privacy notices for completeness"},
        ]
    },
    "iso27001": {
        "name": "ISO 27001:2022",
        "description": "Information Security Management System",
        "requirements": [
            {"id": "A.5.1", "title": "Policies for information security", "desc": "Set of policies for information security defined and approved", "evidence": "Information security policy, management approval", "test": "Verify policy exists, is current, and approved by management"},
            {"id": "A.5.7", "title": "Threat intelligence", "desc": "Information about information security threats collected and analyzed", "evidence": "Threat intelligence feeds, analysis reports", "test": "Verify threat intelligence collection and analysis process"},
            {"id": "A.6.1", "title": "Screening", "desc": "Background verification checks on all candidates", "evidence": "Screening policy, background check records", "test": "Verify background checks for new hires and contractors"},
            {"id": "A.6.3", "title": "Information security awareness and training", "desc": "Personnel receive appropriate awareness education and training", "evidence": "Training program, attendance records", "test": "Verify annual security training completion"},
            {"id": "A.7.1", "title": "Physical security perimeters", "desc": "Security perimeters to protect areas containing information", "evidence": "Physical security plan, access control systems", "test": "Review physical access controls and monitoring"},
            {"id": "A.8.1", "title": "User endpoint devices", "desc": "Information stored on, processed by, or accessible via endpoint devices protected", "evidence": "Endpoint security policy, MDM configuration", "test": "Verify endpoint encryption, AV, patch management"},
            {"id": "A.8.3", "title": "Information access restriction", "desc": "Access to information restricted in accordance with access control policy", "evidence": "Access control lists, RBAC configuration", "test": "Verify role-based access and least privilege"},
            {"id": "A.8.5", "title": "Secure authentication", "desc": "Secure authentication technologies and procedures implemented", "evidence": "Authentication policy, MFA deployment", "test": "Verify MFA, password complexity, account lockout"},
            {"id": "A.8.9", "title": "Configuration management", "desc": "Configurations of hardware, software, services, and networks established and managed", "evidence": "Configuration baselines, hardening guides", "test": "Verify CIS benchmarks or equivalent applied"},
            {"id": "A.8.12", "title": "Data leakage prevention", "desc": "Data leakage prevention measures applied", "evidence": "DLP policy, DLP tool configuration", "test": "Verify DLP coverage for sensitive data channels"},
            {"id": "A.8.15", "title": "Logging", "desc": "Logs that record activities, exceptions, faults, and other relevant events produced and stored", "evidence": "Logging policy, SIEM configuration", "test": "Verify centralized logging and log retention"},
            {"id": "A.8.16", "title": "Monitoring activities", "desc": "Networks, systems, and applications monitored for anomalous behavior", "evidence": "Monitoring procedures, SIEM alerts", "test": "Verify monitoring coverage and alert response times"},
            {"id": "A.8.20", "title": "Networks security", "desc": "Networks and network devices secured, managed, and controlled", "evidence": "Network security policy, firewall rules", "test": "Review network segmentation and firewall rules"},
            {"id": "A.8.23", "title": "Web filtering", "desc": "Access to external websites managed to reduce exposure to malicious content", "evidence": "Web filter policy, proxy configuration", "test": "Verify web filtering/proxy is configured and monitored"},
            {"id": "A.8.24", "title": "Use of cryptography", "desc": "Rules for effective use of cryptography including key management defined", "evidence": "Cryptographic policy, key management procedures", "test": "Verify encryption standards and key management"},
            {"id": "A.8.25", "title": "Secure development lifecycle", "desc": "Rules for secure development of software and systems established", "evidence": "SDLC policy, code review records", "test": "Verify security is integrated into SDLC"},
            {"id": "A.8.28", "title": "Secure coding", "desc": "Secure coding principles applied to software development", "evidence": "Coding standards, SAST/DAST results", "test": "Review secure coding guidelines and scan results"},
            {"id": "A.8.32", "title": "Change management", "desc": "Changes to information processing facilities and systems subject to change management", "evidence": "Change management policy, change tickets", "test": "Review change management process and approvals"},
            {"id": "A.8.34", "title": "Protection of information during audit testing", "desc": "Audit tests planned and agreed to minimize impact on operations", "evidence": "Audit schedule, risk assessment for audits", "test": "Verify audit planning minimizes operational risk"},
        ]
    },
    "gdpr": {
        "name": "GDPR",
        "description": "General Data Protection Regulation",
        "requirements": [
            {"id": "Art.5", "title": "Principles of processing", "desc": "Lawfulness, fairness, transparency, purpose limitation, data minimization, accuracy, storage limitation, integrity", "evidence": "Privacy policy, processing register, data mapping", "test": "Verify data processing aligns with stated purposes"},
            {"id": "Art.6", "title": "Lawfulness of processing", "desc": "At least one legal basis must apply (consent, contract, legal obligation, vital interest, public task, legitimate interest)", "evidence": "Legal basis documentation per processing activity", "test": "Verify legal basis recorded for each data processing activity"},
            {"id": "Art.7", "title": "Conditions for consent", "desc": "Consent must be freely given, specific, informed, unambiguous, and withdrawable", "evidence": "Consent forms, opt-in mechanisms, withdrawal process", "test": "Test consent collection and withdrawal mechanisms"},
            {"id": "Art.12-14", "title": "Transparency and information", "desc": "Provide clear privacy information at time of data collection", "evidence": "Privacy notices, cookie policies", "test": "Review privacy notices for completeness (13 required elements)"},
            {"id": "Art.15-20", "title": "Data subject rights", "desc": "Right of access, rectification, erasure, restriction, portability, objection", "evidence": "DSR procedures, response records", "test": "Test DSR handling process and response times (30 days)"},
            {"id": "Art.25", "title": "Data protection by design and default", "desc": "Implement technical measures and default to minimal data processing", "evidence": "DPIA records, privacy engineering documentation", "test": "Verify privacy is embedded in system design"},
            {"id": "Art.28", "title": "Processor obligations", "desc": "Written contracts with processors, audit rights, sub-processor notification", "evidence": "Processor agreements, vendor assessments", "test": "Review data processing agreements with all vendors"},
            {"id": "Art.30", "title": "Records of processing activities", "desc": "Maintain a register of processing activities (ROPA)", "evidence": "ROPA document", "test": "Verify ROPA is complete and current"},
            {"id": "Art.32", "title": "Security of processing", "desc": "Implement appropriate technical and organizational security measures", "evidence": "Security measures documentation, risk assessment", "test": "Review security controls against risk level"},
            {"id": "Art.33", "title": "Breach notification to authority", "desc": "Notify supervisory authority within 72 hours of awareness of personal data breach", "evidence": "Breach notification procedures, incident response plan", "test": "Verify 72-hour breach notification process"},
            {"id": "Art.35", "title": "Data protection impact assessment", "desc": "DPIA required for high-risk processing activities", "evidence": "DPIA records, risk mitigation plans", "test": "Verify DPIAs conducted for high-risk processing"},
            {"id": "Art.37", "title": "Data Protection Officer", "desc": "Designate DPO when required (public authority, large-scale monitoring, special categories)", "evidence": "DPO appointment, contact details published", "test": "Verify DPO designation and independence"},
        ]
    },
    "nist_800_53": {
        "name": "NIST 800-53 Rev 5",
        "description": "Security and Privacy Controls for Information Systems",
        "requirements": [
            {"id": "AC-1", "title": "Access Control Policy", "desc": "Develop, document, and disseminate access control policy", "evidence": "Access control policy document", "test": "Verify policy exists and is reviewed annually"},
            {"id": "AC-2", "title": "Account Management", "desc": "Manage system accounts including establishing, activating, modifying, disabling, removing", "evidence": "Account management procedures, access reviews", "test": "Review account provisioning and periodic reviews"},
            {"id": "AC-3", "title": "Access Enforcement", "desc": "Enforce approved authorizations for logical access", "evidence": "RBAC configuration, access control lists", "test": "Verify access enforcement mechanisms"},
            {"id": "AC-6", "title": "Least Privilege", "desc": "Employ the principle of least privilege", "evidence": "Privilege analysis, admin account inventory", "test": "Review admin accounts, verify minimal privileges"},
            {"id": "AC-17", "title": "Remote Access", "desc": "Establish usage restrictions for remote access", "evidence": "Remote access policy, VPN configuration", "test": "Verify remote access requires MFA and encryption"},
            {"id": "AT-2", "title": "Security Awareness Training", "desc": "Provide security awareness training to system users", "evidence": "Training program, completion records", "test": "Verify annual training completion"},
            {"id": "AU-2", "title": "Audit Events", "desc": "Identify events that the system is capable of auditing", "evidence": "Audit event list, logging configuration", "test": "Verify required events are being audited"},
            {"id": "AU-6", "title": "Audit Review and Analysis", "desc": "Review and analyze system audit records for indications of inappropriate activity", "evidence": "Audit review procedures, SIEM configuration", "test": "Verify regular audit log review and analysis"},
            {"id": "CA-2", "title": "Security Assessments", "desc": "Assess security controls periodically", "evidence": "Assessment plans, assessment results", "test": "Verify periodic security control assessments"},
            {"id": "CM-6", "title": "Configuration Settings", "desc": "Establish and document configuration settings", "evidence": "Configuration baselines, CIS benchmarks", "test": "Verify systems configured to baseline standards"},
            {"id": "IA-2", "title": "Identification and Authentication", "desc": "Uniquely identify and authenticate organizational users", "evidence": "Authentication configuration, MFA status", "test": "Verify unique IDs and MFA for privileged access"},
            {"id": "IA-5", "title": "Authenticator Management", "desc": "Manage system authenticators (passwords, tokens, certificates)", "evidence": "Password policy, authenticator lifecycle", "test": "Verify password complexity, rotation, and protection"},
            {"id": "IR-1", "title": "Incident Response Policy", "desc": "Develop and document incident response policy", "evidence": "IR policy, IR plan, procedures", "test": "Verify IR plan is current and tested"},
            {"id": "IR-4", "title": "Incident Handling", "desc": "Implement incident handling capability", "evidence": "Incident records, IR team roster", "test": "Review recent incidents and response effectiveness"},
            {"id": "RA-5", "title": "Vulnerability Monitoring and Scanning", "desc": "Monitor and scan for vulnerabilities", "evidence": "Vulnerability scan reports, remediation records", "test": "Verify scanning frequency and remediation SLAs"},
            {"id": "SA-11", "title": "Developer Security Testing", "desc": "Require developers to create and implement security test plan", "evidence": "Security test plans, SAST/DAST results", "test": "Verify security testing in development lifecycle"},
            {"id": "SC-7", "title": "Boundary Protection", "desc": "Monitor and control communications at external boundaries", "evidence": "Firewall configurations, network diagrams", "test": "Review boundary protection and network segmentation"},
            {"id": "SC-8", "title": "Transmission Confidentiality", "desc": "Protect confidentiality of transmitted information", "evidence": "Encryption configuration, TLS certificates", "test": "Verify encryption for data in transit"},
            {"id": "SC-28", "title": "Protection of Information at Rest", "desc": "Protect confidentiality of information at rest", "evidence": "Encryption at rest configuration", "test": "Verify encryption for data at rest"},
            {"id": "SI-2", "title": "Flaw Remediation", "desc": "Identify, report, and correct system flaws", "evidence": "Patch management records, vulnerability reports", "test": "Verify patching cadence and critical patch SLA"},
        ]
    },
}

# ============================================================================
# CROSS-FRAMEWORK MAPPING
# ============================================================================
CROSS_MAPPING = [
    {"control": "Access Control", "pci": "7.1", "hipaa": "164.312(a)(1)", "soc2": "CC5.1", "iso": "A.8.3", "nist": "AC-3", "gdpr": "Art.32"},
    {"control": "Authentication (MFA)", "pci": "8.3", "hipaa": "164.312(d)", "soc2": "CC5.2", "iso": "A.8.5", "nist": "IA-2", "gdpr": "Art.32"},
    {"control": "Encryption at Rest", "pci": "3.2", "hipaa": "164.312(a)(1)", "soc2": "C1.1", "iso": "A.8.24", "nist": "SC-28", "gdpr": "Art.32"},
    {"control": "Encryption in Transit", "pci": "4.1", "hipaa": "164.312(e)(1)", "soc2": "C1.1", "iso": "A.8.24", "nist": "SC-8", "gdpr": "Art.32"},
    {"control": "Logging and Monitoring", "pci": "10.1", "hipaa": "164.312(b)", "soc2": "CC7.1", "iso": "A.8.15", "nist": "AU-2", "gdpr": "Art.32"},
    {"control": "Incident Response", "pci": "12.10", "hipaa": "164.308(a)(6)", "soc2": "CC7.2", "iso": "A.5.24", "nist": "IR-1", "gdpr": "Art.33"},
    {"control": "Vulnerability Management", "pci": "11.3", "hipaa": "164.308(a)(1)", "soc2": "CC8.1", "iso": "A.8.8", "nist": "RA-5", "gdpr": "Art.32"},
    {"control": "Security Training", "pci": "12.6", "hipaa": "164.308(a)(5)", "soc2": "CC1.4", "iso": "A.6.3", "nist": "AT-2", "gdpr": "Art.39"},
    {"control": "Change Management", "pci": "6.5", "hipaa": "164.308(a)(8)", "soc2": "CC6.2", "iso": "A.8.32", "nist": "CM-3", "gdpr": "-"},
    {"control": "Data Classification", "pci": "3.1", "hipaa": "164.312(c)(1)", "soc2": "C1.1", "iso": "A.5.12", "nist": "RA-2", "gdpr": "Art.30"},
    {"control": "Backup and Recovery", "pci": "9.5", "hipaa": "164.308(a)(7)", "soc2": "CC9.1", "iso": "A.8.13", "nist": "CP-9", "gdpr": "Art.32"},
    {"control": "Physical Security", "pci": "9.1", "hipaa": "164.310(a)(1)", "soc2": "CC5.1", "iso": "A.7.1", "nist": "PE-2", "gdpr": "Art.32"},
    {"control": "Network Segmentation", "pci": "1.3", "hipaa": "-", "soc2": "CC6.3", "iso": "A.8.20", "nist": "SC-7", "gdpr": "Art.32"},
    {"control": "Secure Development", "pci": "6.2", "hipaa": "-", "soc2": "CC6.1", "iso": "A.8.25", "nist": "SA-11", "gdpr": "Art.25"},
    {"control": "Breach Notification", "pci": "12.10", "hipaa": "164.308(a)(6)", "soc2": "CC7.2", "iso": "A.5.26", "nist": "IR-6", "gdpr": "Art.33"},
]


class ComplianceEngine:
    name = "Compliance Assessment Engine"
    description = "Multi-framework compliance assessment and gap analysis"
    category = "defense"
    mitre = []

    def __init__(self, target=None, options=None):
        self.options = options or {}
        self.findings = []
        self.assessments = {}

    def run(self, confirm_fn=None):
        print("\n=== AEGIS Compliance Engine ===\n")
        print("Frameworks available:")
        for key, fw in FRAMEWORKS.items():
            print("  " + key + " - " + fw["name"] + " (" + str(len(fw["requirements"])) + " controls)")
        print("\nModes:")
        print("  1. Assess a framework")
        print("  2. Cross-framework mapping")
        print("  3. Gap analysis")
        print("  4. Generate compliance report")
        print()
        mode = input("Select mode (1-4): ").strip()
        if mode == "1": self._assess_framework()
        elif mode == "2": self._cross_mapping()
        elif mode == "3": self._gap_analysis()
        elif mode == "4": self._generate_report()

    def _assess_framework(self):
        fw_key = input("\nFramework key (e.g. pci_dss_4, hipaa, soc2, iso27001, gdpr, nist_800_53): ").strip()
        fw = FRAMEWORKS.get(fw_key)
        if not fw:
            print("Unknown framework: " + fw_key)
            return
        print("\n=== " + fw["name"] + " Assessment ===")
        print(fw["description"])
        print("\nFor each control, enter status: (i)mplemented, (p)artial, (n)ot started, (a)cceptable risk, (s)kip\n")
        results = []
        for req in fw["requirements"]:
            print("[" + req["id"] + "] " + req["title"])
            print("  " + req["desc"])
            status = input("  Status (i/p/n/a/s): ").strip().lower()
            status_map = {"i": "Implemented", "p": "Partial", "n": "Not Started", "a": "Accepted Risk", "s": "Skipped"}
            results.append({"id": req["id"], "title": req["title"], "status": status_map.get(status, "Skipped")})
        self.assessments[fw_key] = results
        # Summary
        total = len(results)
        implemented = sum(1 for r in results if r["status"] == "Implemented")
        partial = sum(1 for r in results if r["status"] == "Partial")
        not_started = sum(1 for r in results if r["status"] == "Not Started")
        print("\n=== Assessment Summary ===")
        print("  Implemented: " + str(implemented) + "/" + str(total) + " (" + str(int(implemented/total*100)) + "%)")
        print("  Partial: " + str(partial))
        print("  Not Started: " + str(not_started))
        print("  Compliance Score: " + str(int((implemented + partial * 0.5) / total * 100)) + "%")

    def _cross_mapping(self):
        print("\n=== Cross-Framework Control Mapping ===\n")
        header = "  {:<25} {:<8} {:<16} {:<8} {:<8} {:<8} {:<8}".format("Control", "PCI", "HIPAA", "SOC2", "ISO", "NIST", "GDPR")
        print(header)
        print("  " + "-" * 90)
        for m in CROSS_MAPPING:
            print("  {:<25} {:<8} {:<16} {:<8} {:<8} {:<8} {:<8}".format(
                m["control"], m["pci"], m["hipaa"], m["soc2"], m["iso"], m["nist"], m["gdpr"]))

    def _gap_analysis(self):
        if not self.assessments:
            print("\n  No assessments completed. Run an assessment first.")
            return
        print("\n=== Gap Analysis ===\n")
        for fw_key, results in self.assessments.items():
            fw = FRAMEWORKS.get(fw_key, {})
            print("  " + fw.get("name", fw_key) + ":")
            gaps = [r for r in results if r["status"] in ("Not Started", "Partial")]
            if gaps:
                for g in gaps:
                    color = "\033[91m" if g["status"] == "Not Started" else "\033[93m"
                    print("    " + color + "[" + g["status"].upper() + "] " + g["id"] + " " + g["title"] + "\033[0m")
            else:
                print("    \033[92mNo gaps found.\033[0m")

    def _generate_report(self):
        if not self.assessments:
            print("\n  No assessments to report. Run an assessment first.")
            return
        print("\n=== Compliance Report ===\n")
        report = "AEGIS COMPLIANCE ASSESSMENT REPORT\n"
        report += "Generated: " + datetime.now().isoformat() + "\n"
        report += "=" * 60 + "\n\n"
        for fw_key, results in self.assessments.items():
            fw = FRAMEWORKS.get(fw_key, {})
            total = len(results)
            implemented = sum(1 for r in results if r["status"] == "Implemented")
            score = int((implemented + sum(0.5 for r in results if r["status"] == "Partial")) / total * 100)
            report += fw.get("name", fw_key) + "\n"
            report += "Score: " + str(score) + "% (" + str(implemented) + "/" + str(total) + " implemented)\n\n"
            for r in results:
                report += "  [" + r["status"] + "] " + r["id"] + " " + r["title"] + "\n"
            report += "\n"
        print(report)

    def get_findings(self):
        return self.findings


if __name__ == "__main__":
    c = ComplianceEngine()
    c.run()
