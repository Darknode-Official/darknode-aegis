#!/usr/bin/env python3
"""
AEGIS Cloud Security Posture Manager
======================================
Multi-cloud configuration auditing, CIS Benchmark compliance checking,
IAM analysis, and compliance mapping for AWS, Azure, and GCP.

EDUCATIONAL USE ONLY - All operations are simulated for training purposes.
"""

import os
import sys
import json
import uuid
import random
import datetime
import argparse
from collections import defaultdict

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.tree import Tree
    from rich.text import Text
    from rich.columns import Columns
except ImportError:
    print("[!] rich library required: pip install rich")
    sys.exit(1)

console = Console()

# ─── CIS Benchmark Checks ──────────────────────────────────────────────
AWS_CIS_CHECKS = [
    {"id": "1.1", "title": "Avoid the use of root account", "section": "IAM",
     "severity": "CRITICAL", "description": "Root account should not be used for daily tasks",
     "remediation": "Create IAM users for daily tasks, enable MFA on root"},
    {"id": "1.2", "title": "Ensure MFA is enabled for all IAM users", "section": "IAM",
     "severity": "HIGH", "description": "Multi-factor authentication should be enabled for all users",
     "remediation": "Enable virtual or hardware MFA for each IAM user"},
    {"id": "1.3", "title": "Ensure credentials unused for 90+ days are disabled", "section": "IAM",
     "severity": "MEDIUM", "description": "Stale credentials increase attack surface",
     "remediation": "Disable or remove IAM credentials not used in 90 days"},
    {"id": "1.4", "title": "Ensure access keys are rotated within 90 days", "section": "IAM",
     "severity": "MEDIUM", "description": "Regular key rotation limits exposure window",
     "remediation": "Rotate access keys every 90 days or less"},
    {"id": "1.5", "title": "Ensure IAM password policy requires uppercase", "section": "IAM",
     "severity": "MEDIUM", "description": "Password complexity reduces brute force risk",
     "remediation": "Update IAM password policy to require uppercase letters"},
    {"id": "1.6", "title": "Ensure IAM password policy requires lowercase", "section": "IAM",
     "severity": "MEDIUM", "description": "Password complexity reduces brute force risk",
     "remediation": "Update IAM password policy to require lowercase letters"},
    {"id": "1.7", "title": "Ensure IAM password policy requires symbols", "section": "IAM",
     "severity": "MEDIUM", "description": "Password complexity reduces brute force risk",
     "remediation": "Update IAM password policy to require symbols"},
    {"id": "1.8", "title": "Ensure IAM password policy requires numbers", "section": "IAM",
     "severity": "MEDIUM", "description": "Password complexity reduces brute force risk",
     "remediation": "Update IAM password policy to require numbers"},
    {"id": "1.9", "title": "Ensure IAM password min length is 14+", "section": "IAM",
     "severity": "MEDIUM", "description": "Longer passwords are harder to crack",
     "remediation": "Set minimum password length to 14 or more characters"},
    {"id": "1.10", "title": "Ensure no root access keys exist", "section": "IAM",
     "severity": "CRITICAL", "description": "Root access keys provide unrestricted access",
     "remediation": "Delete all root access keys"},
    {"id": "2.1", "title": "Ensure CloudTrail is enabled in all regions", "section": "Logging",
     "severity": "HIGH", "description": "CloudTrail provides API call auditing",
     "remediation": "Enable CloudTrail with multi-region trail"},
    {"id": "2.2", "title": "Ensure CloudTrail log file validation is enabled", "section": "Logging",
     "severity": "HIGH", "description": "Log validation detects tampering",
     "remediation": "Enable log file validation on all trails"},
    {"id": "2.3", "title": "Ensure CloudTrail S3 bucket is not public", "section": "Logging",
     "severity": "CRITICAL", "description": "Public log buckets expose sensitive data",
     "remediation": "Remove public access from CloudTrail S3 bucket"},
    {"id": "2.4", "title": "Ensure CloudTrail logs are encrypted", "section": "Logging",
     "severity": "HIGH", "description": "Encryption protects log confidentiality",
     "remediation": "Enable SSE-KMS encryption for CloudTrail logs"},
    {"id": "2.5", "title": "Ensure AWS Config is enabled in all regions", "section": "Logging",
     "severity": "HIGH", "description": "AWS Config tracks configuration changes",
     "remediation": "Enable AWS Config in all regions"},
    {"id": "2.6", "title": "Ensure S3 bucket access logging is enabled for CloudTrail", "section": "Logging",
     "severity": "MEDIUM", "description": "S3 access logs provide audit trail",
     "remediation": "Enable server access logging on CloudTrail S3 bucket"},
    {"id": "3.1", "title": "Ensure VPC flow logging is enabled", "section": "Networking",
     "severity": "MEDIUM", "description": "Flow logs capture network traffic metadata",
     "remediation": "Enable VPC flow logs for all VPCs"},
    {"id": "3.2", "title": "Ensure no security groups allow 0.0.0.0/0 to port 22", "section": "Networking",
     "severity": "HIGH", "description": "Open SSH access from internet is high risk",
     "remediation": "Restrict SSH access to specific IP ranges"},
    {"id": "3.3", "title": "Ensure no security groups allow 0.0.0.0/0 to port 3389", "section": "Networking",
     "severity": "HIGH", "description": "Open RDP access from internet is high risk",
     "remediation": "Restrict RDP access to specific IP ranges"},
    {"id": "3.4", "title": "Ensure default security group restricts all traffic", "section": "Networking",
     "severity": "MEDIUM", "description": "Default SG should not allow any traffic",
     "remediation": "Remove all rules from default security groups"},
    {"id": "4.1", "title": "Ensure S3 buckets have encryption enabled", "section": "Storage",
     "severity": "HIGH", "description": "Encryption at rest protects data confidentiality",
     "remediation": "Enable default encryption on all S3 buckets"},
    {"id": "4.2", "title": "Ensure S3 buckets deny HTTP requests", "section": "Storage",
     "severity": "HIGH", "description": "HTTPS enforcement prevents data interception",
     "remediation": "Add bucket policy denying non-HTTPS requests"},
    {"id": "4.3", "title": "Ensure RDS instances are encrypted", "section": "Storage",
     "severity": "HIGH", "description": "Database encryption protects data at rest",
     "remediation": "Enable encryption on all RDS instances"},
    {"id": "4.4", "title": "Ensure EBS volumes are encrypted", "section": "Storage",
     "severity": "HIGH", "description": "EBS encryption protects data at rest",
     "remediation": "Enable default EBS encryption in all regions"},
    {"id": "4.5", "title": "Ensure S3 bucket versioning is enabled", "section": "Storage",
     "severity": "MEDIUM", "description": "Versioning enables recovery from accidental changes",
     "remediation": "Enable versioning on all S3 buckets"},
]

AZURE_CIS_CHECKS = [
    {"id": "1.1", "title": "Ensure MFA is enabled for all privileged users", "section": "IAM",
     "severity": "CRITICAL", "description": "MFA reduces credential theft impact",
     "remediation": "Enable Azure MFA for all Global Admins and privileged roles"},
    {"id": "1.2", "title": "Ensure Conditional Access policies are configured", "section": "IAM",
     "severity": "HIGH", "description": "Conditional Access enforces context-aware security",
     "remediation": "Create Conditional Access policies for risky sign-ins"},
    {"id": "1.3", "title": "Ensure guest users are reviewed monthly", "section": "IAM",
     "severity": "MEDIUM", "description": "Guest accounts may retain unnecessary access",
     "remediation": "Perform monthly access reviews for guest users"},
    {"id": "1.4", "title": "Ensure Security Defaults are enabled", "section": "IAM",
     "severity": "HIGH", "description": "Security Defaults provide baseline protection",
     "remediation": "Enable Security Defaults or Conditional Access"},
    {"id": "2.1", "title": "Ensure Azure Defender is enabled for servers", "section": "Security",
     "severity": "HIGH", "description": "Azure Defender provides threat detection",
     "remediation": "Enable Azure Defender for Servers in Security Center"},
    {"id": "2.2", "title": "Ensure Azure Defender is enabled for SQL", "section": "Security",
     "severity": "HIGH", "description": "SQL threat detection identifies anomalous activities",
     "remediation": "Enable Azure Defender for SQL databases"},
    {"id": "2.3", "title": "Ensure Azure Defender is enabled for Storage", "section": "Security",
     "severity": "HIGH", "description": "Storage threat detection identifies malicious uploads",
     "remediation": "Enable Azure Defender for Storage accounts"},
    {"id": "3.1", "title": "Ensure NSG flow logs are enabled", "section": "Networking",
     "severity": "MEDIUM", "description": "NSG flow logs provide network traffic visibility",
     "remediation": "Enable NSG flow logs for all Network Security Groups"},
    {"id": "3.2", "title": "Ensure no NSG allows SSH from 0.0.0.0/0", "section": "Networking",
     "severity": "HIGH", "description": "Open SSH from internet is high risk",
     "remediation": "Restrict SSH access in NSG rules"},
    {"id": "3.3", "title": "Ensure no NSG allows RDP from 0.0.0.0/0", "section": "Networking",
     "severity": "HIGH", "description": "Open RDP from internet is high risk",
     "remediation": "Restrict RDP access in NSG rules"},
    {"id": "4.1", "title": "Ensure Storage Account encryption is enabled", "section": "Storage",
     "severity": "HIGH", "description": "Encryption at rest protects data",
     "remediation": "Enable encryption on all Storage Accounts"},
    {"id": "4.2", "title": "Ensure Storage Account requires HTTPS", "section": "Storage",
     "severity": "HIGH", "description": "HTTPS enforcement prevents data interception",
     "remediation": "Enable 'Secure transfer required' on Storage Accounts"},
    {"id": "4.3", "title": "Ensure Blob public access is disabled", "section": "Storage",
     "severity": "HIGH", "description": "Public blob access exposes data",
     "remediation": "Disable public access at Storage Account level"},
    {"id": "5.1", "title": "Ensure diagnostic logs are enabled", "section": "Logging",
     "severity": "MEDIUM", "description": "Diagnostic logs provide operational visibility",
     "remediation": "Enable diagnostic logging for all resources"},
    {"id": "5.2", "title": "Ensure Activity Log retention is 365+ days", "section": "Logging",
     "severity": "MEDIUM", "description": "Long retention supports forensic investigation",
     "remediation": "Set Activity Log retention to 365 days or more"},
]

GCP_CIS_CHECKS = [
    {"id": "1.1", "title": "Ensure MFA is enforced for all users", "section": "IAM",
     "severity": "CRITICAL", "description": "MFA reduces credential compromise risk",
     "remediation": "Enable 2-Step Verification for all users in Admin Console"},
    {"id": "1.2", "title": "Ensure service account keys are rotated", "section": "IAM",
     "severity": "HIGH", "description": "Key rotation limits exposure from compromised keys",
     "remediation": "Rotate service account keys every 90 days"},
    {"id": "1.3", "title": "Ensure service accounts have no admin privileges", "section": "IAM",
     "severity": "CRITICAL", "description": "Least privilege for service accounts",
     "remediation": "Remove admin roles from service accounts"},
    {"id": "1.4", "title": "Ensure user-managed service account keys are minimal", "section": "IAM",
     "severity": "HIGH", "description": "Minimize user-managed keys in favor of GCP-managed",
     "remediation": "Use GCP-managed keys where possible"},
    {"id": "2.1", "title": "Ensure Cloud Audit Logging is configured", "section": "Logging",
     "severity": "HIGH", "description": "Audit logs provide visibility into API calls",
     "remediation": "Enable Data Access audit logs for all services"},
    {"id": "2.2", "title": "Ensure log sinks are configured for all log entries", "section": "Logging",
     "severity": "MEDIUM", "description": "Log sinks ensure log preservation",
     "remediation": "Create log sinks to BigQuery, Storage, or Pub/Sub"},
    {"id": "2.3", "title": "Ensure log metric filters exist for critical events", "section": "Logging",
     "severity": "MEDIUM", "description": "Alerts on critical events enable quick response",
     "remediation": "Create log-based metrics and alerts for IAM changes"},
    {"id": "3.1", "title": "Ensure default network does not exist", "section": "Networking",
     "severity": "HIGH", "description": "Default network has permissive firewall rules",
     "remediation": "Delete default network and create custom VPC"},
    {"id": "3.2", "title": "Ensure SSH is restricted from 0.0.0.0/0", "section": "Networking",
     "severity": "HIGH", "description": "Open SSH from internet is high risk",
     "remediation": "Restrict SSH firewall rules to specific source ranges"},
    {"id": "3.3", "title": "Ensure RDP is restricted from 0.0.0.0/0", "section": "Networking",
     "severity": "HIGH", "description": "Open RDP from internet is high risk",
     "remediation": "Restrict RDP firewall rules to specific source ranges"},
    {"id": "3.4", "title": "Ensure VPC Flow Logs are enabled", "section": "Networking",
     "severity": "MEDIUM", "description": "Flow logs provide network traffic visibility",
     "remediation": "Enable VPC Flow Logs for all subnets"},
    {"id": "4.1", "title": "Ensure Cloud Storage buckets are not public", "section": "Storage",
     "severity": "CRITICAL", "description": "Public buckets expose data",
     "remediation": "Remove allUsers/allAuthenticatedUsers from bucket IAM"},
    {"id": "4.2", "title": "Ensure Cloud SQL requires SSL connections", "section": "Storage",
     "severity": "HIGH", "description": "SSL prevents data interception",
     "remediation": "Enable 'Require SSL' on all Cloud SQL instances"},
    {"id": "4.3", "title": "Ensure Cloud SQL databases are encrypted", "section": "Storage",
     "severity": "HIGH", "description": "Customer-managed encryption keys provide control",
     "remediation": "Enable CMEK for Cloud SQL instances"},
    {"id": "4.4", "title": "Ensure GKE nodes use COS images", "section": "Compute",
     "severity": "MEDIUM", "description": "Container-Optimized OS reduces attack surface",
     "remediation": "Use COS or COS-containerd node images for GKE"},
]

# ─── Compliance Framework Mappings ─────────────────────────────────────
COMPLIANCE_FRAMEWORKS = {
    "SOC2": {
        "name": "SOC 2 Type II",
        "controls": {
            "CC6.1": "Logical and Physical Access Controls",
            "CC6.2": "Security Event Monitoring",
            "CC6.3": "Access Control Mechanisms",
            "CC6.6": "Boundary Protection",
            "CC6.7": "Restricting Transmission of Data",
            "CC6.8": "Preventing Unauthorized Software",
            "CC7.1": "Detecting Changes to Infrastructure",
            "CC7.2": "Monitoring System Components",
            "CC7.3": "Evaluating Security Events",
            "CC8.1": "Authorization and Change Control",
        },
        "iam_controls": ["CC6.1", "CC6.3"],
        "logging_controls": ["CC6.2", "CC7.1", "CC7.2", "CC7.3"],
        "network_controls": ["CC6.6", "CC6.7"],
        "data_controls": ["CC6.7", "CC6.8"],
    },
    "PCI-DSS": {
        "name": "PCI DSS v4.0",
        "controls": {
            "1": "Install and maintain network security controls",
            "2": "Apply secure configurations",
            "3": "Protect stored account data",
            "4": "Protect cardholder data with strong cryptography",
            "5": "Protect against malicious software",
            "6": "Develop and maintain secure systems",
            "7": "Restrict access by business need-to-know",
            "8": "Identify users and authenticate access",
            "10": "Log and monitor all access",
            "11": "Test security regularly",
        },
        "iam_controls": ["7", "8"],
        "logging_controls": ["10"],
        "network_controls": ["1", "2"],
        "data_controls": ["3", "4"],
    },
    "HIPAA": {
        "name": "HIPAA Security Rule",
        "controls": {
            "164.312(a)(1)": "Access Control",
            "164.312(a)(2)(i)": "Unique User Identification",
            "164.312(a)(2)(iii)": "Automatic Logoff",
            "164.312(a)(2)(iv)": "Encryption and Decryption",
            "164.312(b)": "Audit Controls",
            "164.312(c)(1)": "Integrity",
            "164.312(d)": "Person or Entity Authentication",
            "164.312(e)(1)": "Transmission Security",
        },
        "iam_controls": ["164.312(a)(1)", "164.312(a)(2)(i)", "164.312(d)"],
        "logging_controls": ["164.312(b)"],
        "network_controls": ["164.312(e)(1)"],
        "data_controls": ["164.312(a)(2)(iv)", "164.312(c)(1)"],
    },
    "FedRAMP": {
        "name": "FedRAMP (Moderate)",
        "controls": {
            "AC-2": "Account Management",
            "AC-3": "Access Enforcement",
            "AC-6": "Least Privilege",
            "AU-2": "Audit Events",
            "AU-3": "Content of Audit Records",
            "AU-6": "Audit Review, Analysis, and Reporting",
            "CA-7": "Continuous Monitoring",
            "CM-6": "Configuration Settings",
            "IA-2": "Identification and Authentication",
            "SC-7": "Boundary Protection",
            "SC-8": "Transmission Confidentiality and Integrity",
            "SC-28": "Protection of Information at Rest",
        },
        "iam_controls": ["AC-2", "AC-3", "AC-6", "IA-2"],
        "logging_controls": ["AU-2", "AU-3", "AU-6", "CA-7"],
        "network_controls": ["SC-7", "SC-8"],
        "data_controls": ["SC-28", "CM-6"],
    },
}


class CloudPostureCheckResult:
    """Result of a single CIS benchmark check."""

    def __init__(self, check, cloud_provider):
        self.check_id = check["id"]
        self.title = check["title"]
        self.section = check["section"]
        self.severity = check["severity"]
        self.description = check["description"]
        self.remediation = check["remediation"]
        self.cloud_provider = cloud_provider
        self.status = random.choice(["PASS", "PASS", "PASS", "FAIL", "FAIL", "WARNING"])
        self.resources_checked = random.randint(1, 50)
        self.resources_compliant = (self.resources_checked if self.status == "PASS"
                                    else random.randint(0, self.resources_checked - 1))
        self.resources_non_compliant = self.resources_checked - self.resources_compliant

    def to_dict(self):
        return {
            "check_id": self.check_id,
            "title": self.title,
            "section": self.section,
            "severity": self.severity,
            "status": self.status,
            "cloud_provider": self.cloud_provider,
            "resources_checked": self.resources_checked,
            "resources_compliant": self.resources_compliant,
            "resources_non_compliant": self.resources_non_compliant,
            "remediation": self.remediation,
        }


class CloudSecurityPostureManager:
    """
    Cloud Security Posture Manager (CSPM)

    Multi-cloud configuration auditing with CIS Benchmark compliance,
    IAM analysis, and regulatory compliance mapping.

    Usage:
        cspm = CloudSecurityPostureManager()
        cspm.run()
    """

    HELP_TEXT = """
AEGIS Cloud Security Posture Manager
======================================
Multi-cloud configuration audit and compliance assessment.

Commands:
  audit <provider>      Run CIS benchmark audit (aws | azure | gcp)
  audit-all             Run audit across all cloud providers
  iam-analysis          Analyze IAM policies for least privilege
  network-audit         Audit network security configurations
  encryption-check      Verify encryption at rest and in transit
  compliance <fw>       Map findings to compliance framework
  compliance-all        Map to all compliance frameworks
  report                Generate comprehensive posture report
  help                  Show this help message

Providers: aws, azure, gcp
Frameworks: SOC2, PCI-DSS, HIPAA, FedRAMP

Options:
  --provider <name>     Cloud provider to audit
  --framework <name>    Compliance framework for mapping
  --output <file>       Export results to JSON
"""

    def __init__(self):
        """Initialize the Cloud Security Posture Manager."""
        self.results = {"aws": [], "azure": [], "gcp": []}
        self.iam_findings = []
        self.network_findings = []
        self._verify_authorization()

    def _verify_authorization(self):
        """Verify operator authorization."""
        console.print(Panel(
            "[bold yellow]AUTHORIZATION CHECK[/bold yellow]\n\n"
            "This module performs [bold]simulated[/bold] cloud security audits.\n"
            "No actual cloud API calls are made. All results are generated data.\n"
            "For real cloud audits, use AWS Security Hub, Azure Security Center, or GCP SCC.",
            title="AEGIS Cloud Posture Manager",
            border_style="yellow"
        ))

    def audit_provider(self, provider="aws"):
        """Run CIS benchmark audit for a specific cloud provider."""
        checks_map = {
            "aws": ("AWS", AWS_CIS_CHECKS),
            "azure": ("Azure", AZURE_CIS_CHECKS),
            "gcp": ("GCP", GCP_CIS_CHECKS),
        }

        if provider not in checks_map:
            console.print(f"[red]Unknown provider: {provider}. Use: aws, azure, gcp[/red]")
            return []

        provider_name, checks = checks_map[provider]

        console.print(Panel(
            f"[bold cyan]CIS BENCHMARK AUDIT: {provider_name}[/bold cyan]\n\n"
            f"Running {len(checks)} CIS benchmark checks...",
            title=f"{provider_name} Audit",
            border_style="cyan",
        ))

        results = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task(f"[cyan]Auditing {provider_name}...", total=len(checks))
            for check in checks:
                result = CloudPostureCheckResult(check, provider)
                results.append(result)
                progress.advance(task)

        self.results[provider] = results

        # Display results
        table = Table(title=f"CIS Benchmark Results: {provider_name}")
        table.add_column("ID", style="dim", width=6)
        table.add_column("Check", style="white", width=45)
        table.add_column("Section", style="cyan", width=12)
        table.add_column("Severity", width=10)
        table.add_column("Status", width=10)
        table.add_column("Resources", justify="right", width=12)

        for r in results:
            sev_style = {"CRITICAL": "red bold", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(
                r.severity, "white")
            status_style = {"PASS": "green", "FAIL": "red bold", "WARNING": "yellow"}.get(
                r.status, "white")
            table.add_row(
                r.check_id,
                r.title,
                r.section,
                Text(r.severity, style=sev_style),
                Text(r.status, style=status_style),
                f"{r.resources_compliant}/{r.resources_checked}",
            )
        console.print(table)

        # Summary
        passed = sum(1 for r in results if r.status == "PASS")
        failed = sum(1 for r in results if r.status == "FAIL")
        warned = sum(1 for r in results if r.status == "WARNING")
        score = (passed / len(results)) * 100 if results else 0
        score_style = "green" if score >= 80 else "yellow" if score >= 60 else "red"

        console.print(Panel(
            f"[bold]Compliance Score: [{score_style}]{score:.1f}%[/{score_style}][/bold]\n\n"
            f"[green]PASS:[/green]    {passed} checks\n"
            f"[red]FAIL:[/red]    {failed} checks\n"
            f"[yellow]WARNING:[/yellow] {warned} checks\n"
            f"Total:    {len(results)} checks",
            title=f"{provider_name} Audit Summary",
            border_style=score_style,
        ))

        return results

    def audit_all_providers(self):
        """Run CIS benchmark audit across all cloud providers."""
        for provider in ["aws", "azure", "gcp"]:
            self.audit_provider(provider)
            console.print("\n")

        # Cross-cloud summary
        table = Table(title="Multi-Cloud Posture Summary")
        table.add_column("Provider", style="cyan")
        table.add_column("Checks", justify="right")
        table.add_column("Pass", style="green", justify="right")
        table.add_column("Fail", style="red", justify="right")
        table.add_column("Score", style="bold", justify="right")

        for provider, results in self.results.items():
            if results:
                passed = sum(1 for r in results if r.status == "PASS")
                failed = sum(1 for r in results if r.status == "FAIL")
                score = (passed / len(results)) * 100
                score_style = "green" if score >= 80 else "yellow" if score >= 60 else "red"
                table.add_row(
                    provider.upper(),
                    str(len(results)),
                    str(passed),
                    str(failed),
                    f"[{score_style}]{score:.1f}%[/{score_style}]",
                )
        console.print(table)

    def analyze_iam(self, provider="aws"):
        """Analyze IAM policies for least privilege violations."""
        console.print(Panel(
            f"[bold cyan]IAM POLICY ANALYSIS[/bold cyan]\n\n"
            f"Analyzing IAM policies for least privilege violations...",
            title="IAM Analysis",
            border_style="cyan",
        ))

        findings = [
            {"principal": "admin-role", "issue": "Full administrator access (*:*)",
             "severity": "CRITICAL", "recommendation": "Break into specific service permissions"},
            {"principal": "dev-role", "issue": "s3:* on all resources",
             "severity": "HIGH", "recommendation": "Restrict to specific buckets and actions"},
            {"principal": "lambda-exec-role", "issue": "ec2:* and iam:PassRole on *",
             "severity": "HIGH", "recommendation": "Restrict to required EC2 actions only"},
            {"principal": "ci-cd-user", "issue": "Access keys not rotated (180 days old)",
             "severity": "MEDIUM", "recommendation": "Rotate keys and enable automated rotation"},
            {"principal": "backup-role", "issue": "Cross-account access without external ID",
             "severity": "HIGH", "recommendation": "Add external ID condition to trust policy"},
            {"principal": "analytics-role", "issue": "s3:GetObject on sensitive data bucket",
             "severity": "MEDIUM", "recommendation": "Apply row-level security or restrict prefix"},
            {"principal": "old-service-account", "issue": "Unused for 120 days but still active",
             "severity": "MEDIUM", "recommendation": "Disable or delete unused service account"},
            {"principal": "shared-team-role", "issue": "Used by 15 engineers without individual audit",
             "severity": "HIGH", "recommendation": "Create individual roles with session tags"},
        ]

        table = Table(title="IAM Least Privilege Analysis")
        table.add_column("Principal", style="cyan")
        table.add_column("Issue", style="white", width=40)
        table.add_column("Severity", width=10)
        table.add_column("Recommendation", style="dim", width=40)

        for f in findings:
            sev_style = {"CRITICAL": "red bold", "HIGH": "red", "MEDIUM": "yellow"}.get(
                f["severity"], "white")
            table.add_row(
                f["principal"],
                f["issue"],
                Text(f["severity"], style=sev_style),
                f["recommendation"],
            )
        console.print(table)

        self.iam_findings = findings
        return findings

    def audit_network_security(self, provider="aws"):
        """Audit network security group configurations."""
        console.print(Panel(
            f"[bold cyan]NETWORK SECURITY AUDIT[/bold cyan]\n\n"
            f"Analyzing security groups, NACLs, and firewall rules...",
            title="Network Audit",
            border_style="cyan",
        ))

        findings = [
            {"resource": "sg-web-tier", "issue": "Port 443 open to 0.0.0.0/0",
             "severity": "LOW", "status": "ACCEPTABLE", "note": "Web server -- expected"},
            {"resource": "sg-admin", "issue": "Port 22 open to 0.0.0.0/0",
             "severity": "HIGH", "status": "NON-COMPLIANT", "note": "Restrict to bastion host IP"},
            {"resource": "sg-database", "issue": "Port 3306 open to 10.0.0.0/8",
             "severity": "MEDIUM", "status": "REVIEW", "note": "Overly broad internal access"},
            {"resource": "sg-default", "issue": "Default SG allows all internal traffic",
             "severity": "MEDIUM", "status": "NON-COMPLIANT", "note": "Remove all rules from default SG"},
            {"resource": "sg-legacy", "issue": "Ports 20-21 (FTP) open to 0.0.0.0/0",
             "severity": "CRITICAL", "status": "NON-COMPLIANT", "note": "FTP is insecure -- use SFTP"},
            {"resource": "sg-monitoring", "issue": "ICMP open to 0.0.0.0/0",
             "severity": "LOW", "status": "REVIEW", "note": "Consider restricting ICMP"},
        ]

        table = Table(title="Network Security Findings")
        table.add_column("Resource", style="cyan")
        table.add_column("Issue", style="white", width=35)
        table.add_column("Severity", width=10)
        table.add_column("Status", width=15)
        table.add_column("Note", style="dim", width=30)

        for f in findings:
            sev_style = {"CRITICAL": "red bold", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(
                f["severity"], "white")
            status_style = {"NON-COMPLIANT": "red", "REVIEW": "yellow", "ACCEPTABLE": "green"}.get(
                f["status"], "white")
            table.add_row(
                f["resource"],
                f["issue"],
                Text(f["severity"], style=sev_style),
                Text(f["status"], style=status_style),
                f["note"],
            )
        console.print(table)

        self.network_findings = findings
        return findings

    def check_encryption(self, provider="aws"):
        """Verify encryption at rest and in transit."""
        console.print(Panel(
            f"[bold cyan]ENCRYPTION VERIFICATION[/bold cyan]\n\n"
            f"Checking encryption at rest and in transit for all services...",
            title="Encryption Audit",
            border_style="cyan",
        ))

        resources = [
            {"service": "S3", "resource": "app-data-bucket", "at_rest": True,
             "key_type": "SSE-S3", "in_transit": True, "https_enforced": True},
            {"service": "S3", "resource": "logs-bucket", "at_rest": True,
             "key_type": "SSE-KMS", "in_transit": True, "https_enforced": True},
            {"service": "S3", "resource": "legacy-uploads", "at_rest": False,
             "key_type": "None", "in_transit": False, "https_enforced": False},
            {"service": "RDS", "resource": "prod-database", "at_rest": True,
             "key_type": "KMS (CMK)", "in_transit": True, "https_enforced": True},
            {"service": "RDS", "resource": "dev-database", "at_rest": False,
             "key_type": "None", "in_transit": False, "https_enforced": False},
            {"service": "EBS", "resource": "vol-web01", "at_rest": True,
             "key_type": "KMS (Default)", "in_transit": True, "https_enforced": True},
            {"service": "EBS", "resource": "vol-legacy", "at_rest": False,
             "key_type": "None", "in_transit": True, "https_enforced": True},
            {"service": "DynamoDB", "resource": "sessions-table", "at_rest": True,
             "key_type": "KMS (CMK)", "in_transit": True, "https_enforced": True},
        ]

        table = Table(title="Encryption Status")
        table.add_column("Service", style="cyan")
        table.add_column("Resource", style="white")
        table.add_column("At Rest", width=10)
        table.add_column("Key Type", style="yellow")
        table.add_column("In Transit", width=10)
        table.add_column("HTTPS Enforced", width=14)

        for r in resources:
            table.add_row(
                r["service"],
                r["resource"],
                "[green]Yes[/green]" if r["at_rest"] else "[red]No[/red]",
                r["key_type"],
                "[green]Yes[/green]" if r["in_transit"] else "[red]No[/red]",
                "[green]Yes[/green]" if r["https_enforced"] else "[red]No[/red]",
            )
        console.print(table)

        unencrypted = sum(1 for r in resources if not r["at_rest"])
        if unencrypted:
            console.print(f"\n[bold red]WARNING: {unencrypted} resource(s) lack encryption at rest[/bold red]")

    def map_compliance(self, framework_name="SOC2"):
        """Map findings to compliance framework controls."""
        framework = COMPLIANCE_FRAMEWORKS.get(framework_name)
        if not framework:
            console.print(f"[red]Unknown framework: {framework_name}[/red]")
            return

        console.print(Panel(
            f"[bold cyan]COMPLIANCE MAPPING: {framework['name']}[/bold cyan]\n\n"
            f"Mapping cloud posture findings to {framework['name']} controls.",
            title=f"Compliance: {framework_name}",
            border_style="cyan",
        ))

        table = Table(title=f"{framework['name']} Control Mapping")
        table.add_column("Control", style="yellow")
        table.add_column("Description", style="white", width=40)
        table.add_column("Category", style="cyan")
        table.add_column("Status", width=12)
        table.add_column("Gap", style="dim", width=30)

        for control_id, description in framework["controls"].items():
            status = random.choice(["COMPLIANT", "COMPLIANT", "COMPLIANT",
                                     "PARTIAL", "NON-COMPLIANT"])
            status_style = {"COMPLIANT": "green", "PARTIAL": "yellow",
                           "NON-COMPLIANT": "red"}.get(status, "white")

            category = "IAM" if control_id in framework.get("iam_controls", []) else \
                       "Logging" if control_id in framework.get("logging_controls", []) else \
                       "Network" if control_id in framework.get("network_controls", []) else \
                       "Data" if control_id in framework.get("data_controls", []) else "General"

            gap = "" if status == "COMPLIANT" else \
                  "Needs documentation" if status == "PARTIAL" else \
                  "Technical control missing"

            table.add_row(
                control_id,
                description,
                category,
                Text(status, style=status_style),
                gap,
            )
        console.print(table)

        # Compliance score
        controls = list(framework["controls"].keys())
        compliant = int(len(controls) * random.uniform(0.5, 0.85))
        score = (compliant / len(controls)) * 100
        score_style = "green" if score >= 80 else "yellow" if score >= 60 else "red"

        console.print(Panel(
            f"[bold]{framework['name']} Compliance Score: [{score_style}]{score:.1f}%[/{score_style}][/bold]\n\n"
            f"Controls Assessed: {len(controls)}\n"
            f"Compliant:         {compliant}\n"
            f"Non-Compliant:     {len(controls) - compliant}",
            title="Compliance Summary",
            border_style=score_style,
        ))

    def run(self):
        """Main execution entry point."""
        self.audit_all_providers()
        console.print("\n")
        self.analyze_iam()
        console.print("\n")
        self.audit_network_security()
        console.print("\n")
        self.check_encryption()
        console.print("\n")
        self.map_compliance("SOC2")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="AEGIS Cloud Security Posture Manager -- Educational Use Only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("command", nargs="?", default="audit-all",
                        choices=["audit", "audit-all", "iam-analysis",
                                 "network-audit", "encryption-check",
                                 "compliance", "compliance-all", "report", "help"],
                        help="Command to execute")
    parser.add_argument("--provider", "-p", default="aws",
                        choices=["aws", "azure", "gcp"],
                        help="Cloud provider to audit")
    parser.add_argument("--framework", "-f", default="SOC2",
                        choices=list(COMPLIANCE_FRAMEWORKS.keys()),
                        help="Compliance framework")
    parser.add_argument("--output", "-o", default=None,
                        help="Export results to JSON file")

    args = parser.parse_args()
    cspm = CloudSecurityPostureManager()

    if args.command == "help":
        console.print(cspm.HELP_TEXT)
    elif args.command == "audit":
        cspm.audit_provider(args.provider)
    elif args.command == "audit-all":
        cspm.audit_all_providers()
    elif args.command == "iam-analysis":
        cspm.analyze_iam(args.provider)
    elif args.command == "network-audit":
        cspm.audit_network_security(args.provider)
    elif args.command == "encryption-check":
        cspm.check_encryption(args.provider)
    elif args.command == "compliance":
        cspm.map_compliance(args.framework)
    elif args.command == "compliance-all":
        for fw in COMPLIANCE_FRAMEWORKS:
            cspm.map_compliance(fw)
            console.print("\n")
    elif args.command == "report":
        cspm.run()
    else:
        cspm.run()

    if args.output:
        data = {
            "results": {k: [r.to_dict() for r in v] for k, v in cspm.results.items()},
            "iam_findings": cspm.iam_findings,
            "network_findings": cspm.network_findings,
        }
        with open(args.output, "w") as f:
            json.dump(data, f, indent=2)
        console.print(f"[green]Results exported to {args.output}[/green]")


if __name__ == "__main__":
    main()
