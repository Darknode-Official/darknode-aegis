#!/usr/bin/env python3
"""Cloud Security Posture Management -- AWS, Azure, GCP security auditing"""
import json, os, sys
from datetime import datetime

# ============================================================================
# AWS CIS BENCHMARK CHECKS
# ============================================================================
AWS_CIS_CHECKS = [
    {"id": "1.1", "title": "Avoid use of root account", "severity": "CRITICAL", "command": "aws iam generate-credential-report && aws iam get-credential-report --output json | jq -r '.Content' | base64 -d | grep '<root_account>'", "check": "Root account should have no access keys and MFA enabled", "remediation": "Delete root access keys, enable MFA on root"},
    {"id": "1.2", "title": "MFA enabled for all IAM users with console access", "severity": "HIGH", "command": "aws iam list-users --query 'Users[*].UserName' --output text | xargs -I {} aws iam list-mfa-devices --user-name {}", "check": "Every console user should have MFA", "remediation": "Enable MFA for all IAM users"},
    {"id": "1.3", "title": "Credentials unused for 90+ days disabled", "severity": "MEDIUM", "command": "aws iam get-credential-report", "check": "Access keys unused >90 days should be deactivated", "remediation": "Deactivate or delete unused access keys"},
    {"id": "1.4", "title": "Access keys rotated every 90 days", "severity": "MEDIUM", "command": "aws iam list-access-keys --user-name <user> --query 'AccessKeyMetadata[?CreateDate<=`90_days_ago`]'", "check": "Access keys older than 90 days should be rotated", "remediation": "Create new key, update applications, delete old key"},
    {"id": "1.5", "title": "IAM password policy requires complexity", "severity": "MEDIUM", "command": "aws iam get-account-password-policy", "check": "MinLength>=14, RequireSymbols, RequireNumbers, RequireUppercase, RequireLowercase", "remediation": "aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters"},
    {"id": "1.6", "title": "No inline policies on IAM users", "severity": "LOW", "command": "aws iam list-users --query 'Users[*].UserName' --output text | xargs -I {} sh -c 'echo {} && aws iam list-user-policies --user-name {}'", "check": "Users should use group/managed policies, not inline", "remediation": "Convert inline policies to managed policies attached via groups"},
    {"id": "2.1", "title": "CloudTrail enabled in all regions", "severity": "CRITICAL", "command": "aws cloudtrail describe-trails --query 'trailList[*].{Name:Name,IsMultiRegion:IsMultiRegionTrail,IsLogging:IsLogging}'", "check": "At least one trail with IsMultiRegionTrail=true and IsLogging=true", "remediation": "aws cloudtrail create-trail --name aegis-trail --s3-bucket-name <bucket> --is-multi-region-trail"},
    {"id": "2.2", "title": "CloudTrail log file validation enabled", "severity": "HIGH", "command": "aws cloudtrail describe-trails --query 'trailList[*].{Name:Name,LogFileValidation:LogFileValidationEnabled}'", "check": "LogFileValidationEnabled should be true", "remediation": "aws cloudtrail update-trail --name <trail> --enable-log-file-validation"},
    {"id": "2.3", "title": "CloudTrail logs encrypted with KMS", "severity": "MEDIUM", "command": "aws cloudtrail describe-trails --query 'trailList[*].{Name:Name,KmsKeyId:KmsKeyId}'", "check": "KmsKeyId should be set", "remediation": "aws cloudtrail update-trail --name <trail> --kms-key-id <key-arn>"},
    {"id": "2.4", "title": "CloudTrail S3 bucket not public", "severity": "CRITICAL", "command": "aws s3api get-bucket-acl --bucket <trail-bucket>\naws s3api get-bucket-policy --bucket <trail-bucket>", "check": "No public ACLs or bucket policies", "remediation": "Remove public access from trail S3 bucket"},
    {"id": "3.1", "title": "VPC Flow Logs enabled", "severity": "HIGH", "command": "aws ec2 describe-vpcs --query 'Vpcs[*].VpcId' --output text | xargs -I {} aws ec2 describe-flow-logs --filter Name=resource-id,Values={}", "check": "Every VPC should have flow logs enabled", "remediation": "aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> --traffic-type ALL --log-destination-type s3 --log-destination <bucket-arn>"},
    {"id": "3.2", "title": "Security groups: no unrestricted SSH", "severity": "CRITICAL", "command": "aws ec2 describe-security-groups --filters Name=ip-permission.from-port,Values=22 Name=ip-permission.cidr,Values=0.0.0.0/0", "check": "No security groups should allow 0.0.0.0/0 on port 22", "remediation": "Restrict SSH to specific IP ranges or use SSM Session Manager"},
    {"id": "3.3", "title": "Security groups: no unrestricted RDP", "severity": "CRITICAL", "command": "aws ec2 describe-security-groups --filters Name=ip-permission.from-port,Values=3389 Name=ip-permission.cidr,Values=0.0.0.0/0", "check": "No security groups should allow 0.0.0.0/0 on port 3389", "remediation": "Restrict RDP or use AWS Systems Manager"},
    {"id": "3.4", "title": "Default security group restricts all traffic", "severity": "HIGH", "command": "aws ec2 describe-security-groups --filters Name=group-name,Values=default --query 'SecurityGroups[*].{GroupId:GroupId,IngressRules:IpPermissions,EgressRules:IpPermissionsEgress}'", "check": "Default SG should have no inbound/outbound rules", "remediation": "Remove all rules from default security group"},
    {"id": "4.1", "title": "S3 buckets not publicly accessible", "severity": "CRITICAL", "command": "aws s3api list-buckets --query 'Buckets[*].Name' --output text | xargs -I {} aws s3api get-public-access-block --bucket {}", "check": "All four public access block settings should be true", "remediation": "aws s3api put-public-access-block --bucket <bucket> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"},
    {"id": "4.2", "title": "S3 bucket encryption enabled", "severity": "HIGH", "command": "aws s3api get-bucket-encryption --bucket <bucket>", "check": "Server-side encryption should be enabled", "remediation": "aws s3api put-bucket-encryption --bucket <bucket> --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'"},
    {"id": "4.3", "title": "S3 bucket logging enabled", "severity": "MEDIUM", "command": "aws s3api get-bucket-logging --bucket <bucket>", "check": "Access logging should be enabled for sensitive buckets", "remediation": "aws s3api put-bucket-logging --bucket <bucket> --bucket-logging-status '{\"LoggingEnabled\":{\"TargetBucket\":\"<log-bucket>\",\"TargetPrefix\":\"s3-logs/\"}}'"},
    {"id": "5.1", "title": "RDS instances not publicly accessible", "severity": "CRITICAL", "command": "aws rds describe-db-instances --query 'DBInstances[?PubliclyAccessible==`true`].{DB:DBInstanceIdentifier,Public:PubliclyAccessible}'", "check": "No RDS instances should be publicly accessible", "remediation": "Modify RDS instance to set PubliclyAccessible=false"},
    {"id": "5.2", "title": "RDS encryption at rest", "severity": "HIGH", "command": "aws rds describe-db-instances --query 'DBInstances[?StorageEncrypted==`false`].DBInstanceIdentifier'", "check": "All RDS instances should have encryption enabled", "remediation": "Create encrypted snapshot, restore from encrypted snapshot"},
    {"id": "5.3", "title": "RDS automated backups enabled", "severity": "MEDIUM", "command": "aws rds describe-db-instances --query 'DBInstances[?BackupRetentionPeriod==`0`].DBInstanceIdentifier'", "check": "Backup retention should be > 0 days", "remediation": "Modify instance to set backup retention period >= 7 days"},
    {"id": "6.1", "title": "GuardDuty enabled", "severity": "HIGH", "command": "aws guardduty list-detectors", "check": "At least one GuardDuty detector should exist", "remediation": "aws guardduty create-detector --enable"},
    {"id": "6.2", "title": "SecurityHub enabled", "severity": "MEDIUM", "command": "aws securityhub describe-hub", "check": "Security Hub should be enabled for centralized findings", "remediation": "aws securityhub enable-security-hub"},
    {"id": "6.3", "title": "AWS Config enabled", "severity": "HIGH", "command": "aws configservice describe-configuration-recorders", "check": "Config recorder should be running", "remediation": "aws configservice put-configuration-recorder --configuration-recorder ..."},
    {"id": "6.4", "title": "IMDSv2 enforced on EC2", "severity": "HIGH", "command": "aws ec2 describe-instances --query 'Reservations[*].Instances[?MetadataOptions.HttpTokens!=`required`].{ID:InstanceId,IMDS:MetadataOptions.HttpTokens}'", "check": "All instances should require IMDSv2 (HttpTokens=required)", "remediation": "aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required"},
    {"id": "6.5", "title": "EBS volumes encrypted", "severity": "HIGH", "command": "aws ec2 describe-volumes --query 'Volumes[?Encrypted==`false`].{VolumeId:VolumeId,Size:Size}'", "check": "All EBS volumes should be encrypted", "remediation": "Enable default EBS encryption: aws ec2 enable-ebs-encryption-by-default"},
]

# ============================================================================
# AZURE CIS CHECKS
# ============================================================================
AZURE_CIS_CHECKS = [
    {"id": "1.1", "title": "MFA enabled for all privileged users", "severity": "CRITICAL", "command": "az ad user list --query \"[?assignedPlans[?servicePlanId=='...']]\"", "check": "All Global Admin, Security Admin users must have MFA", "remediation": "Enable MFA via Conditional Access policy"},
    {"id": "1.2", "title": "Conditional Access policies configured", "severity": "HIGH", "command": "az rest --method GET --url 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'", "check": "CA policies should enforce MFA, device compliance, location", "remediation": "Create CA policies for critical applications"},
    {"id": "1.3", "title": "Guest user access restricted", "severity": "MEDIUM", "command": "az ad user list --filter \"userType eq 'Guest'\"", "check": "Guest users should have limited access", "remediation": "Configure External Collaboration Settings, review guest access"},
    {"id": "2.1", "title": "Storage account secure transfer required", "severity": "HIGH", "command": "az storage account list --query '[?enableHttpsTrafficOnly==`false`].name'", "check": "All storage accounts should require HTTPS", "remediation": "az storage account update --name <acct> --https-only true"},
    {"id": "2.2", "title": "Storage account public access disabled", "severity": "CRITICAL", "command": "az storage account list --query '[?allowBlobPublicAccess==`true`].name'", "check": "Public blob access should be disabled", "remediation": "az storage account update --name <acct> --allow-blob-public-access false"},
    {"id": "3.1", "title": "Network Security Groups on all subnets", "severity": "HIGH", "command": "az network vnet subnet list --resource-group <rg> --vnet-name <vnet> --query '[?networkSecurityGroup==null].name'", "check": "Every subnet should have an NSG attached", "remediation": "Create and attach NSGs to unprotected subnets"},
    {"id": "3.2", "title": "No unrestricted inbound SSH/RDP", "severity": "CRITICAL", "command": "az network nsg list --query '[].{NSG:name,Rules:securityRules[?access==`Allow` && direction==`Inbound` && (destinationPortRange==`22` || destinationPortRange==`3389`) && sourceAddressPrefix==`*`]}'", "check": "No NSG rules should allow 0.0.0.0/0 to SSH/RDP", "remediation": "Restrict source IP ranges or use Azure Bastion"},
    {"id": "4.1", "title": "SQL Server auditing enabled", "severity": "HIGH", "command": "az sql server audit-policy show --resource-group <rg> --server <srv>", "check": "Auditing should be enabled for all SQL servers", "remediation": "az sql server audit-policy update --resource-group <rg> --server <srv> --state Enabled"},
    {"id": "4.2", "title": "SQL Transparent Data Encryption enabled", "severity": "HIGH", "command": "az sql db tde show --resource-group <rg> --server <srv> --database <db>", "check": "TDE should be enabled for all SQL databases", "remediation": "az sql db tde set --resource-group <rg> --server <srv> --database <db> --status Enabled"},
    {"id": "5.1", "title": "Azure Defender enabled", "severity": "HIGH", "command": "az security pricing list --query '[].{Service:name,Tier:pricingTier}'", "check": "Defender plans should be enabled for critical services", "remediation": "Enable Defender plans in Security Center"},
    {"id": "5.2", "title": "Activity log alerts configured", "severity": "MEDIUM", "command": "az monitor activity-log alert list", "check": "Alerts for critical operations (policy changes, NSG changes)", "remediation": "Create activity log alerts for security-relevant operations"},
]

# ============================================================================
# GCP CIS CHECKS
# ============================================================================
GCP_CIS_CHECKS = [
    {"id": "1.1", "title": "Corporate login enforced (no Gmail accounts)", "severity": "HIGH", "command": "gcloud organizations get-iam-policy <org> --format json | jq '.bindings[] | select(.members[] | contains(\"gmail.com\"))'", "check": "No @gmail.com accounts should have IAM bindings", "remediation": "Remove Gmail accounts, enforce organization domain restriction"},
    {"id": "1.2", "title": "Service account keys rotated", "severity": "MEDIUM", "command": "gcloud iam service-accounts keys list --iam-account <sa> --format json | jq '.[].validAfterTime'", "check": "SA keys older than 90 days should be rotated", "remediation": "Delete old keys, create new ones, use workload identity instead"},
    {"id": "1.3", "title": "No service account admin keys", "severity": "HIGH", "command": "gcloud iam service-accounts keys list --iam-account <sa> --managed-by user", "check": "Prefer no user-managed keys; use workload identity", "remediation": "Use GCE metadata, workload identity federation instead of keys"},
    {"id": "2.1", "title": "Cloud Audit Logging enabled", "severity": "CRITICAL", "command": "gcloud projects get-iam-policy <project> --format json | jq '.auditConfigs'", "check": "Audit logging should cover all services with DATA_READ/DATA_WRITE", "remediation": "Configure audit log configs for all services"},
    {"id": "2.2", "title": "Log sinks configured", "severity": "HIGH", "command": "gcloud logging sinks list", "check": "Logs should be exported to a separate project/bucket for retention", "remediation": "gcloud logging sinks create <sink> <destination>"},
    {"id": "3.1", "title": "Firewall rules: no unrestricted SSH", "severity": "CRITICAL", "command": "gcloud compute firewall-rules list --filter='sourceRanges=0.0.0.0/0 AND allowed[].ports=22'", "check": "No firewall rules should allow 0.0.0.0/0 to SSH", "remediation": "Use IAP TCP forwarding instead of direct SSH, restrict source ranges"},
    {"id": "3.2", "title": "Firewall rules: no unrestricted RDP", "severity": "CRITICAL", "command": "gcloud compute firewall-rules list --filter='sourceRanges=0.0.0.0/0 AND allowed[].ports=3389'", "check": "No firewall rules should allow 0.0.0.0/0 to RDP", "remediation": "Restrict source ranges or use IAP"},
    {"id": "4.1", "title": "GCS buckets not publicly accessible", "severity": "CRITICAL", "command": "gsutil iam get gs://<bucket> | grep allUsers", "check": "No bucket should grant access to allUsers or allAuthenticatedUsers", "remediation": "gsutil iam ch -d allUsers gs://<bucket>"},
    {"id": "4.2", "title": "Uniform bucket-level access enabled", "severity": "MEDIUM", "command": "gsutil uniformbucketlevelaccess get gs://<bucket>", "check": "Uniform access should be enabled (disables object ACLs)", "remediation": "gsutil uniformbucketlevelaccess set on gs://<bucket>"},
    {"id": "5.1", "title": "Shielded VMs enabled", "severity": "MEDIUM", "command": "gcloud compute instances list --format='table(name,shieldedInstanceConfig.enableVtpm,shieldedInstanceConfig.enableIntegrityMonitoring)'", "check": "Shielded VM features should be enabled", "remediation": "Enable vTPM and integrity monitoring on instances"},
    {"id": "5.2", "title": "OS Login enabled", "severity": "HIGH", "command": "gcloud compute project-info describe --format='value(commonInstanceMetadata.items[key=enable-oslogin].value)'", "check": "OS Login should be enabled for IAM-based SSH access", "remediation": "gcloud compute project-info add-metadata --metadata enable-oslogin=TRUE"},
    {"id": "5.3", "title": "Serial port access disabled", "severity": "MEDIUM", "command": "gcloud compute instances list --format='table(name,metadata.items[key=serial-port-enable].value)'", "check": "Serial port should be disabled in production", "remediation": "gcloud compute instances add-metadata <instance> --metadata serial-port-enable=false"},
]

# ============================================================================
# TERRAFORM SECURITY SCANNERS
# ============================================================================
TERRAFORM_SCANNERS = [
    {"name": "tfsec", "description": "Static analysis of Terraform templates for security issues", "install": "brew install tfsec  # or go install github.com/aquasecurity/tfsec/cmd/tfsec@latest", "usage": "tfsec /path/to/terraform/", "checks": "500+ built-in checks for AWS, Azure, GCP"},
    {"name": "checkov", "description": "Policy-as-code for Terraform, CloudFormation, K8s, Dockerfiles", "install": "pip3 install checkov", "usage": "checkov -d /path/to/terraform/", "checks": "1000+ built-in checks across all major clouds"},
    {"name": "terrascan", "description": "IaC security scanner with OPA Rego policies", "install": "brew install terrascan", "usage": "terrascan scan -d /path/to/terraform/", "checks": "500+ policies for IaC security"},
    {"name": "KICS", "description": "Keeping Infrastructure as Code Secure by Checkmarx", "install": "docker pull checkmarx/kics", "usage": "docker run -v /path:/path checkmarx/kics scan -p /path -o /results", "checks": "1700+ queries for IaC security"},
]


class CloudDefense:
    name = "Cloud Security Posture Management"
    description = "AWS, Azure, GCP security auditing and CIS Benchmark compliance"
    category = "defense"
    mitre = ["T1078.004", "T1562.008"]

    def __init__(self, target=None, options=None):
        self.target = target
        self.options = options or {}
        self.findings = []
        self.actions = []

    def run(self, confirm_fn=None):
        cloud = self.options.get("cloud", "aws")
        if cloud == "aws":
            self._audit_aws(confirm_fn)
        elif cloud == "azure":
            self._audit_azure(confirm_fn)
        elif cloud == "gcp":
            self._audit_gcp(confirm_fn)
        elif cloud == "terraform":
            self._show_terraform_scanners()

    def _audit_aws(self, confirm_fn):
        print(f"\n{'='*60}")
        print("AWS CIS BENCHMARK SECURITY AUDIT")
        print(f"{'='*60}\n")
        for check in AWS_CIS_CHECKS:
            sev_colors = {"CRITICAL": "\033[31m", "HIGH": "\033[33m", "MEDIUM": "\033[36m", "LOW": "\033[37m"}
            color = sev_colors.get(check["severity"], "\033[0m")
            print(f"  [{color}{check['severity']}\033[0m] {check['id']} {check['title']}")
            print(f"    Check: {check['check']}")
            print(f"    Command: {check['command'][:120]}...")
            print(f"    Remediation: {check['remediation'][:120]}...")
            print()
            self.findings.append({
                "severity": check["severity"],
                "title": f"AWS CIS {check['id']}: {check['title']}",
                "detail": check["check"],
                "remediation": check["remediation"],
            })

    def _audit_azure(self, confirm_fn):
        print(f"\n{'='*60}")
        print("AZURE CIS BENCHMARK SECURITY AUDIT")
        print(f"{'='*60}\n")
        for check in AZURE_CIS_CHECKS:
            print(f"  [{check['severity']}] {check['id']} {check['title']}")
            print(f"    Check: {check['check']}")
            print()

    def _audit_gcp(self, confirm_fn):
        print(f"\n{'='*60}")
        print("GCP CIS BENCHMARK SECURITY AUDIT")
        print(f"{'='*60}\n")
        for check in GCP_CIS_CHECKS:
            print(f"  [{check['severity']}] {check['id']} {check['title']}")
            print(f"    Check: {check['check']}")
            print()

    def _show_terraform_scanners(self):
        print(f"\n{'='*60}")
        print("TERRAFORM / IaC SECURITY SCANNERS")
        print(f"{'='*60}\n")
        for scanner in TERRAFORM_SCANNERS:
            print(f"  {scanner['name']}")
            print(f"  {scanner['description']}")
            print(f"  Install: {scanner['install']}")
            print(f"  Usage: {scanner['usage']}")
            print(f"  Coverage: {scanner['checks']}")
            print()

    def get_findings(self):
        return self.findings


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="AEGIS Cloud Security Audit")
    parser.add_argument("--cloud", choices=["aws", "azure", "gcp", "terraform"], default="aws")
    args = parser.parse_args()
    mod = CloudDefense(options={"cloud": args.cloud})
    mod.run()
