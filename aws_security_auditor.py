#!/usr/bin/env python3
"""
AWS Security Auditor
====================
Scans your AWS account for common security misconfigurations and outputs
a JSON report that can be consumed by the React dashboard.

Checks performed:
  - S3: Public access, missing encryption, missing versioning, public ACLs
  - IAM: Root MFA, users without MFA, overly permissive policies (*:*)
  - EC2 Security Groups: SSH/RDP open to the world (0.0.0.0/0)
  - EBS: Unencrypted volumes
  - CloudTrail: Disabled or not logging all regions
  - RDS: Publicly accessible instances, unencrypted storage

Usage:
  pip install boto3
  python aws_security_auditor.py                     # uses default AWS profile
  python aws_security_auditor.py --profile myprofile
  python aws_security_auditor.py --region us-east-1  # override region
  python aws_security_auditor.py --output report.json

Requirements:
  AWS credentials configured via ~/.aws/credentials, environment variables,
  or an IAM role. The IAM principal needs read-only permissions:
    - AmazonS3ReadOnlyAccess
    - IAMReadOnlyAccess
    - AmazonEC2ReadOnlyAccess
    - AWSCloudTrailReadOnlyAccess
    - AmazonRDSReadOnlyAccess
"""

import argparse
import json
import sys
from datetime import datetime, timezone

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError, EndpointResolutionError
except ImportError:
    print("ERROR: boto3 is not installed. Run: pip install boto3")
    sys.exit(1)


# ─── Severity helpers ────────────────────────────────────────────────────────

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def finding(severity: str, service: str, resource: str, title: str, description: str, recommendation: str) -> dict:
    return {
        "id": f"{service.upper()}-{abs(hash(resource + title)) % 10000:04d}",
        "severity": severity,
        "service": service,
        "resource": resource,
        "title": title,
        "description": description,
        "recommendation": recommendation,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ─── S3 checks ───────────────────────────────────────────────────────────────

def check_s3(session: boto3.Session) -> list[dict]:
    findings = []
    s3 = session.client("s3")

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        print(f"  [WARN] S3 list_buckets failed: {e}")
        return findings

    for bucket in buckets:
        name = bucket["Name"]

        # Public access block
        try:
            pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            if not all([pab.get("BlockPublicAcls"), pab.get("BlockPublicPolicy"),
                        pab.get("IgnorePublicAcls"), pab.get("RestrictPublicBuckets")]):
                findings.append(finding(
                    "HIGH", "S3", f"s3://{name}",
                    "Public access block not fully enabled",
                    "One or more public access block settings are disabled, which may allow public access.",
                    "Enable all four public access block settings on the bucket."
                ))
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                findings.append(finding(
                    "HIGH", "S3", f"s3://{name}",
                    "No public access block configuration",
                    "The bucket has no public access block configuration set.",
                    "Configure and enable all public access block settings."
                ))

        # Bucket ACL — check for public grants
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            public_uris = [
                "http://acs.amazonaws.com/groups/global/AllUsers",
                "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
            ]
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("URI") in public_uris:
                    findings.append(finding(
                        "CRITICAL", "S3", f"s3://{name}",
                        "Bucket ACL grants public access",
                        f"The bucket ACL grants '{grant['Permission']}' to '{grantee['URI']}'.",
                        "Remove the public grant from the bucket ACL and use bucket policies instead."
                    ))
                    break
        except ClientError:
            pass

        # Encryption
        try:
            s3.get_bucket_encryption(Bucket=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                findings.append(finding(
                    "MEDIUM", "S3", f"s3://{name}",
                    "Default encryption not enabled",
                    "The bucket does not have default server-side encryption configured.",
                    "Enable default SSE-S3 or SSE-KMS encryption on the bucket."
                ))

        # Versioning
        try:
            versioning = s3.get_bucket_versioning(Bucket=name)
            if versioning.get("Status") != "Enabled":
                findings.append(finding(
                    "LOW", "S3", f"s3://{name}",
                    "Versioning not enabled",
                    "Object versioning is disabled, which makes accidental deletions unrecoverable.",
                    "Enable versioning to protect against accidental deletion or overwrite."
                ))
        except ClientError:
            pass

    print(f"  S3: scanned {len(buckets)} buckets → {len(findings)} findings")
    return findings


# ─── IAM checks ──────────────────────────────────────────────────────────────

def check_iam(session: boto3.Session) -> list[dict]:
    findings = []
    iam = session.client("iam")

    # Root account MFA
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        if summary.get("AccountMFAEnabled", 0) == 0:
            findings.append(finding(
                "CRITICAL", "IAM", "Root account",
                "MFA not enabled on root account",
                "The AWS root account does not have MFA enabled, making it highly vulnerable.",
                "Enable a hardware or virtual MFA device on the root account immediately."
            ))
    except ClientError as e:
        print(f"  [WARN] IAM get_account_summary failed: {e}")

    # IAM users: MFA and console access
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                uname = user["UserName"]

                # Check MFA
                mfa_devices = iam.list_mfa_devices(UserName=uname)["MFADevices"]
                login_profile_exists = False
                try:
                    iam.get_login_profile(UserName=uname)
                    login_profile_exists = True
                except ClientError:
                    pass

                if login_profile_exists and not mfa_devices:
                    findings.append(finding(
                        "HIGH", "IAM", f"iam::user/{uname}",
                        f"Console user '{uname}' has no MFA",
                        "This user has console access but no MFA device configured.",
                        "Require MFA for all users with console access via an IAM policy."
                    ))

                # Check for overly permissive inline policies
                inline_policies = iam.list_user_policies(UserName=uname)["PolicyNames"]
                for pname in inline_policies:
                    doc = iam.get_user_policy(UserName=uname, PolicyName=pname)["PolicyDocument"]
                    if _has_star_star(doc):
                        findings.append(finding(
                            "CRITICAL", "IAM", f"iam::user/{uname}",
                            f"Inline policy '{pname}' allows Action:* Resource:*",
                            "This inline policy grants full admin privileges via wildcards.",
                            "Replace wildcards with specific actions and resources following least privilege."
                        ))
    except ClientError as e:
        print(f"  [WARN] IAM list_users failed: {e}")

    # Check managed policies for *:*
    try:
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for policy in page["Policies"]:
                version = iam.get_policy_version(
                    PolicyArn=policy["Arn"],
                    VersionId=policy["DefaultVersionId"]
                )["PolicyVersion"]["Document"]
                if _has_star_star(version):
                    findings.append(finding(
                        "HIGH", "IAM", policy["Arn"],
                        f"Customer-managed policy '{policy['PolicyName']}' allows *:*",
                        "This policy has Action:* and Resource:* which grants full admin access.",
                        "Refine this policy to only allow specific necessary actions and resources."
                    ))
    except ClientError as e:
        print(f"  [WARN] IAM list_policies failed: {e}")

    print(f"  IAM: {len(findings)} findings")
    return findings


def _has_star_star(doc: dict) -> bool:
    """Return True if the policy document has Action:* with Resource:*."""
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        action = stmt.get("Action", [])
        resource = stmt.get("Resource", [])
        if isinstance(action, str):
            action = [action]
        if isinstance(resource, str):
            resource = [resource]
        if "*" in action and "*" in resource:
            return True
    return False


# ─── EC2 Security Group checks ───────────────────────────────────────────────

DANGEROUS_PORTS = {
    22: ("SSH", "HIGH"),
    3389: ("RDP", "HIGH"),
    23: ("Telnet", "CRITICAL"),
    5900: ("VNC", "HIGH"),
    3306: ("MySQL", "MEDIUM"),
    5432: ("PostgreSQL", "MEDIUM"),
    1433: ("MSSQL", "MEDIUM"),
    6379: ("Redis", "HIGH"),
    27017: ("MongoDB", "HIGH"),
}

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def check_security_groups(session: boto3.Session) -> list[dict]:
    findings = []
    ec2 = session.client("ec2")

    try:
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                sg_id = sg["GroupId"]
                sg_name = sg.get("GroupName", sg_id)

                for rule in sg.get("IpPermissions", []):
                    from_port = rule.get("FromPort", 0)
                    to_port = rule.get("ToPort", 65535)
                    protocol = rule.get("IpProtocol", "-1")

                    all_cidrs = (
                        [r["CidrIp"] for r in rule.get("IpRanges", [])] +
                        [r["CidrIpv6"] for r in rule.get("Ipv6Ranges", [])]
                    )

                    is_open = any(c in OPEN_CIDRS for c in all_cidrs)
                    if not is_open:
                        continue

                    # All traffic open
                    if protocol == "-1":
                        findings.append(finding(
                            "CRITICAL", "EC2", f"sg/{sg_id} ({sg_name})",
                            "Security group allows ALL inbound traffic from internet",
                            "The security group has a rule allowing all protocols from 0.0.0.0/0.",
                            "Remove the all-traffic rule and add only the specific ports required."
                        ))
                        continue

                    # Check specific dangerous ports
                    for port, (service_name, sev) in DANGEROUS_PORTS.items():
                        if from_port <= port <= to_port:
                            findings.append(finding(
                                sev, "EC2", f"sg/{sg_id} ({sg_name})",
                                f"{service_name} port {port} open to the internet",
                                f"Port {port} ({service_name}) is accessible from 0.0.0.0/0 or ::/0.",
                                f"Restrict port {port} to known IP ranges or use VPN/bastion host access."
                            ))
    except ClientError as e:
        print(f"  [WARN] EC2 describe_security_groups failed: {e}")

    print(f"  EC2 Security Groups: {len(findings)} findings")
    return findings


# ─── EBS checks ──────────────────────────────────────────────────────────────

def check_ebs(session: boto3.Session) -> list[dict]:
    findings = []
    ec2 = session.client("ec2")

    try:
        paginator = ec2.get_paginator("describe_volumes")
        total = 0
        for page in paginator.paginate():
            for vol in page["Volumes"]:
                total += 1
                if not vol.get("Encrypted", False):
                    vol_id = vol["VolumeId"]
                    state = vol.get("State", "unknown")
                    findings.append(finding(
                        "MEDIUM", "EBS", vol_id,
                        "EBS volume is not encrypted",
                        f"Volume {vol_id} ({state}, {vol.get('Size', '?')}GB) is not encrypted at rest.",
                        "Enable EBS encryption by default in account settings, and re-create unencrypted volumes."
                    ))
        print(f"  EBS: scanned {total} volumes → {len(findings)} unencrypted")
    except ClientError as e:
        print(f"  [WARN] EBS describe_volumes failed: {e}")

    return findings


# ─── CloudTrail checks ───────────────────────────────────────────────────────

def check_cloudtrail(session: boto3.Session) -> list[dict]:
    findings = []
    ct = session.client("cloudtrail")

    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])

        if not trails:
            findings.append(finding(
                "CRITICAL", "CloudTrail", "account",
                "No CloudTrail trails configured",
                "No CloudTrail trail exists in this region. API activity is not being logged.",
                "Create a multi-region CloudTrail trail that logs to an S3 bucket."
            ))
            return findings

        for trail in trails:
            trail_name = trail.get("Name", "unknown")
            trail_arn = trail.get("TrailARN", trail_name)

            # Check if logging is enabled
            status = ct.get_trail_status(Name=trail_arn)
            if not status.get("IsLogging", False):
                findings.append(finding(
                    "HIGH", "CloudTrail", trail_arn,
                    f"Trail '{trail_name}' is not logging",
                    "This CloudTrail trail exists but logging is currently disabled.",
                    "Enable logging on the trail immediately."
                ))

            # Check multi-region
            if not trail.get("IsMultiRegionTrail", False):
                findings.append(finding(
                    "MEDIUM", "CloudTrail", trail_arn,
                    f"Trail '{trail_name}' is not multi-region",
                    "This trail only logs events in a single region.",
                    "Convert to a multi-region trail to capture API activity across all regions."
                ))

            # Check log file validation
            if not trail.get("LogFileValidationEnabled", False):
                findings.append(finding(
                    "LOW", "CloudTrail", trail_arn,
                    f"Trail '{trail_name}' has no log file validation",
                    "Log file validation is disabled; tampered logs cannot be detected.",
                    "Enable log file validation to ensure log integrity."
                ))

    except ClientError as e:
        print(f"  [WARN] CloudTrail checks failed: {e}")

    print(f"  CloudTrail: {len(findings)} findings")
    return findings


# ─── RDS checks ──────────────────────────────────────────────────────────────

def check_rds(session: boto3.Session) -> list[dict]:
    findings = []
    rds = session.client("rds")

    try:
        paginator = rds.get_paginator("describe_db_instances")
        total = 0
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                total += 1
                db_id = db["DBInstanceIdentifier"]

                if db.get("PubliclyAccessible", False):
                    findings.append(finding(
                        "HIGH", "RDS", db_id,
                        f"RDS instance '{db_id}' is publicly accessible",
                        "The instance endpoint is publicly reachable from the internet.",
                        "Set PubliclyAccessible=false and place the instance in a private subnet."
                    ))

                if not db.get("StorageEncrypted", False):
                    findings.append(finding(
                        "MEDIUM", "RDS", db_id,
                        f"RDS instance '{db_id}' storage is not encrypted",
                        "The RDS instance is not using encrypted storage.",
                        "Enable storage encryption. Note: requires a snapshot restore to encrypt existing instances."
                    ))

                if not db.get("MultiAZ", False) and db.get("DBInstanceClass", "").startswith("db."):
                    findings.append(finding(
                        "LOW", "RDS", db_id,
                        f"RDS instance '{db_id}' is not Multi-AZ",
                        "Single-AZ deployment has no automatic failover capability.",
                        "Enable Multi-AZ for production databases to improve availability."
                    ))

        print(f"  RDS: scanned {total} instances → {len(findings)} findings")
    except ClientError as e:
        print(f"  [WARN] RDS checks failed: {e}")

    return findings


# ─── Main ────────────────────────────────────────────────────────────────────

def run_audit(profile: str = None, region: str = None) -> dict:
    print("=" * 60)
    print("  AWS Security Auditor")
    print("=" * 60)

    session_kwargs = {}
    if profile:
        session_kwargs["profile_name"] = profile
    if region:
        session_kwargs["region_name"] = region

    try:
        session = boto3.Session(**session_kwargs)
        # Validate credentials
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        account_id = identity["Account"]
        caller_arn = identity["Arn"]
        current_region = session.region_name or "us-east-1"
        print(f"\n  Account  : {account_id}")
        print(f"  Caller   : {caller_arn}")
        print(f"  Region   : {current_region}")
        print()
    except NoCredentialsError:
        print("ERROR: No AWS credentials found.")
        print("Configure credentials via `aws configure` or environment variables.")
        sys.exit(1)
    except ClientError as e:
        print(f"ERROR: Could not authenticate: {e}")
        sys.exit(1)

    all_findings = []
    checks = [
        ("S3 Buckets", check_s3),
        ("IAM", check_iam),
        ("EC2 Security Groups", check_security_groups),
        ("EBS Volumes", check_ebs),
        ("CloudTrail", check_cloudtrail),
        ("RDS Instances", check_rds),
    ]

    for label, fn in checks:
        print(f"[*] Checking {label}...")
        try:
            results = fn(session)
            all_findings.extend(results)
        except Exception as e:
            print(f"  [ERROR] {label} check crashed: {e}")

    # Sort by severity
    all_findings.sort(key=lambda f: SEVERITY_RANK.get(f["severity"], 0), reverse=True)

    # Summary counts
    summary = {sev: 0 for sev in SEVERITY_RANK}
    for f in all_findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1

    report = {
        "meta": {
            "account_id": account_id,
            "caller_arn": caller_arn,
            "region": current_region,
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(all_findings),
        },
        "summary": summary,
        "findings": all_findings,
    }

    print("\n" + "=" * 60)
    print("  SCAN COMPLETE")
    print("=" * 60)
    print(f"  Total findings : {len(all_findings)}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = summary.get(sev, 0)
        if count:
            print(f"    {sev:<10}: {count}")
    print()

    return report


def main():
    parser = argparse.ArgumentParser(
        description="AWS Security Auditor — scan your AWS account for misconfigurations"
    )
    parser.add_argument("--profile", help="AWS CLI profile name", default=None)
    parser.add_argument("--region", help="AWS region to scan", default=None)
    parser.add_argument("--output", help="Output JSON file path", default="aws_audit_report.json")
    args = parser.parse_args()

    report = run_audit(profile=args.profile, region=args.region)

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"  Report saved to: {args.output}")
    print("  Load this file into the React dashboard to visualize results.\n")


if __name__ == "__main__":
    main()
