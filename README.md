# 🛡️ AWS Security Auditor

A Python-based AWS security misconfiguration scanner with a React dashboard for visualizing results. Designed to identify real-world security risks in your AWS account across multiple services.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![AWS](https://img.shields.io/badge/AWS-boto3-orange?logo=amazonaws)
![React](https://img.shields.io/badge/React-18-61DAFB?logo=react)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 📸 Dashboard Preview

> Load the `aws_audit_report.json` output into the React dashboard to explore findings interactively — filter by severity, service, or keyword, and click any finding to expand remediation steps.

---

## 🔍 What It Checks

| Service | Checks Performed |
|---|---|
| **S3** | Public access blocks, ACL public grants, missing encryption, versioning disabled |
| **IAM** | Root MFA, users without MFA, wildcard `*:*` policies (inline + managed) |
| **EC2** | Security groups exposing SSH, RDP, Telnet, Redis, MongoDB, etc. to `0.0.0.0/0` |
| **EBS** | Unencrypted volumes at rest |
| **CloudTrail** | Logging disabled, single-region trails, missing log validation |
| **RDS** | Publicly accessible instances, unencrypted storage, no Multi-AZ |

---

## ⚙️ Setup

### 1. Install dependencies

```bash
pip install boto3
```

### 2. Configure AWS credentials

You need read-only AWS access. The following managed policies are sufficient:

- `AmazonS3ReadOnlyAccess`
- `IAMReadOnlyAccess`
- `AmazonEC2ReadOnlyAccess`
- `AWSCloudTrailReadOnlyAccess`
- `AmazonRDSReadOnlyAccess`

Configure credentials via:

```bash
aws configure           # Interactive setup (recommended)
# OR set environment variables:
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_DEFAULT_REGION=us-east-1
```

---

## 🚀 Usage

```bash
# Run with default AWS profile
python aws_security_auditor.py

# Use a specific named profile
python aws_security_auditor.py --profile my-audit-profile

# Specify a region
python aws_security_auditor.py --region us-west-2

# Custom output file path
python aws_security_auditor.py --output results/my_report.json
```

### Example output

```
============================================================
  AWS Security Auditor
============================================================

  Account  : 123456789012
  Caller   : arn:aws:iam::123456789012:user/audit-user
  Region   : us-east-1

[*] Checking S3 Buckets...
  S3: scanned 8 buckets → 3 findings
[*] Checking IAM...
  IAM: 4 findings
[*] Checking EC2 Security Groups...
  EC2 Security Groups: 2 findings
[*] Checking EBS Volumes...
  EBS: scanned 12 volumes → 2 unencrypted
[*] Checking CloudTrail...
  CloudTrail: 2 findings
[*] Checking RDS Instances...
  RDS: scanned 2 instances → 1 findings

============================================================
  SCAN COMPLETE
============================================================
  Total findings : 14
    CRITICAL  : 3
    HIGH      : 5
    MEDIUM    : 4
    LOW       : 2

  Report saved to: aws_audit_report.json
```

---

## 📊 Dashboard

The React dashboard (`aws_security_dashboard.jsx`) visualizes the JSON report.

**Features:**
- Risk score calculated from finding severities
- Breakdown by service (S3, IAM, EC2, EBS, CloudTrail, RDS)
- Filter by severity level and service
- Keyword search across all findings
- Click any row to expand full description + recommendation
- Drag-and-drop or file picker to load your report

**To run the dashboard**, paste the JSX into [Claude.ai](https://claude.ai) as an artifact, or set up a local React project:

```bash
npm create vite@latest aws-dashboard -- --template react
cd aws-dashboard
# Replace src/App.jsx with aws_security_dashboard.jsx
npm install && npm run dev
```

---

## 📁 Project Structure

```
aws-security-auditor/
├── aws_security_auditor.py      # Main Python scanner
├── aws_security_dashboard.jsx   # React dashboard component
├── aws_audit_report.json        # Generated report (gitignored)
├── requirements.txt             # Python dependencies
└── README.md
```

---

## 🔒 Security Notes

- The auditor only uses **read-only** AWS API calls — it never modifies resources.
- **Never commit** `aws_audit_report.json` to a public repo — it contains account details.
- Add `aws_audit_report.json` to your `.gitignore`.

---

## 🗺️ Roadmap

- [ ] Add GuardDuty findings integration
- [ ] Support scanning multiple regions simultaneously
- [ ] Export findings as PDF report
- [ ] Add AWS Config rule comparison
- [ ] Slack/email alerting for critical findings

---

## 📄 License

MIT — feel free to use, modify, and extend.
