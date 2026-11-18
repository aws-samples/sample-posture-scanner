# AWS Posture Scanner - Quick Start Guide

## Step 1: Verify Installation

Open a terminal and run:

```bash
aws-posture --version
prowler --version
```

If the commands are not found, restart your shell or run
`source ~/.zshrc` (macOS) / `source ~/.bashrc` (Linux).

Expected output (versions may differ):
```
aws-posture <installed version>
Prowler <installed version>
```

---

## Step 2: Check Prerequisites

```bash
aws-posture check
```

This will show what's working and what needs configuration.

---

## Step 3: Configure AWS Credentials

You need AWS credentials before you can scan. Choose one option:

### Option A: AWS IAM Identity Center / SSO (Recommended)

```bash
aws configure sso
```

Follow the browser prompts to authenticate. This avoids long-lived static keys.
After setup, authenticate your session before scanning:

```bash
aws sso login --profile myprofile
```

### Option B: AWS CLI Profile (static access keys — not recommended for production)

```bash
aws configure --profile myprofile
```

You'll be prompted for:
- **AWS Access Key ID:** `AKIA...`
- **AWS Secret Access Key:** `...`
- **Default region:** `us-east-1` (or your preferred region)
- **Default output format:** `json`

> **Note:** Long-lived IAM user access keys are a higher-risk credential type.
> Prefer IAM Identity Center (Option A) where possible.

### Option C: Environment Variables

```bash
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_DEFAULT_REGION="us-east-1"
```

---

## Step 4: Test AWS Access

```bash
aws sts get-caller-identity --profile myprofile
```

Should return your AWS account ID and user ARN.

---

## Step 5: Set Up Scanner IAM Role

### Preview the role (no changes made):

```bash
aws-posture setup-iam -p myprofile
```

This shows what IAM role will be created.

### Create the role:

```bash
aws-posture setup-iam -p myprofile --apply
```

This creates a CloudFormation stack with a read-only IAM role named `PostureScannerRole`.

**Output will include:**
- Role ARN (save this for scanning)
- CloudFormation stack name
- Permissions summary

---

## Step 6: Run Your First Scan

### Simple scan (all regions, default checks):

```bash
aws-posture scan -p myprofile \
  --role arn:aws:iam::123456789012:role/PostureScannerRole
```

Replace `123456789012` with your actual AWS account ID from step 4.

### Scan with noise reduction:

```bash
aws-posture scan -p myprofile \
  --role arn:aws:iam::123456789012:role/PostureScannerRole \
  --mutelist default
```

The `--mutelist default` suppresses known-noisy checks.

### Scan specific regions only:

```bash
aws-posture scan -p myprofile \
  --role arn:aws:iam::123456789012:role/PostureScannerRole \
  --region us-east-1 --region us-west-2 \
  --mutelist default
```

---

## Step 7: View Results

After the scan completes, results are saved in:

```
results/scan-<timestamp>/
├── scan-manifest.json               # Scan metadata
├── prowler/raw/                     # Raw Prowler output
│   ├── posture-*.ocsf.json         # Detailed findings
│   ├── posture-*.csv               # CSV format
│   ├── posture-*.html              # HTML report
│   └── compliance/*.csv            # Compliance framework mappings (CIS, PCI-DSS, etc.) — not attestations
├── access-analyzer/                 # IAM Access Analyzer findings
│   └── access-analyzer-findings.json
└── report/                          # Consolidated reports
    ├── posture-report.html         # ⭐ Open this in your browser
    ├── posture-report.md           # Markdown summary
    └── posture-summary.json        # Machine-readable summary
```

### Open the main report:

```bash
open results/scan-*/report/posture-report.html
```

---

## Common Workflows

### Workflow 1: Single AWS Account Security Assessment

```bash
# 1. Configure AWS access
aws configure --profile audited-account

# 2. Set up scanner role
aws-posture setup-iam -p audited-account --apply

# 3. Run scan with noise filtering
aws-posture scan -p audited-account \
  --role arn:aws:iam::ACCOUNT-ID:role/PostureScannerRole \
  --mutelist default

# 4. Review HTML report
open results/scan-*/report/posture-report.html
```

### Workflow 2: AWS Organization (All Accounts)

```bash
# Must run from management account or delegated admin
aws-posture setup-org-iam -p management \
  --external-id 'unique-secret-value' \
  --apply

aws-posture scan -p management \
  --organization \
  --member-role-name PostureScannerRole \
  --external-id 'unique-secret-value' \
  --mutelist default
```

### Workflow 3: Repository Security Scan (No AWS needed)

```bash
# Local repository
aws-posture scan-repository ./my-app

# Remote repository (GitHub/GitLab/etc.)
aws-posture scan-repository https://github.com/yourorg/yourrepo.git

# With full Git history for secrets detection
aws-posture scan-repository https://github.com/yourorg/yourrepo.git --history

# Results in:
# results/repository-scan-<timestamp>/report/repository-report.html
```

---

## Troubleshooting

### "Unable to locate credentials"

Run: `aws sts get-caller-identity --profile myprofile`

If this fails, your credentials aren't configured. Repeat Step 3.

### "Prowler not found"

Run: `source ~/.zshrc` then `prowler --version`

### "Package requires Python >=3.10"

Your system is using old Python. The installation already set up Python 3.12 via pyenv.
Run: `source ~/.zshrc`

### Scan fails with permission errors

The profile you're using needs permissions to:
- Assume the scanner role
- Call AWS APIs (already granted by SecurityAudit + ViewOnlyAccess in the role)

---

## Next Steps

### For AWS Posture Scanning:
1. ✅ Configure AWS credentials (Step 3)
2. ✅ Set up scanner role (Step 5)
3. ✅ Run first scan (Step 6)
4. Review findings in HTML report
5. Address Critical/High findings
6. Set up recurring scans (weekly/monthly)

### For Repository Security:
1. Install additional tools: `brew install gitleaks trivy`
2. Install Semgrep: `pipx install --python python3.12 semgrep==1.171.0`
3. Run: `aws-posture check --code`
4. Scan repos: `aws-posture scan-repository <repo-path-or-url>`

---

## Full Documentation

- **Complete guide:** `docs/USAGE.md`
- **README:** `README.md`
- **Markdown guide:** `docs/USAGE.md`

---

## Support Commands

```bash
# Check what's installed
aws-posture check           # AWS posture prerequisites
aws-posture check --code    # Repository scanning prerequisites

# Get help
aws-posture --help
aws-posture scan --help
aws-posture setup-iam --help

# Version info
aws-posture --version
prowler --version
```

---

**Ready to start?** Begin with Step 3 (Configure AWS Credentials)!
