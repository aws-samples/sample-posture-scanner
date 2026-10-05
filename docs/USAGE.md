# aws-posture — Detailed Usage Guide

`aws-posture` is a cross-platform command-line security scanner with two
independent workflows:

1. **AWS posture** — runs Prowler against one AWS account or every active
   account in an AWS Organization.
2. **Repository security** — runs Semgrep CE, Gitleaks, and Trivy against a local
   or remote Git repository for insecure code, secrets, dependency
   vulnerabilities, IaC misconfigurations, licenses, and a software bill of
   materials (SBOM).

Each engine keeps its native evidence. Reports normalize and deduplicate
results but never merge unrelated security domains into one misleading score.

---

## 1. Prerequisites

### 1.1 Always required

| Requirement | Details |
|---|---|
| Operating system | macOS, Linux, or Windows (PowerShell) |
| Python | 3.10, 3.11, 3.12, or 3.13 (Prowler needs Python `<3.14`) |
| `pipx` | Recommended for isolated CLI installs |
| Git | Must be available on `PATH` (used by all repository scans) |

Check Python and Git:

```bash
python3 --version
git --version
```

### 1.2 Pinned scanner engines

`aws-posture` deliberately requires **exact** engine versions so validated
command lines and output schemas cannot drift. `check` fails if a version does
not match.

| Engine | Exact version | Needed for | License |
|---|---|---|---|
| Prowler | 5.36.0 | `scan` (AWS posture) | Apache-2.0 |
| Semgrep CE | 1.171.0 | `scan-code`, `scan-repository` | LGPL-2.1-or-later |
| Gitleaks | 8.30.1 | `scan-repository` | MIT |
| Trivy | 0.72.0 | `scan-repository` | Apache-2.0 |
| promptfoo | 0.123.1 (Node.js 22.22+) | `scan-genai` | MIT |

You only need the engines for the workflow you intend to run. For example, an
AWS-only user needs Prowler; a repository-only user needs Semgrep, Gitleaks, and
Trivy but not Prowler or AWS credentials.

### 1.3 AWS requirements (AWS posture only)

- Valid AWS credentials via any standard boto3 source: named profile, AWS SSO,
  environment variables, or an EC2/ECS/EKS instance role. Long-lived static
  access keys are discouraged.
- Outbound HTTPS access to AWS API endpoints.
- Permissions:
  - The scan identity needs read access. The bundled CloudFormation role grants
    AWS-managed `SecurityAudit` + `ViewOnlyAccess` plus Prowler's read-only
    additions.
  - `setup-iam --apply` needs CloudFormation + IAM permissions to create the role.
  - Organization scans additionally need `organizations:ListAccounts` and
    `sts:AssumeRole` into each member role, plus (for `setup-org-iam`)
    CloudFormation StackSets with **trusted access already enabled**.

### 1.4 Network and data notes

- Semgrep's default `p/default` rules download from the public Semgrep Registry.
  Use a local `--config` path for fully offline SAST.
- Trivy downloads its vulnerability database by default (disable with
  `--trivy-skip-db-update` once a local cache exists). Telemetry and version
  checks are always disabled by aws-posture.
- Gitleaks always runs with 100% secret redaction.

---

## 2. Installation

### 2.0 Obtaining the software

Clone the repository and install from source:

```bash
git clone https://github.com/aws-samples/sample-aws-posture-scanner.git
cd sample-aws-posture-scanner
```

Install the CLI and each engine in **separate** `pipx` environments to avoid
dependency conflicts.

### 2.1 macOS / Linux

```bash
# The aws-posture CLI
pipx install .

# Engines you need (install only what you will use)
pipx install --python python3.12 prowler==5.36.0
pipx install --python python3.12 semgrep==1.171.0

# Gitleaks + Trivy: Homebrew currently ships the pinned versions
brew install gitleaks trivy

# Verify
aws-posture check         # AWS posture prerequisites
aws-posture check --code  # repository-scan prerequisites
```

On Linux without Homebrew, download Gitleaks 8.30.1 and Trivy 0.72.0 from their
official GitHub releases, **verify the published SHA-256/signature**, and place
the binaries on `PATH`.

### 2.2 Windows PowerShell

```powershell
py -m pip install pipx
py -m pipx ensurepath

pipx install .
pipx install --python 3.12 prowler==5.36.0
pipx install --python 3.12 semgrep==1.171.0

# Download official Gitleaks 8.30.1 and Trivy 0.72.0 Windows archives,
# verify checksums, and add the executables to PATH.

# Open a NEW PowerShell after ensurepath, then:
aws-posture check --code
```

### 2.3 Easiest path: convenience installer scripts

Instead of running the commands above by hand, use the bundled installer for your
platform. Each script installs the CLI and pinned Python engines with `pipx`,
installs Gitleaks/Trivy where possible, and finishes by running `check`.

macOS / Linux:

```bash
./scripts/install-prerequisites.sh .
```

Windows PowerShell:

```powershell
.\scripts\install-prerequisites.ps1 -Wheel .
```

The scripts are safe to re-run; they use `pipx install --force` so re-running
repairs or upgrades an environment. Any component they cannot install
automatically (for example Gitleaks/Trivy without Homebrew) is printed with the
official download link so you can install and checksum-verify it manually.

### 2.4 Supply-chain caution (Trivy)

Trivy's release ecosystem had a documented compromise in 2026 affecting older
artifacts and tags. Always pin **0.72.0**, verify official checksums or
signatures, and never use floating `latest` containers or CI actions.

---

## 3. Command overview

```
aws-posture <command> [options]

Commands:
  check            Check prerequisites (AWS posture, or --code for repo scans)
  setup-iam        Plan/create the read-only scanner role in one account
  setup-org-iam    Plan/deploy the scanner role across an Organization
  scan             Run Prowler for one account or the whole Organization
  scan-code        Run Semgrep CE only against a Git repository
  scan-repository  Run Semgrep + Gitleaks + Trivy against a Git repository
  setup-genai-iam  Plan/create the invoke-only GenAI red-team role
  scan-genai       Red-team Bedrock agents, knowledge bases, and managed prompts
  summarize        Rebuild an AWS report from existing Prowler JSON
```

Global:

```bash
aws-posture --version
aws-posture <command> --help
```

### 3.1 Where results are saved

Every scan writes a timestamped folder. By default it is created under
`results/` in your current working directory:

| Command | Default output folder |
|---|---|
| `scan` | `./results/scan-<timestamp>/` |
| `scan-code` | `./results/code-scan-<timestamp>/` |
| `scan-repository` | `./results/repository-scan-<timestamp>/` |

Use `-o` (or `--output`) to choose any location, for example your Desktop:

```bash
# macOS / Linux — save to the Desktop
aws-posture scan -p my-profile --role <role-arn> \
  -o ~/Desktop/aws-posture-results/aws-scan

aws-posture scan-repository ./my-app \
  -o ~/Desktop/aws-posture-results/repo-scan
```

```powershell
# Windows PowerShell — save to the Desktop
aws-posture scan -p my-profile --role <role-arn> `
  -o $HOME\Desktop\aws-posture-results\aws-scan
```

The output folder is created automatically. For `scan-repository` it must be new
or empty so scanner evidence cannot be scanned recursively. `-o` applies to a
single run; there is no persistent default location.

---

## 4. `check` — verify prerequisites

```bash
# AWS posture: checks Python, Prowler 5.36.0, and AWS credentials
aws-posture check
aws-posture check -p my-aws-profile

# Repository scanning: checks Python, Git, Semgrep, Gitleaks, Trivy
aws-posture check --code
```

Exit code `0` means all required components are present; `1` means one or more
are missing or mismatched.

---

## 5. Repository security scanning

### 5.1 `scan-repository` (recommended)

Runs all three engines by default.

```bash
# Local checkout
aws-posture scan-repository ./my-application

# Remote repository (shallow temporary clone, deleted afterward)
aws-posture scan-repository https://github.com/example/app.git

# Specific branch or tag
aws-posture scan-repository https://gitlab.example.com/team/app.git --ref release-2026

# Private repo via existing SSH agent
aws-posture scan-repository git@github.com:example/private-app.git

# AWS CodeCommit (git-remote-codecommit)
aws-posture scan-repository codecommit::us-east-1://security-profile@my-repository

# Full Git history secret scan (requires a complete clone)
aws-posture scan-repository https://github.com/example/app.git --history
```

Options:

| Option | Default | Purpose |
|---|---|---|
| `--ref <branch/tag>` | remote default branch | Which remote ref to clone |
| `--history` | off | Scan complete Git history for secrets, not just the current tree |
| `--config <rules>` (repeatable) | `p/default` | Semgrep registry ruleset or local YAML/dir (local = offline) |
| `--exclude <glob>` (repeatable) | none | Paths excluded from Semgrep and Trivy |
| `--timeout <seconds>` | 30 | Semgrep per-rule timeout |
| `--gitleaks-config <toml>` | built-in | Custom Gitleaks rules |
| `--gitleaks-baseline <json>` | none | Ignore findings already in an approved baseline |
| `--gitleaks-timeout <seconds>` | 0 (none) | Gitleaks timeout |
| `--trivy-timeout <dur>` | `10m` | Trivy timeout (e.g. `30s`, `5m`, `1h`) |
| `--trivy-skip-db-update` | off | Reuse a cached Trivy DB without downloading |
| `--skip-semgrep` / `--skip-gitleaks` / `--skip-trivy` | off | Disable an engine |
| `-o, --output <dir>` | `results/repository-scan-<timestamp>` | Output folder (must be new/empty) |
| `--fail-on-findings` | off | Return exit code 2 when findings exist (for CI) |

Examples:

```bash
# Fully offline SAST rules + reuse cached Trivy DB
aws-posture scan-repository ./app --config ./security-rules --trivy-skip-db-update

# Secrets only
aws-posture scan-repository ./app --skip-semgrep --skip-trivy

# CI gate
aws-posture scan-repository ./app --fail-on-findings
```

#### Private repositories

aws-posture never accepts a credential inside the repository URL — such URLs are
rejected so tokens cannot leak into process listings or reports. Authentication
is handled by your machine's existing, non-interactive Git configuration. Use
one of these:

- **SSH key + agent (recommended).** Load your key (`ssh-add ~/.ssh/id_ed25519`)
  and use the SSH URL:
  ```bash
  aws-posture scan-repository git@github.com:your-org/private-repo.git \
    -o ~/Desktop/aws-posture-results/private
  ```
- **HTTPS + Git credential helper.** If `git` is already authenticated on the
  machine (for example via `gh auth login`, macOS Keychain, or Git Credential
  Manager), the HTTPS URL works without any secret on the command line:
  ```bash
  aws-posture scan-repository https://github.com/your-org/private-repo.git
  ```
- **Pre-cloned checkout (no network auth).** Clone it yourself, then scan the
  local folder:
  ```bash
  git clone git@github.com:your-org/private-repo.git ./repo
  aws-posture scan-repository ./repo
  ```
- **AWS CodeCommit.** Use `codecommit::<region>://<profile>@<repo>` (authenticated
  by your AWS profile) or the HTTPS/SSH clone URL.

Read-only access is sufficient — the tool only clones and reads. Because Git runs
non-interactively, an unauthenticated private clone fails fast with a clear error
(credentials are stripped from the message) rather than prompting for a password.

### 5.2 `scan-code` (Semgrep only)

Backward-compatible SAST-only command with the same source/`--ref`/`--config`/
`--exclude`/`--timeout`/`-o`/`--fail-on-findings` semantics as above.

```bash
aws-posture scan-code ./my-application
aws-posture scan-code https://github.com/example/app.git --ref main
```

### 5.3 Repository output layout

```
results/repository-scan-<timestamp>/
├── repository-scan-manifest.json     # revision + per-scanner status
├── semgrep/raw/semgrep.json          # raw Semgrep output
├── gitleaks/raw/gitleaks.json        # sanitized (no secret values or PII)
├── trivy/raw/trivy.json              # dependency/IaC/license evidence
├── sbom/software-bom.cdx.json        # CycloneDX SBOM
└── report/
    ├── repository-report.html        # unified, domain-separated report
    ├── repository-report.md
    └── repository-summary.json
```

Privacy behavior:

- Gitleaks secret values, matched text, source lines, author, email, and commit
  messages are never written to disk by aws-posture.
- Semgrep/Trivy raw files may contain source context; the consolidated report
  omits snippets.
- No combined score is produced; SAST, secrets, dependencies, IaC, licenses, and
  SBOM are reported separately.

---

## 6. AWS posture scanning

### 6.1 Prepare the scanner role

IAM setup is **plan-only** unless you pass `--apply`.

```bash
# 1. Verify credentials + Prowler
aws-posture check -p my-aws-profile

# 2. Preview the role (no changes)
aws-posture setup-iam -p my-aws-profile

# 3. Create/update the role (approved change)
aws-posture setup-iam -p my-aws-profile --apply
```

Cross-account trust requires an External ID:

```bash
aws-posture setup-iam -p my-aws-profile \
  --trusted-principal arn:aws:iam::111111111111:role/SecurityAuditRunner \
  --external-id '<generated-value>' --apply
```

`setup-iam` / `setup-org-iam` shared options:

| Option | Default | Purpose |
|---|---|---|
| `--apply` | off | Actually create/update resources (else plan only) |
| `-p, --profile` | default creds | AWS profile |
| `--role-name` | `PostureScannerRole` | Scanner role name |
| `--external-id` | empty | Required for cross-account / org trust |
| `--stack-name` | `prowler-scanner-iam` | CloudFormation stack |
| `--stack-region` | profile/`us-east-1` | Deployment region |
| `--trusted-principal` | current identity | Exact IAM role/user/root ARN to trust |
| `--session-duration` | 3600 | Max role session seconds (3600–43200) |

`setup-org-iam` adds:

| Option | Default | Purpose |
|---|---|---|
| `--stack-set-name` | `prowler-scanner-organization` | Service-managed StackSet |
| `--organizational-unit-id` | org root | Target OU/root |
| `--delegated-admin` | off | Run from a delegated administrator account |

### 6.2 Single-account scan

```bash
# Omitting --region scans all enabled Regions
aws-posture scan -p my-aws-profile \
  --role arn:aws:iam::123456789012:role/PostureScannerRole

# Cross-account with External ID
aws-posture scan -p my-aws-profile \
  --role arn:aws:iam::123456789012:role/PostureScannerRole \
  --external-id '<generated-value>'

# Limit Regions
aws-posture scan -p my-aws-profile --role <role-arn> --region us-east-1 eu-west-1
```

### 6.3 Whole-Organization scan

Deploy the role everywhere (from the management account or a delegated admin):

```bash
# Plan
aws-posture setup-org-iam -p management-profile \
  --external-id '<generated-value>'

# Apply (organization-wide change)
aws-posture setup-org-iam -p management-profile \
  --external-id '<generated-value>' --apply

# Target one OU instead of the root
aws-posture setup-org-iam -p management-profile \
  --external-id '<value>' --organizational-unit-id ou-xxxx-yyyyyyyy --apply

# From a delegated administrator
aws-posture setup-org-iam -p delegated-profile \
  --external-id '<value>' --delegated-admin --apply
```

Then scan every active account:

```bash
aws-posture scan -p management-profile \
  --organization \
  --member-role-name PostureScannerRole \
  --external-id '<generated-value>'
```

Notes:
- Service-managed StackSets exclude the management account. When using
  `--delegated-admin`, deploy the management-account role separately with
  `setup-iam`.
- `--organizations-role <arn>` can supply a separate metadata role.

`scan` options:

| Option | Default | Purpose |
|---|---|---|
| `-p, --profile` | default creds | AWS source profile |
| `-r, --region <r...>` | all enabled | Optional Region filter |
| `--role <arn>` | none | Single-account scanner role |
| `--organization` | off | Scan every active Organization account (mutually exclusive with `--role`) |
| `--member-role-name` | `PostureScannerRole` | Role assumed in each member account |
| `--organizations-role <arn>` | none | Management role for account metadata |
| `--external-id <value>` | none | Required for cross-account/org roles |
| `--session-duration` | 3600 | Role session seconds |
| `-o, --output <dir>` | `results/scan-<timestamp>` | Output folder |

### 6.4 AWS output layout

```
results/scan-<timestamp>/
├── scan-manifest.json                # scope, versions, per-account status
├── prowler/raw/
│   ├── *.ocsf.json                   # machine-readable findings
│   ├── *.csv
│   ├── *.html
│   └── compliance/*.csv              # all compliance frameworks
└── report/
    ├── posture-report.html           # consolidated deduplicated report
    ├── posture-report.md
    └── posture-summary.json
```

### 6.5 Rebuild a report without rescanning

```bash
aws-posture summarize ./results/scan-20260725-120000/prowler/raw -o ./report
aws-posture summarize "./results/**/*.ocsf.json" -o ./report
```

### 6.6 Score interpretation

The AWS risk-adjusted score is a **local heuristic**, not Prowler ThreatScore or
a certification. It starts from the resource pass rate and is capped by the
highest open severity: Critical ≤39, High ≤59, Medium ≤74, Low ≤89. Always act
on the prioritized findings, not the score alone.

---

## 6A. GenAI red teaming (`scan-genai`)

> **Active testing.** Adversarial prompts are sent to live Bedrock targets.
> This costs tokens, may trigger guardrail or abuse alarms, and agent action
> groups may perform real actions. Use non-production aliases and knowledge
> bases and get written authorization. Without `--i-understand-active-testing`
> the command refuses to send attacks.

### 6A.1 Prepare

```bash
npm install -g promptfoo@0.123.1          # Node.js 22.22+ required
aws-posture check --genai -p my-profile
aws-posture setup-genai-iam -p my-profile          # plan
aws-posture setup-genai-iam -p my-profile --apply  # creates GenAIRedTeamRole
```

The red-team role is separate from `PostureScannerRole`. It can read agent,
alias, knowledge-base, and prompt definitions, and call `InvokeModel`,
`InvokeAgent`, `Retrieve`, and `RetrieveAndGenerate`. It has no Bedrock
write permissions. `setup-genai-iam` accepts the same options as `setup-iam`
(defaults: role `GenAIRedTeamRole`, stack `genai-redteam-iam`).

### 6A.2 Run

```bash
# 1. Preview: resolves agents/KBs, calls GetPrompt, writes configs, sends nothing.
aws-posture scan-genai -p my-profile -r us-east-1 \
  --role arn:aws:iam::123456789012:role/GenAIRedTeamRole \
  --agent ABCDEFGHIJ:TSTALIASID \
  --knowledge-base KB12345678 --kb-model us.amazon.nova-pro-v1:0 \
  --prompt PROMPT1234@3 \
  --attacker-model us.anthropic.claude-sonnet-5 --plan

# 2. Execute after approval.
aws-posture scan-genai ... --i-understand-active-testing

# Every managed prompt (DRAFT) in the region
aws-posture scan-genai -p my-profile --all-prompts \
  --attacker-model us.anthropic.claude-sonnet-5 --i-understand-active-testing
```

| Option | Default | Purpose |
|---|---|---|
| `--agent ID:ALIAS` (repeatable) | none | Bedrock agent and alias to attack |
| `--knowledge-base ID` (repeatable) | none | Knowledge base attacked through RetrieveAndGenerate |
| `--kb-model <model>` | none | Generation model for knowledge-base targets (required with `--knowledge-base`) |
| `--prompt ID_OR_ARN[@VERSION]` (repeatable) | DRAFT | Managed prompt fetched with GetPrompt |
| `--all-prompts` | off | Add every managed prompt in the region |
| `--prompt-model <model>` | prompt's model | Model for prompts that do not define one |
| `--prompt-inject-var <name>` | first variable | Template variable that receives attacker input |
| `--attacker-model <model>` | required | Bedrock model that generates attacks and grades responses |
| `--purpose <text>` | derived from agent/KB/prompt | Application description used to tailor attacks |
| `--depth quick\|standard\|deep` | standard | Tests per plugin (1/3/5) and attack strategies |
| `--plugin <id>` (repeatable) | none | Add a promptfoo plugin |
| `--allow-remote-generation` | off | Allow Promptfoo-hosted generation (sends data to Promptfoo) |
| `--max-concurrency <n>` | 2 | Concurrent promptfoo requests (1–16) |
| `--timeout <seconds>` | 3600 | Limit per promptfoo step |
| `--role`, `--external-id`, `--session-duration` | none | Assume the red-team role |
| `--plan` | off | Preview only |
| `--i-understand-active-testing` | off | Required to send attacks |
| `-o, --output <dir>` | `results/genai-scan-<timestamp>` | Output folder (new or empty) |
| `--fail-on-findings` | off | Exit code 2 when any attack succeeds |

### 6A.3 How results are judged

promptfoo grades each response with `--attacker-model`. A **successful attack**
means the grader judged that the target violated the plugin's policy (for
example, revealed its instructions or took an unrequested action). Responses the
grader could not judge are counted as errored probes, not findings. Results are
probabilistic. Re-run after fixes, and treat 0% as "these attacks failed" rather
than "secure". The report includes the attack, response, and grader reason for
every successful attack. These can contain sensitive data returned by the
target, so handle the output folder as confidential.

---

## 7. Exit codes

| Code | Meaning |
|---|---|
| `0` | Success / complete (no policy gate triggered) |
| `2` | Completed with findings and `--fail-on-findings`; or a **partial** Organization scan (some accounts failed) |
| `1` | Failure: bad prerequisites, checkout/scanner error, or every account failed |

These make the tool CI-friendly: gate a pipeline on non-zero exit.

---

## 8. Typical workflows

### 8.1 Developer laptop, one repository

```bash
aws-posture check --code
aws-posture scan-repository ./my-service
open results/repository-scan-*/report/repository-report.html
```

### 8.2 CI pipeline (repository)

```bash
aws-posture check --code
aws-posture scan-repository "$CI_PROJECT_DIR" \
  --config ./security-rules \
  --trivy-skip-db-update \
  --fail-on-findings
# non-zero exit fails the job
```

### 8.3 Single AWS account posture

```bash
aws-posture check -p audit
aws-posture setup-iam -p audit --apply
aws-posture scan -p audit --role arn:aws:iam::123456789012:role/PostureScannerRole
```

By default the scan covers **all enabled regions** and, after Prowler
completes, automatically collects **IAM Access Analyzer** ACTIVE findings
(written to `access-analyzer/access-analyzer-findings.json`). Access Analyzer
distinguishes resources that are *provably* externally accessible from
theoretical Prowler misconfigurations. Disable with `--skip-access-analyzer`.

To suppress known-noisy / accepted-risk checks, pass a Prowler mutelist:

```bash
# Bundled default mutelist (confused-deputy heuristic, launch-wizard SGs,
# S3 MFA-delete/KMS-specific checks, hardware-MFA requirement, EBS snapshot
# hygiene, approved delegated administrators)
aws-posture scan -p audit --role <role-arn> --mutelist default

# Or a account-specific mutelist file
aws-posture scan -p audit --role <role-arn> --mutelist ./account-mutelist.yaml
```

Muted findings are still collected by Prowler but marked MUTED, so they no
longer distort the posture score. Review the bundled list with the account
owner before use — muting is a policy decision.

### 8.4 Whole AWS Organization

```bash
aws-posture setup-org-iam -p management --external-id "$EXTERNAL_ID" --apply
aws-posture scan -p management --organization \
  --member-role-name PostureScannerRole --external-id "$EXTERNAL_ID" \
  --mutelist default
```

Organization scans apply the same region behaviour (all enabled regions per
account unless `-r` is given), the same mutelist, and collect Access Analyzer
findings per account under `access-analyzer/<account-id>/`.

---

## 9. Troubleshooting

| Symptom | Cause | Resolution |
|---|---|---|
| `check` shows a scanner as MISS with a version | Wrong engine version installed | Install the exact pinned version (§1.2) |
| `Unsupported Prowler/Semgrep/Gitleaks/Trivy version` | Version mismatch at scan time | Reinstall the pinned version |
| `Git was not found on PATH` | Git missing | Install Git and reopen the shell |
| `Repository URLs must not contain credentials` | Token/password embedded in URL | Use an SSH agent or Git credential helper |
| `Repository scan output must be a new or empty directory` | `-o` points at a non-empty folder | Use a fresh output directory |
| `AWS credentials are not valid or available` | No/expired credentials | Configure a profile, SSO, env vars, or instance role |
| Organization scan returns `2` | One or more accounts failed | Check `scan-manifest.json`; ensure the role is deployed and assumable in each account |
| Trivy scan errors on first run offline | DB not yet cached | Run once with network access, then use `--trivy-skip-db-update` |
| Semgrep needs network for `p/default` | Registry rules download | Use a local `--config` directory for offline scans |

Get detailed diagnostics by running the underlying engine directly (for example
`semgrep --version`, `trivy fs --help`, `gitleaks version`, `prowler --version`).

---

## 10. Safety summary

- IAM changes happen only with `--apply`; everything else is plan/read-only.
- The scanner role is read-only (`SecurityAudit`, `ViewOnlyAccess`, plus Prowler
  read additions; no `securityhub:BatchImportFindings`).
- Repository scans never modify the source; remote clones are temporary and
  deleted after reporting.
- Secrets are fully redacted; credentials are never accepted in URLs or stored in
  manifests, and External IDs are redacted from logs and marked `NoEcho` in
  CloudFormation.
- Known limitation: Prowler accepts the External ID only as a command-line
  argument, so it is briefly visible in the local process list to other users of
  the same machine. Use a single-user or dedicated scan host if this matters in
  your environment.
