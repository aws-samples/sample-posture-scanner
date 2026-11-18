# Sample: AWS posture, repository, and Bedrock GenAI security scanner

`aws-posture` is a cross-platform security assessment CLI with three separate
workflows:

- **AWS posture:** Prowler scans one AWS account or every active account in an
  AWS Organization.
- **Repository security:** Semgrep CE, Gitleaks, and Trivy scan a local or remote
  Git repository for insecure code, secrets, dependency CVEs, IaC
  misconfigurations, licenses, and software components.
- **GenAI red team:** promptfoo actively attacks Amazon Bedrock agents,
  knowledge bases (RAG), and managed prompts (fetched with `GetPrompt`) and
  reports which attacks succeeded, with evidence.

The tools remain independent engines with native evidence. Reports normalize and
deduplicate their results, but intentionally do not combine unrelated security
domains into one misleading score.

> **Detailed guide:** see [`docs/USAGE.md`](docs/USAGE.md) for full prerequisites,
> installation, every command and option, workflows, output layouts, exit codes,
> and troubleshooting.

## Pinned open-source tools

| Tool | Version | Purpose | License |
|---|---:|---|---|
| Prowler | 5.36.0 | AWS configuration posture and compliance | Apache-2.0 |
| Semgrep CE | 1.171.0 | Multi-language SAST | LGPL-2.1-or-later |
| Gitleaks | 8.30.1 | Current-tree and Git-history secret detection | MIT |
| Trivy | 0.72.0 | Dependency CVEs, IaC, licenses, CycloneDX SBOM | Apache-2.0 |
| promptfoo | 0.123.1 | Bedrock agent / knowledge-base / prompt red teaming | MIT |

`aws-posture` requires these exact scanner versions so validated command and
output schemas cannot silently drift.

## Requirements and installation

- Python 3.10–3.13 (Prowler 5.36.0 requires Python `<3.14`)
- Git on `PATH`
- AWS credentials only for AWS posture scans

Install Python tools in separate `pipx` environments:

### macOS/Linux

```bash
pipx install .
pipx install --python python3.12 prowler==5.36.0
pipx install --python python3.12 semgrep==1.171.0

# macOS current formulas provide the pinned releases shown above.
brew install gitleaks trivy

aws-posture check
aws-posture check --code
```

Linux users can instead download Gitleaks 8.30.1 and Trivy 0.72.0 from their
official GitHub releases, verify the published SHA-256/signature, and put the
binaries on `PATH`.

### Windows PowerShell

```powershell
py -m pip install pipx
py -m pipx ensurepath
pipx install .
pipx install --python 3.12 prowler==5.36.0
pipx install --python 3.12 semgrep==1.171.0
```

Download the exact Gitleaks and Trivy Windows archives from their official
release pages, validate the accompanying checksums, and add the extracted
executables to `PATH`. Open a new PowerShell and run:

```powershell
aws-posture check --code
```

**Supply-chain note:** Trivy's release ecosystem had a documented compromise in
2026 affecting older artifacts/tags. This project pins 0.72.0. Do not use
floating `latest` containers/actions; validate official release checksums or
signatures before installation.

## Unified repository scan

`scan-repository` accepts an existing checkout or an HTTPS/SSH/CodeCommit Git
URL. It runs all three repository scanners by default.

```bash
# Local repository: current checkout files and working-tree content.
aws-posture scan-repository ./my-application

# GitHub/GitLab/Bitbucket or another Git server.
aws-posture scan-repository https://github.com/example/my-application.git

# Specific branch or tag.
aws-posture scan-repository \
  https://gitlab.example.com/team/app.git --ref release-2026

# Private repository through an existing SSH agent.
aws-posture scan-repository git@github.com:example/private-app.git

# AWS CodeCommit through git-remote-codecommit.
aws-posture scan-repository \
  codecommit::us-east-1://security-profile@my-repository
```

Remote repositories use a shallow temporary clone by default. The clone is
deleted after reporting. For Gitleaks to inspect all reachable history, request
a full temporary clone explicitly:

```bash
aws-posture scan-repository https://github.com/example/app.git --history
```

For private HTTPS repositories, use the operating system's Git credential
helper. URLs containing HTTP credentials, passwords, query strings, or fragments
are rejected so tokens cannot enter process listings or manifests.

### Scanner controls

```bash
# Semgrep local rules avoid Registry access.
aws-posture scan-repository ./app --config ./security-rules

# Gitleaks custom rules and an approved baseline.
aws-posture scan-repository ./app \
  --gitleaks-config ./.gitleaks.toml \
  --gitleaks-baseline ./approved-gitleaks-baseline.json

# Use a previously cached Trivy database without downloading an update.
aws-posture scan-repository ./app --trivy-skip-db-update

# Exclude paths from Semgrep and Trivy.
aws-posture scan-repository ./app --exclude 'vendor/**'

# Run selected engines only.
aws-posture scan-repository ./app --skip-semgrep --skip-trivy

# Return 2 when a complete scan contains security findings.
aws-posture scan-repository ./app --fail-on-findings
```

Exit codes:

- `0`: complete scan; policy gate not requested or no findings
- `2`: complete scan with findings and `--fail-on-findings`
- `1`: checkout/scanner failure or incomplete scan

`scan-code` remains available as the backward-compatible Semgrep-only command.

### Repository results

```text
results/repository-scan-<timestamp>/
├── repository-scan-manifest.json
├── semgrep/raw/semgrep.json
├── gitleaks/raw/gitleaks.json          # sanitized; no secret values or author PII
├── trivy/raw/trivy.json
├── sbom/software-bom.cdx.json
└── report/
    ├── repository-report.html
    ├── repository-report.md
    └── repository-summary.json
```

Privacy and integrity controls:

- Semgrep metrics/version checks and Trivy telemetry/version checks are disabled.
- Trivy uses offline dependency analysis; only vulnerability/check database
  updates are downloaded unless `--trivy-skip-db-update` is set.
- Trivy secret scanning is disabled to avoid duplicating Gitleaks.
- Gitleaks always runs with 100% redaction. Raw output is staged outside the
  repository, parsed, stripped of secret/match/source-line/author/email/commit
  message fields, and only then persisted.
- Semgrep and Trivy terminal streams are suppressed. Their local raw files can
  contain source context; consolidated reports omit source snippets.
- Scanner outputs are staged outside the target so scanners cannot recursively
  scan their own evidence.
- Findings are deduplicated independently by stable domain-specific keys.
- Licenses and SBOM components are inventory, not counted as vulnerabilities.
- No combined repository or AWS score is generated.

## GenAI red team (Amazon Bedrock)

`scan-genai` is **active testing**, not a posture scan. It sends adversarial
prompts to live Bedrock targets, which costs tokens, can trigger guardrail or
abuse alarms, and can make agent tools perform real actions. Use non-production
agent aliases and knowledge bases. Attacks are only sent with
`--i-understand-active-testing`; `--plan` previews everything without sending any.

Prerequisites: Node.js 22.22+ and the pinned promptfoo release.

```bash
npm install -g promptfoo@0.123.1
aws-posture check --genai -p my-profile

# Separate invoke-only role (Get/List definitions, InvokeModel, InvokeAgent,
# Retrieve/RetrieveAndGenerate; no Bedrock write access). Plan, then apply.
aws-posture setup-genai-iam -p my-profile
aws-posture setup-genai-iam -p my-profile --apply
```

```bash
# Preview targets, plugins, and probe counts; resolves managed prompts via GetPrompt.
aws-posture scan-genai -p my-profile -r us-east-1 \
  --role arn:aws:iam::123456789012:role/GenAIRedTeamRole \
  --agent ABCDEFGHIJ:TSTALIASID \
  --knowledge-base KB12345678 --kb-model us.amazon.nova-pro-v1:0 \
  --prompt PROMPT1234@3 --prompt arn:aws:bedrock:us-east-1:123456789012:prompt/PROMPT5678 \
  --attacker-model us.anthropic.claude-sonnet-5 \
  --plan

# Same command with consent runs the red team.
aws-posture scan-genai ... --i-understand-active-testing --fail-on-findings
```

| Target | promptfoo provider | Main attack areas |
|---|---|---|
| `--agent ID:ALIAS` | `bedrock-agent` (InvokeAgent) | Excessive agency, RBAC, tool discovery, prompt extraction, SQL/shell injection through tools, PII, unauthorized commitments |
| `--knowledge-base ID` | `bedrock:kb` (RetrieveAndGenerate) | PII and privacy leakage, RBAC, prompt extraction, hallucination and over-reliance |
| `--prompt ID[@VERSION]` / `--all-prompts` | `bedrock:converse` using the prompt's own model and inference settings | Prompt extraction, PII, over-reliance; additional template variables get indirect-injection tests |

The attacker and grader is a Bedrock model in your own account
(`--attacker-model`). Promptfoo-hosted generation, telemetry, sharing, update
checks, and the response cache are disabled. In promptfoo 0.123.1 some plugins
work only with hosted generation (BOLA, BFLA, hijacking, system-prompt override,
SSRF, memory poisoning, cross-session leak, RAG document exfiltration and source
attribution, ASCII smuggling, special-token and indirect injection). These are
listed as **not run** in the report. `--allow-remote-generation` enables them,
but it sends the application purpose and attack data to Promptfoo, so it needs
explicit approval.

`--depth quick|standard|deep` controls tests per plugin and strategies (basic,
prompt injection, base64, jailbreak templates; `deep` adds iterative and tree
jailbreaks, Crescendo, and GOAT multi-turn attacks). Knowledge-base poisoning is
not performed because it requires writing documents into the data source.

```text
results/genai-scan-<timestamp>/
├── genai-scan-manifest.json
├── promptfoo/<target>/
│   ├── promptfooconfig.yaml     # generated config (no credentials)
│   ├── managed-prompt.json      # GetPrompt result for prompt targets
│   ├── redteam.yaml             # generated attacks
│   ├── results.json             # raw promptfoo results
│   └── promptfoo.log
└── report/
    ├── genai-report.html
    ├── genai-report.md
    └── genai-summary.json
```

Reports show each target's attack success rate per plugin, mapped to the OWASP
Top 10 for LLM Applications, with the attack, response, and grader reason for
every successful attack. Grader errors are counted as errored probes, not as
findings. No combined score is produced; a passing plugin means only that the
generated attacks failed. AWS credentials reach promptfoo through its process
environment, never through its command line or config files.

Exit codes: `0` complete; `2` complete with successful attacks and
`--fail-on-findings`; `1` a target or the scan failed.

## AWS posture scan

Prowler remains the only AWS posture engine. A normal run covers all Prowler
checks/services, all enabled Regions unless `--region` is supplied, and all
supported compliance reports from the same execution.

### Single account

IAM setup is plan-only unless `--apply` is explicitly supplied.

```bash
aws-posture check -p my-profile
aws-posture setup-iam -p my-profile
aws-posture setup-iam -p my-profile --apply

aws-posture scan -p my-profile \
  --role arn:aws:iam::123456789012:role/PostureScannerRole
```

Scans cover **all enabled regions** unless `-r/--region` filters them. After
Prowler completes, the scan automatically collects **IAM Access Analyzer**
ACTIVE findings into `access-analyzer/access-analyzer-findings.json`,
separating provable external access from theoretical misconfigurations
(disable with `--skip-access-analyzer`). Accepted-risk noise can be suppressed
with a Prowler mutelist: `--mutelist default` applies the bundled list of
known-noisy checks, or pass your own YAML file. Muted findings are
still collected but marked MUTED so they no longer distort the score.

```bash
aws-posture scan -p my-profile \
  --role arn:aws:iam::123456789012:role/PostureScannerRole \
  --mutelist default
```

For cross-account trust, configure and use the same External ID:

```bash
aws-posture setup-iam -p my-profile \
  --trusted-principal arn:aws:iam::111111111111:role/SecurityAuditRunner \
  --external-id '<generated-value>' --apply

aws-posture scan -p my-profile \
  --role arn:aws:iam::123456789012:role/PostureScannerRole \
  --external-id '<generated-value>'
```

The External ID is redacted from command logging and marked `NoEcho` in the
CloudFormation template. Note one inherent limitation: Prowler only accepts the
External ID as a command-line argument, so it is briefly visible to other local
users of the same machine in the process list while the scan starts. Run scans
from a single-user or dedicated host if that is a concern.

### Entire AWS Organization

Run from the Organizations management account or registered CloudFormation
StackSets delegated administrator. StackSets trusted access must already be
enabled, and an External ID is mandatory.

```bash
# Plan only.
aws-posture setup-org-iam -p management-profile \
  --external-id '<generated-value>'

# Approved organization-wide change.
aws-posture setup-org-iam -p management-profile \
  --external-id '<generated-value>' --apply

# Scan every active account.
aws-posture scan -p management-profile \
  --organization \
  --member-role-name PostureScannerRole \
  --external-id '<generated-value>' \
  --mutelist default
```

Organization scans apply the same all-enabled-regions default and mutelist,
and collect IAM Access Analyzer findings per account under
`access-analyzer/<account-id>/`.

To target one OU, add `--organizational-unit-id`. From a delegated administrator,
add `--delegated-admin`. Service-managed StackSets exclude the management
account; in delegated mode, deploy its scanner role separately with `setup-iam`.

Organization scans continue after an account failure and return `2` for partial,
`1` when every account fails, and `0` for complete.

### AWS results and deduplication

```text
results/scan-<timestamp>/
├── scan-manifest.json
├── prowler/raw/
│   ├── *.ocsf.json
│   ├── *.csv
│   ├── *.html
│   └── compliance/*.csv
├── access-analyzer/
│   └── access-analyzer-findings.json
└── report/
    ├── posture-report.html
    ├── posture-report.md
    └── posture-summary.json
```

Resource observations are normalized by account/check/resource/Region with the
newest state retained. Displayed issues are grouped by account/check, preserving
the same check separately in different accounts. Resource PASS/FAIL totals and
distinct issue counts are labeled separately.

The AWS risk-adjusted posture score is a local heuristic, not Prowler
ThreatScore or certification. It starts with resource pass rate and is capped by
the highest open severity: Critical ≤39, High ≤59, Medium ≤74, Low ≤89.

## IAM safety

The generated role contains AWS-managed `SecurityAudit` and `ViewOnlyAccess`
plus Prowler's required read additions, excluding
`securityhub:BatchImportFindings`. Normal scans are read-only.

`setup-iam --apply` and `setup-org-iam --apply` are infrastructure changes.
Review the plan and CloudFormation template with the account owner before applying.
No repository scan modifies the source checkout.

`setup-genai-iam --apply` creates a separate role that can invoke Bedrock
models, agents, and knowledge bases. Delete its stack when red teaming ends.

## Cost

Posture and repository scans use read-only AWS API calls and local tools.
`scan-genai` invokes Amazon Bedrock models, agents, and knowledge bases (the
target plus the attacker/grader model) and is billed at standard Bedrock rates.
Use `--plan` to see probe counts before running, and `--depth quick` for a
first pass. See [Amazon Bedrock pricing](https://aws.amazon.com/bedrock/pricing/).

## Disclaimer

This sample is provided for demonstration and educational purposes. It is not
a substitute for a professional security assessment and does not certify
compliance. Results are point-in-time. Only scan AWS accounts, repositories,
and Bedrock resources that you own or are explicitly authorized to test. GenAI
red teaming generates offensive and adversarial content by design. Review
the third-party tools listed in [THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md)
and their licenses before use.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.
