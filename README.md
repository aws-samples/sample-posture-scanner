# AWS Posture Scanner



## Getting started

To make it easy for you to get started with GitLab, here's a list of recommended next steps.

Already a pro? Just edit this README.md and make it your own. Want to make it easy? [Use the template at the bottom](#editing-this-readme)!

## Add your files

`aws-posture` requires these exact scanner versions so validated command and
output schemas are designed not to silently drift.

## Architecture

```
Figure 1: aws-posture components and trust boundaries

  ┌──────────────────────────────────────────────┐
  │  Operator host / CI runner                   │
  │                                              │
  │  aws-posture CLI                             │
  │    ├─ Prowler ──────────────────────────┐   │
  │    ├─ Semgrep / Gitleaks / Trivy        │   │
  │    │   (local repo; no AWS calls)       │   │
  │    └─ promptfoo (GenAI red team) ───┐   │   │
  └─────────────────────────────────────┼───┼───┘
                sts:AssumeRole (HTTPS)  │   │
                                        │   │ Bedrock API (HTTPS)
                                        ▼   ▼
  ┌──────────────────────┐    ┌────────────────────────────┐
  │  Target AWS          │    │  Amazon Bedrock            │
  │  Account(s)          │    │  (non-prod agents/KBs only)│
  │                      │    │                            │
  │  PostureScannerRole  │    │  GenAIRedTeamRole          │
  │  (read-only)         │    │  (invoke-only)             │
  └──────────────────────┘    └────────────────────────────┘

  setup-org-iam: CloudFormation StackSet deploys PostureScannerRole
  to every member account; AutoDeployment enrolls new accounts.
```

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

# Preferred: download the exact release binaries, verify checksums, place on PATH.
# Gitleaks 8.30.1: https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1
# Trivy 0.72.0:    https://github.com/aquasecurity/trivy/releases/tag/v0.72.0
#
# macOS Homebrew alternative (verify that the current formula ships the pinned version):
# brew install gitleaks trivy

aws-posture check
aws-posture check --code
```

## Integrate with your tools

- [ ] [Set up project integrations](https://gitlab.aws.dev/divz/aws-posture-scanner/-/settings/integrations)

## Collaborate with your team

- [ ] [Invite team members and collaborators](https://docs.gitlab.com/ee/user/project/members/)
- [ ] [Create a new merge request](https://docs.gitlab.com/ee/user/project/merge_requests/creating_merge_requests.html)
- [ ] [Automatically close issues from merge requests](https://docs.gitlab.com/ee/user/project/issues/managing_issues.html#closing-issues-automatically)
- [ ] [Enable merge request approvals](https://docs.gitlab.com/ee/user/project/merge_requests/approvals/)
- [ ] [Set auto-merge](https://docs.gitlab.com/user/project/merge_requests/auto_merge/)

## Test and Deploy

**Supply-chain note:** Trivy has experienced supply-chain incidents affecting
release artifacts and tags. This project pins 0.72.0. Do not use floating
`latest` containers/actions; validate official release checksums or signatures
before installation.

- [ ] [Get started with GitLab CI/CD](https://docs.gitlab.com/ee/ci/quick_start/)
- [ ] [Analyze your code for known vulnerabilities with Static Application Security Testing (SAST)](https://docs.gitlab.com/ee/user/application_security/sast/)
- [ ] [Deploy to Kubernetes, Amazon EC2, or Amazon ECS using Auto Deploy](https://docs.gitlab.com/ee/topics/autodevops/requirements.html)
- [ ] [Use pull-based deployments for improved Kubernetes management](https://docs.gitlab.com/ee/user/clusters/agent/)
- [ ] [Set up protected environments](https://docs.gitlab.com/ee/ci/environments/protected_environments.html)

***

# Editing this README

When you're ready to make this README your own, just edit this file and use the handy template below (or feel free to structure it however you want - this is just a starting point!). Thanks to [makeareadme.com](https://www.makeareadme.com/) for this template.

## Suggestions for a good README

Every project is different, so consider which of these sections apply to yours. The sections used in the template are suggestions for most open source projects. Also keep in mind that while a README can be too long and detailed, too long is better than too short. If you think your README is too long, consider utilizing another form of documentation rather than cutting out information.

## Name
Choose a self-explaining name for your project.

## Description
Let people know what your project can do specifically. Provide context and add a link to any reference visitors might be unfamiliar with. A list of Features or a Background subsection can also be added here. If there are alternatives to your project, this is a good place to list differentiating factors.

## Badges
On some READMEs, you may see small images that convey metadata, such as whether or not all the tests are passing for the project. You can use Shields to add some to your README. Many services also have instructions for adding a badge.

For private HTTPS repositories, use the operating system's Git credential
helper. URLs containing HTTP credentials, passwords, query strings, or fragments
are rejected so that tokens do not enter process listings or manifests.

## Installation
Within a particular ecosystem, there may be a common way of installing things, such as using Yarn, NuGet, or Homebrew. However, consider the possibility that whoever is reading your README is a novice and would like more guidance. Listing specific steps helps remove ambiguity and gets people to using your project as quickly as possible. If it only runs in a specific context like a particular programming language version or operating system or has dependencies that have to be installed manually, also add a Requirements subsection.

## Usage
Use examples liberally, and show the expected output if you can. It's helpful to have inline the smallest example of usage that you can demonstrate, while providing links to more sophisticated examples if they are too long to reasonably include in the README.

## Support
Tell people where they can go to for help. It can be any combination of an issue tracker, a chat room, an email address, etc.

## Roadmap
If you have ideas for releases in the future, it is a good idea to list them in the README.

## Contributing
State if you are open to contributions and what your requirements are for accepting them.

For people who want to make changes to your project, it's helpful to have some documentation on how to get started. Perhaps there is a script that they should run or some environment variables that they need to set. Make these steps explicit. These instructions could also be useful to your future self.

You can also document commands to lint the code or run tests. These steps help to ensure high code quality and reduce the likelihood that the changes inadvertently break something. Having instructions for running tests is especially helpful if it requires external setup, such as starting a Selenium server for testing in a browser.

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
- Gitleaks is configured to run with 100% redaction. Raw output is staged outside the
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
environment, not through its command line or config files.

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

Several of the Prowler read additions go beyond configuration metadata:
`logs:FilterLogEvents` reads log event content, `lambda:GetFunction*` returns
function code and environment variables, `ssm:GetDocument` reads SSM document
content, and `s3:GetObjectAcl` reads object ACLs. The role should therefore be
treated as sensitive — restrict which principals can assume it, always use an
External ID for cross-account trust, and revoke or delete the role when scanning
ends.

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

## Cleanup

The setup commands create persistent AWS resources. Remove them when they are no longer needed.

### Scanner IAM stack (`setup-iam`)

```bash
aws cloudformation delete-stack --stack-name prowler-scanner-iam --profile my-profile
```

### GenAI red-team IAM stack (`setup-genai-iam`)

```bash
aws cloudformation delete-stack --stack-name genai-redteam-iam --profile my-profile
```

### Organization StackSet (`setup-org-iam`)

Remove stack instances from every target OU first, then delete the StackSet itself.
Replace `r-xxxx` with your actual organization root ID (or OU ID) and adjust `--regions`
to match the region(s) you deployed to.

```bash
aws cloudformation delete-stack-instances \
  --stack-set-name prowler-scanner-organization \
  --deployment-targets OrganizationalUnitIds=r-xxxx \
  --regions us-east-1 \
  --no-retain-stacks \
  --profile management-profile

# Wait for the delete-stack-instances operation to complete, then:
aws cloudformation delete-stack-set \
  --stack-set-name prowler-scanner-organization \
  --profile management-profile
```

> **Note:** `delete-stack-instances` is asynchronous. Poll
> `aws cloudformation describe-stack-set-operation` until the status is `SUCCEEDED`
> before running `delete-stack-set`.

### Scan results

The `results/` directory contains customer findings, SBOMs, and red-team evidence.
Remove it when the data is no longer required:

```bash
rm -rf ./results
```

---

## Security considerations

### IAM scope and role sensitivity

`setup-iam` creates a role with AWS-managed `SecurityAudit` + `ViewOnlyAccess`
plus Prowler read additions. Several of those additions read more than
configuration: `logs:FilterLogEvents` reads log event content,
`lambda:GetFunction*` returns function code and environment variables,
`ssm:GetDocument` reads SSM document content, and `s3:GetObjectAcl` reads
object ACLs. Treat `PostureScannerRole` as a sensitive credential:

- Scope its trust policy to the exact IAM principal that runs scans.
- Always use an External ID for cross-account trust.
- Delete or disable the role and its CloudFormation stack when scanning ends
  (see [Cleanup](#cleanup)).

`setup-genai-iam` creates a separate role that can invoke Bedrock models,
agents, and knowledge bases. Scope `AllowedAgentAliasArns`,
`AllowedKnowledgeBaseArns`, and `AllowedModelArns` in the CloudFormation
template to specific target ARNs before production use. Delete the stack as
soon as red teaming ends.

### External ID

The CLI enforces a non-empty External ID for cross-account role trust. Manual
CloudFormation deployments can omit it; doing so weakens the confused-deputy
protection on the trust policy. Always supply `--external-id` with a randomly
generated value.

The External ID is marked `NoEcho` in CloudFormation and is redacted from CLI
logs. Prowler requires it on the command line, so it is briefly visible in the
local process list to other users on the same host — use a single-user or
dedicated scan host if that matters in your environment.

### Results directory

The `results/` directory contains customer security findings, SBOMs, and
red-team evidence including successful attack payloads and model responses.
Handle it as confidential, restrict filesystem access, and delete it when the
data is no longer required (`rm -rf ./results`).

### Network egress

- AWS posture scans make HTTPS calls to AWS service endpoints only.
- Repository scans download Semgrep rules from the public registry and the
  Trivy vulnerability database by default. Use a local `--config` path and
  `--trivy-skip-db-update` for a fully offline scan.
- GenAI red teaming calls Bedrock model, agent, and knowledge-base endpoints.
  Promptfoo-hosted generation, telemetry, sharing, and caching are disabled by
  default; enable with `--allow-remote-generation` after reviewing the data
  sharing implications.

### Active testing risk

`scan-genai` sends adversarial prompts to live Bedrock targets. Agent action
groups can perform real actions (database writes, API calls, emails). Always
use non-production agent aliases and knowledge bases, and confirm with the
resource owner before testing. The `--plan` flag previews everything without
sending any prompts.

### Organization auto-deployment

`setup-org-iam` creates a service-managed CloudFormation StackSet with
`AutoDeployment.Enabled: true`. This means `PostureScannerRole` is
automatically deployed to every new account that joins the target
organizational unit. Review the OU scope and trust policy before applying, and
remove the StackSet (see [Cleanup](#cleanup)) when organization-wide scanning
is no longer required.

To report a security vulnerability, see
[CONTRIBUTING.md](CONTRIBUTING.md#security-issue-notifications).

## License
For open source projects, say how it is licensed.

## Project status
If you have run out of energy or time for your project, put a note at the top of the README saying that development has slowed down or stopped completely. Someone may choose to fork your project or volunteer to step in as a maintainer or owner, allowing your project to keep going. You can also make an explicit request for maintainers.
