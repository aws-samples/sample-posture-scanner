# Scanner selection and boundaries

## AWS posture: Prowler only

Prowler 5.36.0 remains the only AWS configuration-posture engine. It provides
all-Region service checks, JSON-OCSF/CSV/HTML, compliance outputs, role
assumption, and Organizations metadata. ScoutSuite remains excluded because of
coverage overlap and incompatible dependencies.

`aws-posture` adds active-account orchestration, exact-principal IAM deployment,
per-account execution status, and account-aware deduplicated reporting. It also
collects **IAM Access Analyzer** ACTIVE findings after each Prowler run (via the
same read-only scanner role) so provable external access can be distinguished
from theoretical misconfigurations, and supports Prowler **mutelists**
(`--mutelist default` or a custom YAML) to keep accepted-risk checks from
distorting the posture score.

## GenAI red team: promptfoo only

### promptfoo 0.123.1

- Purpose: active adversarial testing of Amazon Bedrock agents (InvokeAgent),
  knowledge bases (RetrieveAndGenerate), and Prompt Management prompts
- License: MIT (promptfoo is owned by OpenAI since 2026 and remains MIT-licensed)
- Runtime: Node.js 22.22+; exact version required so CLI flags and the results
  JSON schema cannot drift
- Managed prompts are read with `bedrock-agent:GetPrompt`; the template, model,
  and inference settings are tested as deployed, and extra template variables
  receive indirect-injection tests
- Attack generation and grading use a Bedrock model you choose; telemetry,
  sharing, update checks, caching, and Promptfoo-hosted generation are disabled
  by default
- Plugins that need hosted generation are skipped and reported unless
  `--allow-remote-generation` is approved
- Runs with a separate invoke-only IAM role (`setup-genai-iam`), not the
  read-only posture role
- Requires explicit `--i-understand-active-testing`; `--plan` sends nothing

Selected over the alternatives because it tests deployed Bedrock agents and RAG
behavior end to end and records attack, response, and grader evidence:

| Tool | Reason not selected |
|---|---|
| garak | Model-level probing; cannot exercise agent tools or knowledge bases |
| PyRIT | Library rather than a pinned CLI; overlaps with promptfoo |
| aws-samples AI/ML security assessment | Configuration checks deployed via CodeBuild/Lambda; overlaps Prowler's Bedrock checks |
| agentic-radar, MCP/skill scanners | Static code analysis of agent frameworks; separate future module |
| Snyk agent-scan | Requires a Snyk token and uploads tool/skill content to Snyk |

Bedrock configuration posture (guardrails, invocation logging, prompt CMK,
agent role least privilege, VPC endpoints) stays with Prowler's `bedrock`
checks in `scan`. Red-team results are never mixed into posture or repository
reports.

## Repository security engines

### Semgrep Community Edition 1.171.0

- Purpose: multi-language static application security testing
- License: LGPL-2.1-or-later
- Runs against the current checkout
- Metrics/version checks disabled
- Supports public Registry or fully local rules
- Consolidated output excludes source snippets

### Gitleaks 8.30.1

- Purpose: secret detection in current files or complete Git history
- License: MIT
- `--redact=100` is mandatory
- Reports are created in temporary storage, then defensively sanitized before
  persistence
- Secret, match, source line, author, email, and commit-message fields are not
  stored by `aws-posture` in its current implementation
- Full history requires explicit `--history` and a complete remote clone

### Trivy 0.72.0

- Purpose: dependency CVEs, IaC misconfigurations, license inventory, and
  CycloneDX SBOM
- License: Apache-2.0
- Secret scanner disabled because Gitleaks owns that domain
- Anonymous telemetry, version checks, external dependency identification API
  calls, and remote check updates disabled
- Vulnerability database updates remain enabled by default for fresh results;
  `--trivy-skip-db-update` requires a usable local cache

Trivy has experienced supply-chain incidents affecting release artifacts and
tags. The integration requires exactly 0.72.0.
Installation guidance requires official release checksum/signature verification
and rejects floating `latest` containers/actions.

## Reporting model

Native evidence is retained under each tool folder. Normalized findings use
separate domain identities:

- SAST: rule + path + source range
- Secret: fingerprint + rule + path + line + commit
- Dependency: vulnerability ID + package + installed version + target
- IaC: check ID + target + line
- License: license + package + path

A combined repository dashboard is generated, but no cross-domain score. License
entries and SBOM components are inventory, not vulnerabilities. AWS posture
findings are never mixed into the repository report.

## Tools not included

| Tool | Reason |
|---|---|
| ScoutSuite | Prowler overlap and dependency conflict |
| Checkov/KICS | Trivy already covers the selected IaC scope |
| Grype/Syft | Trivy provides both vulnerability scanning and CycloneDX SBOM |
| Pacu | Offensive exploitation framework; outside read-only posture scope |
| OpenVAS/GVM | Host/network vulnerability scanning is a separate workflow |
| Nikto, ffuf, gobuster | Web application testing is outside authenticated AWS/repository posture |
| theHarvester, amass | External OSINT/reconnaissance is outside scope |
| Hashcat, GoPhish, Sliver | Offensive tooling outside this product's safety boundary |

OWASP ZAP, OpenSSF Scorecard, Kubernetes-specific scanners, and static agent
or MCP code scanners remain possible future optional modules, each requiring
its own authorization and evidence model.
