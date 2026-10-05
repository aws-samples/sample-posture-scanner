This sample does not bundle or redistribute any of the following tools. Each is
installed separately by the user, from its official source, under its own
license. aws-posture invokes them as external processes.

| Component | Version | License | Source |
|---|---|---|---|
| Prowler | 5.36.0 | Apache-2.0 | https://github.com/prowler-cloud/prowler |
| Semgrep Community Edition | 1.171.0 | LGPL-2.1-or-later | https://github.com/semgrep/semgrep |
| Gitleaks | 8.30.1 | MIT | https://github.com/gitleaks/gitleaks |
| Trivy | 0.72.0 | Apache-2.0 | https://github.com/aquasecurity/trivy |
| promptfoo | 0.123.1 | MIT | https://github.com/promptfoo/promptfoo |

Python runtime dependency (installed from PyPI):

| Component | Version | License | Source |
|---|---|---|---|
| boto3 | 1.43.56 | Apache-2.0 | https://github.com/boto/boto3 |

Semgrep Community Edition rules from the public Semgrep Registry (`p/default`)
are downloaded at run time and are subject to the Semgrep Rules License.
Use local rules with `--config` to avoid them.
