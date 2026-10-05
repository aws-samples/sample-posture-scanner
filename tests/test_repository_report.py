import json

from aws_posture import code_scan, repository_report


def checkout(tmp_path):
    return code_scan.Checkout(
        path=tmp_path,
        repository_root=tmp_path,
        source_type="local",
        source_label=str(tmp_path),
        requested_ref=None,
        commit="a" * 40,
        branch="main",
        dirty=False,
        tracked_files=3,
    )


def test_repository_report_keeps_domains_separate_and_has_no_score(tmp_path):
    semgrep = {
        "total_findings": 1,
        "findings": [
            {
                "severity": "ERROR",
                "rule_id": "rule.<script>",
                "path": "app.py",
                "start_line": 2,
                "message": (
                    "<img src=x onerror=alert(1)> "
                    "![pixel](https://attacker.invalid/pixel) "
                    "[click](https://attacker.invalid/phish)"
                ),
                "fix": "Use a safe API",
            }
        ],
    }
    gitleaks = {
        "total_findings": 1,
        "findings": [
            {
                "rule_id": "aws-key",
                "path": "settings.env",
                "start_line": 1,
                "commit": "b" * 40,
                "description": "Potential key",
                "secret": "<redacted>",
            }
        ],
    }
    trivy = {
        "total_findings": 2,
        "vulnerabilities": 1,
        "misconfigurations": 1,
        "licenses_detected": 1,
        "sbom_components": 4,
        "findings": [
            {
                "domain": "dependency",
                "id": "CVE-2024-1234",
                "severity": "HIGH",
                "target": "requirements.txt",
                "title": "Vulnerable package",
                "package": "demo",
                "installed_version": "1.0",
                "fixed_version": "2.0",
            },
            {
                "domain": "iac",
                "id": "AVD-AWS-1",
                "severity": "CRITICAL",
                "target": "main.tf",
                "start_line": 3,
                "title": "Public resource",
                "message": "Public",
                "resolution": "Make private",
            },
        ],
        "license_inventory": [
            {
                "name": "MIT",
                "package": "demo",
                "path": "package-lock.json",
                "confidence": 1.0,
            }
        ],
    }

    summary = repository_report.build_report(
        checkout(tmp_path), semgrep, gitleaks, trivy, {}, tmp_path / "report"
    )
    html = (tmp_path / "report/repository-report.html").read_text()
    markdown = (tmp_path / "report/repository-report.md").read_text()

    assert summary["counts"] == {
        "sast": 1,
        "secrets": 1,
        "dependency_vulnerabilities": 1,
        "iac_misconfigurations": 1,
        "security_findings": 4,
        "licenses_detected": 1,
        "sbom_components": 4,
    }
    assert summary["score"] is None
    assert "<script>" not in html
    assert "<img src=x" not in html
    assert "<script>" not in markdown
    assert "<img src=x" not in markdown
    assert "![pixel](" not in markdown
    assert "[click](" not in markdown
    assert "\\!\\[pixel\\]\\(" in markdown
    assert "<redacted>" in json.dumps(summary)
