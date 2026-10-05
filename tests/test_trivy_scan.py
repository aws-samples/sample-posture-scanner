import json
import subprocess
from pathlib import Path

import pytest

from aws_posture import code_scan, trivy_scan


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


def trivy_json():
    vulnerability = {
        "VulnerabilityID": "CVE-2024-1234",
        "PkgName": "demo-package",
        "PkgID": "demo-package@1.0.0",
        "InstalledVersion": "1.0.0",
        "FixedVersion": "1.2.0",
        "Severity": "HIGH",
        "Title": "Demo package vulnerability",
        "PrimaryURL": "https://example.test/CVE-2024-1234",
        "References": ["https://example.test/advisory"],
        "PkgIdentifier": {"PURL": "pkg:pypi/demo-package@1.0.0"},
    }
    return {
        "SchemaVersion": 2,
        "ArtifactName": ".",
        "Results": [
            {
                "Target": "requirements.txt",
                "Class": "lang-pkgs",
                "Type": "pip",
                "Vulnerabilities": [vulnerability, vulnerability],
            },
            {
                "Target": "terraform/main.tf",
                "Class": "config",
                "Type": "terraform",
                "Misconfigurations": [
                    {
                        "ID": "AVD-AWS-0001",
                        "Title": "Public resource",
                        "Message": "Resource is public",
                        "Resolution": "Disable public access",
                        "Severity": "CRITICAL",
                        "PrimaryURL": "https://example.test/AVD-AWS-0001",
                        "CauseMetadata": {
                            "StartLine": 5,
                            "EndLine": 8,
                            "Code": {"Lines": [{"Content": "password = secret-value"}]},
                        },
                    }
                ],
            },
            {
                "Target": "package-lock.json",
                "Class": "license",
                "Type": "npm",
                "Licenses": [
                    {
                        "Name": "MIT",
                        "Category": "notice",
                        "PkgName": "demo-package",
                        "FilePath": "package-lock.json",
                        "Confidence": 1.0,
                    }
                ],
            },
        ],
    }


def test_trivy_commands_disable_telemetry_and_generate_sbom(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(trivy_scan, "trivy_path", lambda: "/fake/trivy")
    monkeypatch.setattr(trivy_scan, "trivy_version_number", lambda: "0.72.0")

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        output = Path(command[command.index("--output") + 1])
        output.parent.mkdir(parents=True, exist_ok=True)
        if command[command.index("--format") + 1] == "json":
            output.write_text(json.dumps(trivy_json()), encoding="utf-8")
        else:
            output.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "specVersion": "1.6",
                        "components": [{"name": "demo-package"}],
                    }
                ),
                encoding="utf-8",
            )
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(trivy_scan.subprocess, "run", fake_run)
    raw = tmp_path / "trivy.json"
    sbom = tmp_path / "software-bom.cdx.json"
    commands = trivy_scan.run_trivy(
        checkout(tmp_path),
        raw,
        sbom,
        excludes=["vendor/**"],
        skip_database_update=True,
    )

    assert len(commands) == 2 and len(calls) == 2
    security = commands[0]
    assert security[:2] == ["/fake/trivy", "fs"]
    assert security[security.index("--scanners") + 1] == "vuln,misconfig,license"
    assert "secret" not in security[security.index("--scanners") + 1]
    for flag in (
        "--disable-telemetry",
        "--offline-scan",
        "--skip-version-check",
        "--skip-check-update",
        "--skip-db-update",
    ):
        assert flag in security
    assert commands[1][commands[1].index("--format") + 1] == "cyclonedx"
    assert commands[1][commands[1].index("--scanners") + 1] == "vuln"
    assert "secret" not in commands[1][commands[1].index("--scanners") + 1]
    assert calls[0][1]["stdout"] is subprocess.DEVNULL
    assert calls[0][1]["stderr"] is subprocess.DEVNULL

    summary = trivy_scan.aggregate(raw, sbom, checkout(tmp_path))
    assert summary["total_findings"] == 2
    assert summary["vulnerabilities"] == 1
    assert summary["misconfigurations"] == 1
    assert summary["licenses_detected"] == 1
    assert summary["sbom_components"] == 1
    assert summary["severity_counts"] == {"CRITICAL": 1, "HIGH": 1}
    assert "secret-value" not in json.dumps(summary)


def test_trivy_requires_exact_version(monkeypatch, tmp_path):
    monkeypatch.setattr(trivy_scan, "trivy_path", lambda: "/fake/trivy")
    monkeypatch.setattr(trivy_scan, "trivy_version_number", lambda: "0.71.0")
    with pytest.raises(trivy_scan.TrivyError, match="0.72.0"):
        trivy_scan.run_trivy(
            checkout(tmp_path),
            tmp_path / "trivy.json",
            tmp_path / "sbom.json",
        )
