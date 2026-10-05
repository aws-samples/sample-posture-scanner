import json
import subprocess
from pathlib import Path

import pytest

from aws_posture import code_scan, gitleaks_scan


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
        tracked_files=1,
    )


def leaked_record():
    return {
        "Description": "AWS access key",
        "StartLine": 3,
        "EndLine": 3,
        "StartColumn": 10,
        "EndColumn": 30,
        "Match": "AWS_SECRET_ACCESS_KEY=super-secret-value",
        "Secret": "super-secret-value",
        "Line": "AWS_SECRET_ACCESS_KEY=super-secret-value",
        "File": "settings.env",
        "Commit": "b" * 40,
        "Author": "Private Person",
        "Email": "person@example.test",
        "Date": "2026-01-01T00:00:00Z",
        "Message": "commit containing super-secret-value",
        "RuleID": "aws-access-token",
        "Fingerprint": f"{'b' * 40}:settings.env:aws-access-token:3",
        "Tags": ["aws"],
        "Link": "https://example.test/commit",
    }


def test_gitleaks_history_scan_redacts_before_persisting(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(gitleaks_scan, "gitleaks_path", lambda: "/fake/gitleaks")
    monkeypatch.setattr(
        gitleaks_scan, "gitleaks_version_number", lambda: "8.30.1"
    )

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        report = Path(command[command.index("--report-path") + 1])
        report.write_text(json.dumps([leaked_record(), leaked_record()]), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(gitleaks_scan.subprocess, "run", fake_run)
    raw = tmp_path / "out" / "gitleaks.json"
    command = gitleaks_scan.run_gitleaks(
        checkout(tmp_path), raw, history=True, timeout=20
    )

    assert command[:2] == ["/fake/gitleaks", "git"]
    assert "--redact=100" in command
    assert command[command.index("--exit-code") + 1] == "0"
    assert "--log-opts=--all" in command
    assert calls[0][1]["stdout"] is subprocess.DEVNULL
    assert calls[0][1]["stderr"] is subprocess.DEVNULL

    persisted = raw.read_text()
    assert "super-secret-value" not in persisted
    assert "Private Person" not in persisted
    assert "person@example.test" not in persisted
    data = json.loads(persisted)
    assert data[0]["Secret"] == "<redacted>"
    assert data[0]["Match"] == "<redacted>"
    assert data[0]["Line"] == "<redacted>"

    summary = gitleaks_scan.aggregate(raw, checkout(tmp_path), history=True)
    assert summary["total_findings"] == 1
    assert summary["secrets_redacted"] is True
    assert summary["findings"][0]["secret"] == "<redacted>"
    assert "super-secret-value" not in json.dumps(summary)


def test_gitleaks_current_tree_uses_dir_mode(monkeypatch, tmp_path):
    monkeypatch.setattr(gitleaks_scan, "gitleaks_path", lambda: "/fake/gitleaks")
    monkeypatch.setattr(
        gitleaks_scan, "gitleaks_version_number", lambda: "8.30.1"
    )

    def fake_run(command, **kwargs):
        Path(command[command.index("--report-path") + 1]).write_text("[]")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(gitleaks_scan.subprocess, "run", fake_run)
    command = gitleaks_scan.run_gitleaks(
        checkout(tmp_path), tmp_path / "gitleaks.json", history=False
    )
    assert command[1] == "dir"
    assert not any(value.startswith("--log-opts") for value in command)


def test_gitleaks_requires_exact_version(monkeypatch, tmp_path):
    monkeypatch.setattr(gitleaks_scan, "gitleaks_path", lambda: "/fake/gitleaks")
    monkeypatch.setattr(
        gitleaks_scan, "gitleaks_version_number", lambda: "8.29.0"
    )
    with pytest.raises(gitleaks_scan.GitleaksError, match="8.30.1"):
        gitleaks_scan.run_gitleaks(
            checkout(tmp_path), tmp_path / "gitleaks.json"
        )
