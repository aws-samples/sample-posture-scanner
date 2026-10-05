import json
import subprocess
from pathlib import Path

import pytest

from aws_posture import code_scan


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
        tracked_files=2,
    )


def result(rule="python.security.test", path="app.py", line=4, severity="ERROR"):
    return {
        "check_id": rule,
        "path": path,
        "start": {"line": line, "col": 5},
        "end": {"line": line, "col": 20},
        "extra": {
            "severity": severity,
            "message": "Potential command injection",
            "lines": "os.system(user_input)",
            "metadata": {
                "category": "security",
                "confidence": "HIGH",
                "cwe": ["CWE-78"],
                "owasp": ["A03:2021"],
                "references": ["https://example.test/rule"],
            },
        },
    }


def test_run_semgrep_disables_metrics_and_version_check(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(code_scan, "semgrep_path", lambda: "/fake/semgrep")
    monkeypatch.setattr(code_scan, "semgrep_version_number", lambda: "1.171.0")

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        output = Path(command[command.index("--json-output") + 1])
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text('{"version":"1.171.0","results":[],"errors":[]}', encoding="utf-8")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(code_scan, "_run", fake_run)
    raw = tmp_path / "raw" / "semgrep.json"
    command = code_scan.run_semgrep(
        tmp_path,
        raw,
        configs=["p/default", "local-rules.yml"],
        excludes=["vendor/**"],
        timeout=15,
    )

    assert calls and command == calls[0][0]
    assert command[:2] == ["/fake/semgrep", "scan"]
    assert command.count("--config") == 2
    assert command[command.index("--metrics") + 1] == "off"
    assert "--disable-version-check" in command
    assert "--quiet" in command
    assert command[command.index("--timeout") + 1] == "15"
    assert command[command.index("--exclude") + 1] == "vendor/**"
    assert calls[0][1]["env"]["SEMGREP_SEND_METRICS"] == "off"
    assert calls[0][1]["env"]["SEMGREP_ENABLE_VERSION_CHECK"] == "0"
    assert calls[0][1]["stdout"] is subprocess.DEVNULL
    assert calls[0][1]["stderr"] is subprocess.DEVNULL


def test_findings_are_deduplicated_and_sorted_by_severity(tmp_path):
    data = {
        "results": [
            result(),
            result(),
            result("javascript.security.low", "web.js", 9, "INFO"),
            result("generic.critical", "config.yml", 1, "CRITICAL"),
        ]
    }

    findings = code_scan.normalize_findings(data, checkout(tmp_path))

    assert len(findings) == 3
    assert [item["severity"] for item in findings] == ["CRITICAL", "ERROR", "INFO"]
    assert findings[1]["cwe"] == ["CWE-78"]


def test_summary_omits_source_snippets_and_html_escapes_content(tmp_path):
    dangerous = result(rule="rule.<script>")
    dangerous["extra"]["message"] = (
        "<img src=x onerror=alert(1)> ![pixel](https://attacker.invalid/pixel) "
        "[click](https://attacker.invalid/phish)"
    )
    data = {"version": "1.171.0", "results": [dangerous], "errors": []}
    summary = code_scan.aggregate(data, checkout(tmp_path), ["p/default"])

    encoded = json.dumps(summary)
    rendered = code_scan.render_html(summary)
    markdown = code_scan.render_markdown(summary)

    assert "os.system(user_input)" not in encoded
    assert "<script>" not in rendered
    assert "<img src=x" not in rendered
    assert "&lt;script&gt;" in rendered
    assert "<script>" not in markdown
    assert "<img src=x" not in markdown
    assert "![pixel](" not in markdown
    assert "[click](" not in markdown
    assert "\\!\\[pixel\\]\\(" in markdown
    assert "&lt;script&gt;" in markdown
    assert summary["severity_counts"] == {"ERROR": 1}


def test_https_repository_credentials_are_rejected():
    with pytest.raises(ValueError, match="must not contain credentials"):
        with code_scan.checkout_source("https://token@example.test/org/repo.git"):
            pass


def test_remote_repository_is_shallow_cloned_at_requested_ref(monkeypatch, tmp_path):
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        destination = Path(command[-1])
        destination.mkdir(parents=True)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(code_scan.shutil, "which", lambda name: "/usr/bin/git")
    monkeypatch.setattr(code_scan, "_run", fake_run)
    monkeypatch.setattr(
        code_scan,
        "_checkout_details",
        lambda target, source_type, source_label, requested_ref: code_scan.Checkout(
            path=target,
            repository_root=target,
            source_type=source_type,
            source_label=source_label,
            requested_ref=requested_ref,
            commit="b" * 40,
            branch="release",
            dirty=False,
            tracked_files=5,
        ),
    )

    with code_scan.checkout_source(
        "https://example.test/org/repo.git", ref="release"
    ) as checked_out:
        assert checked_out.path.exists()
        assert checked_out.source_label == "https://example.test/org/repo.git"
        assert checked_out.requested_ref == "release"

    command = commands[0]
    assert command[:2] == ["git", "clone"]
    assert command[command.index("--depth") + 1] == "1"
    assert "--no-tags" in command
    assert command[command.index("--branch") + 1] == "release"
    assert "--single-branch" in command
    assert "--" in command


def test_ssh_repository_password_is_rejected():
    with pytest.raises(ValueError, match="must not contain credentials"):
        with code_scan.checkout_source("ssh://git:secret@example.test/org/repo.git"):
            pass


def test_run_semgrep_rejects_other_1_x_versions(monkeypatch, tmp_path):
    monkeypatch.setattr(code_scan, "semgrep_path", lambda: "/fake/semgrep")
    monkeypatch.setattr(code_scan, "semgrep_version_number", lambda: "1.170.0")

    with pytest.raises(code_scan.CodeScanError, match="install Semgrep 1.171.0"):
        code_scan.run_semgrep(
            tmp_path,
            tmp_path / "semgrep.json",
            configs=["p/default"],
        )


def test_remote_history_clone_fetches_complete_repository(monkeypatch):
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        Path(command[-1]).mkdir(parents=True)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(code_scan.shutil, "which", lambda name: "/usr/bin/git")
    monkeypatch.setattr(code_scan, "_run", fake_run)
    monkeypatch.setattr(
        code_scan,
        "_checkout_details",
        lambda target, source_type, source_label, requested_ref: code_scan.Checkout(
            path=target,
            repository_root=target,
            source_type=source_type,
            source_label=source_label,
            requested_ref=requested_ref,
            commit="c" * 40,
            branch="release",
            dirty=False,
            tracked_files=5,
        ),
    )

    with code_scan.checkout_source(
        "https://example.test/org/repo.git", ref="release", full_history=True
    ):
        pass

    command = commands[0]
    assert "--depth" not in command
    assert "--no-tags" not in command
    assert "--single-branch" not in command
    assert command[command.index("--branch") + 1] == "release"
