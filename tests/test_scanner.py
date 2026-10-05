import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from aws_posture import scanner


def test_run_prowler_uses_one_current_full_scan(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(scanner, "tool_path", lambda name: "/fake/prowler")
    monkeypatch.setattr(scanner, "prowler_major_version", lambda: 5)

    def fake_run(command, **kwargs):
        calls.append(command)
        output = Path(command[command.index("--output-directory") + 1])
        output.mkdir(parents=True, exist_ok=True)
        (output / "posture.ocsf.json").write_text("[]", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(scanner.subprocess, "run", fake_run)

    scanner.run_prowler(
        str(tmp_path),
        "timestamp",
        profile="customer",
        role="arn:aws:iam::111111111111:role/PostureScannerRole",
        external_id="external-value",
        session_duration=7200,
    )

    assert len(calls) == 1
    command = calls[0]
    formats = command[command.index("--output-formats") + 1 : command.index("--output-directory")]
    assert formats == ["json-ocsf", "csv", "html"]
    assert "json" not in formats
    assert "--compliance" not in command
    assert "--filter-region" not in command  # omission means all enabled regions
    assert command[command.index("--external-id") + 1] == "external-value"


def test_run_prowler_raises_on_real_scanner_error(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner, "tool_path", lambda name: "/fake/prowler")
    monkeypatch.setattr(scanner, "prowler_major_version", lambda: 5)
    monkeypatch.setattr(
        scanner.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 2),
    )

    with pytest.raises(scanner.ScannerError, match="code 2"):
        scanner.run_prowler(str(tmp_path), "timestamp")


def test_command_display_redacts_external_id():
    rendered = scanner._display_command(
        ["prowler", "aws", "--external-id", "do-not-print", "--role", "role-arn"]
    )
    assert "do-not-print" not in rendered
    assert "<redacted>" in rendered


def test_list_organization_accounts_returns_active_only(monkeypatch):
    pages = [
        {
            "Accounts": [
                {"Id": "222222222222", "Name": "prod", "State": "ACTIVE"},
                {"Id": "333333333333", "Name": "old", "State": "SUSPENDED"},
                {"Id": "111111111111", "Name": "security", "Status": "ACTIVE"},
            ]
        }
    ]
    paginator = SimpleNamespace(paginate=lambda: pages)
    organizations = SimpleNamespace(get_paginator=lambda name: paginator)
    session = SimpleNamespace(client=lambda name: organizations)
    monkeypatch.setattr(scanner.boto3, "Session", lambda **kwargs: session)

    accounts = scanner.list_organization_accounts("customer")

    assert [account["id"] for account in accounts] == ["111111111111", "222222222222"]


def test_run_prowler_rejects_unknown_major(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner, "tool_path", lambda name: "/fake/prowler")
    monkeypatch.setattr(scanner, "prowler_major_version", lambda: None)

    with pytest.raises(scanner.ScannerError, match="install Prowler 5.36.0"):
        scanner.run_prowler(str(tmp_path), "timestamp")


def test_run_prowler_passes_mutelist_file(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(scanner, "tool_path", lambda name: "/fake/prowler")
    monkeypatch.setattr(scanner, "prowler_major_version", lambda: 5)

    def fake_run(command, **kwargs):
        calls.append(command)
        output = Path(command[command.index("--output-directory") + 1])
        output.mkdir(parents=True, exist_ok=True)
        (output / "posture.ocsf.json").write_text("[]", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(scanner.subprocess, "run", fake_run)

    scanner.run_prowler(str(tmp_path), "timestamp", mutelist="/tmp/mutelist.yaml")

    command = calls[0]
    assert command[command.index("--mutelist-file") + 1] == "/tmp/mutelist.yaml"


def test_run_prowler_omits_mutelist_by_default(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(scanner, "tool_path", lambda name: "/fake/prowler")
    monkeypatch.setattr(scanner, "prowler_major_version", lambda: 5)

    def fake_run(command, **kwargs):
        calls.append(command)
        output = Path(command[command.index("--output-directory") + 1])
        output.mkdir(parents=True, exist_ok=True)
        (output / "posture.ocsf.json").write_text("[]", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(scanner.subprocess, "run", fake_run)

    scanner.run_prowler(str(tmp_path), "timestamp")

    assert "--mutelist-file" not in calls[0]


def test_resolve_mutelist_returns_none_when_unset():
    assert scanner.resolve_mutelist(None) is None
    assert scanner.resolve_mutelist("") is None


def test_resolve_mutelist_default_uses_bundled_file():
    path = scanner.resolve_mutelist("default")

    assert path is not None
    content = Path(path).read_text(encoding="utf-8")
    assert "Mutelist:" in content
    assert "iam_role_cross_service_confused_deputy_prevention" in content
    assert "ec2_securitygroup_from_launch_wizard" in content
    assert "organizations_delegated_administrators" in content


def test_resolve_mutelist_custom_file(tmp_path):
    custom = tmp_path / "custom.yaml"
    custom.write_text("Mutelist:\n  Accounts: {}\n", encoding="utf-8")

    assert scanner.resolve_mutelist(str(custom)) == str(custom)


def test_resolve_mutelist_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError, match="Mutelist file not found"):
        scanner.resolve_mutelist(str(tmp_path / "missing.yaml"))
