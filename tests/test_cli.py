import json
from contextlib import contextmanager

from aws_posture import cli, code_scan, gitleaks_scan
from aws_posture.cli import build_parser


def test_account_scan_defaults_to_all_regions():
    args = build_parser().parse_args(["scan"])
    assert args.region is None
    assert args.organization is False


def test_organization_mode_and_member_role_parse():
    args = build_parser().parse_args(
        [
            "scan",
            "--organization",
            "--member-role-name",
            "Security/PostureScannerRole",
            "--external-id",
            "example",
        ]
    )
    assert args.organization is True
    assert args.member_role_name == "Security/PostureScannerRole"
    assert args.external_id == "example"


def test_scan_code_parses_remote_repository_options():
    args = build_parser().parse_args(
        [
            "scan-code",
            "https://github.com/example/project.git",
            "--ref",
            "release",
            "--config",
            "p/default",
            "--config",
            "./company-rules",
            "--exclude",
            "vendor/**",
            "--fail-on-findings",
        ]
    )

    assert args.source == "https://github.com/example/project.git"
    assert args.ref == "release"
    assert args.config == ["p/default", "./company-rules"]
    assert args.exclude == ["vendor/**"]
    assert args.fail_on_findings is True


def test_scan_code_defaults_to_community_rules_at_execution_time():
    args = build_parser().parse_args(["scan-code", "."])
    assert args.config is None
    assert args.ref is None
    assert args.timeout == 30


def test_check_code_mode_parses_without_aws_profile():
    args = build_parser().parse_args(["check", "--code"])
    assert args.code is True
    assert args.profile is None


def test_scan_repository_defaults_to_all_three_scanners():
    args = build_parser().parse_args(["scan-repository", "."])
    assert args.skip_semgrep is False
    assert args.skip_gitleaks is False
    assert args.skip_trivy is False
    assert args.history is False
    assert args.trivy_skip_db_update is False


def test_scan_repository_parses_history_and_policy_options():
    args = build_parser().parse_args(
        [
            "scan-repository",
            "https://example.test/org/repo.git",
            "--ref",
            "release",
            "--history",
            "--gitleaks-config",
            "gitleaks.toml",
            "--trivy-skip-db-update",
            "--exclude",
            "vendor/**",
            "--fail-on-findings",
        ]
    )
    assert args.ref == "release"
    assert args.history is True
    assert args.gitleaks_config == "gitleaks.toml"
    assert args.trivy_skip_db_update is True
    assert args.exclude == ["vendor/**"]
    assert args.fail_on_findings is True


def _fake_checkout(tmp_path):
    @contextmanager
    def manager(*args, **kwargs):
        yield code_scan.Checkout(
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

    return manager


def test_scan_repository_returns_two_when_policy_findings_exist(monkeypatch, tmp_path):
    monkeypatch.setattr(cli.code_scan, "checkout_source", _fake_checkout(tmp_path))

    def fake_gitleaks(checkout, raw_output, **kwargs):
        raw_output.parent.mkdir(parents=True, exist_ok=True)
        raw_output.write_text(
            json.dumps(
                [
                    {
                        "Description": "Potential key",
                        "StartLine": 1,
                        "EndLine": 1,
                        "File": "settings.env",
                        "Commit": "",
                        "RuleID": "generic-key",
                        "Fingerprint": "settings.env:generic-key:1",
                        "Secret": "<redacted>",
                    }
                ]
            )
        )
        return []

    monkeypatch.setattr(cli.gitleaks_scan, "run_gitleaks", fake_gitleaks)
    args = build_parser().parse_args(
        [
            "scan-repository",
            ".",
            "--skip-semgrep",
            "--skip-trivy",
            "--fail-on-findings",
            "--output",
            str(tmp_path / "out"),
        ]
    )
    assert args.func(args) == 2
    summary = json.loads((tmp_path / "out/report/repository-summary.json").read_text())
    assert summary["counts"]["secrets"] == 1


def test_scan_repository_returns_one_on_scanner_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(cli.code_scan, "checkout_source", _fake_checkout(tmp_path))
    monkeypatch.setattr(
        cli.gitleaks_scan,
        "run_gitleaks",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            gitleaks_scan.GitleaksError("scanner failed")
        ),
    )
    args = build_parser().parse_args(
        [
            "scan-repository",
            ".",
            "--skip-semgrep",
            "--skip-trivy",
            "--output",
            str(tmp_path / "out"),
        ]
    )
    assert args.func(args) == 1
    manifest = json.loads((tmp_path / "out/repository-scan-manifest.json").read_text())
    assert manifest["status"] == "failed"
