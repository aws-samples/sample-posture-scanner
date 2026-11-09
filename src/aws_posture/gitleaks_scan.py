"""Privacy-safe Gitleaks secret scanning and normalization."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .code_scan import Checkout, relative_repository_path

RECOMMENDED_GITLEAKS_VERSION = "8.30.1"


class GitleaksError(RuntimeError):
    """Raised when Gitleaks cannot complete or produce valid output."""


def gitleaks_path() -> Optional[str]:
    return shutil.which("gitleaks")


def gitleaks_version() -> Optional[str]:
    executable = gitleaks_path()
    if not executable:
        return None
    completed = subprocess.run(  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit -- executes pinned Gitleaks binary with static [executable, "version"] list; shell=False by default, no user-controlled string interpolation
        [executable, "version"],
        check=False,
        capture_output=True,
        text=True,
    )
    return (completed.stdout or completed.stderr).strip() or None


def gitleaks_version_number() -> Optional[str]:
    version = gitleaks_version()
    if not version:
        return None
    match = re.search(r"(?<!\d)(\d+\.\d+\.\d+)(?!\d)", version)
    return match.group(1) if match else None


def _sanitize_record(record: dict, checkout: Checkout) -> dict:
    """Retain evidence identifiers while deleting secrets, source lines, and PII."""
    return {
        "Description": str(record.get("Description") or "Potential secret"),
        "StartLine": int(record.get("StartLine") or 0),
        "EndLine": int(record.get("EndLine") or 0),
        "StartColumn": int(record.get("StartColumn") or 0),
        "EndColumn": int(record.get("EndColumn") or 0),
        "Secret": "<redacted>",
        "Match": "<redacted>",
        "Line": "<redacted>",
        "File": relative_repository_path(str(record.get("File") or "unknown"), checkout),
        "Commit": str(record.get("Commit") or ""),
        "Date": str(record.get("Date") or ""),
        "RuleID": str(record.get("RuleID") or "unknown"),
        "Fingerprint": str(record.get("Fingerprint") or ""),
        "Tags": [str(tag) for tag in (record.get("Tags") or []) if tag],
        "Link": str(record.get("Link") or ""),
    }


def sanitize_findings(data, checkout: Checkout) -> list[dict]:
    if not isinstance(data, list):
        raise GitleaksError("Gitleaks JSON output must be an array.")
    findings = []
    for record in data:
        if isinstance(record, dict):
            findings.append(_sanitize_record(record, checkout))
    return findings


def run_gitleaks(
    checkout: Checkout,
    raw_output: Path,
    history: bool = False,
    config: Optional[str] = None,
    baseline: Optional[str] = None,
    timeout: int = 0,
) -> list[str]:
    """Run one Gitleaks scan and write only sanitized JSON to the result folder."""
    executable = gitleaks_path()
    if not executable:
        raise FileNotFoundError(
            "Gitleaks was not found on PATH. Install exact release "
            f"{RECOMMENDED_GITLEAKS_VERSION}."
        )
    installed = gitleaks_version_number()
    if installed != RECOMMENDED_GITLEAKS_VERSION:
        raise GitleaksError(
            f"Unsupported Gitleaks version {installed or 'unknown'}; install "
            f"Gitleaks {RECOMMENDED_GITLEAKS_VERSION}."
        )
    if timeout < 0:
        raise ValueError("Gitleaks timeout cannot be negative.")

    raw_output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="aws-posture-gitleaks-", ignore_cleanup_errors=True
    ) as temporary:
        temporary_report = Path(temporary, "gitleaks.json")
        mode = "git" if history else "dir"
        command = [
            executable,
            mode,
            "--redact=100",
            "--report-format",
            "json",
            "--report-path",
            str(temporary_report),
            "--exit-code",
            "0",
            "--no-banner",
            "--no-color",
            "--log-level",
            "error",
            "--gitleaks-ignore-path",
            str(checkout.repository_root),
        ]
        if history:
            command += ["--log-opts=--all"]
        if config:
            config_path = Path(config).expanduser()
            command += ["--config", str(config_path.resolve())]
        if baseline:
            baseline_path = Path(baseline).expanduser()
            command += ["--baseline-path", str(baseline_path.resolve())]
        if timeout:
            command += ["--timeout", str(timeout)]
        command.append(str(checkout.path))

        completed = subprocess.run(  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit -- executes pinned Gitleaks binary with a structured list built from validated flags and a caller-controlled checkout path; shell=False by default
            command,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        if completed.returncode != 0:
            raise GitleaksError(
                f"Gitleaks exited with code {completed.returncode}; verify its "
                "configuration or run it directly for diagnostic output."
            )
        if not temporary_report.is_file():
            raise GitleaksError("Gitleaks completed without producing JSON output.")
        try:
            data = json.loads(temporary_report.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise GitleaksError(f"Could not parse Gitleaks JSON output: {exc}") from exc
        sanitized = sanitize_findings(data, checkout)
        raw_output.write_text(json.dumps(sanitized, indent=2), encoding="utf-8")
    return command


def aggregate(raw_output: Path, checkout: Checkout, history: bool) -> dict:
    try:
        data = json.loads(raw_output.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GitleaksError(f"Could not parse sanitized Gitleaks output: {exc}") from exc
    if not isinstance(data, list):
        raise GitleaksError("Sanitized Gitleaks output must be an array.")

    deduplicated: dict[tuple, dict] = {}
    for record in data:
        if not isinstance(record, dict):
            continue
        fingerprint = str(record.get("Fingerprint") or "")
        key = (
            fingerprint,
            str(record.get("RuleID") or "unknown"),
            str(record.get("File") or "unknown"),
            int(record.get("StartLine") or 0),
            str(record.get("Commit") or ""),
        )
        deduplicated[key] = {
            "domain": "secret",
            "rule_id": key[1],
            "description": str(record.get("Description") or "Potential secret"),
            "path": key[2],
            "start_line": key[3],
            "end_line": int(record.get("EndLine") or 0),
            "commit": key[4],
            "date": str(record.get("Date") or ""),
            "fingerprint": fingerprint,
            "tags": [str(tag) for tag in (record.get("Tags") or [])],
            "link": str(record.get("Link") or ""),
            "secret": "<redacted>",
        }
    findings = sorted(
        deduplicated.values(),
        key=lambda item: (item["path"], item["start_line"], item["rule_id"], item["commit"]),
    )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scanner": "Gitleaks",
        "scanner_version": RECOMMENDED_GITLEAKS_VERSION,
        "history_scanned": history,
        "repository_commit": checkout.commit,
        "total_findings": len(findings),
        "affected_files": len({item["path"] for item in findings}),
        "distinct_rules": len({item["rule_id"] for item in findings}),
        "secrets_redacted": True,
        "findings": findings,
    }
