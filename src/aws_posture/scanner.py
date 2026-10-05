"""Cross-platform Prowler execution and AWS Organizations discovery."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Sequence

import boto3

SUPPORTED_PROWLER_MAJOR = 5


class ScannerError(RuntimeError):
    """Raised when Prowler cannot complete successfully."""


def tool_path(name: str) -> Optional[str]:
    return shutil.which(name)


def tool_version(name: str) -> Optional[str]:
    executable = tool_path(name)
    if not executable:
        return None
    completed = subprocess.run(
        [executable, "--version"], capture_output=True, text=True, check=False
    )
    output = (completed.stdout or completed.stderr).strip()
    return output or None


def prowler_major_version() -> Optional[int]:
    output = tool_version("prowler")
    if not output:
        return None
    match = re.search(r"(?<!\d)(\d+)\.\d+(?:\.\d+)?", output)
    return int(match.group(1)) if match else None


def _display_command(command: Sequence[str]) -> str:
    rendered = []
    redact_next = False
    for value in command:
        if redact_next:
            rendered.append("<redacted>")
            redact_next = False
        else:
            rendered.append(value)
            redact_next = value in {"--external-id", "-I"}
    return " ".join(rendered)


def list_organization_accounts(profile: Optional[str] = None) -> list[dict]:
    """Return every ACTIVE account visible to the management/delegated account."""
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    organizations = session.client("organizations")
    accounts = []
    for page in organizations.get_paginator("list_accounts").paginate():
        for account in page.get("Accounts", []):
            state = account.get("State") or account.get("Status")
            if state == "ACTIVE":
                accounts.append(
                    {
                        "id": account["Id"],
                        "name": account.get("Name", ""),
                        "email": account.get("Email", ""),
                    }
                )
    return sorted(accounts, key=lambda item: item["id"])


def resolve_mutelist(value: Optional[str]) -> Optional[str]:
    """Resolve --mutelist to a readable file path.

    "default" (case-insensitive) resolves to the bundled mutelist that mutes
    known-noisy checks; any other value must be an existing YAML file.
    """
    if not value:
        return None
    if value.lower() == "default":
        from importlib.resources import as_file, files

        resource = files("aws_posture").joinpath("data", "default-mutelist.yaml")
        with as_file(resource) as path:
            return str(path)
    path = Path(value)
    if not path.is_file():
        raise FileNotFoundError(f"Mutelist file not found: {value}")
    return str(path)


def run_prowler(
    raw_dir: str,
    timestamp: str,
    profile: Optional[str] = None,
    regions: Optional[Sequence[str]] = None,
    role: Optional[str] = None,
    external_id: Optional[str] = None,
    session_duration: int = 3600,
    organizations_role: Optional[str] = None,
    mutelist: Optional[str] = None,
) -> int:
    """Run one full Prowler scan.

    Current Prowler creates JSON-OCSF, CSV, HTML, and all compliance CSVs from
    this one execution. With no region filter it scans all enabled AWS regions.
    """
    executable = tool_path("prowler")
    if not executable:
        raise FileNotFoundError(
            "Prowler was not found on PATH. Install it with "
            "`pipx install --python python3.12 prowler==5.36.0`."
        )
    major = prowler_major_version()
    if major != SUPPORTED_PROWLER_MAJOR:
        detected = "unknown" if major is None else f"{major}.x"
        raise ScannerError(
            f"Unsupported Prowler version {detected}; install Prowler 5.36.0."
        )
    if external_id and not role:
        raise ValueError("--external-id requires a scanner role.")
    if not 900 <= session_duration <= 43200:
        raise ValueError("Session duration must be between 900 and 43200 seconds.")

    Path(raw_dir).mkdir(parents=True, exist_ok=True)
    command = [
        executable,
        "aws",
        "--output-formats",
        "json-ocsf",
        "csv",
        "html",
        "--output-directory",
        raw_dir,
        "--output-filename",
        f"posture-{timestamp}",
        "--ignore-exit-code-3",
    ]
    if profile:
        command += ["--profile", profile]
    if regions:
        command += ["--filter-region", *regions]
    if role:
        command += ["--role", role, "--session-duration", str(session_duration)]
    if external_id:
        command += ["--external-id", external_id]
    if organizations_role:
        command += ["--organizations-role", organizations_role]
    if mutelist:
        command += ["--mutelist-file", mutelist]

    print(f"==> Running Prowler{f' against {role}' if role else ''}...")
    print("    $ " + _display_command(command))
    completed = subprocess.run(command, check=False)
    if completed.returncode != 0:
        raise ScannerError(
            f"Prowler exited with code {completed.returncode}; inspect its console output."
        )
    if not list(Path(raw_dir).glob("*.ocsf.json")):
        raise ScannerError(
            "Prowler completed but produced no JSON-OCSF file in the output directory."
        )
    return completed.returncode
