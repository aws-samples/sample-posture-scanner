"""Trivy filesystem scanning, CycloneDX generation, and result normalization."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

from .code_scan import Checkout, relative_repository_path

RECOMMENDED_TRIVY_VERSION = "0.72.0"
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITY_ORDER)}


class TrivyError(RuntimeError):
    """Raised when Trivy cannot complete or produce valid output."""


def trivy_path() -> Optional[str]:
    return shutil.which("trivy")


def trivy_version() -> Optional[str]:
    executable = trivy_path()
    if not executable:
        return None
    completed = subprocess.run(  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit -- executes pinned Trivy binary with static ["--version"] arg; shell=False by default, no user-controlled string interpolation
        [executable, "--version"],
        check=False,
        capture_output=True,
        text=True,
    )
    return (completed.stdout or completed.stderr).strip() or None


def trivy_version_number() -> Optional[str]:
    version = trivy_version()
    if not version:
        return None
    match = re.search(r"(?<!\d)(\d+\.\d+\.\d+)(?!\d)", version)
    return match.group(1) if match else None


def _common_flags(skip_database_update: bool) -> list[str]:
    flags = [
        "--quiet",
        "--disable-telemetry",
        "--offline-scan",
        "--skip-version-check",
        "--skip-check-update",
    ]
    if skip_database_update:
        flags.append("--skip-db-update")
    return flags


def run_trivy(
    checkout: Checkout,
    raw_output: Path,
    sbom_output: Path,
    excludes: Sequence[str] = (),
    timeout: str = "10m",
    skip_database_update: bool = False,
) -> list[list[str]]:
    """Run one security scan plus one SBOM generation pass."""
    executable = trivy_path()
    if not executable:
        raise FileNotFoundError(
            "Trivy was not found on PATH. Install exact release "
            f"{RECOMMENDED_TRIVY_VERSION}."
        )
    installed = trivy_version_number()
    if installed != RECOMMENDED_TRIVY_VERSION:
        raise TrivyError(
            f"Unsupported Trivy version {installed or 'unknown'}; install "
            f"Trivy {RECOMMENDED_TRIVY_VERSION}."
        )
    if not re.fullmatch(r"\d+(?:ms|s|m|h)", timeout):
        raise ValueError("Trivy timeout must look like 30s, 5m, or 1h.")

    raw_output.parent.mkdir(parents=True, exist_ok=True)
    sbom_output.parent.mkdir(parents=True, exist_ok=True)
    skip_args = ["--skip-dirs", ".git"]
    for pattern in excludes:
        skip_args += ["--skip-dirs", pattern, "--skip-files", pattern]

    security_command = [
        executable,
        "fs",
        "--scanners",
        "vuln,misconfig,license",
        "--format",
        "json",
        "--output",
        str(raw_output),
        "--exit-code",
        "0",
        "--timeout",
        timeout,
        *_common_flags(skip_database_update),
        *skip_args,
        str(checkout.path),
    ]
    sbom_command = [
        executable,
        "fs",
        "--scanners",
        "vuln",
        "--format",
        "cyclonedx",
        "--output",
        str(sbom_output),
        "--timeout",
        timeout,
        *_common_flags(skip_database_update),
        *skip_args,
        str(checkout.path),
    ]
    for command, expected in (
        (security_command, raw_output),
        (sbom_command, sbom_output),
    ):
        completed = subprocess.run(  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit -- executes pinned Trivy binary with a structured list built from validated flags; shell=False by default, no user-controlled string interpolation
            command,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        if completed.returncode != 0:
            raise TrivyError(
                f"Trivy exited with code {completed.returncode}; verify database "
                "availability and configuration or run it directly for diagnostics."
            )
        if not expected.is_file():
            raise TrivyError(f"Trivy completed without producing {expected.name}.")
    return [security_command, sbom_command]


def _normalize_vulnerability(item: dict, target: str) -> dict:
    package_identifier = item.get("PkgIdentifier") or {}
    return {
        "domain": "dependency",
        "id": str(item.get("VulnerabilityID") or "unknown"),
        "severity": str(item.get("Severity") or "UNKNOWN").upper(),
        "title": str(item.get("Title") or item.get("Description") or "Vulnerable dependency"),
        "target": target,
        "package": str(item.get("PkgName") or "unknown"),
        "package_id": str(item.get("PkgID") or ""),
        "installed_version": str(item.get("InstalledVersion") or ""),
        "fixed_version": str(item.get("FixedVersion") or ""),
        "status": str(item.get("Status") or ""),
        "purl": str(package_identifier.get("PURL") or ""),
        "primary_url": str(item.get("PrimaryURL") or ""),
        "references": [str(value) for value in (item.get("References") or []) if value],
    }


def _normalize_misconfiguration(item: dict, target: str) -> dict:
    cause = item.get("CauseMetadata") or {}
    return {
        "domain": "iac",
        "id": str(item.get("ID") or item.get("AVDID") or "unknown"),
        "severity": str(item.get("Severity") or "UNKNOWN").upper(),
        "title": str(item.get("Title") or item.get("Message") or "IaC misconfiguration"),
        "message": str(item.get("Message") or item.get("Description") or ""),
        "target": target,
        "start_line": int(cause.get("StartLine") or 0),
        "end_line": int(cause.get("EndLine") or 0),
        "resolution": str(item.get("Resolution") or ""),
        "primary_url": str(item.get("PrimaryURL") or ""),
        "references": [str(value) for value in (item.get("References") or []) if value],
    }


def _normalize_license(item: dict, target: str, checkout: Checkout) -> dict:
    file_path = str(item.get("FilePath") or target)
    return {
        "domain": "license",
        "name": str(item.get("Name") or "unknown"),
        "category": str(item.get("Category") or ""),
        "package": str(item.get("PkgName") or ""),
        "path": relative_repository_path(file_path, checkout),
        "confidence": float(item.get("Confidence") or 0),
        "link": str(item.get("Link") or ""),
    }


def aggregate(raw_output: Path, sbom_output: Path, checkout: Checkout) -> dict:
    try:
        data = json.loads(raw_output.read_text(encoding="utf-8"))
        sbom = json.loads(sbom_output.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TrivyError(f"Could not parse Trivy output: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(sbom, dict):
        raise TrivyError("Trivy JSON and CycloneDX outputs must be objects.")

    vulnerabilities: dict[tuple, dict] = {}
    misconfigurations: dict[tuple, dict] = {}
    licenses: dict[tuple, dict] = {}
    for result in data.get("Results", []) or []:
        if not isinstance(result, dict):
            continue
        target = relative_repository_path(str(result.get("Target") or "unknown"), checkout)
        for item in result.get("Vulnerabilities", []) or []:
            if not isinstance(item, dict):
                continue
            finding = _normalize_vulnerability(item, target)
            key = (
                finding["id"],
                finding["package"],
                finding["installed_version"],
                finding["target"],
            )
            vulnerabilities[key] = finding
        for item in result.get("Misconfigurations", []) or []:
            if not isinstance(item, dict):
                continue
            finding = _normalize_misconfiguration(item, target)
            key = (finding["id"], finding["target"], finding["start_line"])
            misconfigurations[key] = finding
        for item in result.get("Licenses", []) or []:
            if not isinstance(item, dict):
                continue
            finding = _normalize_license(item, target, checkout)
            key = (finding["name"], finding["package"], finding["path"])
            licenses[key] = finding

    security_findings = list(vulnerabilities.values()) + list(misconfigurations.values())
    security_findings.sort(
        key=lambda item: (
            SEVERITY_RANK.get(item["severity"], len(SEVERITY_RANK)),
            item.get("target", ""),
            item["id"],
            item.get("package", ""),
        )
    )
    severity_counts: dict[str, int] = {}
    for finding in security_findings:
        severity = finding["severity"]
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    components = sbom.get("components") or []
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scanner": "Trivy",
        "scanner_version": RECOMMENDED_TRIVY_VERSION,
        "telemetry_enabled": False,
        "offline_dependency_analysis": True,
        "repository_commit": checkout.commit,
        "total_findings": len(security_findings),
        "vulnerabilities": len(vulnerabilities),
        "misconfigurations": len(misconfigurations),
        "licenses_detected": len(licenses),
        "sbom_components": len(components) if isinstance(components, list) else 0,
        "severity_counts": dict(
            sorted(
                severity_counts.items(),
                key=lambda item: SEVERITY_RANK.get(item[0], len(SEVERITY_RANK)),
            )
        ),
        "findings": security_findings,
        "license_inventory": sorted(
            licenses.values(), key=lambda item: (item["name"], item["package"], item["path"])
        ),
    }
