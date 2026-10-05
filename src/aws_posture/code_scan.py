"""Semgrep Community Edition scanning for local and remote Git repositories."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional, Sequence
from urllib.parse import urlsplit, urlunsplit

from .report_text import html_escape, md_escape

RECOMMENDED_SEMGREP_VERSION = "1.171.0"
DEFAULT_CONFIG = "p/default"

SEVERITY_ORDER = ("CRITICAL", "HIGH", "ERROR", "MEDIUM", "WARNING", "LOW", "INFO")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITY_ORDER)}


class CodeScanError(RuntimeError):
    """Raised when source checkout or Semgrep execution cannot complete."""


@dataclass(frozen=True)
class Checkout:
    path: Path
    repository_root: Path
    source_type: str
    source_label: str
    requested_ref: Optional[str]
    commit: str
    branch: str
    dirty: bool
    tracked_files: int


def _run(command: Sequence[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(list(command), check=False, text=True, **kwargs)


def _git(args: Sequence[str], cwd: Path, required: bool = True) -> str:
    completed = _run(
        ["git", "-C", str(cwd), *args],
        capture_output=True,
    )
    if completed.returncode != 0:
        if required:
            message = (completed.stderr or completed.stdout or "Git command failed").strip()
            raise CodeScanError(message)
        return ""
    return completed.stdout.strip()


def _is_remote_source(source: str) -> bool:
    if re.match(r"^[A-Za-z]:[\\/]", source):
        return False
    if source.startswith("codecommit::"):
        return True
    parsed = urlsplit(source)
    if parsed.scheme.lower() in {"https", "http", "ssh", "git"}:
        return True
    return bool(re.match(r"^[^/@\s]+@[^:/\s]+:.+$", source))


def _safe_remote_label(source: str) -> str:
    if source.startswith("codecommit::"):
        return re.sub(r"(codecommit::[^:]+://)[^@/]+@", r"\1", source)
    parsed = urlsplit(source)
    if parsed.scheme:
        host = parsed.hostname or "unknown-host"
        port = f":{parsed.port}" if parsed.port else ""
        return urlunsplit((parsed.scheme, host + port, parsed.path, "", ""))
    return source.split("@", 1)[-1]


def _validate_remote_source(source: str) -> None:
    parsed = urlsplit(source)
    if parsed.password is not None or (
        parsed.scheme.lower() in {"http", "https", "git"}
        and parsed.username is not None
    ):
        raise ValueError(
            "Repository URLs must not contain credentials. Use a Git credential helper "
            "or SSH agent for private repositories."
        )
    if parsed.query or parsed.fragment:
        raise ValueError("Repository URLs with query strings or fragments are not accepted.")


def _checkout_details(
    target: Path,
    source_type: str,
    source_label: str,
    requested_ref: Optional[str],
) -> Checkout:
    root = Path(_git(["rev-parse", "--show-toplevel"], target)).resolve()
    commit = _git(["rev-parse", "HEAD"], target)
    branch = _git(["symbolic-ref", "--short", "-q", "HEAD"], target, required=False)
    dirty = bool(_git(["status", "--porcelain"], target, required=False))
    tracked = _git(["ls-files"], target, required=False)
    tracked_files = len(tracked.splitlines()) if tracked else 0
    return Checkout(
        path=target.resolve(),
        repository_root=root,
        source_type=source_type,
        source_label=source_label,
        requested_ref=requested_ref,
        commit=commit,
        branch=branch,
        dirty=dirty,
        tracked_files=tracked_files,
    )


@contextmanager
def checkout_source(
    source: str,
    ref: Optional[str] = None,
    full_history: bool = False,
) -> Iterator[Checkout]:
    """Yield a local Git checkout, optionally cloning complete remote history."""
    if not shutil.which("git"):
        raise FileNotFoundError("Git was not found on PATH.")

    local = Path(source).expanduser()
    if local.exists():
        if ref:
            raise ValueError("--ref is only supported when aws-posture clones a remote repository.")
        if not local.is_dir():
            raise ValueError(f"Repository path is not a directory: {local}")
        try:
            yield _checkout_details(local, "local", str(local.resolve()), None)
        except CodeScanError as exc:
            raise ValueError(f"Not a readable Git checkout: {local}: {exc}") from exc
        return

    if not _is_remote_source(source):
        raise FileNotFoundError(f"Repository path does not exist: {source}")
    _validate_remote_source(source)

    with tempfile.TemporaryDirectory(
        prefix="aws-posture-git-", ignore_cleanup_errors=True
    ) as temporary:
        destination = Path(temporary, "repository")
        command = ["git", "clone"]
        if not full_history:
            command += ["--depth", "1", "--no-tags"]
        if ref:
            command += ["--branch", ref]
            if not full_history:
                command.append("--single-branch")
        command += ["--", source, str(destination)]
        environment = os.environ.copy()
        environment["GIT_TERMINAL_PROMPT"] = "0"
        completed = _run(command, capture_output=True, env=environment)
        if completed.returncode != 0:
            message = (completed.stderr or completed.stdout or "Git clone failed").strip()
            message = message.replace(source, _safe_remote_label(source))
            raise CodeScanError(f"Could not clone repository: {message}")
        yield _checkout_details(
            destination,
            "remote",
            _safe_remote_label(source),
            ref,
        )


def git_version() -> Optional[str]:
    executable = shutil.which("git")
    if not executable:
        return None
    completed = _run([executable, "--version"], capture_output=True)
    return (completed.stdout or completed.stderr).strip() or None


def semgrep_path() -> Optional[str]:
    return shutil.which("semgrep")


def semgrep_version() -> Optional[str]:
    executable = semgrep_path()
    if not executable:
        return None
    completed = _run([executable, "--version"], capture_output=True)
    return (completed.stdout or completed.stderr).strip() or None


def semgrep_version_number() -> Optional[str]:
    version = semgrep_version()
    if not version:
        return None
    match = re.search(r"(?<!\d)(\d+\.\d+(?:\.\d+)?)(?!\d)", version)
    return match.group(1) if match else None


def _config_argument(config: str) -> str:
    path = Path(config).expanduser()
    return str(path.resolve()) if path.exists() else config


def run_semgrep(
    repository: Path,
    raw_output: Path,
    configs: Sequence[str],
    excludes: Sequence[str] = (),
    timeout: int = 30,
) -> list[str]:
    """Run one Semgrep CE scan with metrics and version checks disabled."""
    executable = semgrep_path()
    if not executable:
        raise FileNotFoundError(
            "Semgrep was not found on PATH. Install it with "
            f"`pipx install semgrep=={RECOMMENDED_SEMGREP_VERSION}`."
        )
    installed_version = semgrep_version_number()
    if installed_version != RECOMMENDED_SEMGREP_VERSION:
        detected = installed_version or "unknown"
        raise CodeScanError(
            f"Unsupported Semgrep version {detected}; install "
            f"Semgrep {RECOMMENDED_SEMGREP_VERSION}."
        )
    if not configs:
        raise ValueError("At least one Semgrep configuration is required.")
    if timeout < 0:
        raise ValueError("Semgrep timeout cannot be negative.")

    raw_output.parent.mkdir(parents=True, exist_ok=True)
    command = [executable, "scan"]
    for config in configs:
        command += ["--config", _config_argument(config)]
    command += [
        "--metrics",
        "off",
        "--disable-version-check",
        "--quiet",
        "--json-output",
        str(raw_output),
        "--timeout",
        str(timeout),
    ]
    for pattern in excludes:
        command += ["--exclude", pattern]
    command.append(str(repository))

    environment = os.environ.copy()
    environment["SEMGREP_SEND_METRICS"] = "off"
    environment["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
    completed = _run(
        command,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if completed.returncode != 0:
        raise CodeScanError(
            f"Semgrep exited with code {completed.returncode}; verify the selected "
            "configuration or run Semgrep directly for diagnostic output."
        )
    if not raw_output.is_file():
        raise CodeScanError("Semgrep completed without producing JSON output.")
    return command


def _string_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item]
    return [str(value)]


def relative_repository_path(value: str, checkout: Checkout) -> str:
    """Return a repository-relative POSIX path, falling back to the base name."""
    path = Path(value)
    if not path.is_absolute():
        return path.as_posix()
    try:
        return path.resolve().relative_to(checkout.repository_root).as_posix()
    except ValueError:
        return path.name


def normalize_findings(data: dict, checkout: Checkout) -> list[dict]:
    """Normalize and deduplicate findings by rule, file, and source range."""
    deduplicated: dict[tuple, dict] = {}
    for result in data.get("results", []):
        if not isinstance(result, dict):
            continue
        extra = result.get("extra") or {}
        metadata = extra.get("metadata") or {}
        start = result.get("start") or {}
        end = result.get("end") or {}
        severity = str(extra.get("severity") or "INFO").upper()
        finding = {
            "rule_id": str(result.get("check_id") or "unknown"),
            "path": relative_repository_path(str(result.get("path") or "unknown"), checkout),
            "start_line": int(start.get("line") or 0),
            "start_column": int(start.get("col") or 0),
            "end_line": int(end.get("line") or 0),
            "end_column": int(end.get("col") or 0),
            "severity": severity,
            "message": str(extra.get("message") or ""),
            "fix": str(extra.get("fix") or ""),
            "category": str(metadata.get("category") or "security"),
            "confidence": str(metadata.get("confidence") or ""),
            "impact": str(metadata.get("impact") or ""),
            "likelihood": str(metadata.get("likelihood") or ""),
            "cwe": _string_list(metadata.get("cwe")),
            "owasp": _string_list(metadata.get("owasp")),
            "references": _string_list(metadata.get("references")),
        }
        key = (
            finding["rule_id"],
            finding["path"],
            finding["start_line"],
            finding["start_column"],
            finding["end_line"],
            finding["end_column"],
        )
        deduplicated[key] = finding
    return sorted(
        deduplicated.values(),
        key=lambda item: (
            SEVERITY_RANK.get(item["severity"], len(SEVERITY_RANK)),
            item["path"],
            item["start_line"],
            item["rule_id"],
        ),
    )


def aggregate(data: dict, checkout: Checkout, configs: Sequence[str]) -> dict:
    findings = normalize_findings(data, checkout)
    severity_counts: dict[str, int] = {}
    rule_ids: set[str] = set()
    files: set[str] = set()
    for finding in findings:
        severity = finding["severity"]
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        rule_ids.add(finding["rule_id"])
        files.add(finding["path"])
    errors = []
    for error in data.get("errors", []):
        if not isinstance(error, dict):
            continue
        normalized_error = {
            key: str(error.get(key) or "")
            for key in ("type", "level", "message", "code")
            if error.get(key) is not None
        }
        if error.get("path"):
            normalized_error["path"] = relative_repository_path(
                str(error["path"]), checkout
            )
        errors.append(normalized_error)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scanner": "Semgrep Community Edition",
        "scanner_version": str(data.get("version") or semgrep_version() or "unknown"),
        "metrics_enabled": False,
        "repository": {
            "source_type": checkout.source_type,
            "source": checkout.source_label,
            "requested_ref": checkout.requested_ref,
            "commit": checkout.commit,
            "branch": checkout.branch,
            "dirty": checkout.dirty,
            "tracked_files": checkout.tracked_files,
        },
        "configs": list(configs),
        "total_findings": len(findings),
        "affected_files": len(files),
        "distinct_rules": len(rule_ids),
        "severity_counts": dict(
            sorted(
                severity_counts.items(),
                key=lambda item: SEVERITY_RANK.get(item[0], len(SEVERITY_RANK)),
            )
        ),
        "scan_errors": len(errors),
        "errors": errors,
        "findings": findings,
    }




def render_markdown(summary: dict) -> str:
    repository = summary["repository"]
    lines = [
        "# Code vulnerability report",
        "",
        f"- Scanner: **{md_escape(summary['scanner'])} {md_escape(summary['scanner_version'])}**",
        f"- Source: `{md_escape(repository['source'])}`",
        f"- Commit: `{md_escape(repository['commit'])}`",
        f"- Branch: `{md_escape(repository['branch'] or 'detached')}`",
        f"- Working tree dirty: **{'yes' if repository['dirty'] else 'no'}**",
        f"- Findings: **{summary['total_findings']}** across **{summary['affected_files']}** files",
        "- Semgrep metrics: **disabled**",
        "",
        "Semgrep findings are potential vulnerabilities and require developer validation. "
        "They are intentionally separate from the AWS posture score.",
        "",
        "## Severity summary",
        "",
        "| Severity | Findings |",
        "|---|---:|",
    ]
    for severity, count in summary["severity_counts"].items():
        lines.append(f"| {md_escape(severity)} | {count} |")
    if not summary["severity_counts"]:
        lines.append("| None | 0 |")
    lines += ["", "## Findings", ""]
    if not summary["findings"]:
        lines.append("No code vulnerabilities were reported by the selected rules.")
    for index, finding in enumerate(summary["findings"], 1):
        lines += [
            f"### {index}. [{md_escape(finding['severity'])}] {md_escape(finding['rule_id'])}",
            "",
            f"- Location: `{md_escape(finding['path'])}:{finding['start_line']}:{finding['start_column']}`",
            f"- Message: {md_escape(finding['message'])}",
        ]
        if finding["cwe"]:
            lines.append(f"- CWE: {md_escape(', '.join(finding['cwe']))}")
        if finding["owasp"]:
            lines.append(f"- OWASP: {md_escape(', '.join(finding['owasp']))}")
        if finding["confidence"]:
            lines.append(f"- Confidence: {md_escape(finding['confidence'])}")
        if finding["fix"]:
            lines.append(f"- Suggested fix: {md_escape(finding['fix'])}")
        if finding["references"]:
            lines.append(f"- References: {md_escape(', '.join(finding['references']))}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_html(summary: dict) -> str:
    repository = summary["repository"]
    severity_rows = "".join(
        f"<tr><td>{html_escape(severity)}</td><td>{count}</td></tr>"
        for severity, count in summary["severity_counts"].items()
    ) or "<tr><td>None</td><td>0</td></tr>"
    cards = []
    for finding in summary["findings"]:
        details = [
            f"<p><b>Location:</b> <code>{html_escape(finding['path'])}:{finding['start_line']}:{finding['start_column']}</code></p>",
            f"<p><b>Message:</b> {html_escape(finding['message'])}</p>",
        ]
        if finding["cwe"]:
            details.append(f"<p><b>CWE:</b> {html_escape(', '.join(finding['cwe']))}</p>")
        if finding["owasp"]:
            details.append(f"<p><b>OWASP:</b> {html_escape(', '.join(finding['owasp']))}</p>")
        if finding["confidence"]:
            details.append(f"<p><b>Confidence:</b> {html_escape(finding['confidence'])}</p>")
        if finding["fix"]:
            details.append(f"<p><b>Suggested fix:</b> {html_escape(finding['fix'])}</p>")
        if finding["references"]:
            details.append(f"<p><b>References:</b> {html_escape(', '.join(finding['references']))}</p>")
        cards.append(
            f"<section class='finding'><h3>[{html_escape(finding['severity'])}] "
            f"{html_escape(finding['rule_id'])}</h3>{''.join(details)}</section>"
        )
    findings_html = "".join(cards) or "<p>No code vulnerabilities were reported by the selected rules.</p>"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Code vulnerability report</title>
<style>body{{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#17202a}}table{{border-collapse:collapse}}th,td{{border:1px solid #ccd1d1;padding:.45rem .8rem;text-align:left}}.finding{{border-left:5px solid #c0392b;background:#f8f9f9;padding:.5rem 1rem;margin:1rem 0}}code{{overflow-wrap:anywhere}}.note{{background:#fff4ce;padding:.8rem}}</style></head>
<body><h1>Code vulnerability report</h1>
<ul><li>Scanner: <b>{html_escape(summary['scanner'])} {html_escape(summary['scanner_version'])}</b></li>
<li>Source: <code>{html_escape(repository['source'])}</code></li><li>Commit: <code>{html_escape(repository['commit'])}</code></li>
<li>Branch: <code>{html_escape(repository['branch'] or 'detached')}</code></li>
<li>Working tree dirty: <b>{'yes' if repository['dirty'] else 'no'}</b></li>
<li>Findings: <b>{summary['total_findings']}</b> across <b>{summary['affected_files']}</b> files</li>
<li>Semgrep metrics: <b>disabled</b></li></ul>
<p class="note">Semgrep findings are potential vulnerabilities and require developer validation. They are intentionally separate from the AWS posture score.</p>
<h2>Severity summary</h2><table><thead><tr><th>Severity</th><th>Findings</th></tr></thead><tbody>{severity_rows}</tbody></table>
<h2>Findings</h2>{findings_html}</body></html>"""


def build_report(raw_input: Path, checkout: Checkout, configs: Sequence[str], report_dir: Path) -> dict:
    try:
        data = json.loads(raw_input.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CodeScanError(f"Could not parse Semgrep JSON output: {exc}") from exc
    if not isinstance(data, dict):
        raise CodeScanError("Semgrep JSON output must be an object.")
    summary = aggregate(data, checkout, configs)
    report_dir.mkdir(parents=True, exist_ok=True)
    Path(report_dir, "code-summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )
    Path(report_dir, "code-report.md").write_text(
        render_markdown(summary), encoding="utf-8"
    )
    Path(report_dir, "code-report.html").write_text(
        render_html(summary), encoding="utf-8"
    )
    return summary
