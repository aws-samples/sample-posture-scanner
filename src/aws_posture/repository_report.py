"""Unified reporting for Semgrep, Gitleaks, and Trivy repository scans."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .code_scan import Checkout
from .report_text import html_escape, md_escape


def combine(
    checkout: Checkout,
    semgrep: Optional[dict],
    gitleaks: Optional[dict],
    trivy: Optional[dict],
    failures: dict[str, str],
) -> dict:
    sast = semgrep["total_findings"] if semgrep else 0
    secrets = gitleaks["total_findings"] if gitleaks else 0
    dependencies = trivy["vulnerabilities"] if trivy else 0
    iac = trivy["misconfigurations"] if trivy else 0
    licenses = trivy["licenses_detected"] if trivy else 0
    components = trivy["sbom_components"] if trivy else 0
    scanners = {
        "semgrep": semgrep,
        "gitleaks": gitleaks,
        "trivy": trivy,
    }
    successful = [name for name, value in scanners.items() if value is not None]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": (
            "failed" if not successful else ("partial" if failures else "complete")
        ),
        "repository": {
            "source_type": checkout.source_type,
            "source": checkout.source_label,
            "requested_ref": checkout.requested_ref,
            "commit": checkout.commit,
            "branch": checkout.branch,
            "dirty": checkout.dirty,
            "tracked_files": checkout.tracked_files,
        },
        "successful_scanners": successful,
        "failed_scanners": failures,
        "counts": {
            "sast": sast,
            "secrets": secrets,
            "dependency_vulnerabilities": dependencies,
            "iac_misconfigurations": iac,
            "security_findings": sast + secrets + dependencies + iac,
            "licenses_detected": licenses,
            "sbom_components": components,
        },
        "semgrep": semgrep,
        "gitleaks": gitleaks,
        "trivy": trivy,
        "score": None,
        "score_note": (
            "No combined score is calculated because cloud posture, SAST, secrets, "
            "dependencies, IaC, and license evidence have different risk models."
        ),
    }




def render_markdown(summary: dict) -> str:
    repository = summary["repository"]
    counts = summary["counts"]
    lines = [
        "# Repository security report",
        "",
        f"- Status: **{md_escape(summary['status'])}**",
        f"- Source: `{md_escape(repository['source'])}`",
        f"- Commit: `{md_escape(repository['commit'])}`",
        f"- Branch: `{md_escape(repository['branch'] or 'detached')}`",
        f"- Working tree dirty: **{'yes' if repository['dirty'] else 'no'}**",
        f"- Successful scanners: **{md_escape(', '.join(summary['successful_scanners']) or 'none')}**",
        "",
        "## Security domains",
        "",
        "| Domain | Findings |",
        "|---|---:|",
        f"| SAST | {counts['sast']} |",
        f"| Secrets | {counts['secrets']} |",
        f"| Dependency vulnerabilities | {counts['dependency_vulnerabilities']} |",
        f"| IaC misconfigurations | {counts['iac_misconfigurations']} |",
        f"| **Total security findings** | **{counts['security_findings']}** |",
        f"| License inventory entries | {counts['licenses_detected']} |",
        f"| SBOM components | {counts['sbom_components']} |",
        "",
        f"> {md_escape(summary['score_note'])}",
        "",
    ]
    if summary["failed_scanners"]:
        lines += ["## Scanner failures", ""]
        for scanner, error in summary["failed_scanners"].items():
            lines.append(f"- **{md_escape(scanner)}:** {md_escape(error)}")
        lines.append("")

    semgrep = summary.get("semgrep")
    lines += ["## SAST findings (Semgrep)", ""]
    if not semgrep or not semgrep["findings"]:
        lines.append("No SAST findings reported.")
    else:
        for finding in semgrep["findings"]:
            lines += [
                f"### [{md_escape(finding['severity'])}] {md_escape(finding['rule_id'])}",
                f"- Location: `{md_escape(finding['path'])}:{finding['start_line']}`",
                f"- Message: {md_escape(finding['message'])}",
            ]
            if finding.get("fix"):
                lines.append(f"- Suggested fix: {md_escape(finding['fix'])}")
            lines.append("")

    gitleaks = summary.get("gitleaks")
    lines += ["## Secret findings (Gitleaks)", ""]
    if not gitleaks or not gitleaks["findings"]:
        lines.append("No secret findings reported.")
    else:
        for finding in gitleaks["findings"]:
            lines += [
                f"### [SECRET] {md_escape(finding['rule_id'])}",
                f"- Location: `{md_escape(finding['path'])}:{finding['start_line']}`",
                f"- Commit: `{md_escape(finding['commit'] or 'working tree')}`",
                f"- Description: {md_escape(finding['description'])}",
                "- Secret value: **fully redacted**",
                "",
            ]

    trivy = summary.get("trivy")
    lines += ["## Dependency and IaC findings (Trivy)", ""]
    if not trivy or not trivy["findings"]:
        lines.append("No dependency or IaC findings reported.")
    else:
        for finding in trivy["findings"]:
            if finding["domain"] == "dependency":
                location = finding["target"]
                details = (
                    f"Package `{md_escape(finding['package'])}` "
                    f"{md_escape(finding['installed_version'])}; fixed in "
                    f"{md_escape(finding['fixed_version'] or 'not published')}"
                )
            else:
                location = f"{finding['target']}:{finding['start_line']}"
                details = md_escape(finding.get("resolution") or finding.get("message"))
            lines += [
                f"### [{md_escape(finding['severity'])}] {md_escape(finding['id'])}",
                f"- Domain: {md_escape(finding['domain'])}",
                f"- Location: `{md_escape(location)}`",
                f"- Title: {md_escape(finding['title'])}",
                f"- Remediation: {details}",
                "",
            ]

    lines += ["## License inventory", ""]
    licenses = trivy["license_inventory"] if trivy else []
    if not licenses:
        lines.append("No package license entries reported.")
    else:
        lines += ["| License | Package | Path | Confidence |", "|---|---|---|---:|"]
        for item in licenses:
            lines.append(
                f"| {md_escape(item['name'])} | {md_escape(item['package'])} | "
                f"{md_escape(item['path'])} | {item['confidence']:.2f} |"
            )
    return "\n".join(lines).rstrip() + "\n"


def render_html(summary: dict) -> str:
    repository = summary["repository"]
    counts = summary["counts"]
    domain_rows = "".join(
        f"<tr><td>{html_escape(label)}</td><td>{value}</td></tr>"
        for label, value in (
            ("SAST", counts["sast"]),
            ("Secrets", counts["secrets"]),
            ("Dependency vulnerabilities", counts["dependency_vulnerabilities"]),
            ("IaC misconfigurations", counts["iac_misconfigurations"]),
            ("Total security findings", counts["security_findings"]),
            ("License inventory entries", counts["licenses_detected"]),
            ("SBOM components", counts["sbom_components"]),
        )
    )
    sections = []
    for finding in (summary.get("semgrep") or {}).get("findings", []):
        sections.append(
            f"<section><h3>[{html_escape(finding['severity'])}] {html_escape(finding['rule_id'])}</h3>"
            f"<p><b>SAST</b> — <code>{html_escape(finding['path'])}:{finding['start_line']}</code></p>"
            f"<p>{html_escape(finding['message'])}</p></section>"
        )
    for finding in (summary.get("gitleaks") or {}).get("findings", []):
        sections.append(
            f"<section><h3>[SECRET] {html_escape(finding['rule_id'])}</h3>"
            f"<p><code>{html_escape(finding['path'])}:{finding['start_line']}</code> — "
            f"secret fully redacted</p><p>{html_escape(finding['description'])}</p></section>"
        )
    for finding in (summary.get("trivy") or {}).get("findings", []):
        location = finding.get("target", "")
        if finding["domain"] == "iac":
            location += f":{finding['start_line']}"
        sections.append(
            f"<section><h3>[{html_escape(finding['severity'])}] {html_escape(finding['id'])}</h3>"
            f"<p><b>{html_escape(finding['domain'])}</b> — <code>{html_escape(location)}</code></p>"
            f"<p>{html_escape(finding['title'])}</p></section>"
        )
    failures = "".join(
        f"<li><b>{html_escape(name)}:</b> {html_escape(error)}</li>"
        for name, error in summary["failed_scanners"].items()
    )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Repository security report</title>
<style>body{{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#17202a}}table{{border-collapse:collapse}}th,td{{border:1px solid #ccd1d1;padding:.45rem .8rem;text-align:left}}section{{border-left:5px solid #c0392b;background:#f8f9f9;padding:.4rem 1rem;margin:1rem 0}}code{{overflow-wrap:anywhere}}.note{{background:#fff4ce;padding:.8rem}}</style></head><body>
<h1>Repository security report</h1><ul><li>Status: <b>{html_escape(summary['status'])}</b></li>
<li>Source: <code>{html_escape(repository['source'])}</code></li><li>Commit: <code>{html_escape(repository['commit'])}</code></li>
<li>Branch: <code>{html_escape(repository['branch'] or 'detached')}</code></li>
<li>Successful scanners: {html_escape(', '.join(summary['successful_scanners']) or 'none')}</li></ul>
<h2>Security domains</h2><table><thead><tr><th>Domain</th><th>Count</th></tr></thead><tbody>{domain_rows}</tbody></table>
<p class="note">{html_escape(summary['score_note'])}</p>
{'<h2>Scanner failures</h2><ul>'+failures+'</ul>' if failures else ''}
<h2>Security findings</h2>{''.join(sections) or '<p>No security findings reported.</p>'}
</body></html>"""


def build_report(
    checkout: Checkout,
    semgrep: Optional[dict],
    gitleaks: Optional[dict],
    trivy: Optional[dict],
    failures: dict[str, str],
    report_dir: Path,
) -> dict:
    summary = combine(checkout, semgrep, gitleaks, trivy, failures)
    report_dir.mkdir(parents=True, exist_ok=True)
    Path(report_dir, "repository-summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )
    Path(report_dir, "repository-report.md").write_text(
        render_markdown(summary), encoding="utf-8"
    )
    Path(report_dir, "repository-report.html").write_text(
        render_html(summary), encoding="utf-8"
    )
    return summary
