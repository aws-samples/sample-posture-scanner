"""GenAI red-team reporting (JSON, Markdown, HTML).

Each target is reported separately with per-plugin attack success rates. No
combined score is produced and nothing is merged with AWS posture results.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .promptfoo_scan import SEVERITY_RANK
from .report_text import html_escape, md_escape


def combine(target_summaries: list[dict], failures: dict[str, str], context: dict) -> dict:
    findings = [item for summary in target_summaries for item in summary["findings"]]
    findings.sort(
        key=lambda item: (SEVERITY_RANK.get(item["severity"], 99), item["target"], item["plugin"])
    )
    requested = context.get("targets", [])
    status = (
        "failed"
        if not target_summaries
        else ("partial" if failures else "complete")
    )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": status,
        **context,
        "requested_targets": len(requested),
        "completed_targets": [summary["target"] for summary in target_summaries],
        "failed_targets": failures,
        "counts": {
            "probes": sum(summary["total_probes"] for summary in target_summaries),
            "errored_probes": sum(summary["errored_probes"] for summary in target_summaries),
            "successful_attacks": len(findings),
            "vulnerable_target_plugins": sum(
                summary["vulnerable_plugins"] for summary in target_summaries
            ),
        },
        "severity_counts": dict(
            sorted(
                Counter(item["severity"] for item in findings).items(),
                key=lambda item: SEVERITY_RANK.get(item[0], 99),
            )
        ),
        "targets": target_summaries,
        "findings": findings,
        "score": None,
        "score_note": (
            "No combined score is calculated. Red-team results are probabilistic: "
            "a passing plugin means these generated attacks failed, not that the "
            "target is secure. Attack success rates are per target and plugin."
        ),
    }


def render_markdown(summary: dict) -> str:
    counts = summary["counts"]
    lines = [
        "# GenAI red-team report (Amazon Bedrock)",
        "",
        f"- Status: **{md_escape(summary['status'])}**",
        f"- Account / region: `{md_escape(summary.get('account'))}` / `{md_escape(summary.get('region'))}`",
        f"- Engine: promptfoo {md_escape(summary.get('promptfoo_version'))}; depth "
        f"**{md_escape(summary.get('depth'))}**; hosted generation "
        f"**{'allowed' if summary.get('remote_generation') else 'disabled'}**",
        f"- Probes: {counts['probes']} ({counts['errored_probes']} errored)",
        f"- Successful attacks: **{counts['successful_attacks']}**",
        "",
        f"> {md_escape(summary['score_note'])}",
        "",
    ]
    if summary["failed_targets"]:
        lines += ["## Target failures", ""]
        lines += [f"- **{md_escape(k)}:** {md_escape(v)}" for k, v in summary["failed_targets"].items()]
        lines.append("")
    for target in summary["targets"]:
        lines += [
            f"## {md_escape(target['target'])} ({md_escape(target['target_kind'])})",
            "",
            f"Attack success rate: **{target['attack_success_rate']}%** of "
            f"{target['total_probes'] - target['errored_probes']} graded probes.",
            "",
            "| Plugin | OWASP LLM | Attempts | Successful attacks | Rate |",
            "|---|---|---:|---:|---:|",
        ]
        for item in target["plugins"]:
            lines.append(
                f"| {md_escape(item['plugin'])} | {md_escape(item['owasp_llm'])} | {item['attempts']} | "
                f"{item['successful_attacks']} | {item['attack_success_rate']}% |"
            )
        if target.get("skipped_plugins"):
            lines += [
                "",
                "Not run (require Promptfoo-hosted generation): "
                + md_escape(", ".join(target["skipped_plugins"])),
            ]
        lines.append("")
    lines += ["## Successful attacks (evidence)", ""]
    if not summary["findings"]:
        lines.append("No generated attack succeeded.")
    for finding in summary["findings"]:
        lines += [
            f"### [{md_escape(finding['severity'].upper())}] {md_escape(finding['plugin'])} — {md_escape(finding['target'])}",
            f"- Strategy: {md_escape(finding['strategy'])}; OWASP: {md_escape(finding['owasp_llm'] or 'n/a')}",
            f"- Attack: {md_escape(finding['attack'])}",
            f"- Response: {md_escape(finding['response'])}",
            f"- Grader: {md_escape(finding['grader_reason'])}",
            "",
        ]
    return "\n".join(lines).rstrip() + "\n"


def render_html(summary: dict) -> str:
    counts = summary["counts"]
    target_sections = []
    for target in summary["targets"]:
        rows = "".join(
            f"<tr><td>{html_escape(i['plugin'])}</td><td>{html_escape(i['owasp_llm'])}</td>"
            f"<td>{i['attempts']}</td><td>{i['successful_attacks']}</td>"
            f"<td>{i['attack_success_rate']}%</td></tr>"
            for i in target["plugins"]
        )
        skipped = (
            f"<p>Not run (require hosted generation): {html_escape(', '.join(target['skipped_plugins']))}</p>"
            if target.get("skipped_plugins")
            else ""
        )
        target_sections.append(
            f"<h3>{html_escape(target['target'])} ({html_escape(target['target_kind'])})</h3>"
            f"<p>Attack success rate: <b>{html_escape(target['attack_success_rate'])}%</b></p>"
            "<table><thead><tr><th scope=col>Plugin</th><th scope=col>OWASP LLM</th>"
            "<th scope=col>Attempts</th><th scope=col>Successful</th><th scope=col>Rate</th>"
            f"</tr></thead><tbody>{rows}</tbody></table>{skipped}"
        )
    evidence = "".join(
        f"<section><h3>[{html_escape(f['severity'].upper())}] {html_escape(f['plugin'])} — {html_escape(f['target'])}</h3>"
        f"<p>Strategy {html_escape(f['strategy'])}; {html_escape(f['owasp_llm'])}</p>"
        f"<p><b>Attack</b></p><pre>{html_escape(f['attack'])}</pre>"
        f"<p><b>Response</b></p><pre>{html_escape(f['response'])}</pre>"
        f"<p><b>Grader</b>: {html_escape(f['grader_reason'])}</p></section>"
        for f in summary["findings"]
    )
    failures = "".join(
        f"<li><b>{html_escape(k)}:</b> {html_escape(v)}</li>" for k, v in summary["failed_targets"].items()
    )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>GenAI red-team report</title>
<style>body{{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#17202a}}table{{border-collapse:collapse}}th,td{{border:1px solid #ccd1d1;padding:.45rem .8rem;text-align:left}}section{{border-left:5px solid #c0392b;background:#f8f9f9;padding:.4rem 1rem;margin:1rem 0}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}.note{{background:#fff4ce;padding:.8rem}}</style></head><body>
<h1>GenAI red-team report (Amazon Bedrock)</h1><ul><li>Status: <b>{html_escape(summary['status'])}</b></li>
<li>Account / region: <code>{html_escape(summary.get('account'))}</code> / <code>{html_escape(summary.get('region'))}</code></li>
<li>promptfoo {html_escape(summary.get('promptfoo_version'))}, depth {html_escape(summary.get('depth'))}</li>
<li>Probes: {counts['probes']} ({counts['errored_probes']} errored); successful attacks: <b>{counts['successful_attacks']}</b></li></ul>
<p class="note">{html_escape(summary['score_note'])}</p>
{'<h2>Target failures</h2><ul>' + failures + '</ul>' if failures else ''}
<h2>Targets</h2>{''.join(target_sections) or '<p>No target completed.</p>'}
<h2>Successful attacks</h2>{evidence or '<p>No generated attack succeeded.</p>'}
</body></html>"""


def build_report(
    target_summaries: list[dict], failures: dict[str, str], context: dict, report_dir: Path
) -> dict:
    summary = combine(target_summaries, failures, context)
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "genai-summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (report_dir / "genai-report.md").write_text(render_markdown(summary), encoding="utf-8")
    (report_dir / "genai-report.html").write_text(render_html(summary), encoding="utf-8")
    return summary
