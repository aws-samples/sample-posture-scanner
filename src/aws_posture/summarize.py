"""Parse Prowler results and build a deduplicated posture report.

Prowler v4/v5 JSON-OCSF is preferred. Native Prowler v3 JSON remains supported
for importing historical reports. Multiple files are treated as snapshots: for a
given account/check/resource/region, the newest observation wins.
"""

from __future__ import annotations

import glob
import html
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional, Sequence

SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITY_ORDER)}
SEVERITY_SCORE_CAP = {
    "critical": 39.0,
    "high": 59.0,
    "medium": 74.0,
    "low": 89.0,
    "informational": 99.0,
}


def _norm_severity(value) -> str:
    normalized = str(value or "informational").strip().lower()
    if normalized in {"info", "none"}:
        normalized = "informational"
    return normalized if normalized in SEVERITY_RANK else "informational"


def _norm_status(value) -> str:
    normalized = str(value or "INFO").strip().upper()
    if normalized in {"PASS", "PASSED"}:
        return "PASS"
    if normalized in {"FAIL", "FAILED", "FAILURE"}:
        return "FAIL"
    return "INFO"


def _time_value(value) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if not value:
        return 0.0
    text = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except ValueError:
        return 0.0


def _native_finding(record: dict) -> dict:
    remediation = record.get("Remediation") or {}
    code = remediation.get("Code") or {} if isinstance(remediation, dict) else {}
    recommendation = (
        remediation.get("Recommendation") or {} if isinstance(remediation, dict) else {}
    )
    return {
        "observed_at": _time_value(record.get("AssessmentStartTime")),
        "check_id": record.get("CheckID") or "unknown",
        "title": record.get("CheckTitle") or record.get("CheckID") or "",
        "status": _norm_status(record.get("Status")),
        "severity": _norm_severity(record.get("Severity")),
        "service": str(record.get("ServiceName") or "unknown").lower(),
        "region": record.get("Region") or "global",
        "account": str(record.get("AccountId") or ""),
        "resource": record.get("ResourceArn") or record.get("ResourceId") or "",
        "status_extended": record.get("StatusExtended") or "",
        "risk": record.get("Risk") or "",
        "remediation_text": (
            recommendation.get("Text") if isinstance(recommendation, dict) else ""
        )
        or "",
        "remediation_cli": (
            code.get("CLI") if isinstance(code, dict) else ""
        )
        or "",
        "related_url": record.get("RelatedUrl") or "",
    }


def _ocsf_finding(record: dict) -> dict:
    metadata = record.get("metadata") or {}
    finding_info = record.get("finding_info") or {}
    resources = record.get("resources") or []
    resource = resources[0] if resources else {}
    group = resource.get("group") or {}
    cloud = record.get("cloud") or {}
    account = cloud.get("account") or {}
    remediation = record.get("remediation") or {}
    unmapped = record.get("unmapped") or {}
    references = remediation.get("references") or [] if isinstance(remediation, dict) else []
    related_url = unmapped.get("related_url") or (references[0] if references else "")
    return {
        "observed_at": _time_value(record.get("time_dt") or record.get("time")),
        "check_id": metadata.get("event_code") or finding_info.get("title") or "unknown",
        "title": finding_info.get("title") or metadata.get("event_code") or "",
        "status": _norm_status(record.get("status_code") or record.get("status")),
        "severity": _norm_severity(record.get("severity")),
        "service": str(group.get("name") or resource.get("type") or "unknown").lower(),
        "region": resource.get("region") or cloud.get("region") or "global",
        "account": str(account.get("uid") or ""),
        "resource": resource.get("uid") or resource.get("name") or "",
        "status_extended": record.get("status_detail") or record.get("message") or "",
        "risk": record.get("risk_details") or "",
        "remediation_text": (
            remediation.get("desc") if isinstance(remediation, dict) else ""
        )
        or "",
        "remediation_cli": "",
        "related_url": related_url,
    }


def _is_compliance_path(path: str) -> bool:
    return "compliance" in {part.lower() for part in Path(path).parts}


def expand_inputs(inputs: Sequence[str]) -> list[str]:
    """Expand input paths, preferring OCSF over native JSON per directory."""
    selected: list[str] = []
    for item in inputs:
        if os.path.isdir(item):
            candidates = glob.glob(os.path.join(item, "**", "*.json"), recursive=True)
            candidates = [
                path
                for path in candidates
                if not _is_compliance_path(path)
                and not path.endswith("posture-summary.json")
            ]
            ocsf = [path for path in candidates if path.endswith(".ocsf.json")]
            selected.extend(ocsf or candidates)
        elif any(character in item for character in "*?["):
            selected.extend(glob.glob(item, recursive=True))
        else:
            selected.append(item)
    return sorted(
        {
            path
            for path in selected
            if path.endswith(".json")
            and not _is_compliance_path(path)
            and not path.endswith("posture-summary.json")
        }
    )


def load_findings(paths: Iterable[str]) -> list[dict]:
    """Load findings, retaining only the newest state for each resource/check."""
    latest: dict[tuple[str, str, str, str], dict] = {}
    for path in paths:
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (json.JSONDecodeError, OSError) as exc:
            print(f"  ! skipping {path}: {exc}", file=sys.stderr)
            continue
        records = data if isinstance(data, list) else [data]
        for record in records:
            if not isinstance(record, dict):
                continue
            finding = None
            if "CheckID" in record:
                finding = _native_finding(record)
            elif "status_code" in record and "finding_info" in record:
                finding = _ocsf_finding(record)
            if not finding:
                continue
            identity = (
                finding["account"],
                finding["check_id"],
                finding["resource"],
                finding["region"],
            )
            current = latest.get(identity)
            if current is None or finding["observed_at"] >= current["observed_at"]:
                latest[identity] = finding
    return list(latest.values())


def _highest_severity(findings: Sequence[dict]) -> Optional[str]:
    failing = [finding["severity"] for finding in findings if finding["status"] == "FAIL"]
    return min(failing, key=SEVERITY_RANK.get) if failing else None


def aggregate(findings: Sequence[dict], input_file_count: int = 0) -> dict:
    """Aggregate resource results and account-level distinct failing checks."""
    status_counts: defaultdict[str, int] = defaultdict(int)
    accounts, regions = set(), set()
    grouped: dict[tuple[str, str], dict] = {}

    for finding in findings:
        status_counts[finding["status"]] += 1
        if finding["account"]:
            accounts.add(finding["account"])
        if finding["region"]:
            regions.add(finding["region"])
        if finding["status"] != "FAIL":
            continue

        key = (finding["account"], finding["check_id"])
        group = grouped.get(key)
        if group is None:
            group = {
                "account": finding["account"],
                "check_id": finding["check_id"],
                "title": finding["title"],
                "severity": finding["severity"],
                "service": finding["service"],
                "risk": finding["risk"],
                "remediation_text": finding["remediation_text"],
                "remediation_cli": finding["remediation_cli"],
                "related_url": finding["related_url"],
                "resources": set(),
                "regions": set(),
                "sample_status": finding["status_extended"],
            }
            grouped[key] = group
        elif SEVERITY_RANK[finding["severity"]] < SEVERITY_RANK[group["severity"]]:
            group["severity"] = finding["severity"]
        if finding["resource"]:
            group["resources"].add(finding["resource"])
        if finding["region"]:
            group["regions"].add(finding["region"])

    deduped = []
    severity_counts: defaultdict[str, int] = defaultdict(int)
    service_counts: defaultdict[str, int] = defaultdict(int)
    for group in grouped.values():
        group["regions"] = sorted(group["regions"])
        group["resource_count"] = max(
            len(group["resources"]), len(group["regions"]), 1
        )
        group["resources"] = sorted(group["resources"])
        severity_counts[group["severity"]] += 1
        service_counts[group["service"]] += 1
        deduped.append(group)
    deduped.sort(
        key=lambda item: (
            SEVERITY_RANK[item["severity"]],
            item["account"],
            -item["resource_count"],
            item["check_id"],
        )
    )

    passed = status_counts["PASS"]
    failed = status_counts["FAIL"]
    evaluated = passed + failed
    pass_rate = round(100.0 * passed / evaluated, 1) if evaluated else None
    highest = _highest_severity(findings)
    score = None
    if pass_rate is not None:
        score = pass_rate if highest is None else min(pass_rate, SEVERITY_SCORE_CAP[highest])
        score = round(score, 1)

    return {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "input_file_count": input_file_count,
        "accounts": sorted(accounts),
        "regions": sorted(region for region in regions if region and region != "global"),
        "total": sum(status_counts.values()),
        "passed": passed,
        "failed": failed,
        "evaluated": evaluated,
        "info": status_counts["INFO"],
        "pass_rate": pass_rate,
        "score": score,
        "highest_failed_severity": highest,
        "sev_fail": {severity: severity_counts[severity] for severity in SEVERITY_ORDER},
        "service_fail": dict(
            sorted(service_counts.items(), key=lambda item: (-item[1], item[0]))
        ),
        "deduped": deduped,
        "distinct_failed_checks": len(deduped),
        "finding_count": len(findings),
    }


def grade(score: Optional[float]) -> str:
    if score is None:
        return "Not rated"
    if score >= 90:
        return "A (Strong)"
    if score >= 75:
        return "B (Good)"
    if score >= 60:
        return "C (Needs work)"
    if score >= 40:
        return "D (Weak)"
    return "F (Critical exposure)"


def _number(value: Optional[float]) -> str:
    return "N/A" if value is None else f"{value:.1f}"


def render_markdown(summary: dict) -> str:
    lines = [
        "# AWS Account Posture Report\n",
        f"**Generated:** {summary['generated']}  ",
        f"**Account(s):** {', '.join(summary['accounts']) or 'n/a'}  ",
        f"**Regions represented in findings:** {len(summary['regions'])} "
        f"({', '.join(summary['regions']) or 'n/a'})  ",
        f"**Source JSON files:** {summary['input_file_count']}\n",
        "## Posture Summary\n",
        f"- **Risk-adjusted posture score:** {_number(summary['score'])} / 100 — "
        f"**{grade(summary['score'])}**",
        "- **Score method:** resource pass rate capped by the highest outstanding "
        "severity (local heuristic; not Prowler ThreatScore).",
        f"- **Resource pass rate:** {_number(summary['pass_rate'])}% "
        f"({summary['passed']} passed / {summary['evaluated']} evaluated)",
        f"- **Resource findings:** {summary['total']} total "
        f"(FAIL {summary['failed']}, PASS {summary['passed']}, INFO {summary['info']})",
        f"- **Distinct failing checks:** {summary['distinct_failed_checks']} "
        f"across {len(summary['accounts']) or 1} account(s)\n",
        "## Distinct Failures by Severity\n",
        "| Severity | Failing checks |",
        "|---|---:|",
    ]
    for severity in SEVERITY_ORDER:
        lines.append(f"| {severity.capitalize()} | {summary['sev_fail'][severity]} |")
    lines += [
        "",
        "## Distinct Failures by Service (top 15)\n",
        "| Service | Failing checks |",
        "|---|---:|",
    ]
    for service, count in list(summary["service_fail"].items())[:15]:
        lines.append(f"| {service} | {count} |")
    lines += ["", "## Prioritised Findings\n"]
    lines.append(
        "> Every item below is a **FAILED** check. The heading states the actual "
        "failing condition; **Control checked** is Prowler's compliant control name "
        "(the desired state).\n"
    )
    for finding in summary["deduped"]:
        problem = finding["sample_status"] or finding["title"]
        lines.append(f"### [{finding['severity'].upper()}] {problem}")
        lines.append(
            f"- **Status:** FAIL — not met for {finding['resource_count']} resource(s)."
        )
        lines.append(f"- **Control checked:** {finding['title']}")
        lines.append(
            f"- **Account:** `{finding['account'] or 'n/a'}` | "
            f"**Check:** `{finding['check_id']}` | **Service:** {finding['service']} | "
            f"**Affected resources/regions:** {finding['resource_count']} | "
            f"**Regions:** {', '.join(finding['regions']) or 'global'}"
        )
        if finding["remediation_text"]:
            lines.append(f"- **Remediation:** {finding['remediation_text']}")
        if finding["remediation_cli"]:
            lines.append(f"- **CLI:** `{finding['remediation_cli']}`")
        if finding["related_url"]:
            lines.append(f"- **Reference:** {finding['related_url']}")
        lines.append("")
    return "\n".join(lines)


def render_html(summary: dict) -> str:
    severity_color = {
        "critical": "#8b0000",
        "high": "#d9534f",
        "medium": "#f0ad4e",
        "low": "#5bc0de",
        "informational": "#777",
    }
    finding_rows = []
    for finding in summary["deduped"]:
        problem = finding.get("sample_status") or finding["title"]
        finding_rows.append(
            "<tr>"
            f"<td><span class='badge' style='background:{severity_color[finding['severity']]}'>{html.escape(finding['severity'].upper())}</span></td>"
            f"<td>{html.escape(finding['account'] or 'n/a')}</td>"
            f"<td><b>{html.escape(problem)}</b><br><code>{html.escape(finding['check_id'])}</code>"
            f"<br><span style='color:#555'>Control checked: {html.escape(finding['title'])}</span></td>"
            f"<td>{html.escape(finding['service'])}</td>"
            f"<td class='number'>{finding['resource_count']}</td>"
            f"<td>{html.escape(finding['remediation_text'][:300])}</td>"
            "</tr>"
        )
    severity_rows = "".join(
        f"<tr><td>{severity.capitalize()}</td><td class='number'>{summary['sev_fail'][severity]}</td></tr>"
        for severity in SEVERITY_ORDER
    )
    service_rows = "".join(
        f"<tr><td>{html.escape(service)}</td><td class='number'>{count}</td></tr>"
        for service, count in list(summary["service_fail"].items())[:15]
    )
    score = _number(summary["score"])
    score_color = (
        "#777"
        if summary["score"] is None
        else "#5cb85c"
        if summary["score"] >= 75
        else "#f0ad4e"
        if summary["score"] >= 40
        else "#d9534f"
    )
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>AWS Posture Report</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:40px;color:#222;background:#fafafa}}
h1{{border-bottom:3px solid #232f3e;padding-bottom:8px}} .score{{font-size:54px;font-weight:700;color:{score_color}}}
.card{{background:#fff;border:1px solid #e2e2e2;border-radius:10px;padding:18px 22px;margin:16px 0;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
table{{border-collapse:collapse;width:100%;margin-top:8px}} th,td{{border:1px solid #e4e4e4;padding:8px 10px;font-size:14px;vertical-align:top}}
th{{background:#232f3e;color:#fff;text-align:left}} .number{{text-align:right}} .badge{{color:#fff;padding:2px 8px;border-radius:10px;font-size:12px;font-weight:600}}
code{{background:#f2f2f2;padding:1px 5px;border-radius:4px;font-size:12px}} .meta{{color:#666;font-size:14px}}
</style></head><body>
<h1>AWS Account Posture Report</h1>
<p class="meta">Generated {html.escape(summary['generated'])} &middot; Accounts: {html.escape(', '.join(summary['accounts']) or 'n/a')} &middot; Regions represented: {len(summary['regions'])}</p>
<div class="card"><div class="score">{score}/100</div><div><b>{html.escape(grade(summary['score']))}</b></div>
<div class="meta">Local risk-adjusted score: resource pass rate capped by highest outstanding severity; not Prowler ThreatScore.</div>
<div>{summary['total']} resource findings &middot; {summary['failed']} failed &middot; {summary['distinct_failed_checks']} distinct failing checks</div></div>
<div class="card"><h2>Distinct Failures by Severity</h2><table><tr><th>Severity</th><th>Failing checks</th></tr>{severity_rows}</table></div>
<div class="card"><h2>Distinct Failures by Service</h2><table><tr><th>Service</th><th>Failing checks</th></tr>{service_rows}</table></div>
<div class="card"><h2>Prioritised Findings</h2><p class="meta">Every row is a <b>FAILED</b> check. The finding shows the actual failing condition; <i>Control checked</i> is Prowler's compliant control name (the desired state).</p><table><tr><th>Severity</th><th>Account</th><th>Failing condition</th><th>Service</th><th>Affected</th><th>Remediation</th></tr>{''.join(finding_rows)}</table></div>
</body></html>"""


def build_report(inputs: Sequence[str], outdir: str) -> dict:
    paths = expand_inputs(inputs)
    if not paths:
        raise FileNotFoundError("No Prowler JSON input files were found.")
    findings = load_findings(paths)
    if not findings:
        raise ValueError("No Prowler v3 or JSON-OCSF findings could be parsed.")
    summary = aggregate(findings, input_file_count=len(paths))
    Path(outdir).mkdir(parents=True, exist_ok=True)
    Path(outdir, "posture-report.md").write_text(
        render_markdown(summary), encoding="utf-8"
    )
    Path(outdir, "posture-report.html").write_text(
        render_html(summary), encoding="utf-8"
    )
    serializable = {key: value for key, value in summary.items() if key != "deduped"}
    serializable["deduped"] = [
        {key: value for key, value in finding.items() if key != "resources"}
        for finding in summary["deduped"]
    ]
    Path(outdir, "posture-summary.json").write_text(
        json.dumps(serializable, indent=2), encoding="utf-8"
    )
    return summary
