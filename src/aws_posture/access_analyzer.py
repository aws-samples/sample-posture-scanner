"""IAM Access Analyzer findings collection.

Pulls ACTIVE findings from every IAM Access Analyzer in the requested regions
so the posture report can distinguish *proven* external/unused access from the
theoretical misconfigurations Prowler flags.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Optional, Sequence

import boto3
from botocore.exceptions import BotoCoreError, ClientError


class AccessAnalyzerError(RuntimeError):
    """Raised when Access Analyzer findings cannot be collected."""


def _session(profile: Optional[str] = None) -> boto3.Session:
    return boto3.Session(profile_name=profile) if profile else boto3.Session()


def _assumed_session(
    base: boto3.Session,
    role: Optional[str],
    external_id: Optional[str],
    session_duration: int,
) -> boto3.Session:
    """Assume the scanner role when one is provided, mirroring the Prowler run."""
    if not role:
        return base
    params = {
        "RoleArn": role,
        "RoleSessionName": "aws-posture-access-analyzer",
        "DurationSeconds": session_duration,
    }
    if external_id:
        params["ExternalId"] = external_id
    credentials = base.client("sts").assume_role(**params)["Credentials"]
    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


def _enabled_regions(session: boto3.Session) -> list[str]:
    ec2 = session.client("ec2", region_name="us-east-1")
    response = ec2.describe_regions(
        Filters=[
            {"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}
        ]
    )
    return sorted(region["RegionName"] for region in response["Regions"])


def collect_findings(
    profile: Optional[str] = None,
    regions: Optional[Sequence[str]] = None,
    role: Optional[str] = None,
    external_id: Optional[str] = None,
    session_duration: int = 3600,
) -> dict:
    """Collect ACTIVE findings from all analyzers in scope.

    Returns a summary dictionary; raises AccessAnalyzerError only when nothing
    could be collected at all (credential/permission failure everywhere).
    """
    base = _session(profile)
    session = _assumed_session(base, role, external_id, session_duration)
    try:
        target_regions = list(regions) if regions else _enabled_regions(session)
    except (ClientError, BotoCoreError) as exc:
        raise AccessAnalyzerError(f"Could not enumerate enabled regions: {exc}") from exc

    analyzers: list[dict] = []
    findings: list[dict] = []
    region_errors: dict[str, str] = {}
    for region in target_regions:
        client = session.client("accessanalyzer", region_name=region)
        try:
            region_analyzers = []
            for page in client.get_paginator("list_analyzers").paginate():
                region_analyzers.extend(page.get("analyzers", []))
        except (ClientError, BotoCoreError) as exc:
            region_errors[region] = str(exc)
            continue
        for analyzer in region_analyzers:
            analyzers.append(
                {
                    "arn": analyzer["arn"],
                    "name": analyzer.get("name", ""),
                    "type": analyzer.get("type", ""),
                    "status": analyzer.get("status", ""),
                    "region": region,
                }
            )
            try:
                paginator = client.get_paginator("list_findings_v2")
                pages = paginator.paginate(
                    analyzerArn=analyzer["arn"],
                    filter={"status": {"eq": ["ACTIVE"]}},
                )
                for page in pages:
                    for finding in page.get("findings", []):
                        findings.append(
                            {
                                "id": finding.get("id", ""),
                                "analyzer": analyzer.get("name", ""),
                                "analyzer_type": analyzer.get("type", ""),
                                "region": region,
                                "resource": finding.get("resource", ""),
                                "resource_type": finding.get("resourceType", ""),
                                "resource_owner_account": finding.get(
                                    "resourceOwnerAccount", ""
                                ),
                                "finding_type": finding.get("findingType", ""),
                                "status": finding.get("status", ""),
                                "created_at": str(finding.get("createdAt", "")),
                            }
                        )
            except (ClientError, BotoCoreError) as exc:
                region_errors[region] = str(exc)

    if not analyzers and region_errors and len(region_errors) == len(target_regions):
        raise AccessAnalyzerError(
            "Access Analyzer could not be queried in any region; first error: "
            + next(iter(region_errors.values()))
        )

    by_resource_type = Counter(finding["resource_type"] for finding in findings)
    by_finding_type = Counter(
        finding["finding_type"] or "ExternalAccess" for finding in findings
    )
    return {
        "regions_checked": target_regions,
        "region_errors": region_errors,
        "analyzers": analyzers,
        "analyzer_count": len(analyzers),
        "active_finding_count": len(findings),
        "findings_by_resource_type": dict(by_resource_type),
        "findings_by_finding_type": dict(by_finding_type),
        "findings": findings,
        "note": (
            "No analyzers found. Enable IAM Access Analyzer to validate which "
            "resources are actually externally accessible."
            if not analyzers
            else ""
        ),
    }


def write_findings(summary: dict, output_dir: str | Path) -> Path:
    """Write the collected findings to access-analyzer-findings.json."""
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / "access-analyzer-findings.json"
    destination.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    return destination
