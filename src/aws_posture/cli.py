"""Command-line interface for aws-posture."""

from __future__ import annotations

import argparse
import datetime
import json
import platform
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Optional, Sequence

from . import (
    __version__,
    access_analyzer,
    bedrock_targets,
    code_scan,
    genai_report,
    gitleaks_scan,
    promptfoo_scan,
    repository_report,
    scanner,
    summarize,
    trivy_scan,
)


def _timestamp() -> str:
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S")


def _score(value: Optional[float]) -> str:
    return "N/A" if value is None else f"{value:.1f}"


def cmd_check(args) -> int:
    if getattr(args, "genai", False):
        mode = "GenAI red-team"
    else:
        mode = "code scanning" if args.code else "AWS posture scanning"
    print(f"aws-posture check — verifying {mode} prerequisites\n")
    ok = True
    python_supported = sys.version_info >= (3, 10)
    print(
        f"  [{'OK ' if python_supported else 'MISS'}] Python          "
        f"{platform.python_version()} (3.10+ required)"
    )
    ok = ok and python_supported

    if getattr(args, "genai", False):
        node_major = promptfoo_scan.node_major_version()
        node_ok = node_major is not None and node_major >= promptfoo_scan.MINIMUM_NODE_MAJOR
        print(
            f"  [{'OK ' if node_ok else 'MISS'}] Node.js         "
            f"{promptfoo_scan.node_version() or 'not found'} "
            f"({promptfoo_scan.MINIMUM_NODE_MAJOR}.22+ required by promptfoo)"
        )
        promptfoo_ok = (
            promptfoo_scan.promptfoo_version_number()
            == promptfoo_scan.RECOMMENDED_PROMPTFOO_VERSION
        )
        print(
            f"  [{'OK ' if promptfoo_ok else 'MISS'}] promptfoo       "
            + (
                promptfoo_scan.promptfoo_version()
                or "not found; npm install -g "
                f"promptfoo@{promptfoo_scan.RECOMMENDED_PROMPTFOO_VERSION}"
            )
        )
        ok = ok and node_ok and promptfoo_ok
        try:
            from . import iam

            account, arn = iam.whoami(args.profile)
            print(f"  [OK ] AWS credentials account {account} ({arn})")
        except Exception as exc:  # noqa: BLE001
            print(f"  [MISS] AWS credentials {exc}")
            ok = False
    elif args.code:
        git_version = code_scan.git_version()
        git_ok = bool(git_version)
        print(f"  [{'OK ' if git_ok else 'MISS'}] Git             {git_version or 'not found'}")
        ok = ok and git_ok

        semgrep_version = code_scan.semgrep_version()
        semgrep_number = code_scan.semgrep_version_number()
        semgrep_ok = semgrep_number == code_scan.RECOMMENDED_SEMGREP_VERSION
        print(
            f"  [{'OK ' if semgrep_ok else 'MISS'}] Semgrep CE      "
            f"{semgrep_version or 'not found; install Semgrep 1.171.0 with pipx'}"
        )
        ok = ok and semgrep_ok

        gitleaks_version = gitleaks_scan.gitleaks_version()
        gitleaks_ok = (
            gitleaks_scan.gitleaks_version_number()
            == gitleaks_scan.RECOMMENDED_GITLEAKS_VERSION
        )
        print(
            f"  [{'OK ' if gitleaks_ok else 'MISS'}] Gitleaks        "
            f"{gitleaks_version or 'not found; install Gitleaks 8.30.1'}"
        )
        ok = ok and gitleaks_ok

        trivy_version = trivy_scan.trivy_version()
        trivy_ok = (
            trivy_scan.trivy_version_number() == trivy_scan.RECOMMENDED_TRIVY_VERSION
        )
        print(
            f"  [{'OK ' if trivy_ok else 'MISS'}] Trivy           "
            f"{trivy_version or 'not found; install Trivy 0.72.0'}"
        )
        ok = ok and trivy_ok
    else:
        prowler_version = scanner.tool_version("prowler")
        prowler_major = scanner.prowler_major_version()
        prowler_ok = bool(scanner.tool_path("prowler")) and (
            prowler_major == scanner.SUPPORTED_PROWLER_MAJOR
        )
        print(
            f"  [{'OK ' if prowler_ok else 'MISS'}] Prowler         "
            f"{prowler_version or 'not found; install Prowler 5.36.0 with pipx'}"
        )
        ok = ok and prowler_ok

        try:
            from . import iam

            account, arn = iam.whoami(args.profile)
            print(f"  [OK ] AWS credentials account {account} ({arn})")
        except Exception as exc:  # noqa: BLE001
            print(f"  [MISS] AWS credentials {exc}")
            ok = False

    print(
        "\nAll required components are present."
        if ok
        else "\nOne or more required components are missing."
    )
    return 0 if ok else 1


def cmd_setup_iam(args) -> int:
    from . import iam

    try:
        result = iam.setup_role(
            profile=args.profile,
            role_name=args.role_name,
            external_id=args.external_id or "",
            stack_name=args.stack_name,
            trusted_principal=args.trusted_principal,
            stack_region=args.stack_region,
            session_duration=args.session_duration,
            apply=args.apply,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if not result["applied"]:
        print("\nPLAN (no changes made):")
        print(f"  Account          : {result['account_id']}")
        print(f"  Stack            : {result['stack_name']} ({result['stack_region']})")
        print(f"  Role name        : {result['role_name']}")
        print(f"  Trusted principal: {result['trusted_principal']}")
        print(
            "  ExternalId       : "
            + ("<configured>" if result["external_id_configured"] else "<none>")
        )
        print(f"  Max session      : {result['session_duration']} seconds")
        print(f"  Template         : {result['template']} (validated by AWS)")
        print("  Policies         : SecurityAudit, ViewOnlyAccess, read-only additions")
        print("\nRe-run with --apply to create the CloudFormation stack.")
        return 0

    print("\nIAM scanner role is ready.")
    print(f"  Role ARN: {result['role_arn']}")
    if result.get("note"):
        print(f"  Note: {result['note']}")
    suffix = " --external-id <value>" if result["external_id_configured"] else ""
    print(f"\nScan with:\n  aws-posture scan --role {result['role_arn']}{suffix}")
    return 0


def cmd_setup_org_iam(args) -> int:
    from . import iam

    try:
        result = iam.setup_organization_roles(
            profile=args.profile,
            role_name=args.role_name,
            external_id=args.external_id,
            stack_name=args.stack_name,
            stack_set_name=args.stack_set_name,
            trusted_principal=args.trusted_principal,
            organizational_unit_id=args.organizational_unit_id,
            stack_region=args.stack_region,
            session_duration=args.session_duration,
            delegated_admin=args.delegated_admin,
            apply=args.apply,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if not result["applied"]:
        print("\nORGANIZATION PLAN (no changes made):")
        print(f"  Management/delegated account: {result['account_id']}")
        print(f"  Trusted principal           : {result['trusted_principal']}")
        print(f"  Organization root/OU        : {result['organizational_unit_id']}")
        local_stack = result["local_stack_name"] or "<not needed in delegated account>"
        print(f"  Local stack                 : {local_stack}")
        print(f"  Service-managed StackSet    : {result['stack_set_name']}")
        print(f"  Deployment region           : {result['stack_region']}")
        print(f"  Member role                 : {result['role_name']}")
        print("  ExternalId                  : <configured>")
        print("\nThis deploys an IAM role to every StackSet-supported account in the root/OU.")
        if result["management_account_requires_setup"]:
            print(
                "  IMPORTANT: service-managed StackSets exclude management account "
                f"{result['management_account_id']}; deploy its role separately with setup-iam."
            )
        print("Re-run with --apply only after the customer approves the StackSet change.")
        return 0

    print("\nOrganization member scanner roles are ready.")
    if result.get("local_role_arn"):
        print(f"  Management role ARN: {result['local_role_arn']}")
    if result["management_account_requires_setup"]:
        print(
            "  IMPORTANT: deploy PostureScannerRole separately in management account "
            f"{result['management_account_id']} before expecting a complete scan."
        )
    print(f"  StackSet operation: {result['stack_set_operation_id']}")
    print(
        "\nScan all active accounts with:\n"
        f"  aws-posture scan --organization --member-role-name {result['role_name']} "
        "--external-id <value>"
    )
    return 0


def _write_manifest(path: Path, manifest: dict) -> None:
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def _member_role_arn(partition: str, account_id: str, role_name: str) -> str:
    return f"arn:{partition}:iam::{account_id}:role/{role_name.lstrip('/')}"


def cmd_scan(args) -> int:
    if args.organization and not args.external_id:
        print("ERROR: --external-id is required for organization scans.", file=sys.stderr)
        return 1
    try:
        mutelist_path = scanner.resolve_mutelist(args.mutelist)
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    try:
        from . import iam

        source_account, source_arn = iam.whoami(args.profile)
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    accounts = [{"id": source_account, "name": "current account"}]
    if args.organization:
        try:
            accounts = scanner.list_organization_accounts(args.profile)
        except Exception as exc:  # noqa: BLE001
            print(f"ERROR: could not list AWS Organization accounts: {exc}", file=sys.stderr)
            return 1
        if not accounts:
            print("ERROR: AWS Organizations returned no active accounts.", file=sys.stderr)
            return 1

    timestamp = _timestamp()
    output_root = Path(args.output or Path.cwd() / "results" / f"scan-{timestamp}")
    raw_root = output_root / "prowler" / "raw"
    report_dir = output_root / "report"
    raw_root.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "tool_version": __version__,
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "running",
        "source_account": source_account,
        "source_identity": source_arn,
        "scope": "organization" if args.organization else "account",
        "regions": args.region or "all enabled regions",
        "mutelist": mutelist_path or "none",
        "access_analyzer": "disabled" if args.skip_access_analyzer else "enabled",
        "prowler_version": scanner.tool_version("prowler"),
        "requested_accounts": [
            {"id": account["id"], "name": account.get("name", "")} for account in accounts
        ],
        "account_results": [],
    }
    manifest_path = output_root / "scan-manifest.json"
    _write_manifest(manifest_path, manifest)

    print("#" * 60)
    print(f"# AWS posture scan -> {output_root}")
    print(f"# Source identity  -> {source_arn}")
    print(f"# Scope            -> {len(accounts)} account(s), all enabled regions by default")
    print("#" * 60)

    partition = source_arn.split(":", 2)[1]
    successful = 0
    failed_accounts = []
    access_analyzer_results: dict[str, dict] = {}
    for account in accounts:
        account_id = account["id"]
        if args.organization:
            role = _member_role_arn(partition, account_id, args.member_role_name)
            account_raw = raw_root / account_id
        else:
            role = args.role
            account_raw = raw_root
        try:
            scanner.run_prowler(
                str(account_raw),
                f"{timestamp}-{account_id}" if args.organization else timestamp,
                profile=args.profile,
                regions=args.region,
                role=role,
                external_id=args.external_id,
                session_duration=args.session_duration,
                organizations_role=args.organizations_role,
                mutelist=mutelist_path,
            )
            successful += 1
            manifest["account_results"].append(
                {"account_id": account_id, "status": "complete", "role": role}
            )
        except Exception as exc:  # noqa: BLE001 - continue remaining organization accounts
            failed_accounts.append(account_id)
            manifest["account_results"].append(
                {
                    "account_id": account_id,
                    "status": "failed",
                    "role": role,
                    "error": str(exc),
                }
            )
            print(f"ERROR: account {account_id}: {exc}", file=sys.stderr)
            _write_manifest(manifest_path, manifest)
            continue

        if not args.skip_access_analyzer:
            print(f"==> Collecting IAM Access Analyzer findings for {account_id}...")
            try:
                aa_summary = access_analyzer.collect_findings(
                    profile=args.profile,
                    regions=args.region,
                    role=role,
                    external_id=args.external_id,
                    session_duration=args.session_duration,
                )
                aa_dir = output_root / "access-analyzer"
                if args.organization:
                    aa_dir = aa_dir / account_id
                access_analyzer.write_findings(aa_summary, aa_dir)
                access_analyzer_results[account_id] = {
                    "status": "complete",
                    "analyzers": aa_summary["analyzer_count"],
                    "active_findings": aa_summary["active_finding_count"],
                }
                if aa_summary.get("note"):
                    print(f"    NOTE: {aa_summary['note']}")
                else:
                    print(
                        f"    {aa_summary['analyzer_count']} analyzer(s), "
                        f"{aa_summary['active_finding_count']} ACTIVE finding(s)"
                    )
            except Exception as exc:  # noqa: BLE001 - Access Analyzer is best-effort
                access_analyzer_results[account_id] = {
                    "status": "failed",
                    "error": str(exc),
                }
                print(
                    f"WARNING: Access Analyzer collection failed for {account_id}: {exc}",
                    file=sys.stderr,
                )
        _write_manifest(manifest_path, manifest)

    manifest["access_analyzer_results"] = access_analyzer_results

    if successful == 0:
        manifest.update(
            {
                "status": "failed",
                "completed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "error": "Prowler failed for every requested account.",
            }
        )
        _write_manifest(manifest_path, manifest)
        return 1

    print("==> Building one deduplicated report across successful accounts...")
    try:
        summary = summarize.build_report([str(raw_root)], str(report_dir))
    except (FileNotFoundError, ValueError) as exc:
        manifest.update(
            {
                "status": "failed",
                "completed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "error": str(exc),
            }
        )
        _write_manifest(manifest_path, manifest)
        print(f"ERROR: could not build report: {exc}", file=sys.stderr)
        return 1

    partial = bool(failed_accounts)
    manifest.update(
        {
            "status": "partial" if partial else "complete",
            "completed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "successful_accounts": successful,
            "failed_accounts": failed_accounts,
            "posture_score": summary["score"],
            "resource_pass_rate": summary["pass_rate"],
            "distinct_failed_checks": summary["distinct_failed_checks"],
        }
    )
    _write_manifest(manifest_path, manifest)

    print(
        f"\nRisk-adjusted score: {_score(summary['score'])}/100 "
        f"({summarize.grade(summary['score'])})"
    )
    print(
        f"Resource pass rate : {_score(summary['pass_rate'])}% "
        f"({summary['passed']}/{summary['evaluated']})"
    )
    print(
        f"Failed resources   : {summary['failed']} -> "
        f"{summary['distinct_failed_checks']} distinct account/check findings"
    )
    print(f"Accounts completed : {successful}/{len(accounts)}")
    print(f"\nResults: {output_root}")
    print("  report/posture-report.html   consolidated deduplicated report")
    print("  report/posture-summary.json  machine-readable summary")
    print("  prowler/raw/                  raw findings and all compliance CSVs")
    if not args.skip_access_analyzer:
        print("  access-analyzer/              IAM Access Analyzer ACTIVE findings")
    print("  scan-manifest.json            account-by-account execution status")
    return 2 if partial else 0


def cmd_scan_code(args) -> int:
    timestamp = _timestamp()
    output_root = Path(args.output or Path.cwd() / "results" / f"code-scan-{timestamp}")
    raw_output = output_root / "semgrep" / "raw" / "semgrep.json"
    report_dir = output_root / "report"
    manifest_path = output_root / "code-scan-manifest.json"
    configs = args.config or [code_scan.DEFAULT_CONFIG]

    try:
        with code_scan.checkout_source(args.source, args.ref) as checkout:
            output_root.mkdir(parents=True, exist_ok=True)
            manifest = {
                "tool_version": __version__,
                "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "status": "running",
                "scanner": "Semgrep Community Edition",
                "semgrep_version": code_scan.semgrep_version(),
                "metrics_enabled": False,
                "source_type": checkout.source_type,
                "source": checkout.source_label,
                "requested_ref": checkout.requested_ref,
                "commit": checkout.commit,
                "branch": checkout.branch,
                "dirty": checkout.dirty,
                "tracked_files": checkout.tracked_files,
                "configs": configs,
            }
            _write_manifest(manifest_path, manifest)
            print("#" * 60)
            print(f"# Code vulnerability scan -> {output_root}")
            print(f"# Source                  -> {checkout.source_label}")
            print(f"# Commit                  -> {checkout.commit}")
            print("# Semgrep metrics         -> disabled")
            print("#" * 60)

            code_scan.run_semgrep(
                checkout.path,
                raw_output,
                configs=configs,
                excludes=args.exclude or (),
                timeout=args.timeout,
            )
            summary = code_scan.build_report(raw_output, checkout, configs, report_dir)
            manifest.update(
                {
                    "status": "complete",
                    "completed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "total_findings": summary["total_findings"],
                    "affected_files": summary["affected_files"],
                    "distinct_rules": summary["distinct_rules"],
                    "scan_errors": summary["scan_errors"],
                }
            )
            _write_manifest(manifest_path, manifest)
    except (FileNotFoundError, ValueError, code_scan.CodeScanError) as exc:
        output_root.mkdir(parents=True, exist_ok=True)
        failed = {
            "tool_version": __version__,
            "status": "failed",
            "completed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "metrics_enabled": False,
            "error": str(exc),
        }
        _write_manifest(manifest_path, failed)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"\nCode findings     : {summary['total_findings']}")
    print(f"Affected files    : {summary['affected_files']}")
    print(f"Distinct rules    : {summary['distinct_rules']}")
    print(f"Scan errors       : {summary['scan_errors']}")
    print(f"\nResults: {output_root}")
    print("  report/code-report.html     developer-readable report")
    print("  report/code-summary.json    deduplicated machine-readable findings")
    print("  semgrep/raw/semgrep.json    complete local Semgrep output")
    print("  code-scan-manifest.json     repository revision and execution metadata")
    return 2 if args.fail_on_findings and summary["total_findings"] else 0


def cmd_scan_repository(args) -> int:
    enabled = {
        "semgrep": not args.skip_semgrep,
        "gitleaks": not args.skip_gitleaks,
        "trivy": not args.skip_trivy,
    }
    if not any(enabled.values()):
        print("ERROR: at least one repository scanner must be enabled.", file=sys.stderr)
        return 1

    timestamp = _timestamp()
    output_root = Path(
        args.output or Path.cwd() / "results" / f"repository-scan-{timestamp}"
    )
    report_dir = output_root / "report"
    manifest_path = output_root / "repository-scan-manifest.json"
    configs = args.config or [code_scan.DEFAULT_CONFIG]

    try:
        with code_scan.checkout_source(
            args.source, args.ref, full_history=args.history
        ) as checkout, tempfile.TemporaryDirectory(
            prefix="aws-posture-repository-", ignore_cleanup_errors=True
        ) as temporary:
            stage = Path(temporary)
            if output_root.exists() and any(output_root.iterdir()):
                raise ValueError(
                    "Repository scan output must be a new or empty directory so scanner "
                    "evidence cannot be scanned recursively."
                )
            manifest = {
                "tool_version": __version__,
                "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "status": "running",
                "source_type": checkout.source_type,
                "source": checkout.source_label,
                "requested_ref": checkout.requested_ref,
                "commit": checkout.commit,
                "branch": checkout.branch,
                "dirty": checkout.dirty,
                "tracked_files": checkout.tracked_files,
                "history_requested": args.history,
                "enabled_scanners": [name for name, value in enabled.items() if value],
                "scanner_results": {},
            }
            print("#" * 64)
            print(f"# Repository security scan -> {output_root}")
            print(f"# Source                   -> {checkout.source_label}")
            print(f"# Commit                   -> {checkout.commit}")
            print(f"# Secret history           -> {'full' if args.history else 'current tree'}")
            print("#" * 64)

            semgrep_summary = None
            gitleaks_summary = None
            trivy_summary = None
            failures: dict[str, str] = {}

            gitleaks_raw = stage / "gitleaks.json"
            if enabled["gitleaks"]:
                try:
                    gitleaks_scan.run_gitleaks(
                        checkout,
                        gitleaks_raw,
                        history=args.history,
                        config=args.gitleaks_config,
                        baseline=args.gitleaks_baseline,
                        timeout=args.gitleaks_timeout,
                    )
                    gitleaks_summary = gitleaks_scan.aggregate(
                        gitleaks_raw, checkout, args.history
                    )
                except (FileNotFoundError, ValueError, gitleaks_scan.GitleaksError) as exc:
                    failures["gitleaks"] = str(exc)

            semgrep_raw = stage / "semgrep.json"
            if enabled["semgrep"]:
                try:
                    code_scan.run_semgrep(
                        checkout.path,
                        semgrep_raw,
                        configs=configs,
                        excludes=args.exclude or (),
                        timeout=args.timeout,
                    )
                    semgrep_summary = code_scan.build_report(
                        semgrep_raw, checkout, configs, stage / "semgrep-report"
                    )
                except (FileNotFoundError, ValueError, code_scan.CodeScanError) as exc:
                    failures["semgrep"] = str(exc)

            trivy_raw = stage / "trivy.json"
            sbom_raw = stage / "software-bom.cdx.json"
            if enabled["trivy"]:
                try:
                    trivy_scan.run_trivy(
                        checkout,
                        trivy_raw,
                        sbom_raw,
                        excludes=args.exclude or (),
                        timeout=args.trivy_timeout,
                        skip_database_update=args.trivy_skip_db_update,
                    )
                    trivy_summary = trivy_scan.aggregate(
                        trivy_raw, sbom_raw, checkout
                    )
                except (FileNotFoundError, ValueError, trivy_scan.TrivyError) as exc:
                    failures["trivy"] = str(exc)

            output_root.mkdir(parents=True, exist_ok=True)
            copies = (
                (semgrep_raw, output_root / "semgrep" / "raw" / "semgrep.json"),
                (gitleaks_raw, output_root / "gitleaks" / "raw" / "gitleaks.json"),
                (trivy_raw, output_root / "trivy" / "raw" / "trivy.json"),
                (sbom_raw, output_root / "sbom" / "software-bom.cdx.json"),
            )
            for source, destination in copies:
                if source.is_file():
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source, destination)

            summary = repository_report.build_report(
                checkout,
                semgrep_summary,
                gitleaks_summary,
                trivy_summary,
                failures,
                report_dir,
            )
            successes = summary["successful_scanners"]
            status = "failed" if not successes else ("partial" if failures else "complete")
            manifest.update(
                {
                    "status": status,
                    "completed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "scanner_results": {
                        "semgrep": (
                            {"status": "complete", "findings": semgrep_summary["total_findings"]}
                            if semgrep_summary
                            else {"status": "skipped" if not enabled["semgrep"] else "failed"}
                        ),
                        "gitleaks": (
                            {"status": "complete", "findings": gitleaks_summary["total_findings"], "secrets_redacted": True}
                            if gitleaks_summary
                            else {"status": "skipped" if not enabled["gitleaks"] else "failed"}
                        ),
                        "trivy": (
                            {"status": "complete", "findings": trivy_summary["total_findings"], "sbom_components": trivy_summary["sbom_components"]}
                            if trivy_summary
                            else {"status": "skipped" if not enabled["trivy"] else "failed"}
                        ),
                    },
                    "failures": failures,
                    "counts": summary["counts"],
                }
            )
            _write_manifest(manifest_path, manifest)
    except (FileNotFoundError, ValueError, code_scan.CodeScanError) as exc:
        output_root.mkdir(parents=True, exist_ok=True)
        _write_manifest(
            manifest_path,
            {
                "tool_version": __version__,
                "status": "failed",
                "completed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "error": str(exc),
            },
        )
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    counts = summary["counts"]
    print(f"\nSAST findings               : {counts['sast']}")
    print(f"Secret findings             : {counts['secrets']}")
    print(f"Dependency vulnerabilities  : {counts['dependency_vulnerabilities']}")
    print(f"IaC misconfigurations       : {counts['iac_misconfigurations']}")
    print(f"License inventory entries   : {counts['licenses_detected']}")
    print(f"SBOM components             : {counts['sbom_components']}")
    if summary["failed_scanners"]:
        print("Scanner failures             : " + ", ".join(summary["failed_scanners"]))
    print(f"\nResults: {output_root}")
    print("  report/repository-report.html      unified developer report")
    print("  report/repository-summary.json     normalized machine-readable report")
    if semgrep_summary:
        print("  semgrep/raw/semgrep.json           SAST evidence")
    if gitleaks_summary:
        print("  gitleaks/raw/gitleaks.json         sanitized secret evidence")
    if trivy_summary:
        print("  trivy/raw/trivy.json               dependency/IaC/license evidence")
        print("  sbom/software-bom.cdx.json         CycloneDX SBOM")
    print("  repository-scan-manifest.json      revision and scanner status")

    if summary["status"] != "complete":
        return 1
    return 2 if args.fail_on_findings and counts["security_findings"] else 0


def cmd_setup_genai_iam(args) -> int:
    from . import iam

    try:
        result = iam.setup_role(
            profile=args.profile,
            role_name=args.role_name,
            external_id=args.external_id or "",
            stack_name=args.stack_name,
            trusted_principal=args.trusted_principal,
            stack_region=args.stack_region,
            session_duration=args.session_duration,
            apply=args.apply,
            template=iam.GENAI_REDTEAM_TEMPLATE,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    if not result["applied"]:
        print("\nPLAN (no changes made):")
        print(f"  Account          : {result['account_id']}")
        print(f"  Stack            : {result['stack_name']} ({result['stack_region']})")
        print(f"  Role name        : {result['role_name']}")
        print(f"  Trusted principal: {result['trusted_principal']}")
        print(f"  Template         : {result['template']} (validated by AWS)")
        print(
            "  Permissions      : Get/List agent, KB, prompt definitions; InvokeModel, "
            "InvokeAgent, Retrieve(AndGenerate). No write access to Bedrock resources."
        )
        print("\nRe-run with --apply to create the CloudFormation stack.")
        return 0
    print(f"\nGenAI red-team role is ready.\n  Role ARN: {result['role_arn']}")
    suffix = " --external-id <value>" if result["external_id_configured"] else ""
    print(
        f"\nRed team with:\n  aws-posture scan-genai --role {result['role_arn']}{suffix} "
        "--agent AGENT_ID:ALIAS_ID --i-understand-active-testing"
    )
    return 0


def _resolve_genai_targets(aws_session, args) -> tuple[list, dict[str, str]]:
    targets: list = []
    failures: dict[str, str] = {}
    for spec in args.agent or []:
        try:
            agent_id, alias_id = bedrock_targets.parse_agent(spec)
            targets.append(bedrock_targets.describe_agent(aws_session, agent_id, alias_id))
        except (ValueError, bedrock_targets.BedrockTargetError) as exc:
            failures[f"agent:{spec}"] = str(exc)
    for kb_id in args.knowledge_base or []:
        try:
            targets.append(bedrock_targets.describe_knowledge_base(aws_session, kb_id))
        except (ValueError, bedrock_targets.BedrockTargetError) as exc:
            failures[f"kb:{kb_id}"] = str(exc)
    prompt_specs = list(args.prompt or [])
    if args.all_prompts:
        try:
            prompt_specs += bedrock_targets.list_prompt_ids(aws_session)
        except bedrock_targets.BedrockTargetError as exc:
            failures["prompt:*"] = str(exc)
    for spec in dict.fromkeys(prompt_specs):
        try:
            identifier, version = bedrock_targets.parse_prompt(spec)
            print(f"==> GetPrompt {identifier}@{version}")
            targets.append(bedrock_targets.fetch_prompt(aws_session, identifier, version))
        except (ValueError, bedrock_targets.BedrockTargetError) as exc:
            failures[f"prompt:{spec}"] = str(exc)
    return targets, failures


def cmd_scan_genai(args) -> int:
    if not (args.agent or args.knowledge_base or args.prompt or args.all_prompts):
        print(
            "ERROR: specify at least one --agent, --knowledge-base, --prompt, or --all-prompts.",
            file=sys.stderr,
        )
        return 1
    if args.external_id and not args.role:
        print("ERROR: --external-id requires --role.", file=sys.stderr)
        return 1
    if not args.plan and not args.i_understand_active_testing:
        print(
            "ERROR: scan-genai sends adversarial prompts to live Bedrock targets. It "
            "costs tokens, may trigger guardrail/abuse alarms, and agent tools may "
            "perform real actions. Target non-production aliases only, then re-run "
            "with --i-understand-active-testing (or use --plan to preview).",
            file=sys.stderr,
        )
        return 1

    timestamp = _timestamp()
    output_root = Path(args.output or Path.cwd() / "results" / f"genai-scan-{timestamp}")
    if output_root.exists() and any(output_root.iterdir()):
        print("ERROR: GenAI scan output must be a new or empty directory.", file=sys.stderr)
        return 1
    output_root.mkdir(parents=True, exist_ok=True)
    manifest_path = output_root / "genai-scan-manifest.json"

    try:
        from . import iam

        account, caller = iam.whoami(args.profile)
        aws_session = bedrock_targets.session(
            args.profile, args.region, args.role, args.external_id, args.session_duration
        )
        region = aws_session.region_name or "us-east-1"
        targets, failures = _resolve_genai_targets(aws_session, args)
    except Exception as exc:  # noqa: BLE001
        _write_manifest(
            manifest_path,
            {"tool_version": __version__, "status": "failed", "error": str(exc)},
        )
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    context = {
        "tool_version": __version__,
        "account": account,
        "source_identity": caller,
        "role": args.role,
        "region": region,
        "promptfoo_version": promptfoo_scan.RECOMMENDED_PROMPTFOO_VERSION,
        "attacker_model": args.attacker_model,
        "depth": args.depth,
        "remote_generation": args.allow_remote_generation,
        "targets": [target.label for target in targets] + list(failures),
    }
    manifest = {
        **context,
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "running",
        "plans": [],
        "target_results": {},
    }

    jobs = []
    for target in targets:
        try:
            config, plan = promptfoo_scan.build_config(
                target,
                region=region,
                attacker_model=args.attacker_model,
                depth=args.depth,
                purpose=args.purpose,
                kb_model=args.kb_model,
                prompt_model=args.prompt_model,
                inject_var=args.prompt_inject_var,
                allow_remote_generation=args.allow_remote_generation,
                extra_plugins=args.plugin or (),
            )
        except ValueError as exc:
            failures[target.label] = str(exc)
            continue
        work_dir = output_root / "promptfoo" / promptfoo_scan.slug(target.label)
        config_path = promptfoo_scan.write_config(config, work_dir)
        if isinstance(target, bedrock_targets.PromptTarget):
            (work_dir / "managed-prompt.json").write_text(
                json.dumps(target.__dict__, indent=2), encoding="utf-8"
            )
        manifest["plans"].append({**plan, "config": str(config_path)})
        jobs.append((target, plan, config, work_dir, config_path))

    print("#" * 64)
    print(f"# GenAI red team -> {output_root}")
    print(f"# Account/region -> {account} / {region}")
    print(f"# Depth          -> {args.depth}; attacker/grader {args.attacker_model}")
    print(
        "# Hosted gen.    -> "
        + ("ALLOWED (attack prompts sent to Promptfoo)" if args.allow_remote_generation else "disabled")
    )
    print("#" * 64)
    for _, plan, *_ in jobs:
        print(
            f"  {plan['target']}: {len(plan['plugins'])} plugins x "
            f"{len(plan['strategies'])} strategies, ~{plan['estimated_probes']} probes"
        )
        if plan["skipped_plugins_remote_generation"]:
            print(
                "    skipped (need hosted generation): "
                + ", ".join(plan["skipped_plugins_remote_generation"])
            )
    for label, error in failures.items():
        print(f"  {label}: FAILED — {error}", file=sys.stderr)

    if args.plan:
        manifest.update({"status": "planned", "failures": failures})
        _write_manifest(manifest_path, manifest)
        print(f"\nPlan only; configs written under {output_root / 'promptfoo'}.")
        return 0 if jobs and not failures else 1

    _write_manifest(manifest_path, manifest)
    credentials = bedrock_targets.credential_environment(aws_session)
    if args.role and args.session_duration < 2 * args.timeout:
        print(
            f"WARNING: assumed-role credentials expire after {args.session_duration}s but "
            f"each target may run for up to {2 * args.timeout}s. Long scans can fail with "
            "ExpiredToken; raise --session-duration or lower --timeout/--depth.",
            file=sys.stderr,
        )
    summaries = []
    for target, plan, config, work_dir, config_path in jobs:
        print(f"==> promptfoo red team: {target.label}")
        try:
            results = promptfoo_scan.run_promptfoo(
                config_path,
                work_dir,
                credentials,
                region,
                allow_remote_generation=args.allow_remote_generation,
                max_concurrency=args.max_concurrency,
                timeout=args.timeout,
            )
            summary = promptfoo_scan.aggregate(
                results, target.label, plan["kind"], config["redteam"]["injectVar"]
            )
            summary["skipped_plugins"] = plan["skipped_plugins_remote_generation"]
            summaries.append(summary)
            manifest["target_results"][target.label] = {
                "status": "complete",
                "probes": summary["total_probes"],
                "successful_attacks": summary["successful_attacks"],
            }
        except (FileNotFoundError, ValueError, promptfoo_scan.PromptfooError) as exc:
            failures[target.label] = str(exc)
            manifest["target_results"][target.label] = {"status": "failed", "error": str(exc)}
            print(f"ERROR: {target.label}: {exc}", file=sys.stderr)
        _write_manifest(manifest_path, manifest)

    report = genai_report.build_report(summaries, failures, context, output_root / "report")
    manifest.update(
        {
            "status": report["status"],
            "completed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "failures": failures,
            "counts": report["counts"],
        }
    )
    _write_manifest(manifest_path, manifest)

    counts = report["counts"]
    print(f"\nProbes              : {counts['probes']} ({counts['errored_probes']} errored)")
    print(f"Successful attacks  : {counts['successful_attacks']}")
    print(f"Targets completed   : {len(summaries)}/{len(summaries) + len(failures)}")
    print(f"\nResults: {output_root}")
    print("  report/genai-report.html          red-team report with evidence")
    print("  report/genai-summary.json         normalized machine-readable results")
    print("  promptfoo/<target>/               config, generated attacks, raw results, log")
    print("  genai-scan-manifest.json          targets, plans, and execution status")
    if report["status"] != "complete":
        return 1
    return 2 if args.fail_on_findings and counts["successful_attacks"] else 0


def cmd_summarize(args) -> int:
    try:
        summary = summarize.build_report(args.inputs, args.output)
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(
        f"Risk-adjusted score: {_score(summary['score'])}/100 "
        f"({summarize.grade(summary['score'])})"
    )
    print(
        f"Failed resources: {summary['failed']} -> "
        f"{summary['distinct_failed_checks']} distinct account/check findings"
    )
    print(f"Report written to: {args.output}")
    return 0


def _add_setup_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--apply", action="store_true", help="Create/update AWS resources.")
    parser.add_argument("-p", "--profile", help="AWS deployment profile.")
    parser.add_argument("--role-name", default="PostureScannerRole")
    parser.add_argument("--external-id", default="", help="External ID for role trust.")
    parser.add_argument("--stack-name", default="prowler-scanner-iam")
    parser.add_argument("--stack-region", help="CloudFormation region.")
    parser.add_argument("--trusted-principal", help="Exact IAM role/user/root ARN to trust.")
    parser.add_argument("--session-duration", type=int, default=3600)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws-posture",
        description="Cross-platform AWS posture and Git source-code security scanner.",
    )
    parser.add_argument("--version", action="version", version=f"aws-posture {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    check = commands.add_parser("check", help="Check AWS or code-scan prerequisites.")
    check.add_argument("-p", "--profile", help="AWS source profile.")
    check.add_argument(
        "--code",
        action="store_true",
        help="Check Git and Semgrep CE instead of Prowler and AWS credentials.",
    )
    check.add_argument(
        "--genai",
        action="store_true",
        help="Check Node.js, promptfoo, and AWS credentials for scan-genai.",
    )
    check.set_defaults(func=cmd_check)

    setup = commands.add_parser("setup-iam", help="Plan/create one account scanner role.")
    _add_setup_common(setup)
    setup.set_defaults(func=cmd_setup_iam)

    setup_org = commands.add_parser(
        "setup-org-iam", help="Plan/deploy scanner roles to an organization root/OU."
    )
    _add_setup_common(setup_org)
    setup_org.add_argument("--stack-set-name", default="prowler-scanner-organization")
    setup_org.add_argument("--organizational-unit-id", help="OU or root ID; defaults to root.")
    setup_org.add_argument("--delegated-admin", action="store_true")
    setup_org.set_defaults(func=cmd_setup_org_iam)

    scan = commands.add_parser("scan", help="Run complete Prowler scans.")
    scan.add_argument("-p", "--profile", help="AWS source profile.")
    scan.add_argument("-r", "--region", nargs="+", help="Optional region filter; default is all.")
    scope = scan.add_mutually_exclusive_group()
    scope.add_argument("--role", help="Single-account scanner role ARN.")
    scope.add_argument(
        "--organization",
        action="store_true",
        help="List every active Organization account and scan each one.",
    )
    scan.add_argument("--member-role-name", default="PostureScannerRole")
    scan.add_argument("--organizations-role", help="Optional management role ARN for account metadata.")
    scan.add_argument("--external-id", help="External ID required by cross-account roles.")
    scan.add_argument("--session-duration", type=int, default=3600)
    scan.add_argument(
        "--mutelist",
        help=(
            "Prowler mutelist YAML to suppress accepted-risk findings. "
            "Use 'default' for the bundled list of known-noisy checks."
        ),
    )
    scan.add_argument(
        "--skip-access-analyzer",
        action="store_true",
        help="Skip IAM Access Analyzer findings collection after the Prowler run.",
    )
    scan.add_argument("-o", "--output", help="Output folder.")
    scan.set_defaults(func=cmd_scan)

    code = commands.add_parser(
        "scan-code",
        help="Clone or open a Git repository and scan tracked source with Semgrep CE.",
    )
    code.add_argument(
        "source",
        help="Local Git checkout or HTTPS/SSH Git repository URL.",
    )
    code.add_argument(
        "--ref",
        help="Remote branch or tag to clone; the remote default branch is used when omitted.",
    )
    code.add_argument(
        "--config",
        action="append",
        help=(
            "Semgrep registry ruleset or local YAML/directory; repeat for multiple. "
            f"Default: {code_scan.DEFAULT_CONFIG}."
        ),
    )
    code.add_argument(
        "--exclude",
        action="append",
        help="Gitignore-style path pattern to exclude; repeat for multiple.",
    )
    code.add_argument("--timeout", type=int, default=30, help="Per-rule timeout in seconds.")
    code.add_argument("-o", "--output", help="Output folder.")
    code.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Return exit code 2 when findings are present (default remains 0).",
    )
    code.set_defaults(func=cmd_scan_code)

    repository = commands.add_parser(
        "scan-repository",
        help="Scan a Git repository with Semgrep CE, Gitleaks, and Trivy.",
    )
    repository.add_argument(
        "source", help="Local Git checkout or HTTPS/SSH/CodeCommit repository URL."
    )
    repository.add_argument(
        "--ref", help="Remote branch or tag; default branch is used when omitted."
    )
    repository.add_argument(
        "--history",
        action="store_true",
        help="Clone and scan complete Git history for secrets instead of current tree only.",
    )
    repository.add_argument(
        "--config",
        action="append",
        help=f"Semgrep registry or local rules; repeatable. Default: {code_scan.DEFAULT_CONFIG}.",
    )
    repository.add_argument(
        "--exclude",
        action="append",
        help="Path/glob excluded by Semgrep and Trivy; repeatable.",
    )
    repository.add_argument("--timeout", type=int, default=30, help="Semgrep per-rule timeout.")
    repository.add_argument("--gitleaks-config", help="Custom Gitleaks TOML configuration.")
    repository.add_argument("--gitleaks-baseline", help="Approved Gitleaks JSON baseline.")
    repository.add_argument("--gitleaks-timeout", type=int, default=0)
    repository.add_argument("--trivy-timeout", default="10m")
    repository.add_argument(
        "--trivy-skip-db-update",
        action="store_true",
        help="Use an already cached Trivy database without downloading updates.",
    )
    repository.add_argument("--skip-semgrep", action="store_true")
    repository.add_argument("--skip-gitleaks", action="store_true")
    repository.add_argument("--skip-trivy", action="store_true")
    repository.add_argument("-o", "--output", help="Output folder.")
    repository.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Return exit code 2 when a complete scan contains security findings.",
    )
    repository.set_defaults(func=cmd_scan_repository)

    genai_iam = commands.add_parser(
        "setup-genai-iam",
        help="Plan/create the invoke-only GenAI red-team role (separate from the scanner role).",
    )
    _add_setup_common(genai_iam)
    genai_iam.set_defaults(
        func=cmd_setup_genai_iam, role_name="GenAIRedTeamRole", stack_name="genai-redteam-iam"
    )

    genai = commands.add_parser(
        "scan-genai",
        help="Red-team Bedrock agents, knowledge bases, and managed prompts with promptfoo.",
    )
    genai.add_argument("-p", "--profile", help="AWS source profile.")
    genai.add_argument("-r", "--region", help="Bedrock region (default: profile region).")
    genai.add_argument("--role", help="GenAI red-team role ARN to assume.")
    genai.add_argument("--external-id", help="External ID for --role.")
    genai.add_argument("--session-duration", type=int, default=3600)
    genai.add_argument(
        "--agent", action="append", metavar="AGENT_ID:ALIAS_ID",
        help="Bedrock agent and alias to attack; repeatable. Use a non-production alias.",
    )
    genai.add_argument(
        "--knowledge-base", action="append", metavar="KB_ID",
        help="Bedrock knowledge base to attack via RetrieveAndGenerate; repeatable.",
    )
    genai.add_argument(
        "--prompt", action="append", metavar="ID_OR_ARN[@VERSION]",
        help="Managed prompt fetched with GetPrompt (default version DRAFT); repeatable.",
    )
    genai.add_argument(
        "--all-prompts", action="store_true",
        help="Fetch every managed prompt in the region (DRAFT versions).",
    )
    genai.add_argument(
        "--attacker-model", required=True,
        help="Bedrock model/inference-profile ID used to generate attacks and grade results.",
    )
    genai.add_argument("--kb-model", help="Generation model for --knowledge-base targets.")
    genai.add_argument("--prompt-model", help="Model for managed prompts that do not define one.")
    genai.add_argument(
        "--prompt-inject-var",
        help="Prompt variable that receives attacker input (default: first variable).",
    )
    genai.add_argument("--purpose", help="Override the auto-derived application purpose.")
    genai.add_argument("--depth", choices=sorted(promptfoo_scan.DEPTHS), default="standard")
    genai.add_argument("--plugin", action="append", help="Additional promptfoo plugin ID.")
    genai.add_argument("--max-concurrency", type=int, default=2)
    genai.add_argument("--timeout", type=int, default=3600, help="Seconds per promptfoo step.")
    genai.add_argument(
        "--allow-remote-generation", action="store_true",
        help=(
            "Allow Promptfoo-hosted attack generation (sends purpose/attack data to "
            "Promptfoo) to enable BOLA, BFLA, SSRF, memory-poisoning, and RAG exfiltration."
        ),
    )
    genai.add_argument(
        "--plan", action="store_true",
        help="Resolve targets (incl. GetPrompt) and write configs without sending attacks.",
    )
    genai.add_argument(
        "--i-understand-active-testing", action="store_true",
        help="Required to send adversarial prompts to live targets.",
    )
    genai.add_argument("-o", "--output", help="Output folder (must be new or empty).")
    genai.add_argument(
        "--fail-on-findings", action="store_true",
        help="Return exit code 2 when any attack succeeds.",
    )
    genai.set_defaults(func=cmd_scan_genai)

    report = commands.add_parser("summarize", help="Report from existing Prowler JSON.")
    report.add_argument("inputs", nargs="+", help="Prowler JSON files, directories, or globs.")
    report.add_argument("-o", "--output", default="posture-report")
    report.set_defaults(func=cmd_summarize)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
