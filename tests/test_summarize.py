import json

from aws_posture import summarize


def native(account="111111111111", status="FAIL", severity="high", resource="arn:aws:s3:::demo"):
    return {
        "AssessmentStartTime": "2026-01-01T00:00:00+00:00",
        "FindingUniqueId": "finding-1",
        "CheckID": "s3_bucket_public_access",
        "CheckTitle": "S3 bucket is not public",
        "Status": status,
        "Severity": severity,
        "ServiceName": "s3",
        "Region": "us-east-1",
        "AccountId": account,
        "ResourceArn": resource,
        "StatusExtended": "Bucket is public",
        "Remediation": {"Recommendation": {"Text": "Block public access"}},
    }


def ocsf(account="111111111111", status="FAIL", severity="High", resource="arn:aws:s3:::demo"):
    return {
        "time_dt": "2026-01-01T00:00:00+00:00",
        "status_code": status,
        "severity": severity,
        "status_detail": "Bucket is public",
        "metadata": {"event_code": "s3_bucket_public_access"},
        "finding_info": {"uid": "finding-1", "title": "S3 bucket is not public"},
        "cloud": {"account": {"uid": account}},
        "resources": [
            {
                "uid": resource,
                "name": "demo",
                "region": "us-east-1",
                "group": {"name": "s3"},
                "type": "AwsS3Bucket",
            }
        ],
        "remediation": {"desc": "Block public access", "references": ["https://example.test"]},
        "unmapped": {"compliance": {"CIS": ["2.1"]}},
    }


def test_duplicate_native_and_ocsf_sources_collapse_to_one_finding(tmp_path):
    native_path = tmp_path / "scan.json"
    ocsf_path = tmp_path / "scan.ocsf.json"
    native_path.write_text(json.dumps([native()]), encoding="utf-8")
    ocsf_path.write_text(json.dumps([ocsf()]), encoding="utf-8")

    findings = summarize.load_findings([str(native_path), str(ocsf_path)])
    result = summarize.aggregate(findings, input_file_count=2)

    assert result["total"] == 1
    assert result["failed"] == 1
    assert result["distinct_failed_checks"] == 1
    assert result["sev_fail"]["high"] == 1


def test_directory_prefers_ocsf_over_native_json(tmp_path):
    (tmp_path / "scan.json").write_text(json.dumps([native()]), encoding="utf-8")
    ocsf_path = tmp_path / "scan.ocsf.json"
    ocsf_path.write_text(json.dumps([ocsf()]), encoding="utf-8")

    assert summarize.expand_inputs([str(tmp_path)]) == [str(ocsf_path)]


def test_same_check_in_two_accounts_remains_two_account_findings():
    findings = [
        summarize._native_finding(native(account="111111111111")),
        summarize._native_finding(native(account="222222222222")),
    ]
    result = summarize.aggregate(findings)

    assert result["distinct_failed_checks"] == 2
    assert {item["account"] for item in result["deduped"]} == {
        "111111111111",
        "222222222222",
    }


def test_critical_failure_caps_score_below_40_even_with_many_passes():
    findings = [summarize._native_finding(native(severity="critical"))]
    for index in range(1000):
        findings.append(
            summarize._native_finding(
                native(status="PASS", severity="low", resource=f"arn:aws:s3:::pass-{index}")
            )
        )

    result = summarize.aggregate(findings)

    assert result["pass_rate"] > 99
    assert result["score"] == 39.0
    assert summarize.grade(result["score"]).startswith("F")


def test_report_contains_one_detail_heading_per_account_check(tmp_path):
    source = tmp_path / "scan.ocsf.json"
    source.write_text(json.dumps([ocsf(), ocsf()]), encoding="utf-8")
    output = tmp_path / "report"

    summary = summarize.build_report([str(source)], str(output))
    markdown = (output / "posture-report.md").read_text(encoding="utf-8")

    assert summary["distinct_failed_checks"] == 1
    # Heading is now the actual failing condition (Prowler status_detail).
    assert markdown.count("### [HIGH] Bucket is public") == 1
    assert "**Control checked:** S3 bucket is not public" in markdown


def test_failed_findings_are_clearly_marked_fail_with_actual_state(tmp_path):
    source = tmp_path / "scan.ocsf.json"
    source.write_text(json.dumps([ocsf()]), encoding="utf-8")
    output = tmp_path / "report"

    summary = summarize.build_report([str(source)], str(output))
    markdown = (output / "posture-report.md").read_text(encoding="utf-8")
    html_report = (output / "posture-report.html").read_text(encoding="utf-8")

    assert summary["distinct_failed_checks"] == 1
    assert summary["highest_failed_severity"] == "high"
    # The failing condition is the headline; the compliant control name is secondary.
    assert "### [HIGH] Bucket is public" in markdown
    assert "**Status:** FAIL" in markdown
    assert "**Control checked:** S3 bucket is not public" in markdown
    assert "Every item below is a **FAILED** check" in markdown
    assert "<b>Bucket is public</b>" in html_report
    assert "Control checked: S3 bucket is not public" in html_report
