import json
from types import SimpleNamespace

import pytest

from aws_posture import access_analyzer


class FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        return iter(self._pages)


class FakeAccessAnalyzerClient:
    def __init__(self, analyzers, findings):
        self._analyzers = analyzers
        self._findings = findings

    def get_paginator(self, name):
        if name == "list_analyzers":
            return FakePaginator([{"analyzers": self._analyzers}])
        if name == "list_findings_v2":
            return FakePaginator([{"findings": self._findings}])
        raise AssertionError(f"unexpected paginator {name}")


def _fake_session(clients):
    return SimpleNamespace(client=lambda name, region_name=None: clients[(name, region_name)])


def test_collect_findings_aggregates_active_findings(monkeypatch):
    analyzers = [
        {"arn": "arn:aws:access-analyzer:us-east-1:1:analyzer/a", "name": "a",
         "type": "ACCOUNT", "status": "ACTIVE"}
    ]
    findings = [
        {"id": "f-1", "resource": "arn:aws:s3:::open-bucket",
         "resourceType": "AWS::S3::Bucket", "resourceOwnerAccount": "1",
         "findingType": "ExternalAccess", "status": "ACTIVE"},
        {"id": "f-2", "resource": "arn:aws:iam::1:role/shared",
         "resourceType": "AWS::IAM::Role", "resourceOwnerAccount": "1",
         "findingType": "ExternalAccess", "status": "ACTIVE"},
    ]
    clients = {("accessanalyzer", "us-east-1"): FakeAccessAnalyzerClient(analyzers, findings)}
    monkeypatch.setattr(access_analyzer, "_session", lambda profile=None: _fake_session(clients))

    summary = access_analyzer.collect_findings(regions=["us-east-1"])

    assert summary["analyzer_count"] == 1
    assert summary["active_finding_count"] == 2
    assert summary["findings_by_resource_type"] == {
        "AWS::S3::Bucket": 1,
        "AWS::IAM::Role": 1,
    }
    assert summary["region_errors"] == {}
    assert summary["note"] == ""


def test_collect_findings_notes_missing_analyzers(monkeypatch):
    clients = {("accessanalyzer", "us-east-1"): FakeAccessAnalyzerClient([], [])}
    monkeypatch.setattr(access_analyzer, "_session", lambda profile=None: _fake_session(clients))

    summary = access_analyzer.collect_findings(regions=["us-east-1"])

    assert summary["analyzer_count"] == 0
    assert summary["active_finding_count"] == 0
    assert "Enable IAM Access Analyzer" in summary["note"]


def test_collect_findings_raises_when_all_regions_fail(monkeypatch):
    class FailingClient:
        def get_paginator(self, name):
            raise access_analyzer.ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "denied"}}, "ListAnalyzers"
            )

    clients = {("accessanalyzer", "us-east-1"): FailingClient()}
    monkeypatch.setattr(access_analyzer, "_session", lambda profile=None: _fake_session(clients))

    with pytest.raises(access_analyzer.AccessAnalyzerError, match="any region"):
        access_analyzer.collect_findings(regions=["us-east-1"])


def test_collect_findings_assumes_role_when_provided(monkeypatch):
    assumed = {}

    class FakeSTS:
        def assume_role(self, **params):
            assumed.update(params)
            return {
                "Credentials": {
                    "AccessKeyId": "AKIA",
                    "SecretAccessKey": "secret",
                    "SessionToken": "token",
                }
            }

    base_clients = {("sts", None): FakeSTS()}
    aa_clients = {("accessanalyzer", "us-east-1"): FakeAccessAnalyzerClient([], [])}
    monkeypatch.setattr(
        access_analyzer, "_session", lambda profile=None: _fake_session(base_clients)
    )
    monkeypatch.setattr(
        access_analyzer.boto3,
        "Session",
        lambda **kwargs: _fake_session(aa_clients),
    )

    access_analyzer.collect_findings(
        regions=["us-east-1"],
        role="arn:aws:iam::1:role/PostureScannerRole",
        external_id="ext",
        session_duration=1800,
    )

    assert assumed["RoleArn"] == "arn:aws:iam::1:role/PostureScannerRole"
    assert assumed["ExternalId"] == "ext"
    assert assumed["DurationSeconds"] == 1800


def test_write_findings_creates_json(tmp_path):
    summary = {"analyzer_count": 0, "active_finding_count": 0, "findings": []}

    destination = access_analyzer.write_findings(summary, tmp_path / "aa")

    assert destination.is_file()
    assert json.loads(destination.read_text()) == summary
