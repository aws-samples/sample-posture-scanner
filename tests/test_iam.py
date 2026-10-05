from types import SimpleNamespace

from botocore.exceptions import ClientError
import pytest

from aws_posture import iam


def client_error(code, message):
    return ClientError({"Error": {"Code": code, "Message": message}}, "Operation")


def test_resolve_assumed_role_to_exact_iam_role_arn():
    iam_client = SimpleNamespace(
        get_role=lambda RoleName: {
            "Role": {"Arn": f"arn:aws:iam::111111111111:role/security/{RoleName}"}
        }
    )
    session = SimpleNamespace(client=lambda service: iam_client)

    result = iam.resolve_trusted_principal(
        session, "arn:aws:sts::111111111111:assumed-role/SecurityAdmin/alice"
    )

    assert result == "arn:aws:iam::111111111111:role/security/SecurityAdmin"


def test_direct_iam_user_is_preserved():
    arn = "arn:aws:iam::111111111111:user/security-scanner"
    assert iam.resolve_trusted_principal(SimpleNamespace(), arn) == arn


def test_only_missing_stack_validation_error_is_treated_as_absent():
    assert iam._stack_missing(
        client_error("ValidationError", "Stack with id example does not exist")
    )
    assert not iam._stack_missing(client_error("AccessDenied", "Denied"))


def test_delegated_stack_set_request_uses_valid_service_managed_shapes(monkeypatch):
    """Botocore Stubber validates every request against the CloudFormation model."""
    import boto3
    from botocore.stub import Stubber

    cloudformation = boto3.client(
        "cloudformation",
        region_name="us-east-1",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        aws_session_token="testing",
    )
    stubber = Stubber(cloudformation)
    stubber.add_client_error(
        "describe_stack_set",
        service_error_code="StackSetNotFoundException",
        expected_params={
            "StackSetName": "scanner-set",
            "CallAs": "DELEGATED_ADMIN",
        },
    )
    stubber.add_response(
        "create_stack_set",
        {"StackSetId": "scanner-set:id"},
        {
            "StackSetName": "scanner-set",
            "Description": "Read-only Prowler scanner role managed by aws-posture",
            "TemplateBody": iam._template_text(),
            "Parameters": [
                {"ParameterKey": "RoleName", "ParameterValue": "PostureScannerRole"},
                {"ParameterKey": "TrustedPrincipalArn", "ParameterValue": "arn:aws:iam::222222222222:role/AuditRunner"},
                {"ParameterKey": "ExternalId", "ParameterValue": "external-value"},
                {"ParameterKey": "MaxSessionDurationSeconds", "ParameterValue": "3600"},
            ],
            "Capabilities": ["CAPABILITY_NAMED_IAM"],
            "PermissionModel": "SERVICE_MANAGED",
            "AutoDeployment": {
                "Enabled": True,
                "RetainStacksOnAccountRemoval": False,
            },
            "ManagedExecution": {"Active": True},
            "CallAs": "DELEGATED_ADMIN",
        },
    )
    stubber.add_response(
        "list_stack_instances",
        {"Summaries": []},
        {"StackSetName": "scanner-set", "CallAs": "DELEGATED_ADMIN"},
    )
    stubber.add_response(
        "create_stack_instances",
        {"OperationId": "operation-1"},
        {
            "StackSetName": "scanner-set",
            "DeploymentTargets": {"OrganizationalUnitIds": ["r-example"]},
            "Regions": ["us-east-1"],
            "OperationPreferences": {
                "FailureTolerancePercentage": 10,
                "MaxConcurrentPercentage": 10,
                "RegionConcurrencyType": "PARALLEL",
                "ConcurrencyMode": "SOFT_FAILURE_TOLERANCE",
            },
            "CallAs": "DELEGATED_ADMIN",
        },
    )
    stubber.add_response(
        "describe_stack_set_operation",
        {
            "StackSetOperation": {
                "OperationId": "operation-1",
                "StackSetId": "scanner-set:id",
                "Action": "CREATE",
                "Status": "SUCCEEDED",
            }
        },
        {
            "StackSetName": "scanner-set",
            "OperationId": "operation-1",
            "CallAs": "DELEGATED_ADMIN",
        },
    )

    sts = SimpleNamespace(
        get_caller_identity=lambda: {
            "Account": "222222222222",
            "Arn": "arn:aws:iam::222222222222:role/AuditRunner",
        }
    )
    organizations = SimpleNamespace(
        describe_organization=lambda: {
            "Organization": {"MasterAccountId": "111111111111"}
        },
        list_roots=lambda: {"Roots": [{"Id": "r-example"}]},
    )

    class Session:
        region_name = "us-east-1"

        def client(self, service, region_name=None):
            return {
                "sts": sts,
                "organizations": organizations,
                "cloudformation": cloudformation,
            }[service]

    monkeypatch.setattr(iam, "_session", lambda profile=None: Session())
    monkeypatch.setattr(
        iam,
        "setup_role",
        lambda **kwargs: pytest.fail("delegated mode must not create a conflicting local role"),
    )

    with stubber:
        result = iam.setup_organization_roles(
            external_id="external-value",
            stack_set_name="scanner-set",
            delegated_admin=True,
            apply=True,
        )

    assert result["applied"] is True
    assert result["local_role_arn"] is None
    assert result["management_account_id"] == "111111111111"
    assert result["management_account_requires_setup"] is True


def test_non_management_caller_must_explicitly_use_delegated_mode(monkeypatch):
    sts = SimpleNamespace(
        get_caller_identity=lambda: {
            "Account": "222222222222",
            "Arn": "arn:aws:iam::222222222222:role/AuditRunner",
        }
    )
    organizations = SimpleNamespace(
        describe_organization=lambda: {
            "Organization": {"MasterAccountId": "111111111111"}
        }
    )
    session = SimpleNamespace(
        client=lambda service, **kwargs: {"sts": sts, "organizations": organizations}[service]
    )
    monkeypatch.setattr(iam, "_session", lambda profile=None: session)

    with pytest.raises(ValueError, match="--delegated-admin"):
        iam.setup_organization_roles(external_id="external-value")
