"""AWS identity and scanner-role bootstrap through boto3."""

from __future__ import annotations

from importlib.resources import files
from typing import Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError


def _session(profile: Optional[str] = None) -> boto3.Session:
    return boto3.Session(profile_name=profile) if profile else boto3.Session()


def whoami(profile: Optional[str] = None) -> tuple[str, str]:
    """Return the source account ID and caller ARN."""
    try:
        identity = _session(profile).client("sts").get_caller_identity()
        return identity["Account"], identity["Arn"]
    except (NoCredentialsError, ClientError, BotoCoreError) as exc:
        raise RuntimeError(
            f"AWS credentials are not valid or available: {exc}\n"
            "Configure an AWS profile, SSO session, instance role, or environment variables."
        ) from exc


SCANNER_TEMPLATE = "prowler-scanner-role.yaml"
GENAI_REDTEAM_TEMPLATE = "genai-redteam-role.yaml"


def _template_text(template: str = SCANNER_TEMPLATE) -> str:
    return files("aws_posture").joinpath("data", template).read_text(encoding="utf-8")


def _template_description(template: str = SCANNER_TEMPLATE) -> str:
    return f"aws_posture/data/{template}"


def _account_from_arn(arn: str) -> str:
    parts = arn.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn" or not parts[4]:
        raise ValueError(f"Invalid AWS principal ARN: {arn}")
    return parts[4]


def resolve_trusted_principal(session: boto3.Session, caller_arn: str) -> str:
    """Resolve an STS assumed-role ARN to its exact IAM role ARN.

    CloudFormation trust policies cannot use an STS session ARN as a principal.
    IAM user, role, and root ARNs are already suitable.
    """
    parts = caller_arn.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn":
        raise ValueError(f"Invalid caller ARN: {caller_arn}")
    service, resource = parts[2], parts[5]
    if service == "iam" and (
        resource == "root"
        or resource.startswith("user/")
        or resource.startswith("role/")
    ):
        return caller_arn
    if service == "sts" and resource.startswith("assumed-role/"):
        segments = resource.split("/")
        if len(segments) < 3:
            raise ValueError(f"Invalid assumed-role ARN: {caller_arn}")
        role_name = segments[1]
        try:
            return session.client("iam").get_role(RoleName=role_name)["Role"]["Arn"]
        except (ClientError, BotoCoreError) as exc:
            raise RuntimeError(
                "Could not resolve the current assumed role to an IAM role ARN. "
                "Pass --trusted-principal with the exact IAM role/user ARN."
            ) from exc
    raise ValueError(
        "The current identity cannot be used directly in an IAM trust policy. "
        "Pass --trusted-principal with an IAM role/user/root ARN."
    )


def _stack_missing(exc: ClientError) -> bool:
    error = exc.response.get("Error", {})
    return error.get("Code") == "ValidationError" and "does not exist" in error.get(
        "Message", ""
    )


def setup_role(
    profile: Optional[str] = None,
    role_name: str = "PostureScannerRole",
    external_id: str = "",
    stack_name: str = "prowler-scanner-iam",
    trusted_principal: Optional[str] = None,
    stack_region: Optional[str] = None,
    session_duration: int = 3600,
    apply: bool = False,
    template: str = SCANNER_TEMPLATE,
) -> dict:
    """Validate, plan, or deploy a dedicated role from a bundled template."""
    if not 3600 <= session_duration <= 43200:
        raise ValueError("Role session duration must be between 3600 and 43200 seconds.")

    session = _session(profile)
    try:
        identity = session.client("sts").get_caller_identity()
    except (NoCredentialsError, ClientError, BotoCoreError) as exc:
        raise RuntimeError(f"Unable to identify the AWS caller: {exc}") from exc

    account_id, caller_arn = identity["Account"], identity["Arn"]
    principal = trusted_principal or resolve_trusted_principal(session, caller_arn)
    principal_account = _account_from_arn(principal)
    if principal_account != account_id and not external_id:
        raise ValueError(
            "A non-empty --external-id is required for cross-account trust."
        )

    region = stack_region or session.region_name or "us-east-1"
    template_body = _template_text(template)
    cloudformation = session.client("cloudformation", region_name=region)
    cloudformation.validate_template(TemplateBody=template_body)

    plan = {
        "account_id": account_id,
        "caller_arn": caller_arn,
        "stack_name": stack_name,
        "stack_region": region,
        "role_name": role_name,
        "trusted_principal": principal,
        "external_id_configured": bool(external_id),
        "session_duration": session_duration,
        "template": _template_description(template),
        "template_valid": True,
        "applied": False,
    }
    if not apply:
        return plan

    parameters = [
        {"ParameterKey": "RoleName", "ParameterValue": role_name},
        {"ParameterKey": "TrustedPrincipalArn", "ParameterValue": principal},
        {"ParameterKey": "ExternalId", "ParameterValue": external_id},
        {
            "ParameterKey": "MaxSessionDurationSeconds",
            "ParameterValue": str(session_duration),
        },
    ]
    capabilities = ["CAPABILITY_NAMED_IAM"]

    exists = True
    try:
        cloudformation.describe_stacks(StackName=stack_name)
    except ClientError as exc:
        if _stack_missing(exc):
            exists = False
        else:
            raise

    if exists:
        try:
            cloudformation.update_stack(
                StackName=stack_name,
                TemplateBody=template_body,
                Parameters=parameters,
                Capabilities=capabilities,
                Tags=[{"Key": "ManagedBy", "Value": "aws-posture"}],
            )
            cloudformation.get_waiter("stack_update_complete").wait(
                StackName=stack_name
            )
        except ClientError as exc:
            if "No updates are to be performed" in str(exc):
                plan["note"] = "Stack already up to date."
            else:
                raise
    else:
        cloudformation.create_stack(
            StackName=stack_name,
            TemplateBody=template_body,
            Parameters=parameters,
            Capabilities=capabilities,
            Tags=[{"Key": "ManagedBy", "Value": "aws-posture"}],
            EnableTerminationProtection=False,
        )
        cloudformation.get_waiter("stack_create_complete").wait(StackName=stack_name)

    outputs = cloudformation.describe_stacks(StackName=stack_name)["Stacks"][0].get(
        "Outputs", []
    )
    role_arn = next(
        (item["OutputValue"] for item in outputs if item["OutputKey"] == "RoleArn"),
        None,
    )
    if not role_arn:
        raise RuntimeError("CloudFormation completed without returning the scanner role ARN.")
    plan.update({"applied": True, "role_arn": role_arn})
    return plan


def _wait_for_stack_set_operation(
    cloudformation, stack_set_name: str, operation_id: str, call_as: str
) -> None:
    """Wait for a StackSet operation and raise with its final status reason."""
    import time

    while True:
        response = cloudformation.describe_stack_set_operation(
            StackSetName=stack_set_name,
            OperationId=operation_id,
            CallAs=call_as,
        )
        operation = response["StackSetOperation"]
        status = operation["Status"]
        if status in {"RUNNING", "QUEUED", "STOPPING"}:
            time.sleep(5)
            continue
        if status != "SUCCEEDED":
            raise RuntimeError(
                f"StackSet operation {operation_id} ended as {status}: "
                f"{operation.get('StatusReason', 'no reason returned')}"
            )
        return


def setup_organization_roles(
    profile: Optional[str] = None,
    role_name: str = "PostureScannerRole",
    external_id: str = "",
    stack_name: str = "prowler-scanner-iam",
    stack_set_name: str = "prowler-scanner-organization",
    trusted_principal: Optional[str] = None,
    organizational_unit_id: Optional[str] = None,
    stack_region: Optional[str] = None,
    session_duration: int = 3600,
    delegated_admin: bool = False,
    apply: bool = False,
) -> dict:
    """Plan or deploy the scanner role to the organization root/OU.

    Uses a service-managed CloudFormation StackSet with auto-deployment. When
    called from the management account, a normal local stack covers that account
    because service-managed StackSets exclude it. In delegated-administrator mode,
    the management-account role must be deployed separately.
    """
    if not external_id:
        raise ValueError("--external-id is required for organization-wide role trust.")
    if not 3600 <= session_duration <= 43200:
        raise ValueError("Role session duration must be between 3600 and 43200 seconds.")

    session = _session(profile)
    identity = session.client("sts").get_caller_identity()
    account_id, caller_arn = identity["Account"], identity["Arn"]
    principal = trusted_principal or resolve_trusted_principal(session, caller_arn)
    if _account_from_arn(principal) != account_id:
        raise ValueError(
            "For organization deployment, --trusted-principal must belong to the "
            "management/delegated account running the scan."
        )

    organizations = session.client("organizations")
    organization = organizations.describe_organization()["Organization"]
    management_account_id = organization.get("ManagementAccountId") or organization.get(
        "MasterAccountId"
    )
    if not management_account_id:
        raise RuntimeError("AWS Organizations did not return a management account ID.")
    if delegated_admin and account_id == management_account_id:
        raise ValueError(
            "Do not use --delegated-admin from the organization management account."
        )
    if not delegated_admin and account_id != management_account_id:
        raise ValueError(
            "This caller is not in the organization management account. "
            "Use --delegated-admin from a registered CloudFormation StackSets "
            "delegated administrator."
        )

    target_id = organizational_unit_id
    if not target_id:
        roots = organizations.list_roots().get("Roots", [])
        if not roots:
            raise RuntimeError("AWS Organizations returned no organization root.")
        target_id = roots[0]["Id"]

    region = stack_region or session.region_name or "us-east-1"
    plan = {
        "account_id": account_id,
        "caller_arn": caller_arn,
        "trusted_principal": principal,
        "external_id_configured": True,
        "role_name": role_name,
        "local_stack_name": stack_name if not delegated_admin else None,
        "management_account_id": management_account_id,
        "management_account_requires_setup": delegated_admin,
        "stack_set_name": stack_set_name,
        "stack_region": region,
        "organizational_unit_id": target_id,
        "delegated_admin": delegated_admin,
        "session_duration": session_duration,
        "applied": False,
    }
    if not apply:
        # Validate the template without changing either the local account or members.
        session.client("cloudformation", region_name=region).validate_template(
            TemplateBody=_template_text()
        )
        plan["template_valid"] = True
        return plan

    local = None
    if not delegated_admin:
        local = setup_role(
            profile=profile,
            role_name=role_name,
            external_id=external_id,
            stack_name=stack_name,
            trusted_principal=principal,
            stack_region=region,
            session_duration=session_duration,
            apply=True,
        )

    cloudformation = session.client("cloudformation", region_name=region)
    call_as = "DELEGATED_ADMIN" if delegated_admin else "SELF"
    parameters = [
        {"ParameterKey": "RoleName", "ParameterValue": role_name},
        {"ParameterKey": "TrustedPrincipalArn", "ParameterValue": principal},
        {"ParameterKey": "ExternalId", "ParameterValue": external_id},
        {
            "ParameterKey": "MaxSessionDurationSeconds",
            "ParameterValue": str(session_duration),
        },
    ]
    stack_set_exists = True
    try:
        cloudformation.describe_stack_set(StackSetName=stack_set_name, CallAs=call_as)
    except ClientError as exc:
        error = exc.response.get("Error", {})
        if error.get("Code") == "StackSetNotFoundException":
            stack_set_exists = False
        else:
            raise

    common = {
        "StackSetName": stack_set_name,
        "Description": "Read-only Prowler scanner role managed by aws-posture",
        "TemplateBody": _template_text(),
        "Parameters": parameters,
        "Capabilities": ["CAPABILITY_NAMED_IAM"],
        "PermissionModel": "SERVICE_MANAGED",
        "AutoDeployment": {
            "Enabled": True,
            "RetainStacksOnAccountRemoval": False,
        },
        "ManagedExecution": {"Active": True},
        "CallAs": call_as,
    }
    if stack_set_exists:
        update = cloudformation.update_stack_set(**common)
        _wait_for_stack_set_operation(
            cloudformation, stack_set_name, update["OperationId"], call_as
        )
    else:
        cloudformation.create_stack_set(**common)

    targets = {"OrganizationalUnitIds": [target_id]}
    operation_preferences = {
        "FailureTolerancePercentage": 10,
        "MaxConcurrentPercentage": 10,
        "RegionConcurrencyType": "PARALLEL",
        "ConcurrencyMode": "SOFT_FAILURE_TOLERANCE",
    }
    targeted_instance_exists = False
    next_token = None
    while True:
        list_args = {"StackSetName": stack_set_name, "CallAs": call_as}
        if next_token:
            list_args["NextToken"] = next_token
        response = cloudformation.list_stack_instances(**list_args)
        if any(
            summary.get("OrganizationalUnitId") == target_id
            for summary in response.get("Summaries", [])
        ):
            targeted_instance_exists = True
            break
        next_token = response.get("NextToken")
        if not next_token:
            break

    if targeted_instance_exists:
        operation = cloudformation.update_stack_instances(
            StackSetName=stack_set_name,
            DeploymentTargets=targets,
            Regions=[region],
            ParameterOverrides=[],
            OperationPreferences=operation_preferences,
            CallAs=call_as,
        )
    else:
        operation = cloudformation.create_stack_instances(
            StackSetName=stack_set_name,
            DeploymentTargets=targets,
            Regions=[region],
            OperationPreferences=operation_preferences,
            CallAs=call_as,
        )
    _wait_for_stack_set_operation(
        cloudformation, stack_set_name, operation["OperationId"], call_as
    )
    plan.update(
        {
            "applied": True,
            "local_role_arn": local["role_arn"] if local else None,
            "stack_set_operation_id": operation["OperationId"],
        }
    )
    return plan
