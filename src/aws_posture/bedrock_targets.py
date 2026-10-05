"""Read-only discovery of Amazon Bedrock red-team targets.

Fetches managed prompts with ``bedrock-agent:GetPrompt`` and agent / knowledge
base metadata so the promptfoo red team can be given an accurate purpose.
Nothing here invokes a model or changes AWS state.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

AGENT_SPEC = re.compile(r"^([A-Z0-9]{10}):([A-Z0-9]{10}|TSTALIASID)$")
KB_ID = re.compile(r"^[A-Z0-9]{10}$")
PROMPT_VERSION = re.compile(r"^(DRAFT|[0-9]{1,5})$")
TEMPLATE_VARIABLE = re.compile(r"{{\s*([A-Za-z_][A-Za-z0-9_]*)\s*}}")


class BedrockTargetError(RuntimeError):
    """Raised when a Bedrock target cannot be resolved."""


@dataclass
class AgentTarget:
    agent_id: str
    alias_id: str
    name: str = ""
    description: str = ""
    instruction: str = ""
    foundation_model: str = ""
    guardrail: str = ""

    @property
    def label(self) -> str:
        return f"agent:{self.agent_id}/{self.alias_id}"


@dataclass
class KnowledgeBaseTarget:
    knowledge_base_id: str
    name: str = ""
    description: str = ""

    @property
    def label(self) -> str:
        return f"kb:{self.knowledge_base_id}"


@dataclass
class PromptTarget:
    prompt_id: str
    arn: str
    name: str
    version: str
    variant: str
    template_type: str
    template: str
    messages: list = field(default_factory=list)
    model_id: str = ""
    inference: dict = field(default_factory=dict)
    variables: list = field(default_factory=list)
    description: str = ""
    encrypted_with_cmk: bool = False

    @property
    def label(self) -> str:
        return f"prompt:{self.prompt_id}@{self.version}"


def session(
    profile: Optional[str] = None,
    region: Optional[str] = None,
    role: Optional[str] = None,
    external_id: Optional[str] = None,
    session_duration: int = 3600,
) -> boto3.Session:
    """Return a boto3 session, assuming the red-team role when provided."""
    base = boto3.Session(profile_name=profile, region_name=region)
    if not role:
        return base
    params = {
        "RoleArn": role,
        "RoleSessionName": "aws-posture-genai-redteam",
        "DurationSeconds": session_duration,
    }
    if external_id:
        params["ExternalId"] = external_id
    try:
        credentials = base.client("sts").assume_role(**params)["Credentials"]
    except (ClientError, BotoCoreError) as exc:
        raise BedrockTargetError(f"Could not assume {role}: {exc}") from exc
    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=region or base.region_name,
    )


def credential_environment(aws_session: boto3.Session) -> dict[str, str]:
    """Credentials for the promptfoo child process (environment, never argv)."""
    credentials = aws_session.get_credentials()
    if credentials is None:
        raise BedrockTargetError("No AWS credentials are available for the red team.")
    frozen = credentials.get_frozen_credentials()
    environment = {
        "AWS_ACCESS_KEY_ID": frozen.access_key,
        "AWS_SECRET_ACCESS_KEY": frozen.secret_key,
    }
    if frozen.token:
        environment["AWS_SESSION_TOKEN"] = frozen.token
    return environment


def parse_agent(spec: str) -> tuple[str, str]:
    match = AGENT_SPEC.match(spec.strip())
    if not match:
        raise ValueError(
            f"Invalid --agent {spec!r}; expected AGENT_ID:ALIAS_ID (10-character IDs)."
        )
    return match.group(1), match.group(2)


def parse_prompt(spec: str) -> tuple[str, str]:
    """Split ``IDENTIFIER[@VERSION]``; identifiers may be IDs or prompt ARNs."""
    identifier, _, version = spec.strip().partition("@")
    version = version or "DRAFT"
    if not identifier:
        raise ValueError("--prompt requires a prompt ID or ARN.")
    if not PROMPT_VERSION.match(version):
        raise ValueError(f"Invalid prompt version {version!r}; use DRAFT or a number.")
    return identifier, version


def describe_agent(aws_session: boto3.Session, agent_id: str, alias_id: str) -> AgentTarget:
    client = aws_session.client("bedrock-agent")
    try:
        agent = client.get_agent(agentId=agent_id)["agent"]
        client.get_agent_alias(agentId=agent_id, agentAliasId=alias_id)
    except (ClientError, BotoCoreError) as exc:
        raise BedrockTargetError(f"Agent {agent_id}/{alias_id}: {exc}") from exc
    guardrail = agent.get("guardrailConfiguration") or {}
    return AgentTarget(
        agent_id=agent_id,
        alias_id=alias_id,
        name=agent.get("agentName", ""),
        description=agent.get("description", ""),
        instruction=agent.get("instruction", ""),
        foundation_model=agent.get("foundationModel", ""),
        guardrail=guardrail.get("guardrailIdentifier", ""),
    )


def describe_knowledge_base(aws_session: boto3.Session, kb_id: str) -> KnowledgeBaseTarget:
    if not KB_ID.match(kb_id):
        raise ValueError(f"Invalid --knowledge-base {kb_id!r}; expected a 10-character ID.")
    try:
        kb = aws_session.client("bedrock-agent").get_knowledge_base(
            knowledgeBaseId=kb_id
        )["knowledgeBase"]
    except (ClientError, BotoCoreError) as exc:
        raise BedrockTargetError(f"Knowledge base {kb_id}: {exc}") from exc
    return KnowledgeBaseTarget(
        knowledge_base_id=kb_id,
        name=kb.get("name", ""),
        description=kb.get("description", ""),
    )


def _content_text(blocks: list) -> str:
    return "\n".join(
        block["text"] for block in blocks or [] if isinstance(block, dict) and "text" in block
    )


def normalize_prompt(response: dict, variant_name: Optional[str] = None) -> PromptTarget:
    """Convert a GetPrompt response into one testable prompt variant."""
    variants = response.get("variants") or []
    if not variants:
        raise BedrockTargetError(f"Prompt {response.get('id')} has no variants.")
    wanted = variant_name or response.get("defaultVariant")
    variant = next((item for item in variants if item.get("name") == wanted), variants[0])
    configuration = variant.get("templateConfiguration") or {}
    template_type = variant.get("templateType", "TEXT")

    messages: list[dict] = []
    if template_type == "CHAT":
        chat = configuration.get("chat") or {}
        system = _content_text(chat.get("system"))
        if system:
            messages.append({"role": "system", "content": system})
        for message in chat.get("messages") or []:
            messages.append(
                {"role": message.get("role", "user"), "content": _content_text(message.get("content"))}
            )
        declared = chat.get("inputVariables") or []
        template = "\n\n".join(message["content"] for message in messages)
    else:
        text = configuration.get("text") or {}
        template = text.get("text", "")
        declared = text.get("inputVariables") or []
    if not template.strip():
        raise BedrockTargetError(f"Prompt {response.get('id')} has an empty template.")

    variables = [item["name"] for item in declared if item.get("name")]
    for name in TEMPLATE_VARIABLE.findall(template):
        if name not in variables:
            variables.append(name)

    inference = (variant.get("inferenceConfiguration") or {}).get("text") or {}
    return PromptTarget(
        prompt_id=response.get("id", ""),
        arn=response.get("arn", ""),
        name=response.get("name", ""),
        version=str(response.get("version", "DRAFT")),
        variant=variant.get("name", ""),
        template_type=template_type,
        template=template,
        messages=messages,
        model_id=variant.get("modelId", ""),
        inference={key: value for key, value in inference.items() if value is not None},
        variables=variables,
        description=response.get("description", ""),
        encrypted_with_cmk=bool(response.get("customerEncryptionKeyArn")),
    )


def fetch_prompt(
    aws_session: boto3.Session, identifier: str, version: str = "DRAFT"
) -> PromptTarget:
    """Call GetPrompt for one managed prompt version."""
    params = {"promptIdentifier": identifier}
    if version != "DRAFT":
        params["promptVersion"] = version
    try:
        response = aws_session.client("bedrock-agent").get_prompt(**params)
    except (ClientError, BotoCoreError) as exc:
        raise BedrockTargetError(f"GetPrompt {identifier}@{version}: {exc}") from exc
    return normalize_prompt(response)


def list_prompt_ids(aws_session: boto3.Session) -> list[str]:
    """Return every managed prompt ID in the session region (DRAFT versions)."""
    client = aws_session.client("bedrock-agent")
    identifiers: list[str] = []
    try:
        for page in client.get_paginator("list_prompts").paginate():
            identifiers.extend(item["id"] for item in page.get("promptSummaries", []))
    except (ClientError, BotoCoreError) as exc:
        raise BedrockTargetError(f"ListPrompts: {exc}") from exc
    return sorted(set(identifiers))
