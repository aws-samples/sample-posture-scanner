import json
import re
import subprocess
from pathlib import Path

import boto3
import pytest
from botocore.stub import Stubber

from aws_posture import bedrock_targets, cli, genai_report, promptfoo_scan
from aws_posture.bedrock_targets import AgentTarget, KnowledgeBaseTarget

MODEL = "us.amazon.nova-pro-v1:0"


def chat_prompt_response():
    return {
        "id": "PRMPT12345",
        "arn": "arn:aws:bedrock:us-east-1:111122223333:prompt/PRMPT12345",
        "name": "triage",
        "version": "3",
        "defaultVariant": "v1",
        "customerEncryptionKeyArn": "arn:aws:kms:us-east-1:111122223333:key/abc",
        "variants": [
            {
                "name": "v1",
                "templateType": "CHAT",
                "modelId": MODEL,
                "inferenceConfiguration": {"text": {"temperature": 0.2, "maxTokens": 512}},
                "templateConfiguration": {
                    "chat": {
                        "system": [{"text": "You are an insurance triage bot."}],
                        "messages": [
                            {
                                "role": "user",
                                "content": [{"text": "Ticket: {{ticket}}\nNotes: {{notes}}"}],
                            }
                        ],
                        "inputVariables": [{"name": "ticket"}, {"name": "notes"}],
                    }
                },
            }
        ],
        "createdAt": "2026-01-01T00:00:00Z",
        "updatedAt": "2026-01-01T00:00:00Z",
    }


def text_prompt_response(text="Summarize: {{ document }}", model=MODEL):
    variant = {
        "name": "default",
        "templateType": "TEXT",
        "templateConfiguration": {"text": {"text": text}},
    }
    if model:
        variant["modelId"] = model
    return {
        "id": "TEXTP12345",
        "arn": "arn:aws:bedrock:us-east-1:111122223333:prompt/TEXTP12345",
        "name": "summarizer",
        "version": "DRAFT",
        "variants": [variant],
        "createdAt": "2026-01-01T00:00:00Z",
        "updatedAt": "2026-01-01T00:00:00Z",
    }


# ---------------------------------------------------------------- targets


def test_normalize_chat_prompt_keeps_roles_variables_and_inference():
    target = bedrock_targets.normalize_prompt(chat_prompt_response())
    assert target.label == "prompt:PRMPT12345@3"
    assert target.template_type == "CHAT"
    assert target.messages[0] == {"role": "system", "content": "You are an insurance triage bot."}
    assert target.variables == ["ticket", "notes"]
    assert target.inference == {"temperature": 0.2, "maxTokens": 512}
    assert target.encrypted_with_cmk is True


def test_normalize_text_prompt_detects_undeclared_variables():
    target = bedrock_targets.normalize_prompt(text_prompt_response())
    assert target.variables == ["document"]
    assert target.template == "Summarize: {{ document }}"


def test_normalize_rejects_empty_template():
    with pytest.raises(bedrock_targets.BedrockTargetError, match="empty"):
        bedrock_targets.normalize_prompt(text_prompt_response(text="  "))


def test_fetch_prompt_calls_get_prompt_with_version():
    client = boto3.client("bedrock-agent", region_name="us-east-1")
    stubber = Stubber(client)
    stubber.add_response(
        "get_prompt",
        chat_prompt_response(),
        {"promptIdentifier": "PRMPT12345", "promptVersion": "3"},
    )

    class FakeSession:
        def client(self, name):
            assert name == "bedrock-agent"
            return client

    with stubber:
        target = bedrock_targets.fetch_prompt(FakeSession(), "PRMPT12345", "3")
    assert target.version == "3"
    stubber.assert_no_pending_responses()


def test_fetch_prompt_draft_omits_version_and_wraps_errors():
    client = boto3.client("bedrock-agent", region_name="us-east-1")
    stubber = Stubber(client)
    stubber.add_client_error(
        "get_prompt",
        service_error_code="AccessDeniedException",
        expected_params={"promptIdentifier": "PRMPT12345"},
    )
    session = type("S", (), {"client": lambda self, name: client})()
    with stubber, pytest.raises(bedrock_targets.BedrockTargetError, match="GetPrompt"):
        bedrock_targets.fetch_prompt(session, "PRMPT12345", "DRAFT")


@pytest.mark.parametrize("spec", ["short:ALIAS", "ABCDEFGHIJ", "abcdefghij:TSTALIASID"])
def test_parse_agent_rejects_invalid(spec):
    with pytest.raises(ValueError):
        bedrock_targets.parse_agent(spec)


def test_parse_prompt_defaults_to_draft_and_validates_version():
    assert bedrock_targets.parse_prompt("PRMPT12345") == ("PRMPT12345", "DRAFT")
    assert bedrock_targets.parse_prompt("arn:aws:bedrock:us-east-1:1:prompt/X@2")[1] == "2"
    with pytest.raises(ValueError):
        bedrock_targets.parse_prompt("PRMPT12345@latest")


# ---------------------------------------------------------------- config


def test_agent_config_uses_bedrock_agent_provider_and_local_generation():
    target = AgentTarget("ABCDEFGHIJ", "TSTALIASID", name="support", instruction="Help")
    config, plan = promptfoo_scan.build_config(target, region="us-east-1", attacker_model=MODEL)
    provider = config["targets"][0]
    assert provider["id"] == "bedrock-agent:ABCDEFGHIJ"
    assert provider["config"]["agentAliasId"] == "TSTALIASID"
    assert config["redteam"]["provider"]["id"] == f"bedrock:converse:{MODEL}"
    assert config["defaultTest"]["options"]["provider"]["config"]["temperature"] == 0
    assert "excessive-agency" in plan["plugins"]
    assert "bola" in plan["skipped_plugins_remote_generation"]
    assert not set(plan["plugins"]) & promptfoo_scan.REMOTE_ONLY_PLUGINS
    assert "Help" in config["redteam"]["purpose"]


def test_remote_generation_keeps_all_plugins():
    target = AgentTarget("ABCDEFGHIJ", "TSTALIASID")
    _, plan = promptfoo_scan.build_config(
        target, region="us-east-1", attacker_model=MODEL, allow_remote_generation=True
    )
    assert "bola" in plan["plugins"] and not plan["skipped_plugins_remote_generation"]


def test_knowledge_base_requires_generation_model():
    target = KnowledgeBaseTarget("KBID123456")
    with pytest.raises(ValueError, match="--kb-model"):
        promptfoo_scan.build_config(target, region="us-east-1", attacker_model=MODEL)
    config, _ = promptfoo_scan.build_config(
        target, region="us-east-1", attacker_model=MODEL, kb_model=MODEL
    )
    assert config["targets"][0]["id"] == f"bedrock:kb:{MODEL}"
    assert config["targets"][0]["config"]["knowledgeBaseId"] == "KBID123456"


def test_managed_prompt_config_injects_first_variable_and_tests_the_rest():
    target = bedrock_targets.normalize_prompt(chat_prompt_response())
    config, plan = promptfoo_scan.build_config(
        target, region="us-east-1", attacker_model=MODEL, allow_remote_generation=True
    )
    assert config["redteam"]["injectVar"] == "ticket"
    assert json.loads(config["prompts"][0])[0]["role"] == "system"
    assert config["defaultTest"]["vars"] == {"notes": "example notes"}
    assert {"id": "indirect-prompt-injection", "config": {"indirectInjectionVar": "notes"}} in (
        config["redteam"]["plugins"]
    )
    assert config["targets"][0]["config"]["maxTokens"] == 512
    assert plan["kind"] == "prompt"


def test_managed_prompt_without_variables_gets_user_turn_and_needs_model():
    target = bedrock_targets.normalize_prompt(
        text_prompt_response(text="You are a helpful bot.", model=None)
    )
    with pytest.raises(ValueError, match="--prompt-model"):
        promptfoo_scan.build_config(target, region="us-east-1", attacker_model=MODEL)
    config, _ = promptfoo_scan.build_config(
        target, region="us-east-1", attacker_model=MODEL, prompt_model=MODEL
    )
    assert config["prompts"][0].endswith("{{prompt}}")
    assert config["redteam"]["injectVar"] == "prompt"


def test_invalid_inject_var_and_depth_rejected():
    target = bedrock_targets.normalize_prompt(chat_prompt_response())
    with pytest.raises(ValueError, match="not a variable"):
        promptfoo_scan.build_config(
            target, region="us-east-1", attacker_model=MODEL, inject_var="nope"
        )
    with pytest.raises(ValueError, match="depth"):
        promptfoo_scan.build_config(target, region="us-east-1", attacker_model=MODEL, depth="x")


def test_environment_disables_telemetry_sharing_and_remote_generation():
    env = promptfoo_scan.base_environment()
    for key in (
        "PROMPTFOO_DISABLE_TELEMETRY",
        "PROMPTFOO_DISABLE_SHARING",
        "PROMPTFOO_DISABLE_UPDATE",
        "PROMPTFOO_DISABLE_REMOTE_GENERATION",
        "PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION",
    ):
        assert env[key] in {"1", "true"}
    remote = promptfoo_scan.base_environment(allow_remote_generation=True)
    assert "PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION" not in remote
    assert remote["PROMPTFOO_DISABLE_TELEMETRY"] == "1"


# ---------------------------------------------------------------- execution


def promptfoo_results():
    def row(plugin, success, reason, severity="high", attack="attack text"):
        return {
            "success": success,
            "vars": {"prompt": attack},
            "response": {"output": "agent said something"},
            "gradingResult": {"pass": success, "score": 1 if success else 0, "reason": reason},
            "testCase": {"metadata": {"pluginId": plugin, "severity": severity}},
            "metadata": {"strategyId": "base64"},
        }

    return {
        "results": {
            "results": [
                row("prompt-extraction", False, "Revealed system prompt"),
                row("prompt-extraction", True, "Refused"),
                row("pii:direct", False, "Could not extract JSON from llm-rubric response"),
                row("excessive-agency", False, "Took unrequested action", "medium", "x" * 5000),
                {"success": False, "error": "ThrottlingException", "testCase": {"metadata": {"pluginId": "rbac"}}},
            ]
        }
    }


def test_aggregate_counts_attacks_and_ignores_grader_errors(tmp_path):
    path = tmp_path / "results.json"
    path.write_text(json.dumps(promptfoo_results()))
    summary = promptfoo_scan.aggregate(path, "agent:A/B", "agent", "prompt")
    assert summary["total_probes"] == 5
    assert summary["errored_probes"] == 2
    assert summary["successful_attacks"] == 2
    assert summary["attack_success_rate"] == pytest.approx(66.7)
    first = summary["findings"][0]
    assert first["plugin"] == "prompt-extraction"
    assert first["owasp_llm"].startswith("LLM07")
    assert first["strategy"] == "base64"
    assert len(summary["findings"][1]["attack"]) < 1600
    rates = {item["plugin"]: item["attack_success_rate"] for item in summary["plugins"]}
    assert rates["prompt-extraction"] == 50.0


def test_aggregate_rejects_malformed_output(tmp_path):
    path = tmp_path / "results.json"
    path.write_text("{}")
    with pytest.raises(promptfoo_scan.PromptfooError):
        promptfoo_scan.aggregate(path, "t", "agent", "prompt")


def test_run_promptfoo_generates_then_evaluates_with_isolated_environment(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(promptfoo_scan, "promptfoo_path", lambda: "/fake/promptfoo")
    monkeypatch.setattr(promptfoo_scan, "promptfoo_version_number", lambda: "0.123.1")
    monkeypatch.setenv("AWS_PROFILE", "should-not-leak")

    def fake_run(command, **kwargs):
        calls.append((command, kwargs["env"]))
        Path(command[command.index("-o") + 1]).write_text("{}")
        return subprocess.CompletedProcess(command, 0 if command[2] == "generate" else 100)

    monkeypatch.setattr(promptfoo_scan.subprocess, "run", fake_run)
    config = tmp_path / "promptfooconfig.yaml"
    config.write_text("{}")
    creds = {"AWS_ACCESS_KEY_ID": "AKIAEXAMPLE", "AWS_SECRET_ACCESS_KEY": "secret"}
    result = promptfoo_scan.run_promptfoo(config, tmp_path, creds, "eu-west-1")

    assert result == tmp_path / "results.json"
    assert [command[2] for command, _ in calls] == ["generate", "eval"]
    command, env = calls[1]
    assert "--no-share" in command and "--no-cache" in command
    assert "secret" not in " ".join(command)
    assert env["AWS_SECRET_ACCESS_KEY"] == "secret" and "AWS_PROFILE" not in env
    assert env["AWS_REGION"] == "eu-west-1"
    assert env["PROMPTFOO_CONFIG_DIR"].startswith(str(tmp_path))


def test_run_promptfoo_requires_exact_version_and_reports_failures(monkeypatch, tmp_path):
    monkeypatch.setattr(promptfoo_scan, "promptfoo_path", lambda: "/fake/promptfoo")
    monkeypatch.setattr(promptfoo_scan, "promptfoo_version_number", lambda: "0.120.0")
    with pytest.raises(promptfoo_scan.PromptfooError, match="0.123.1"):
        promptfoo_scan.run_promptfoo(tmp_path / "c", tmp_path, {}, "us-east-1")

    monkeypatch.setattr(promptfoo_scan, "promptfoo_version_number", lambda: "0.123.1")
    monkeypatch.setattr(
        promptfoo_scan.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 1),
    )
    with pytest.raises(promptfoo_scan.PromptfooError, match="generation"):
        promptfoo_scan.run_promptfoo(tmp_path / "c", tmp_path, {}, "us-east-1")


# ---------------------------------------------------------------- report


def test_report_escapes_evidence_and_has_no_score(tmp_path):
    path = tmp_path / "results.json"
    data = promptfoo_results()
    data["results"]["results"][0]["response"]["output"] = "<script>alert(1)</script>"
    path.write_text(json.dumps(data))
    summary = promptfoo_scan.aggregate(path, "agent:A/B", "agent", "prompt")
    summary["skipped_plugins"] = ["bola"]
    report = genai_report.build_report(
        [summary], {"kb:X": "denied"}, {"account": "1", "region": "us-east-1"}, tmp_path / "r"
    )
    assert report["status"] == "partial" and report["score"] is None
    html_text = (tmp_path / "r/genai-report.html").read_text()
    assert "<script>" not in html_text and "&lt;script&gt;" in html_text
    assert "bola" in (tmp_path / "r/genai-report.md").read_text()
    assert json.loads((tmp_path / "r/genai-summary.json").read_text())["counts"][
        "successful_attacks"
    ] == 2


# ---------------------------------------------------------------- CLI


def _cli_fakes(monkeypatch):
    class FakeSession:
        region_name = "us-east-1"

    monkeypatch.setattr("aws_posture.iam.whoami", lambda profile: ("111122223333", "arn:x"))
    monkeypatch.setattr(bedrock_targets, "session", lambda *a, **k: FakeSession())
    monkeypatch.setattr(
        bedrock_targets,
        "describe_agent",
        lambda s, a, b: AgentTarget(a, b, name="support"),
    )
    monkeypatch.setattr(
        bedrock_targets,
        "fetch_prompt",
        lambda s, i, v: bedrock_targets.normalize_prompt(chat_prompt_response()),
    )
    monkeypatch.setattr(bedrock_targets, "credential_environment", lambda s: {})


BASE_ARGS = ["scan-genai", "--agent", "ABCDEFGHIJ:TSTALIASID", "--attacker-model", MODEL]


def test_scan_genai_requires_explicit_active_testing_consent(tmp_path, capsys):
    args = cli.build_parser().parse_args([*BASE_ARGS, "-o", str(tmp_path / "o")])
    assert args.func(args) == 1
    assert "--i-understand-active-testing" in capsys.readouterr().err


def test_scan_genai_plan_fetches_prompts_without_running_promptfoo(monkeypatch, tmp_path):
    _cli_fakes(monkeypatch)
    monkeypatch.setattr(
        promptfoo_scan, "run_promptfoo", lambda *a, **k: pytest.fail("attacks sent in plan")
    )
    out = tmp_path / "o"
    args = cli.build_parser().parse_args(
        [*BASE_ARGS, "--prompt", "PRMPT12345@3", "--plan", "-o", str(out)]
    )
    assert args.func(args) == 0
    manifest = json.loads((out / "genai-scan-manifest.json").read_text())
    assert manifest["status"] == "planned"
    assert {plan["target"] for plan in manifest["plans"]} == {
        "agent:ABCDEFGHIJ/TSTALIASID",
        "prompt:PRMPT12345@3",
    }
    assert (out / "promptfoo/prompt_PRMPT12345_3/managed-prompt.json").is_file()


def test_scan_genai_runs_reports_and_gates(monkeypatch, tmp_path):
    _cli_fakes(monkeypatch)

    def fake_run(config_path, work_dir, credentials, region, **kwargs):
        path = work_dir / "results.json"
        path.write_text(json.dumps(promptfoo_results()))
        return path

    monkeypatch.setattr(promptfoo_scan, "run_promptfoo", fake_run)
    out = tmp_path / "o"
    args = cli.build_parser().parse_args(
        [*BASE_ARGS, "--i-understand-active-testing", "--fail-on-findings", "-o", str(out)]
    )
    assert args.func(args) == 2
    summary = json.loads((out / "report/genai-summary.json").read_text())
    assert summary["status"] == "complete"
    assert summary["targets"][0]["skipped_plugins"]
    assert (out / "report/genai-report.html").is_file()


def test_scan_genai_returns_one_when_a_target_fails(monkeypatch, tmp_path):
    _cli_fakes(monkeypatch)
    monkeypatch.setattr(
        promptfoo_scan,
        "run_promptfoo",
        lambda *a, **k: (_ for _ in ()).throw(promptfoo_scan.PromptfooError("boom")),
    )
    out = tmp_path / "o"
    args = cli.build_parser().parse_args(
        [*BASE_ARGS, "--i-understand-active-testing", "-o", str(out)]
    )
    assert args.func(args) == 1
    manifest = json.loads((out / "genai-scan-manifest.json").read_text())
    assert manifest["status"] == "failed"
    assert manifest["target_results"]["agent:ABCDEFGHIJ/TSTALIASID"]["status"] == "failed"


def test_setup_genai_iam_uses_separate_template_and_names(monkeypatch):
    captured = {}

    def fake_setup_role(**kwargs):
        captured.update(kwargs)
        return {
            "applied": False, "account_id": "1", "stack_name": kwargs["stack_name"],
            "stack_region": "us-east-1", "role_name": kwargs["role_name"],
            "trusted_principal": "arn:aws:iam::1:role/x", "template": kwargs["template"],
        }

    monkeypatch.setattr("aws_posture.iam.setup_role", fake_setup_role)
    args = cli.build_parser().parse_args(["setup-genai-iam"])
    assert args.func(args) == 0
    assert captured["template"] == "genai-redteam-role.yaml"
    assert captured["role_name"] == "GenAIRedTeamRole"
    assert captured["stack_name"] == "genai-redteam-iam"
    assert captured["apply"] is False


def test_genai_role_template_is_invoke_only():
    from importlib.resources import files  # nosemgrep: python.lang.compatibility.python37.python37-compatibility-importlib2 -- pyproject.toml requires Python >=3.10; importlib.resources is available since Python 3.7

    text = files("aws_posture").joinpath("data", "genai-redteam-role.yaml").read_text()
    assert "bedrock:InvokeAgent" in text and "bedrock:GetPrompt" in text
    actions = [line.strip()[2:] for line in text.splitlines() if line.strip().startswith("- ")]
    granted = [a for a in actions if re.fullmatch(r"[a-z0-9-]+:[A-Za-z*]+", a)]
    assert granted and all(
        a.startswith("bedrock:") or a == "kms:Decrypt" for a in granted
    ), granted
    for action in granted:
        assert not action.startswith(("bedrock:Create", "bedrock:Update", "bedrock:Delete"))
        assert "*" not in action


def test_scan_genai_warns_when_role_session_expires_before_timeout(monkeypatch, tmp_path, capsys):
    _cli_fakes(monkeypatch)
    monkeypatch.setattr(
        promptfoo_scan,
        "run_promptfoo",
        lambda *a, **k: (_ for _ in ()).throw(promptfoo_scan.PromptfooError("stop")),
    )
    args = cli.build_parser().parse_args(
        [
            *BASE_ARGS, "--i-understand-active-testing",
            "--role", "arn:aws:iam::111122223333:role/GenAIRedTeamRole",
            "--session-duration", "3600", "--timeout", "3600",
            "-o", str(tmp_path / "o"),
        ]
    )
    args.func(args)
    assert "ExpiredToken" in capsys.readouterr().err
