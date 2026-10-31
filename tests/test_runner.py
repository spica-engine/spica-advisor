import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import BaseModel, ValidationError

from spica_advisor import runner as runner_module
from spica_advisor.agent import Agent
from spica_advisor.runner import DEFAULT_MODEL, KNOWN_MODELS, MAX_ATTEMPTS, MAX_TURNS, ClaudeError, ClaudeRunner


class Answer(BaseModel):
    label: str


AGENT = Agent(name="Classifier", instructions="Classify.", output_type=Answer)
FUNCTIONS = [{"_id": "fn/1", "name": "Orders", "content": "export const a = 1;"}]


def assistant(*blocks):
    return {"type": "assistant", "message": {"content": list(blocks)}}


def tool_use(name):
    return {"type": "tool_use", "name": name, "input": {}}


def result(structured_output=None, is_error=False, subtype="success", **extra):
    return {
        "type": "result",
        "subtype": subtype,
        "is_error": is_error,
        "num_turns": 3,
        "total_cost_usd": 0.0125,
        "structured_output": structured_output,
        "modelUsage": {
            "claude-test": {"inputTokens": 5, "outputTokens": 40, "cacheReadInputTokens": 100,
                            "cacheCreationInputTokens": 20, "thinkingTokens": 7},
            "claude-helper": {"inputTokens": 1, "outputTokens": 2},
        },
        **extra,
    }


def stream(*events):
    return "\n".join(json.dumps(event) for event in events) + "\n"


class FakeSubprocess:
    def __init__(self, stdout="", stderr="", error=None):
        self.stdout = stdout
        self.stderr = stderr
        self.error = error
        self.command = None
        self.kwargs = None
        self.workspace_files = {}

    def __call__(self, command, **kwargs):
        self.command = command
        self.kwargs = kwargs
        self.workspace_files = {path.name: path.read_text() for path in Path(kwargs["cwd"]).iterdir()}
        if self.error:
            raise self.error
        stdout = self.stdout.pop(0) if isinstance(self.stdout, list) else self.stdout
        return SimpleNamespace(stdout=stdout, stderr=self.stderr, returncode=0)


@pytest.fixture
def fake_subprocess(monkeypatch):
    def install(**kwargs):
        fake = FakeSubprocess(**kwargs)
        monkeypatch.setattr(runner_module.subprocess, "run", fake)
        return fake
    return install


@pytest.fixture(autouse=True)
def no_backoff(monkeypatch):
    sleeps = []
    monkeypatch.setattr(runner_module.time, "sleep", sleeps.append)
    return sleeps


@pytest.fixture
def cli_installed(monkeypatch):
    monkeypatch.setattr(runner_module.shutil, "which", lambda name: "/usr/bin/claude")
    monkeypatch.setattr(runner_module, "load_dotenv", lambda: None)


def flag(command, name):
    return command[command.index(name) + 1]


def test_run_returns_validated_output_and_records_usage(fake_subprocess):
    fake = fake_subprocess(stdout=stream(
        {"type": "system", "subtype": "init"},
        assistant(tool_use("Grep"), tool_use("Read")),
        assistant(tool_use("StructuredOutput")),
        result({"label": "pos"}),
    ))
    runner = ClaudeRunner("claude-test")

    assert runner.run(AGENT, "I love it") == Answer(label="pos")

    [call] = runner.calls
    assert (call.agent, call.model, call.status) == ("Classifier", "claude-test", "ok")
    assert (call.requests, call.tool_calls) == (3, 2)
    assert (call.input_tokens, call.cached_input_tokens, call.cache_write_tokens) == (126, 100, 20)
    assert (call.output_tokens, call.reasoning_tokens, call.cost_usd) == (42, 7, 0.0125)
    assert fake.kwargs["input"] == "I love it"


def test_command_passes_agent_instructions_schema_model_and_turn_limit(fake_subprocess):
    fake = fake_subprocess(stdout=stream(result({"label": "pos"})))

    ClaudeRunner("claude-test").run(AGENT, "prompt")

    command = fake.command
    assert command[:2] == ["claude", "-p"]
    assert {"--safe-mode", "--restricted", "--no-session-persistence"} <= set(command)
    assert flag(command, "--system-prompt") == "Classify."
    assert json.loads(flag(command, "--json-schema")) == Answer.model_json_schema()
    assert flag(command, "--model") == "claude-test"
    assert flag(command, "--max-turns") == str(MAX_TURNS)
    assert flag(command, "--tools") == ""
    assert "--effort" not in command
    assert fake.workspace_files == {}


def test_effort_is_passed_when_set(fake_subprocess):
    fake = fake_subprocess(stdout=stream(result({"label": "pos"})))

    ClaudeRunner("claude-test", "high").run(AGENT, "prompt")

    assert flag(fake.command, "--effort") == "high"


def test_unknown_effort_is_rejected():
    with pytest.raises(ValueError, match="Unknown effort"):
        ClaudeRunner("claude-test", "extreme")


def test_api_key_is_removed_so_claude_uses_the_subscription(fake_subprocess, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "paid-key")
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "subscription-token")
    fake = fake_subprocess(stdout=stream(result({"label": "pos"})))

    ClaudeRunner().run(AGENT, "prompt")

    assert "ANTHROPIC_API_KEY" not in fake.kwargs["env"]
    assert fake.kwargs["env"]["CLAUDE_CODE_OAUTH_TOKEN"] == "subscription-token"


def test_functions_are_searched_as_files_with_file_tools(fake_subprocess):
    fake = fake_subprocess(stdout=stream(result({"label": "pos"})))

    ClaudeRunner().run(AGENT, "Search the functions.", functions=FUNCTIONS)

    assert flag(fake.command, "--tools") == "Grep,Glob,Read"
    assert fake.workspace_files == {"fn_1.js": "export const a = 1;"}
    assert fake.kwargs["input"].startswith("Search the functions.\n\n")
    assert "- fn_1.js: function_id fn/1, name Orders" in fake.kwargs["input"]


def test_error_result_raises_and_records_usage(fake_subprocess):
    fake_subprocess(stdout=stream(result(is_error=True, subtype="error_max_turns", errors=["Reached max turns"])))
    runner = ClaudeRunner()

    with pytest.raises(ClaudeError, match="error_max_turns"):
        runner.run(AGENT, "prompt")

    assert len(runner.calls) == MAX_ATTEMPTS
    assert all(call.status == "ClaudeError" and (call.requests, call.input_tokens) == (3, 126) for call in runner.calls)


def test_missing_result_raises_with_stderr(fake_subprocess):
    fake_subprocess(stdout="not json\n", stderr="Not logged in")
    runner = ClaudeRunner()

    with pytest.raises(ClaudeError, match="Not logged in"):
        runner.run(AGENT, "prompt")

    assert all((call.status, call.requests, call.input_tokens, call.cost_usd) == ("ClaudeError", 0, 0, None)
               for call in runner.calls)


def test_output_that_breaks_the_schema_raises(fake_subprocess):
    fake_subprocess(stdout=stream(result({"wrong": "field"})))
    runner = ClaudeRunner()

    with pytest.raises(ValidationError):
        runner.run(AGENT, "prompt")

    assert runner.calls[0].status == "ValidationError"


def test_failed_attempts_are_retried_with_backoff_and_each_is_recorded(fake_subprocess, no_backoff):
    fake_subprocess(stdout="not json\n", stderr="Overloaded")
    runner = ClaudeRunner()

    with pytest.raises(ClaudeError, match="Overloaded"):
        runner.run(AGENT, "prompt")

    assert [call.status for call in runner.calls] == ["ClaudeError"] * MAX_ATTEMPTS
    assert no_backoff == [2, 4]


def test_a_retry_that_succeeds_returns_its_output(fake_subprocess):
    fake_subprocess(stdout=["not json\n", stream(result({"label": "pos"}))])
    runner = ClaudeRunner()

    assert runner.run(AGENT, "prompt") == Answer(label="pos")
    assert [call.status for call in runner.calls] == ["ClaudeError", "ok"]


def test_timeout_is_retried_then_reraised(fake_subprocess):
    fake_subprocess(error=runner_module.subprocess.TimeoutExpired("claude", 900))
    runner = ClaudeRunner()

    with pytest.raises(runner_module.subprocess.TimeoutExpired):
        runner.run(AGENT, "prompt")

    assert [call.status for call in runner.calls] == ["TimeoutExpired"] * MAX_ATTEMPTS


def test_schema_violations_are_not_retried(fake_subprocess):
    fake_subprocess(stdout=stream(result({"wrong": "field"})))
    runner = ClaudeRunner()

    with pytest.raises(ValidationError):
        runner.run(AGENT, "prompt")

    assert len(runner.calls) == 1


def test_create_requires_the_cli(monkeypatch):
    monkeypatch.setattr(runner_module, "load_dotenv", lambda: None)
    monkeypatch.setattr(runner_module.shutil, "which", lambda name: None)

    with pytest.raises(RuntimeError, match="Claude Code"):
        ClaudeRunner.create()


def test_create_rejects_unknown_models(cli_installed):
    with pytest.raises(ValueError, match="Unknown model 'claude-sonet-5-5'"):
        ClaudeRunner.create("claude-sonet-5-5")


def test_create_loads_dotenv_before_checking_the_cli(monkeypatch, cli_installed):
    loaded = []
    monkeypatch.setattr(runner_module, "load_dotenv", lambda: loaded.append(True))

    ClaudeRunner.create("claude-haiku-4-5")

    assert loaded == [True]
    assert DEFAULT_MODEL in KNOWN_MODELS


def test_from_env_reads_model_and_effort(monkeypatch, cli_installed):
    monkeypatch.setenv("SPICA_ADVISOR_MODEL", "claude-opus-5-5")
    monkeypatch.setenv("SPICA_ADVISOR_EFFORT", "max")

    runner = ClaudeRunner.from_env()

    assert (runner.model, runner.effort) == ("claude-opus-5-5", "max")


def test_from_env_defaults_when_unset_or_empty(monkeypatch, cli_installed):
    monkeypatch.setenv("SPICA_ADVISOR_MODEL", " ")
    monkeypatch.delenv("SPICA_ADVISOR_EFFORT", raising=False)

    runner = ClaudeRunner.from_env()

    assert (runner.model, runner.effort) == (DEFAULT_MODEL, None)
