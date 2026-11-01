import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from dotenv import load_dotenv

from spica_advisor.function_files import write_function_files
from spica_advisor.log import LOGGER
from spica_advisor.metrics import OK_STATUS, CallRecord


CLI = "claude"
MODEL_ENV_VAR = "SPICA_ADVISOR_MODEL"
EFFORT_ENV_VAR = "SPICA_ADVISOR_EFFORT"
DEFAULT_MODEL = "claude-haiku-5-5"
KNOWN_MODELS = ("claude-haiku-4-5", "claude-haiku-5-5", "claude-sonnet-5-5", "claude-opus-5-5", "claude-fable-5-1")
EFFORTS = ("low", "medium", "high", "xhigh", "max")
MAX_TURNS = 10
FILE_TOOLS = ("Grep", "Glob", "Read")
STRUCTURED_OUTPUT_TOOL = "StructuredOutput"
CALL_TIMEOUT_SECONDS = 900
MAX_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = 2
# The CLI bills this key instead of the signed-in subscription whenever it is set.
API_KEY_ENV_VAR = "ANTHROPIC_API_KEY"


class ClaudeError(RuntimeError):
    pass


RETRYABLE_ERRORS = (ClaudeError, subprocess.TimeoutExpired)


def check_model(model):
    if model not in KNOWN_MODELS:
        raise ValueError(f"Unknown model {model!r} (choose from {', '.join(KNOWN_MODELS)})")
    return model


def require_cli():
    if not shutil.which(CLI):
        raise RuntimeError(f"Claude Code ({CLI}) must be on PATH and signed in")


def subscription_env():
    return {name: value for name, value in os.environ.items() if name != API_KEY_ENV_VAR}


def read_events(stdout):
    return [json.loads(line) for line in stdout.splitlines() if line.startswith("{")]


def result_event(events):
    return next((event for event in reversed(events) if event.get("type") == "result"), None)


def tool_uses(events):
    return [
        block
        for event in events if event.get("type") == "assistant"
        for block in event["message"]["content"] if block.get("type") == "tool_use"
    ]


def structured_output(agent, events, stderr):
    result = result_event(events)
    if result is None:
        raise ClaudeError(stderr.strip() or "Claude Code returned no result")
    if result.get("is_error") or result.get("structured_output") is None:
        details = result.get("errors") or [result.get("result")]
        raise ClaudeError(f"{result.get('subtype')}: {details}")
    return agent.output_type.model_validate(result["structured_output"])


def call_record(agent, model, status, wall_seconds, events):
    result = result_event(events) or {}
    usages = (result.get("modelUsage") or {}).values()

    def total(key):
        return sum(usage.get(key, 0) for usage in usages)

    cached, cache_write = total("cacheReadInputTokens"), total("cacheCreationInputTokens")
    return CallRecord(
        agent=agent,
        model=model,
        status=status,
        wall_seconds=round(wall_seconds, 3),
        requests=result.get("num_turns", 0),
        tool_calls=sum(tool_use["name"] != STRUCTURED_OUTPUT_TOOL for tool_use in tool_uses(events)),
        input_tokens=total("inputTokens") + cached + cache_write,
        cached_input_tokens=cached,
        cache_write_tokens=cache_write,
        output_tokens=total("outputTokens"),
        reasoning_tokens=total("thinkingTokens"),
        cost_usd=result.get("total_cost_usd"),
    )


class ClaudeRunner:
    def __init__(self, model=DEFAULT_MODEL, effort=None):
        if effort is not None and effort not in EFFORTS:
            raise ValueError(f"Unknown effort {effort!r} (choose from {', '.join(EFFORTS)})")
        self.model = model
        self.effort = effort
        self.calls: list[CallRecord] = []

    @classmethod
    def create(cls, model=DEFAULT_MODEL, effort=None):
        load_dotenv()
        require_cli()
        return cls(check_model(model), effort)

    @classmethod
    def from_env(cls):
        load_dotenv()
        return cls.create(
            os.environ.get(MODEL_ENV_VAR, "").strip() or DEFAULT_MODEL,
            os.environ.get(EFFORT_ENV_VAR, "").strip() or None,
        )

    def command(self, agent, tools):
        effort = ["--effort", self.effort] if self.effort else []
        return [
            CLI, "-p", "--safe-mode", "--restricted", "--no-session-persistence",
            "--output-format", "stream-json", "--verbose",
            "--max-turns", str(MAX_TURNS),
            "--model", self.model,
            *effort,
            "--tools", ",".join(tools),
            "--system-prompt", agent.instructions,
            "--json-schema", json.dumps(agent.output_type.model_json_schema()),
        ]

    def execute(self, agent, prompt, functions):
        # An empty working directory keeps the file tools away from everything but the given sources.
        with tempfile.TemporaryDirectory() as workspace:
            tools = ()
            if functions:
                prompt = f"{prompt}\n\n{write_function_files(functions, Path(workspace))}"
                tools = FILE_TOOLS
            return subprocess.run(
                self.command(agent, tools),
                input=prompt,
                cwd=workspace,
                env=subscription_env(),
                capture_output=True,
                text=True,
                timeout=CALL_TIMEOUT_SECONDS,
            )

    def run(self, agent, prompt, functions=()):
        LOGGER.debug("Claude call started for %s", agent.name, extra={"payload": {
            "agent": agent.name,
            "system_prompt": agent.instructions,
            "prompt": prompt,
        }})
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                return self._attempt(agent, prompt, functions)
            except RETRYABLE_ERRORS as error:
                if attempt == MAX_ATTEMPTS:
                    raise
                LOGGER.warning("Claude call for %s failed (attempt %d of %d): %s",
                               agent.name, attempt, MAX_ATTEMPTS, error)
                time.sleep(RETRY_BACKOFF_SECONDS * 2 ** (attempt - 1))

    def _attempt(self, agent, prompt, functions):
        started = time.perf_counter()
        events = []
        try:
            completed = self.execute(agent, prompt, functions)
            events = read_events(completed.stdout)
            output = structured_output(agent, events, completed.stderr)
        except Exception as error:
            self._record(agent, type(error).__name__, started, events)
            raise
        self._record(agent, OK_STATUS, started, events)
        return output

    def _record(self, agent, status, started, events):
        LOGGER.debug("Claude call finished for %s", agent.name, extra={"payload": {
            "agent": agent.name,
            "status": status,
            "tool_calls": [{"name": tool_use["name"], "input": tool_use.get("input")} for tool_use in tool_uses(events)],
            "result": result_event(events),
        }})
        self.calls.append(call_record(agent.name, self.model, status, time.perf_counter() - started, events))
