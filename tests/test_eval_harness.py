import csv
from dataclasses import replace

import pytest

from evals.cases import EvalCase
from evals.harness import (
    Matrix,
    VariantRunner,
    matrix_jobs,
    new_run_dir,
    output_path,
    resolve_matrix,
    run_matrix,
    run_task,
)
from evals.prompts import BASELINE_VARIANT, load_variants
from evals.storage import read_json, read_jsonl
from evals.summary import write_summary
from evals.tasks import TASKS
from spica_advisor.investigations.broken_access_control.agents import BUCKET_ACL_AGENT, POLICY_ATTACHMENT_AGENT
from spica_advisor.investigations.broken_access_control.models import (
    BucketAclReport,
    CodeLocation,
    Report,
    ReportResponse,
    RowLevelSecurityReport,
)
from spica_advisor.investigations.sensitive_env_vars.agents import SENSITIVENESS_AGENT
from spica_advisor.investigations.sensitive_env_vars.models import EnvVarSensitiveness, SensitivenessResponse
from spica_advisor.investigations.unauthenticated_endpoints.agents import ENDPOINT_RISK_AGENT
from spica_advisor.investigations.unauthenticated_endpoints.models import FunctionRisk, FunctionRiskResponse, MethodRisk
from spica_advisor.metrics import CallRecord


PUBLIC_SCHEMA = """\
_id: fn-public
name: Public
triggers:
  create:
    type: http
    active: true
    options:
      authorize: false
"""

PRIVATE_SCHEMA = """\
_id: fn-private
name: Private
triggers:
  attach:
    type: http
    active: true
    options:
      authorize: true
"""

LABELS = {
    "sensitive-env-vars.yaml": "API_KEY: high\nLOG_LEVEL: low\n",
    "unauthenticated-endpoints.yaml": "fn-public:\n  create: high\n",
    "policy-attachments.yaml": "- function_id: fn-private\n  policy_id: policy-1\n",
    "bucket-acl.yaml": (
        "bucket-1:\n  includes_sensitive_information: true\n  read: applied\n  write: not_applied\n"
        "bucket-2:\n  includes_sensitive_information: false\n  read: not_applied\n  write: not_applied\n"
    ),
}


def write_file(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


@pytest.fixture
def case(tmp_path):
    case = EvalCase("demo", tmp_path / "resources" / "demo", tmp_path / "expected" / "demo")
    write_file(case.project_dir / "function/Public/schema.yaml", PUBLIC_SCHEMA)
    write_file(case.project_dir / "function/Public/index.mjs", "// public source\nexport function create(req, res) {}\n")
    write_file(case.project_dir / "function/Private/schema.yaml", PRIVATE_SCHEMA)
    write_file(case.project_dir / "function/Private/index.mjs", "// private source\n")
    write_file(case.project_dir / "env-var/API_KEY/schema.yaml", "_id: env-1\nkey: API_KEY\nvalue: secret\n")
    write_file(case.project_dir / "env-var/LOG_LEVEL/schema.yaml", "_id: env-2\nkey: LOG_LEVEL\n")
    write_file(case.project_dir / "bucket/One/schema.yaml", "_id: bucket-1\ntitle: Users\n")
    write_file(case.project_dir / "bucket/Two/schema.yaml", "_id: bucket-2\ntitle: Settings\n")
    write_file(case.project_dir / "bucket/Three/schema.yaml", "_id: bucket-3\ntitle: Unlabeled\n")
    for name, content in LABELS.items():
        write_file(case.expected_dir / name, content)
    return case


def acl(status):
    return RowLevelSecurityReport(row_level_security_status=status, reason="r")


RESPONSES = {
    SENSITIVENESS_AGENT.name: SensitivenessResponse(env_vars=[
        EnvVarSensitiveness(name="API_KEY", sensitiveness_level="high", reason="r"),
        EnvVarSensitiveness(name="LOG_LEVEL", sensitiveness_level="medium", reason="r"),
    ]),
    ENDPOINT_RISK_AGENT.name: FunctionRiskResponse(functions=[
        FunctionRisk(function_id="fn-public", methods=[MethodRisk(name="create", risk_level="high", reason="r")]),
    ]),
    POLICY_ATTACHMENT_AGENT.name: ReportResponse(reports=[Report(
        attachment=CodeLocation(function_id="fn-private", match="attach"),
        definition=CodeLocation(function_id="fn-private", match="const"),
        policy_id="policy-1",
        policy_name=None,
    )]),
    BUCKET_ACL_AGENT.name: BucketAclReport(
        includes_sensitive_information=True, read=acl("applied"), write=acl("not_applied"),
    ),
}


class FakeRunner:
    def __init__(self, model="claude-haiku-4-5", failing_prompts=()):
        self.model = model
        self.calls = []
        self.prompts = []
        self.agents = []
        self.failing_prompts = failing_prompts

    def run(self, agent, prompt, functions=()):
        self.prompts.append((agent.name, prompt))
        self.agents.append(agent)
        failed = any(marker in prompt for marker in self.failing_prompts)
        self.calls.append(CallRecord(
            agent=agent.name, model=self.model, status="ModelBehaviorError" if failed else "ok",
            wall_seconds=1.0, requests=1, tool_calls=0, input_tokens=1000, cached_input_tokens=0,
            cache_write_tokens=0, output_tokens=100, reasoning_tokens=0, cost_usd=0.001,
        ))
        if failed:
            raise RuntimeError("model failed")
        return RESPONSES[agent.name]


def prompts_for(runner, agent):
    return [prompt for name, prompt in runner.prompts if name == agent.name]


def test_endpoint_task_sends_only_public_function_source(case):
    runner = FakeRunner()

    prediction = TASKS["unauthenticated_endpoints"].predict(case, case.load_labels(), runner)

    [prompt] = prompts_for(runner, ENDPOINT_RISK_AGENT)
    assert "// public source" in prompt and "// private source" not in prompt
    assert prediction == [{"function_id": "fn-public", "methods": [
        {"name": "create", "risk_level": "high", "reason": "r"},
    ]}]


def test_env_var_task_sends_names_without_values(case):
    runner = FakeRunner()

    prediction = TASKS["sensitive_env_vars"].predict(case, case.load_labels(), runner)

    [prompt] = prompts_for(runner, SENSITIVENESS_AGENT)
    assert "API_KEY" in prompt and "secret" not in prompt
    assert prediction["LOG_LEVEL"]["sensitiveness_level"] == "medium"


def test_bucket_task_evaluates_only_labeled_buckets_and_survives_failures(case):
    runner = FakeRunner(failing_prompts=("Settings",))

    prediction = TASKS["bucket_acl"].predict(case, case.load_labels(), runner)

    assert len(prompts_for(runner, BUCKET_ACL_AGENT)) == 2
    assert list(prediction) == ["bucket-1"]


def test_run_task_skips_tasks_without_input(tmp_path, case):
    empty = EvalCase("empty", tmp_path / "resources" / "empty", case.expected_dir)
    empty.project_dir.mkdir(parents=True)
    runner = FakeRunner()

    run_task(tmp_path / "run", runner, empty, case.load_labels(), 1, TASKS["policy_attachments"])

    assert runner.prompts == []
    assert not (tmp_path / "run").exists()


def test_run_task_records_output_run_and_tagged_calls(tmp_path, case):
    run_dir = tmp_path / "run"

    run_task(run_dir, FakeRunner(), case, case.load_labels(), 2, TASKS["policy_attachments"])

    output = read_json(output_path(run_dir, "claude-haiku-4-5", "demo", 2, "policy_attachments"))
    assert output["status"] == "ok"
    assert output["prediction"][0]["policy_id"] == "policy-1"
    [run] = read_jsonl(run_dir / "runs.jsonl")
    assert run == {"model": "claude-haiku-4-5", "effort": "default", "case": "demo", "repeat": 2, "task": "policy_attachments",
                   "prompt": "baseline", "status": "ok", "wall_seconds": run["wall_seconds"], "calls": 1}
    [call] = read_jsonl(run_dir / "calls.jsonl")
    assert (call["case"], call["repeat"], call["task"], call["agent"]) == (
        "demo", 2, "policy_attachments", POLICY_ATTACHMENT_AGENT.name,
    )


def test_run_task_records_failed_prediction(tmp_path, case):
    run_dir = tmp_path / "run"

    run_task(run_dir, FakeRunner(failing_prompts=("Environment",)), case, case.load_labels(), 1,
             TASKS["sensitive_env_vars"])

    output = read_json(output_path(run_dir, "claude-haiku-4-5", "demo", 1, "sensitive_env_vars"))
    assert output == {"status": "RuntimeError", "prediction": None}
    [call] = read_jsonl(run_dir / "calls.jsonl")
    assert call["status"] == "ModelBehaviorError"


def test_matrix_run_produces_scored_summary(tmp_path, case):
    run_dir = tmp_path / "run"
    matrix = Matrix(models=["claude-haiku-4-5"], cases=["demo"], repeats=2, tasks=list(TASKS), efforts=["high"])
    efforts = []

    def create_runner(model, effort):
        efforts.append(effort)
        return FakeRunner(model)

    run_matrix(matrix, run_dir, [case], create_runner=create_runner)
    summary_path = write_summary(run_dir, expected_root=tmp_path / "expected", resources_root=tmp_path / "resources")

    summary = summary_path.read_text()
    assert "### sensitive_env_vars" in summary
    with (run_dir / "summary.csv").open() as file:
        rows = {(row["task"], row["case"]): row for row in csv.DictReader(file)}
    overall_env = rows[("sensitive_env_vars", "all")]
    assert float(overall_env["accuracy"]) == pytest.approx(0.5)
    assert float(overall_env["consistency"]) == 1.0
    assert overall_env["runs"] == "2"
    assert float(rows[("bucket_acl", "all")]["read_accuracy"]) == pytest.approx(0.5)
    assert float(rows[("policy_attachments", "all")]["f1"]) == 1.0
    assert float(rows[("bucket_acl", "all")]["cost_per_run"]) == pytest.approx(2 * 0.001)
    assert set(efforts) == {"high"}


    results = read_json(run_dir / "results.json")
    assert results["matrix"]["models"] == ["claude-haiku-4-5"]
    assert results["matrix"]["efforts"] == ["high"]
    assert results["matrix"]["compares_efforts"] is False
    assert results["metadata"]["agents"]["bucket_acl"]["prompt_fingerprint"]
    assert results["tasks"]["sensitive_env_vars"]["primary_metric"] == "accuracy"
    assert "high_as_low" not in results["tasks"]["sensitive_env_vars"]["percent_metrics"]
    report = (run_dir / "report.html").read_text()
    assert "__BENCHMARK_DATA__" not in report
    assert '"run": "run"' in report


def test_matrix_runs_jobs_concurrently(tmp_path, case):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    matrix = Matrix(models=["claude-haiku-4-5", "claude-opus-5-5"], cases=["demo"], repeats=2, tasks=list(TASKS))

    run_matrix(matrix, run_dir, [case], create_runner=lambda model, effort: FakeRunner(model), workers=2)

    runs = read_jsonl(run_dir / "runs.jsonl")
    assert len(runs) == 2 * 2 * len(TASKS)
    assert {run["status"] for run in runs} == {"ok"}
    assert sum(run["calls"] for run in runs) == len(read_jsonl(run_dir / "calls.jsonl"))
    assert read_json(output_path(run_dir, "claude-opus-5-5", "demo", 2, "bucket_acl"))["status"] == "ok"


def test_matrix_jobs_alternate_models_first(case):
    matrix = Matrix(models=["a", "b"], cases=["demo"], repeats=2, tasks=["sensitive_env_vars", "bucket_acl"])
    variants = {task: {"baseline": BASELINE_VARIANT} for task in matrix.tasks}

    jobs = matrix_jobs(matrix, [case], variants)

    assert [(job.repeat, job.task, job.model) for job in jobs[:4]] == [
        (1, "sensitive_env_vars", "a"), (1, "sensitive_env_vars", "b"), (1, "bucket_acl", "a"), (1, "bucket_acl", "b"),
    ]
    assert len(jobs) == 8


def test_new_run_dirs_never_collide(tmp_path):
    first, second = new_run_dir(tmp_path), new_run_dir(tmp_path)

    assert first != second
    assert first.is_dir() and second.is_dir()


@pytest.fixture
def prompts_root(tmp_path):
    folder = tmp_path / "prompts" / "unauthenticated_endpoints"
    folder.mkdir(parents=True)
    (folder / "strict.yaml").write_text(
        "description: Stricter.\ninput: source-only\ninstructions: Only the listed handlers.\n", encoding="utf-8",
    )
    return tmp_path / "prompts"


def test_variant_run_swaps_instructions_and_input_and_tags_the_prompt(tmp_path, case, prompts_root):
    run_dir = tmp_path / "run"
    runner = FakeRunner()
    variant = load_variants("unauthenticated_endpoints", prompts_root)["strict"]

    run_task(run_dir, runner, case, case.load_labels(), 1, TASKS["unauthenticated_endpoints"], variant)

    [agent] = runner.agents
    assert agent.instructions == "Only the listed handlers."
    [prompt] = prompts_for(runner, ENDPOINT_RISK_AGENT)
    assert "http_handlers" not in prompt
    assert "export function create(req, res)" in prompt
    assert read_json(output_path(run_dir, "claude-haiku-4-5", "demo", 1, "unauthenticated_endpoints", "strict"))
    [run] = read_jsonl(run_dir / "runs.jsonl")
    [call] = read_jsonl(run_dir / "calls.jsonl")
    assert run["prompt"] == call["prompt"] == "strict"


def test_variant_runner_only_replaces_its_own_agent():
    runner = FakeRunner()
    replacement = replace(ENDPOINT_RISK_AGENT, instructions="Only the listed handlers.")
    variant_runner = VariantRunner(runner, ENDPOINT_RISK_AGENT, replacement)

    variant_runner.run(ENDPOINT_RISK_AGENT, "endpoints")
    variant_runner.run(SENSITIVENESS_AGENT, "Environment variables")

    assert runner.agents == [replacement, SENSITIVENESS_AGENT]


def test_prompt_matrix_reports_one_series_per_model_and_prompt(tmp_path, case, prompts_root):
    run_dir = tmp_path / "run"
    matrix = Matrix(models=["claude-haiku-4-5"], cases=["demo"], repeats=1,
                    tasks=["unauthenticated_endpoints", "sensitive_env_vars"],
                    prompts={"unauthenticated_endpoints": ["baseline", "strict"]})

    run_matrix(matrix, run_dir, [case], create_runner=lambda model, effort: FakeRunner(model),
               prompts_root=prompts_root)
    write_summary(run_dir, expected_root=tmp_path / "expected", resources_root=tmp_path / "resources")

    results = read_json(run_dir / "results.json")
    assert [series["name"] for series in results["matrix"]["series"]] == [
        "claude-haiku-4-5 · baseline", "claude-haiku-4-5 · strict",
    ]
    overall = {(row["series"], row["task"]) for row in results["rows"] if row["case"] == "all"}
    assert overall == {
        ("claude-haiku-4-5 · baseline", "unauthenticated_endpoints"),
        ("claude-haiku-4-5 · strict", "unauthenticated_endpoints"),
        ("claude-haiku-4-5 · baseline", "sensitive_env_vars"),
    }
    prompts = results["metadata"]["agents"]["unauthenticated_endpoints"]["prompts"]
    assert prompts["strict"]["input"] == "source-only"
    assert "+Only the listed handlers." in prompts["strict"]["diff"]
    assert "model · prompt" in (run_dir / "summary.md").read_text()


def test_model_matrix_keeps_model_names_as_series(tmp_path, case):
    run_dir = tmp_path / "run"
    matrix = Matrix(models=["claude-haiku-4-5"], cases=["demo"], repeats=1, tasks=["sensitive_env_vars"])

    run_matrix(matrix, run_dir, [case], create_runner=lambda model, effort: FakeRunner(model))
    write_summary(run_dir, expected_root=tmp_path / "expected", resources_root=tmp_path / "resources")

    results = read_json(run_dir / "results.json")
    assert [series["name"] for series in results["matrix"]["series"]] == ["claude-haiku-4-5"]
    assert {row["series"] for row in results["rows"]} == {"claude-haiku-4-5"}


@pytest.mark.parametrize(("prompts", "problem"), [
    ({"unauthenticated_endpoints": ["missing"]}, "unknown prompt unauthenticated_endpoints:missing"),
    ({"bucket_acl": ["baseline"]}, "not in the run"),
    ({"unauthenticated_endpoints": ["strict", "strict"]}, "without duplicates"),
])
def test_resolve_matrix_rejects_bad_prompt_selections(tmp_path, prompts_root, prompts, problem):
    matrix_path = tmp_path / "matrix.yaml"
    matrix_path.write_text("models: [claude-haiku-4-5]\ncases: [demo]\nrepeats: 1\ntasks: all\n")

    with pytest.raises(ValueError, match=problem):
        resolve_matrix(matrix_path, tasks=["unauthenticated_endpoints"], prompts=prompts, prompts_root=prompts_root)


def test_resolve_matrix_rejects_unknown_models(tmp_path):
    matrix_path = tmp_path / "matrix.yaml"
    matrix_path.write_text("models: [claude-sonet-5-5]\ncases: [demo]\nrepeats: 1\ntasks: all\n")

    with pytest.raises(ValueError, match="unknown models \\['claude-sonet-5-5'\\]"):
        resolve_matrix(matrix_path)


def test_matrix_compares_efforts_as_separate_series(tmp_path, case):
    run_dir = tmp_path / "run"
    matrix = Matrix(models=["claude-haiku-4-5"], cases=["demo"], repeats=1, tasks=["sensitive_env_vars"],
                    efforts=["default", "high"])
    flags = []

    def create_runner(model, effort):
        flags.append(effort)
        return FakeRunner(model)

    run_matrix(matrix, run_dir, [case], create_runner=create_runner)
    write_summary(run_dir, expected_root=tmp_path / "expected", resources_root=tmp_path / "resources")

    results = read_json(run_dir / "results.json")
    assert [series["name"] for series in results["matrix"]["series"]] == [
        "claude-haiku-4-5 · default", "claude-haiku-4-5 · high"]
    assert {row["series"] for row in results["rows"]} == {"claude-haiku-4-5 · default", "claude-haiku-4-5 · high"}
    assert sorted(flags, key=str) == [None, None, "high", "high"]
    for effort in ("default", "high"):
        assert read_json(output_path(run_dir, "claude-haiku-4-5", "demo", 1, "sensitive_env_vars", effort=effort))
    assert "model · effort" in (run_dir / "summary.md").read_text()


def test_resolve_matrix_rejects_unknown_effort(tmp_path):
    matrix_path = tmp_path / "matrix.yaml"
    matrix_path.write_text("models: [claude-haiku-4-5]\ncases: [demo]\nrepeats: 1\ntasks: all\nefforts: [extreme]\n")

    with pytest.raises(ValueError, match="unknown \\['extreme'\\]"):
        resolve_matrix(matrix_path)


def test_resolve_matrix_takes_effort_from_the_argument_over_the_file(tmp_path):
    matrix_path = tmp_path / "matrix.yaml"
    matrix_path.write_text("models: [claude-haiku-4-5]\ncases: [demo]\nrepeats: 1\ntasks: all\nefforts: [low]\n")

    assert resolve_matrix(matrix_path, efforts=["max", "high"]).efforts == ["max", "high"]
    assert resolve_matrix(matrix_path).efforts == ["low"]


def test_resolve_matrix_rejects_duplicate_efforts(tmp_path):
    matrix_path = tmp_path / "matrix.yaml"
    matrix_path.write_text("models: [claude-haiku-4-5]\ncases: [demo]\nrepeats: 1\ntasks: all\n")

    with pytest.raises(ValueError, match="without duplicates"):
        resolve_matrix(matrix_path, efforts=["low", "low"])
