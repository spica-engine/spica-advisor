import re
from pathlib import Path

import pytest

from evals.assessment import (
    ASSESSMENT_INSTRUCTIONS,
    ENDPOINT_ASSESSMENT_AGENT,
    EndpointAssessmentResponse,
    FunctionAssessment,
    HandlerAssessment,
    SkippedHandler,
    predict_endpoint_assessment,
    report_decision,
)
from evals.cases import EvalCase
from evals.scoring import (
    MISSING,
    endpoint_assessment_items,
    endpoint_assessment_metrics,
    merge_counts,
    score_endpoint_assessment,
)
from evals.validation import check_case
from tests.test_eval_validation import LABELS, write_label, write


EXPECTED = {
    "handlers": {
        "fn-1": {
            "create": {"auth": "none", "impact": "high"},
            "ping": {"auth": "none", "impact": "low"},
            "confirm": {"auth": "authentication", "impact": "high"},
        },
    },
    "skipped": {"fn-1": ["login"]},
}


def handler(name, auth, impact):
    return {"name": name, "auth_reason": "r", "auth": auth, "impact_reason": "r", "impact": impact}


def prediction(handlers, skipped=()):
    return {
        "functions": [{"function_id": "fn-1", "handlers": handlers}],
        "skipped": [{"function_id": "fn-1", "name": name, "reason": "r"} for name in skipped],
    }


def test_report_decision_follows_the_policy_table():
    assert [report_decision("none", impact) for impact in ("low", "medium", "high")] == ["low", "medium", "high"]
    assert report_decision("authentication", "high") == "low"
    assert report_decision("authentication", "medium") == "none"
    assert report_decision("authorization", "high") == "none"


def test_perfect_answers_score_one_everywhere():
    counts = score_endpoint_assessment(prediction(
        [handler("create", "none", "high"), handler("ping", "none", "low"), handler("confirm", "authentication", "high")],
        skipped=["login"],
    ), EXPECTED)

    metrics = endpoint_assessment_metrics(counts)

    assert metrics["auth_accuracy"] == metrics["impact_accuracy"] == metrics["decision_accuracy"] == 1.0
    assert (metrics["reported_precision"], metrics["reported_recall"], metrics["skipped_recall"]) == (1.0, 1.0, 1.0)
    assert metrics["wrongly_skipped"] == 0


def test_wrong_missing_and_skipped_answers_are_counted_separately():
    counts = score_endpoint_assessment(prediction(
        [handler("create", "authentication", "high"), handler("ping", "none", "medium")],
        skipped=["confirm"],
    ), EXPECTED)

    metrics = endpoint_assessment_metrics(counts)

    assert metrics["auth_accuracy"] == pytest.approx(1 / 3)
    assert metrics["impact_accuracy"] == pytest.approx(1 / 3)
    assert metrics["wrongly_skipped"] == 1
    assert metrics["skipped_recall"] == 0.0
    assert counts["skip"] == {"skipped": {"missing": 1}}
    assert counts["auth"]["authentication"] == {"skipped": 1}


def test_a_failed_run_with_an_empty_prediction_scores_zero_and_merges_with_others():
    empty = score_endpoint_assessment({"functions": [], "skipped": []}, EXPECTED)
    good = score_endpoint_assessment(prediction(
        [handler("create", "none", "high"), handler("ping", "none", "low"), handler("confirm", "authentication", "high")],
        skipped=["login"],
    ), EXPECTED)

    metrics = endpoint_assessment_metrics(merge_counts(merge_counts({}, empty), good))

    assert metrics["auth_accuracy"] == pytest.approx(0.5)
    assert metrics["reported_recall"] == pytest.approx(0.5)


def test_items_show_each_labeled_handler_s_answer():
    items = endpoint_assessment_items(prediction([handler("create", "none", "high")], skipped=["login"]), EXPECTED)

    assert items == {
        "fn-1.create": "none/high",
        "fn-1.ping": MISSING,
        "fn-1.confirm": MISSING,
        "fn-1.login": "skipped",
    }


class FakeRunner:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def run(self, agent, prompt, functions=()):
        self.calls.append((agent, prompt, functions))
        return next(self.responses)


def test_prediction_runs_one_call_per_public_function_and_maps_file_names_back(tmp_path):
    case = EvalCase("demo", tmp_path / "resources" / "demo", tmp_path / "expected" / "demo")
    write(case, "function/Signup/schema.yaml",
          "_id: fn-1\nname: Signup\ntriggers:\n  create:\n    type: http\n    active: true\n    options: {}\n")
    write(case, "function/Signup/index.mjs", "export function create(req, res) {}\n")
    runner = FakeRunner([EndpointAssessmentResponse(
        functions=[FunctionAssessment(function_id="fn-1.js", handlers=[
            HandlerAssessment(name="create", auth_reason="r", auth="none", impact_reason="r", impact="high")])],
        skipped=[SkippedHandler(function_id="fn-1.js", name="login", reason="sign-in")],
    )])

    result = predict_endpoint_assessment(case, None, runner)

    [(agent, prompt, functions)] = runner.calls
    assert agent is ENDPOINT_ASSESSMENT_AGENT
    assert "function_id: fn-1" in prompt and "http_handlers: create" in prompt
    assert [function["_id"] for function in functions] == ["fn-1"]
    assert result["functions"][0]["function_id"] == "fn-1"
    assert result["skipped"][0]["function_id"] == "fn-1"


def test_the_draft_document_and_the_agent_use_the_same_prompt():
    draft = Path("evals/drafts/endpoint-auth-impact.md").read_text(encoding="utf-8")
    draft_prompt = re.search(r"## Prompt\n\n```\n(.*?)\n```", draft, re.S).group(1)

    assert ASSESSMENT_INSTRUCTIONS.strip() == draft_prompt.strip()


@pytest.fixture
def labeled_case(tmp_path):
    from tests.test_eval_validation import PRIVATE_FUNCTION_SCHEMA, FUNCTION_SCHEMA, POLICY_SCHEMA, new_case

    case = new_case(tmp_path, "demo")
    write(case, "function/Signup/schema.yaml", FUNCTION_SCHEMA)
    write(case, "function/Signup/index.mjs", "export function register(req, res) {}\n")
    write(case, "function/Private/schema.yaml", PRIVATE_FUNCTION_SCHEMA)
    write(case, "function/Private/index.mjs", "export function handler() {}\n")
    write(case, "bucket/Users/schema.yaml", "_id: bucket-users\ntitle: Users\n")
    write(case, "policy/User/schema.yaml", POLICY_SCHEMA)
    write(case, "env-var/API_SECRET/schema.yaml", "_id: env-1\nkey: API_SECRET\n")
    for name, content in LABELS.items():
        write_label(case, name, content)
    return case


def test_assessment_labels_are_optional(labeled_case):
    assert check_case(labeled_case) == []
    assert labeled_case.load_labels().endpoint_assessment.handlers == {}


def test_valid_assessment_labels_load_and_pass_the_check(labeled_case):
    write_label(labeled_case, "endpoint-assessment.yaml",
                "handlers:\n  fn-signup:\n    register: {auth: none, impact: high}\n")

    assert check_case(labeled_case) == []
    assert labeled_case.load_labels().endpoint_assessment.handlers["fn-signup"]["register"].auth == "none"


@pytest.mark.parametrize(("content", "problem"), [
    ("handlers:\n  fn-signup:\n    register: {auth: maybe, impact: high}\n", "endpoint-assessment.yaml"),
    ("handlers:\n  fn-signup:\n    missing: {auth: none, impact: low}\n", "fn-signup.missing is not a public http trigger"),
    ("handlers:\n  fn-other:\n    register: {auth: none, impact: low}\n", "unexpected public function fn-other"),
    ("handlers:\n  fn-signup:\n    register: {auth: none, impact: low}\nskipped:\n  fn-signup: [register]\n",
     "fn-signup.register is both labeled and skipped"),
])
def test_invalid_assessment_labels_are_reported(labeled_case, content, problem):
    write_label(labeled_case, "endpoint-assessment.yaml", content)

    assert any(problem in line for line in check_case(labeled_case))
