import argparse
from types import SimpleNamespace

import pytest

from evals.cli import prompt_selection
from evals.inputs import endpoint_prompts_without_handler_names
from evals.prompts import BASELINE, describe_variant, load_variants
from spica_advisor.investigations.unauthenticated_endpoints.agents import ENDPOINT_RISK_AGENT


TASK = "unauthenticated_endpoints"


def write_variant(root, name, content, task=TASK):
    folder = root / task
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{name}.yaml").write_text(content, encoding="utf-8")


def test_baseline_is_always_available_and_uses_the_production_prompt(tmp_path):
    variants = load_variants(TASK, tmp_path)

    assert list(variants) == [BASELINE]
    assert variants[BASELINE].agent_for(ENDPOINT_RISK_AGENT) is ENDPOINT_RISK_AGENT


def test_variant_replaces_instructions_and_keeps_the_agent_otherwise(tmp_path):
    write_variant(tmp_path, "strict", "description: Stricter.\ninstructions: Only report handlers.\n")

    variant = load_variants(TASK, tmp_path)["strict"]
    agent = variant.agent_for(ENDPOINT_RISK_AGENT)

    assert agent.instructions == "Only report handlers."
    assert agent.name == ENDPOINT_RISK_AGENT.name
    assert agent.output_type is ENDPOINT_RISK_AGENT.output_type
    assert ENDPOINT_RISK_AGENT.instructions != "Only report handlers."


def test_input_only_variant_keeps_the_baseline_instructions(tmp_path):
    write_variant(tmp_path, "names", "input: source-only\n")

    details = describe_variant(TASK, load_variants(TASK, tmp_path)["names"])

    assert details["input"] == "source-only"
    assert details["instructions"] == ENDPOINT_RISK_AGENT.instructions
    assert details["diff"] == []


def test_describe_variant_diffs_instructions_against_baseline(tmp_path):
    write_variant(tmp_path, "short", "instructions: Report everything.\n")

    diff = describe_variant(TASK, load_variants(TASK, tmp_path)["short"])["diff"]

    assert "+Report everything." in diff
    assert any(line.startswith("-") and "Analyze" in line for line in diff)


@pytest.mark.parametrize(("name", "content", "problem"), [
    ("baseline", "instructions: x\n", "reserved for the production prompt"),
    ("Bad_Name", "instructions: x\n", "invalid variant name"),
    ("unknown-input", "input: everything\n", "unknown input 'everything'"),
    ("blank", "instructions: '  '\n", "instructions are empty"),
])
def test_invalid_variants_are_rejected(tmp_path, name, content, problem):
    write_variant(tmp_path, name, content)

    with pytest.raises(ValueError, match=problem):
        load_variants(TASK, tmp_path)


def test_unknown_variant_fields_are_rejected(tmp_path):
    write_variant(tmp_path, "typo", "instruction: x\n")

    with pytest.raises(ValueError):
        load_variants(TASK, tmp_path)


def test_prompt_selection_parses_task_and_variants():
    assert prompt_selection("unauthenticated_endpoints=baseline, combined") == (TASK, ["baseline", "combined"])
    with pytest.raises(argparse.ArgumentTypeError):
        prompt_selection("unauthenticated_endpoints")


def test_source_only_input_rebuilds_the_legacy_prompt_input():
    schema = {"triggers": {"create": {"type": "http", "active": True, "options": {}}}}
    context = SimpleNamespace(public_functions=[
        {"_id": "fn-1", "schema": schema, "content": "export function create(req, res) {}"},
    ])

    [call] = endpoint_prompts_without_handler_names(context)

    assert call.functions == ()
    assert call.prompt == "Functions:\nfunction_id: fn-1\n```\nexport function create(req, res) {}\n```"
