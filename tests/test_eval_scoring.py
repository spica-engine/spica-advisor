import pytest

from evals.scoring import (
    MISSING,
    macro_f1,
    merge_counts,
    bucket_acl_metrics,
    policy_attachment_metrics,
    score_bucket_acl,
    score_policy_attachments,
    score_sensitive_env_vars,
    score_unauthenticated_endpoints,
    sensitive_env_var_metrics,
    unauthenticated_endpoint_metrics,
)
from evals.summary import call_cost, consistency, percentile


def env_report(level):
    return {"sensitiveness_level": level, "reason": "r"}


def test_env_var_scoring_counts_levels_missing_and_unexpected_names():
    counts = score_sensitive_env_vars(
        {"API_KEY": env_report("high"), "LOG_LEVEL": env_report("medium"), "INVENTED": env_report("low")},
        {"API_KEY": "high", "LOG_LEVEL": "low", "DB_URL": "medium"},
    )

    assert counts == {
        "levels": {"high": {"high": 1}, "low": {"medium": 1}, "medium": {MISSING: 1}},
        "unexpected_names": 1,
    }
    metrics = sensitive_env_var_metrics(counts)
    assert metrics["accuracy"] == pytest.approx(1 / 3)
    assert metrics["coverage"] == pytest.approx(2 / 3)
    assert metrics["reported_precision"] == pytest.approx(1 / 2)
    assert metrics["reported_recall"] == pytest.approx(1 / 2)
    assert metrics["high_as_low"] == 0
    assert metrics["unexpected_names"] == 1


def test_macro_f1_averages_classes_that_appear():
    matrix = {"low": {"low": 1}, "high": {"low": 1}}

    assert macro_f1(matrix, ("low", "medium", "high")) == pytest.approx((2 / 3 + 0) / 2)


def test_endpoint_scoring_matches_function_and_handler_pairs():
    prediction = [
        {"function_id": "fn-1", "methods": [
            {"name": "create", "risk_level": "high", "reason": "r"},
            {"name": "helper", "risk_level": "low", "reason": "r"},
        ]},
        {"function_id": "fn-invented", "methods": [{"name": "x", "risk_level": "low", "reason": "r"}]},
    ]
    expected = {"fn-1": {"create": "medium", "health": "low"}, "fn-2": {}}

    counts = score_unauthenticated_endpoints(prediction, expected)

    assert counts == {
        "true_positives": 1,
        "false_positives": 2,
        "false_negatives": 1,
        "risk": {"medium": {"high": 1}},
        "unknown_functions": 1,
    }
    metrics = unauthenticated_endpoint_metrics(counts)
    assert metrics["precision"] == pytest.approx(1 / 3)
    assert metrics["recall"] == pytest.approx(1 / 2)
    assert metrics["risk_accuracy"] == 0


def attachment_report(function_id, policy_id=None, policy_name=None):
    location = {"function_id": function_id, "match": "code"}
    return {"attachment": location, "definition": location, "policy_id": policy_id, "policy_name": policy_name}


def test_attachment_scoring_matches_references_regardless_of_field_and_case():
    prediction = [
        attachment_report("fn-a", policy_id="64a1"),
        attachment_report("fn-b", policy_id="partner_policy_id"),
        attachment_report("fn-c", policy_id="64a9"),
    ]
    expected = [
        {"function_id": "fn-a", "policy_id": "64a1", "policy_name": None},
        {"function_id": "fn-b", "policy_id": None, "policy_name": "PARTNER_POLICY_ID"},
        {"function_id": "fn-d", "policy_id": "64a4", "policy_name": None},
    ]

    counts = score_policy_attachments(prediction, expected)

    assert counts == {"labeled": 3, "labeled_found": 2, "predicted": 3, "predicted_correct": 2}
    assert policy_attachment_metrics(counts)["f1"] == pytest.approx(2 / 3)


def bucket_report(sensitive, read, write):
    return {
        "includes_sensitive_information": sensitive,
        "read": {"row_level_security_status": read, "reason": "r"},
        "write": {"row_level_security_status": write, "reason": "r"},
    }


def test_bucket_scoring_counts_each_rule_and_missing_buckets():
    expected = {
        "b1": {"includes_sensitive_information": True, "read": "applied", "write": "not_applied"},
        "b2": {"includes_sensitive_information": False, "read": "not_applied", "write": "not_applied"},
    }

    counts = score_bucket_acl({"b1": bucket_report(True, "applied_but_in_risk", "not_applied")}, expected)

    metrics = bucket_acl_metrics(counts)
    assert metrics["read_accuracy"] == 0
    assert metrics["write_accuracy"] == pytest.approx(1 / 2)
    assert metrics["sensitive_precision"] == 1
    assert metrics["sensitive_recall"] == 1
    assert metrics["coverage"] == pytest.approx(1 / 2)


def test_merge_counts_sums_nested_counts():
    total = merge_counts({}, {"levels": {"high": {"high": 1}}, "unexpected_names": 1})
    merge_counts(total, {"levels": {"high": {"high": 2, "low": 1}}, "unexpected_names": 0})

    assert total == {"levels": {"high": {"high": 3, "low": 1}}, "unexpected_names": 1}


def test_consistency_is_majority_agreement_per_item_across_repeats():
    runs = [
        {"case": "c1", "items": {"A": "high", "B": "low"}},
        {"case": "c1", "items": {"A": "high", "B": "medium"}},
        {"case": "c1", "items": {"A": "high", "B": "high"}},
        {"case": "c2", "items": {"C": "low"}},
    ]

    assert consistency(runs) == pytest.approx((1 + 1 / 3) / 2)


def test_call_cost_is_the_cost_claude_reported():
    assert call_cost({"input_tokens": 10, "cost_usd": 0.25}) == 0.25
    assert call_cost({"input_tokens": 10, "cost_usd": None}) is None
    assert call_cost({"input_tokens": 10}) is None


def test_percentile_uses_nearest_rank():
    assert percentile([5, 1, 3, 2, 4], 95) == 5
    assert percentile([], 95) is None


def test_every_reported_metric_has_a_plain_language_explanation():
    from evals.scoring import SCORERS
    from evals.summary import USAGE_HELP, USAGE_METRICS

    for scorer in SCORERS.values():
        assert set(scorer.metrics({})) <= set(scorer.metric_help)
    assert set(USAGE_METRICS) <= set(USAGE_HELP)
