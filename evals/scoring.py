from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from evals.assessment import NOT_REPORTED, report_decision
from spica_advisor.investigations.broken_access_control.steps import clean


MISSING = "missing"
LEVELS = ("low", "medium", "high")
REPORTED_LEVELS = ("medium", "high")


def ratio(numerator, denominator):
    if numerator is None or not denominator:
        return None
    return numerator / denominator


def f1(precision, recall):
    if precision is None or recall is None or precision + recall == 0:
        return None
    return 2 * precision * recall / (precision + recall)


def confusion(pairs):
    matrix = {}
    for expected, predicted in pairs:
        row = matrix.setdefault(str(expected), {})
        row[str(predicted)] = row.get(str(predicted), 0) + 1
    return matrix


def merge_counts(total, counts):
    for key, value in counts.items():
        if isinstance(value, dict):
            merge_counts(total.setdefault(key, {}), value)
        else:
            total[key] = total.get(key, 0) + value
    return total


def cell(matrix, expected, predicted):
    return matrix.get(expected, {}).get(predicted, 0)


def row_total(matrix, expected):
    return sum(matrix.get(expected, {}).values())


def column_total(matrix, predicted):
    return sum(row.get(predicted, 0) for row in matrix.values())


def matrix_total(matrix):
    return sum(sum(row.values()) for row in matrix.values())


def accuracy(matrix):
    return ratio(sum(cell(matrix, label, label) for label in matrix), matrix_total(matrix))


def coverage(matrix):
    total = matrix_total(matrix)
    return ratio(total - column_total(matrix, MISSING), total)


def class_f1(matrix, label):
    hits = cell(matrix, label, label)
    precision = ratio(hits, column_total(matrix, label)) or 0.0
    recall = ratio(hits, row_total(matrix, label)) or 0.0
    return f1(precision, recall) or 0.0


def macro_f1(matrix, classes):
    present = [label for label in classes if row_total(matrix, label) or column_total(matrix, label)]
    return ratio(sum(class_f1(matrix, label) for label in present), len(present))


def detection(true_positives, false_positives, false_negatives):
    precision = ratio(true_positives, true_positives + false_positives)
    recall = ratio(true_positives, true_positives + false_negatives)
    return {"precision": precision, "recall": recall, "f1": f1(precision, recall)}


def score_sensitive_env_vars(prediction, expected):
    predicted = {name: report["sensitiveness_level"] for name, report in prediction.items()}
    return {
        "levels": confusion((level, predicted.get(name, MISSING)) for name, level in expected.items()),
        "unexpected_names": len(predicted.keys() - expected.keys()),
    }


def sensitive_env_var_metrics(counts):
    levels = counts.get("levels", {})
    reported_hits = sum(cell(levels, expected, predicted) for expected in REPORTED_LEVELS for predicted in REPORTED_LEVELS)
    return {
        "accuracy": accuracy(levels),
        "macro_f1": macro_f1(levels, LEVELS),
        "reported_precision": ratio(reported_hits, sum(column_total(levels, level) for level in REPORTED_LEVELS)),
        "reported_recall": ratio(reported_hits, sum(row_total(levels, level) for level in REPORTED_LEVELS)),
        "coverage": coverage(levels),
        "high_as_low": cell(levels, "high", "low"),
        "unexpected_names": counts.get("unexpected_names", 0),
    }


def sensitive_env_var_items(prediction, expected):
    return {name: prediction.get(name, {}).get("sensitiveness_level", MISSING) for name in expected}


def endpoint_pairs(prediction):
    return {
        (function_risk["function_id"], method["name"]): method["risk_level"]
        for function_risk in prediction
        for method in function_risk["methods"]
    }


def expected_endpoint_pairs(expected):
    return {(function_id, method): risk for function_id, methods in expected.items() for method, risk in methods.items()}


def score_unauthenticated_endpoints(prediction, expected):
    expected_pairs = expected_endpoint_pairs(expected)
    predicted_pairs = endpoint_pairs(prediction)
    found = expected_pairs.keys() & predicted_pairs.keys()
    return {
        "true_positives": len(found),
        "false_positives": len(predicted_pairs.keys() - expected_pairs.keys()),
        "false_negatives": len(expected_pairs.keys() - predicted_pairs.keys()),
        "risk": confusion((expected_pairs[pair], predicted_pairs[pair]) for pair in found),
        "unknown_functions": len({function_risk["function_id"] for function_risk in prediction} - expected.keys()),
    }


def unauthenticated_endpoint_metrics(counts):
    return {
        **detection(counts.get("true_positives", 0), counts.get("false_positives", 0), counts.get("false_negatives", 0)),
        "risk_accuracy": accuracy(counts.get("risk", {})),
        "unknown_functions": counts.get("unknown_functions", 0),
    }


def unauthenticated_endpoint_items(prediction, expected):
    predicted_pairs = endpoint_pairs(prediction)
    return {f"{function_id}.{method}": predicted_pairs.get((function_id, method), MISSING)
            for function_id, method in expected_endpoint_pairs(expected)}


SKIPPED = "skipped"
CLASSIFIED = "classified"


def assessed_handlers(prediction):
    return {(function["function_id"], handler["name"]): handler
            for function in prediction.get("functions", []) for handler in function["handlers"]}


def skipped_handlers(prediction):
    return {(entry["function_id"], entry["name"]) for entry in prediction.get("skipped", [])}


def predicted_assessment(key, assessed, skipped):
    if key in assessed:
        return assessed[key]["auth"], assessed[key]["impact"]
    return (SKIPPED, SKIPPED) if key in skipped else (MISSING, MISSING)


def decision_of(auth, impact):
    return report_decision(auth, impact) if auth in ("none", "authentication", "authorization") else auth


def expected_pairs_of(expected_by_function):
    return [(function_id, handler) for function_id, handlers in expected_by_function.items() for handler in handlers]


def score_endpoint_assessment(prediction, expected):
    assessed, skipped = assessed_handlers(prediction), skipped_handlers(prediction)
    labeled = {(function_id, handler): label
               for function_id, handlers in expected["handlers"].items() for handler, label in handlers.items()}
    answers = {key: predicted_assessment(key, assessed, skipped) for key in labeled}
    decisions = {key: (decision_of(*answers[key]), decision_of(label["auth"], label["impact"]))
                 for key, label in labeled.items()}
    reported = [(predicted != NOT_REPORTED and predicted not in (SKIPPED, MISSING), expected_decision != NOT_REPORTED)
                for predicted, expected_decision in decisions.values()]
    expected_skips = expected_pairs_of(expected["skipped"])
    return {
        "auth": confusion((label["auth"], answers[key][0]) for key, label in labeled.items()),
        "impact": confusion((label["impact"], answers[key][1]) for key, label in labeled.items()),
        "decision": confusion((expected_decision, predicted) for predicted, expected_decision in decisions.values()),
        "true_positives": sum(predicted and wanted for predicted, wanted in reported),
        "false_positives": sum(predicted and not wanted for predicted, wanted in reported),
        "false_negatives": sum(wanted and not predicted for predicted, wanted in reported),
        "skip": confusion((SKIPPED, SKIPPED if key in skipped else CLASSIFIED if key in assessed else MISSING)
                          for key in expected_skips),
        "wrongly_skipped": sum(answers[key][0] == SKIPPED for key in labeled),
    }


def endpoint_assessment_metrics(counts):
    skip = counts.get("skip", {})
    return {
        "auth_accuracy": accuracy(counts.get("auth", {})),
        "impact_accuracy": accuracy(counts.get("impact", {})),
        "decision_accuracy": accuracy(counts.get("decision", {})),
        **{f"reported_{name}": value for name, value in detection(
            counts.get("true_positives", 0), counts.get("false_positives", 0), counts.get("false_negatives", 0)).items()},
        "skipped_recall": ratio(cell(skip, SKIPPED, SKIPPED), row_total(skip, SKIPPED)),
        "wrongly_skipped": counts.get("wrongly_skipped", 0),
    }


def endpoint_assessment_items(prediction, expected):
    assessed, skipped = assessed_handlers(prediction), skipped_handlers(prediction)
    keys = [*(key for key in expected_pairs_of(expected["handlers"])), *expected_pairs_of(expected["skipped"])]
    return {f"{function_id}.{handler}": "/".join(predicted_assessment((function_id, handler), assessed, skipped))
            if (function_id, handler) in assessed else predicted_assessment((function_id, handler), assessed, skipped)[0]
            for function_id, handler in keys}


def attachment_references(function_id, policy_id, policy_name):
    return {(function_id, clean(value)) for value in (policy_id, policy_name) if value}


def predicted_attachment_references(prediction):
    return [
        attachment_references(report["attachment"]["function_id"], report["policy_id"], report["policy_name"])
        for report in prediction
    ]


def expected_attachment_references(expected):
    return [attachment_references(entry["function_id"], entry["policy_id"], entry["policy_name"]) for entry in expected]


def score_policy_attachments(prediction, expected):
    predicted = predicted_attachment_references(prediction)
    labeled = expected_attachment_references(expected)
    all_predicted = set().union(*predicted)
    all_labeled = set().union(*labeled)
    return {
        "labeled": len(labeled),
        "labeled_found": sum(bool(references & all_predicted) for references in labeled),
        "predicted": len(predicted),
        "predicted_correct": sum(bool(references & all_labeled) for references in predicted),
    }


def policy_attachment_metrics(counts):
    precision = ratio(counts.get("predicted_correct", 0), counts.get("predicted", 0))
    recall = ratio(counts.get("labeled_found", 0), counts.get("labeled", 0))
    return {"precision": precision, "recall": recall, "f1": f1(precision, recall)}


def policy_attachment_items(prediction, expected):
    all_predicted = set().union(*predicted_attachment_references(prediction))
    return {str(index): bool(references & all_predicted)
            for index, references in enumerate(expected_attachment_references(expected))}


def bucket_answer(prediction, bucket_id):
    report = prediction.get(bucket_id)
    if report is None:
        return MISSING, MISSING, MISSING
    return (
        report["includes_sensitive_information"],
        report["read"]["row_level_security_status"],
        report["write"]["row_level_security_status"],
    )


def score_bucket_acl(prediction, expected):
    answers = {bucket_id: bucket_answer(prediction, bucket_id) for bucket_id in expected}
    return {
        "sensitive": confusion((label["includes_sensitive_information"], answers[bucket_id][0])
                               for bucket_id, label in expected.items()),
        "read": confusion((label["read"], answers[bucket_id][1]) for bucket_id, label in expected.items()),
        "write": confusion((label["write"], answers[bucket_id][2]) for bucket_id, label in expected.items()),
    }


def bucket_acl_metrics(counts):
    sensitive = counts.get("sensitive", {})
    return {
        "read_accuracy": accuracy(counts.get("read", {})),
        "write_accuracy": accuracy(counts.get("write", {})),
        "sensitive_precision": ratio(cell(sensitive, "True", "True"), column_total(sensitive, "True")),
        "sensitive_recall": ratio(cell(sensitive, "True", "True"), row_total(sensitive, "True")),
        "coverage": coverage(sensitive),
    }


def bucket_acl_items(prediction, expected):
    return {bucket_id: str(bucket_answer(prediction, bucket_id)) for bucket_id in expected}


@dataclass(frozen=True)
class Scorer:
    description: str
    metric_help: dict[str, str]
    empty_prediction: Any
    score: Callable
    metrics: Callable
    items: Callable
    primary_metric: str


SCORERS = {
    "sensitive_env_vars": Scorer(
        "Rates each env var name as low, medium or high sensitivity. Scored per labeled env var.",
        {
            "accuracy": "Out of all env vars, how many got exactly the right sensitivity level.",
            "macro_f1": "Like accuracy, but low, medium and high count equally, so doing well on the common level "
                        "cannot hide mistakes on the rare one.",
            "reported_precision": "When the model calls an env var sensitive (medium or high), how often it really is. "
                                  "Low means false alarms.",
            "reported_recall": "Out of the env vars that really are sensitive, how many the model caught. "
                               "Low means risks slip through.",
            "coverage": "How many env vars got any answer at all. Missing answers count as wrong.",
            "high_as_low": "Highly sensitive env vars the model called low. The most dangerous mistake; it should be 0.",
            "unexpected_names": "Env var names the model mentioned that do not exist in the project.",
        },
        {}, score_sensitive_env_vars, sensitive_env_var_metrics, sensitive_env_var_items, "accuracy",
    ),
    "unauthenticated_endpoints": Scorer(
        "Finds public handlers without an auth check and rates their risk. Scored per function and handler pair.",
        {
            "precision": "When the model reports an unprotected endpoint, how often it really is one. "
                         "Low means false alarms for reviewers.",
            "recall": "Out of the endpoints that really are unprotected, how many the model found. "
                      "Low means real gaps are missed.",
            "f1": "One score that balances precision and recall. It is only high when the model finds the real "
                  "problems without raising false alarms.",
            "risk_accuracy": "For endpoints the model found correctly, how often it also chose the right risk level.",
            "unknown_functions": "Functions the model reported that were not in what it was given.",
        },
        [], score_unauthenticated_endpoints, unauthenticated_endpoint_metrics, unauthenticated_endpoint_items, "f1",
    ),
    "endpoint_assessment": Scorer(
        "Labels each public handler's authentication and impact separately; code turns the pair into a report severity. "
        "Scored per labeled handler.",
        {
            "auth_accuracy": "How often the model chose the right authentication level (none, authentication, "
                             "authorization).",
            "impact_accuracy": "How often the model chose the right impact (low, medium, high), ignoring auth.",
            "decision_accuracy": "How often the pair of answers leads to the same report severity as the labels. "
                                 "This is what a reviewer would see.",
            "reported_precision": "When the model's answers put a handler in the report, how often the labels agree.",
            "reported_recall": "Out of the handlers the labels put in the report, how many the model's answers did.",
            "reported_f1": "One score that balances those two.",
            "skipped_recall": "Out of the sign-in and similar handlers that should be skipped, how many the model "
                              "skipped.",
            "wrongly_skipped": "Handlers that should have been judged but the model skipped. It should be 0.",
        },
        {"functions": [], "skipped": []}, score_endpoint_assessment, endpoint_assessment_metrics,
        endpoint_assessment_items, "decision_accuracy",
    ),
    "policy_attachments": Scorer(
        "Searches function code for policies attached to users. Scored per attachment and policy reference.",
        {
            "precision": "When the model reports that code gives users a policy, how often that is true. "
                         "Low means false alarms.",
            "recall": "Out of the places that really give users a policy, how many the model found. "
                      "Low means permission grants go unnoticed.",
            "f1": "One score that balances precision and recall. It is only high when the model finds the real "
                  "grants without raising false alarms.",
        },
        [], score_policy_attachments, policy_attachment_metrics, policy_attachment_items, "f1",
    ),
    "bucket_acl": Scorer(
        "Judges row-level security of each bucket's read and write rules and whether it holds sensitive data.",
        {
            "read_accuracy": "How often the model correctly judged whether a bucket's read rule limits people to "
                             "their own records.",
            "write_accuracy": "The same for the bucket's write rule.",
            "sensitive_precision": "When the model says a bucket holds personal data, how often it really does.",
            "sensitive_recall": "Out of the buckets that really hold personal data, how many the model recognized.",
            "coverage": "How many buckets got an answer. A failed request leaves a bucket without one.",
        },
        {}, score_bucket_acl, bucket_acl_metrics, bucket_acl_items, "read_accuracy",
    ),
}
