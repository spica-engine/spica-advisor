import csv
import json
import math
from collections import Counter, defaultdict
from pathlib import Path

from evals.cases import EXPECTED_ROOT, RESOURCES_ROOT, find_cases
from evals.harness import output_path
from evals.prompts import BASELINE
from evals.scoring import SCORERS, merge_counts, ratio
from evals.storage import read_json, read_jsonl, write_json
from evals.workspace import render_cases_page
from spica_advisor.metrics import OK_STATUS


REPORT_TEMPLATE_PATH = Path(__file__).with_name("report_template.html")
DATA_PLACEHOLDER = "__BENCHMARK_DATA__"
ALL_CASES = "all"
PER_RUN_FIELDS = ("input_tokens", "cached_input_tokens", "output_tokens", "reasoning_tokens", "requests", "tool_calls")
PERCENT_SUFFIXES = ("accuracy", "precision", "recall", "f1", "coverage", "consistency")
CONSISTENCY_HELP = ("Each test runs several times. This is how often the model gave the same answer each time. "
                    "Low means results depend on luck.")
USAGE_HELP = {
    "runs": "How many times this agent ran: once per case for every repeat.",
    "failed_runs": "Runs that ended in an error and produced no answer. They count as wrong answers.",
    "failed_calls": "Requests to the model that failed, for example when it ran out of allowed steps.",
    "cost_per_run": ("Average dollars a run would cost on the API, as Claude Code estimates it. "
                     "A subscription is not billed per token, but this shows how much of the plan a run uses."),
    "input_tokens_per_run": "How much text was sent to the model per run. A token is roughly three quarters of a word.",
    "cached_input_tokens_per_run": "The part of that text the provider had seen recently and charged less for.",
    "output_tokens_per_run": "How much text the model wrote back per run.",
    "reasoning_tokens_per_run": "Hidden thinking the model did before answering. It is billed like written output.",
    "requests_per_run": "How many times the agent asked the model something during one run.",
    "tool_calls_per_run": "How many code searches the agent ran during one run.",
    "seconds_per_run": "Average time one agent run took, from start to answer.",
    "p95_call_seconds": "95 out of 100 model requests finished faster than this. It shows how slow the slow cases are.",
}


def call_cost(call):
    return call.get("cost_usd")


def total(values):
    values = list(values)
    return None if any(value is None for value in values) else sum(values)


def percentile(values, percent):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percent / 100 * len(ordered)) - 1)]


def group(records, *keys):
    groups = defaultdict(list)
    for record in records:
        groups[tuple(record[key] for key in keys)].append(record)
    return groups


def compares_prompts(matrix):
    return any(names != [BASELINE] for names in (matrix.get("prompts") or {}).values())


def series_name(model, prompt, by_prompt):
    return f"{model} · {prompt}" if by_prompt else model


def matrix_series(matrix):
    by_prompt = compares_prompts(matrix)
    prompts = list(dict.fromkeys(
        prompt for task in matrix["tasks"] for prompt in (matrix.get("prompts") or {}).get(task, [BASELINE])
    ))
    return [
        {"name": series_name(model, prompt, by_prompt), "model": model, "prompt": prompt}
        for model in matrix["models"]
        for prompt in prompts
    ]


def with_series(records, by_prompt):
    tagged = []
    for record in records:
        prompt = record.get("prompt", BASELINE)
        tagged.append({**record, "prompt": prompt, "series": series_name(record["model"], prompt, by_prompt)})
    return tagged


def scored_runs(run_dir, runs, labels):
    scored = []
    for run in runs:
        scorer = SCORERS[run["task"]]
        output = read_json(output_path(run_dir, run["model"], run["case"], run["repeat"], run["task"], run["prompt"]))
        prediction = scorer.empty_prediction if output["prediction"] is None else output["prediction"]
        expected = labels[run["case"]][run["task"]]
        scored.append({**run, "counts": scorer.score(prediction, expected), "items": scorer.items(prediction, expected)})
    return scored


def consistency(runs):
    agreements = []
    for case_runs in group(runs, "case").values():
        if len(case_runs) < 2:
            continue
        for item in case_runs[0]["items"]:
            values = [run["items"][item] for run in case_runs]
            agreements.append(max(Counter(values).values()) / len(values))
    return ratio(sum(agreements), len(agreements))


def accuracy_metrics(task, runs):
    counts = {}
    for run in runs:
        merge_counts(counts, run["counts"])
    return {**SCORERS[task].metrics(counts), "consistency": consistency(runs)}


def usage_metrics(runs, calls):
    run_count = len(runs)
    return {
        "runs": run_count,
        "failed_runs": sum(run["status"] != OK_STATUS for run in runs),
        "failed_calls": sum(call["status"] != OK_STATUS for call in calls),
        "cost_per_run": ratio(total(call_cost(call) for call in calls), run_count),
        **{f"{field}_per_run": ratio(sum(call[field] for call in calls), run_count) for field in PER_RUN_FIELDS},
        "seconds_per_run": ratio(sum(run["wall_seconds"] for run in runs), run_count),
        "p95_call_seconds": percentile([call["wall_seconds"] for call in calls], 95),
    }


USAGE_METRICS = list(usage_metrics([], []))


def series_fields(runs):
    first = runs[0]
    return {"series": first["series"], "model": first["model"], "prompt": first["prompt"]}


def summary_rows(scored, calls):
    calls_by_group = group(calls, "series", "task", "case")
    rows = []
    for (series, task, case), runs in sorted(group(scored, "series", "task", "case").items()):
        rows.append({**series_fields(runs), "task": task, "case": case,
                     **accuracy_metrics(task, runs),
                     **usage_metrics(runs, calls_by_group.get((series, task, case), []))})
    for (series, task), runs in sorted(group(scored, "series", "task").items()):
        task_calls = [call for call in calls if call["series"] == series and call["task"] == task]
        rows.append({**series_fields(runs), "task": task, "case": ALL_CASES,
                     **accuracy_metrics(task, runs),
                     **usage_metrics(runs, task_calls)})
    return rows


def series_totals(calls):
    totals = []
    for (series,), series_calls in sorted(group(calls, "series").items()):
        totals.append({
            **series_fields(series_calls),
            "calls": len(series_calls),
            "failed_calls": sum(call["status"] != OK_STATUS for call in series_calls),
            "total_cost": total(call_cost(call) for call in series_calls),
            "llm_seconds": sum(call["wall_seconds"] for call in series_calls),
        })
    return totals


def format_value(metric, value):
    if value is None:
        return "n/a"
    if "cost" in metric:
        return f"${value:.4f}"
    if "seconds" in metric:
        return f"{value:.1f}s"
    if metric.endswith(PERCENT_SUFFIXES):
        return f"{value:.1%}"
    if isinstance(value, float):
        return f"{value:,.1f}"
    return str(value)


def table(header, rows):
    return [
        "| " + " | ".join(header) + " |",
        "|" + "---|" * len(header),
        *("| " + " | ".join(row) + " |" for row in rows),
    ]


def primary_metric_cell(rows_by_case, row, case):
    metric = SCORERS[row["task"]].primary_metric
    case_row = rows_by_case.get((row["series"], row["task"], case))
    return format_value(metric, case_row[metric]) if case_row else "-"


def prompts_line(matrix):
    prompts = matrix.get("prompts") or {}
    return "Prompts: " + "; ".join(f"{task}: {', '.join(names)}" for task, names in prompts.items())


def render_markdown(run_name, matrix, rows, totals):
    overall = [row for row in rows if row["case"] == ALL_CASES]
    by_prompt = compares_prompts(matrix)
    series_header = "model · prompt" if by_prompt else "model"
    lines = [
        f"# Eval summary: {run_name}",
        "",
        f"Models: {', '.join(matrix['models'])} · Effort: {matrix.get('effort') or 'default'} · "
        f"Cases: {', '.join(matrix['cases'])} · Repeats: {matrix['repeats']}",
        *([prompts_line(matrix)] if by_prompt else []),
        "",
        "Failed runs count as empty predictions. Consistency is the share of repeats that agree with the majority "
        "answer per labeled item. Costs are Claude Code's API-equivalent estimates; n/a means a call reported none.",
        "",
        "## Accuracy",
    ]
    for task in matrix["tasks"]:
        task_rows = [row for row in overall if row["task"] == task]
        if not task_rows:
            continue
        metrics = [*SCORERS[task].metrics({}), "consistency"]
        lines += ["", f"### {task}", "", *table(
            [series_header, *metrics],
            [[row["series"], *(format_value(metric, row[metric]) for metric in metrics)] for row in task_rows],
        )]

    cases = sorted({row["case"] for row in rows} - {ALL_CASES})
    rows_by_case = {(row["series"], row["task"], row["case"]): row for row in rows}
    lines += ["", "## Primary metric per case", "", *table(
        [series_header, "task", "metric", *cases],
        [
            [row["series"], row["task"], SCORERS[row["task"]].primary_metric,
             *(primary_metric_cell(rows_by_case, row, case) for case in cases)]
            for row in overall
        ],
    )]

    lines += ["", "## Cost, tokens and latency per run", "", *table(
        [series_header, "task", *USAGE_METRICS],
        [[row["series"], row["task"], *(format_value(metric, row[metric]) for metric in USAGE_METRICS)] for row in overall],
    )]

    total_metrics = ["calls", "failed_calls", "total_cost", "llm_seconds"]
    lines += ["", f"## Totals per {series_header}", "", *table(
        [series_header, *total_metrics],
        [[row["series"], *(format_value(metric, row[metric]) for metric in total_metrics)] for row in totals],
    ), ""]
    return "\n".join(lines)


def benchmark_data(run_name, matrix, rows, totals):
    return {
        "run": run_name,
        "matrix": {
            **{key: matrix[key] for key in ("models", "cases", "repeats", "tasks")},
            "prompts": matrix.get("prompts") or {},
            "effort": matrix.get("effort"),
            "compares_prompts": compares_prompts(matrix),
            "series": matrix_series(matrix),
        },
        "metadata": matrix.get("metadata", {}),
        "tasks": {
            task: {
                "description": SCORERS[task].description,
                "metrics": [*SCORERS[task].metrics({}), "consistency"],
                "percent_metrics": [
                    metric for metric in [*SCORERS[task].metrics({}), "consistency"]
                    if metric.endswith(PERCENT_SUFFIXES)
                ],
                "primary_metric": SCORERS[task].primary_metric,
                "metric_help": {**SCORERS[task].metric_help, "consistency": CONSISTENCY_HELP},
            }
            for task in matrix["tasks"]
        },
        "usage_metrics": USAGE_METRICS,
        "usage_help": USAGE_HELP,
        "rows": rows,
        "totals": totals,
    }


def render_html(data, template_path=REPORT_TEMPLATE_PATH):
    payload = json.dumps(data).replace("</", "<\\/")
    return template_path.read_text(encoding="utf-8").replace(DATA_PLACEHOLDER, payload)


def write_csv(path, rows):
    columns = list(dict.fromkeys(column for row in rows for column in row))
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def write_summary(run_dir, expected_root=EXPECTED_ROOT, resources_root=RESOURCES_ROOT):
    matrix = read_json(run_dir / "matrix.json")
    by_prompt = compares_prompts(matrix)
    runs = with_series(read_jsonl(run_dir / "runs.jsonl"), by_prompt)
    calls = with_series(read_jsonl(run_dir / "calls.jsonl"), by_prompt)
    labels = {
        case.name: case.load_labels().model_dump()
        for case in find_cases(expected_root, resources_root, matrix["cases"])
    }
    rows = summary_rows(scored_runs(run_dir, runs, labels), calls)
    totals = series_totals(calls)
    summary_path = run_dir / "summary.md"
    summary_path.write_text(render_markdown(run_dir.name, matrix, rows, totals), encoding="utf-8")
    write_csv(run_dir / "summary.csv", rows)
    data = benchmark_data(run_dir.name, matrix, rows, totals)
    write_json(run_dir / "results.json", data)
    (run_dir / "report.html").write_text(render_html(data), encoding="utf-8")
    (run_dir / "cases.html").write_text(render_cases_page(data), encoding="utf-8")
    return summary_path
