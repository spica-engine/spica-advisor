# Evals

Labeled Spica projects used to compare models, and prompt variants, on accuracy, cost, token usage and latency.

Only the LLM agents are evaluated: each label is the output an agent should produce for the input
the production code gives it. Deterministic code is covered by unit tests in `tests/`.

```
python -m evals check                    # validate every case
python -m evals check spica-orchestrator # validate selected cases
python -m evals run                      # run evals/matrix.yaml, then summarize
python -m evals run --models claude-haiku-4-5 --cases synthetic-01 --repeats 1
python -m evals run --models claude-opus-5-5 --effort low high --workers 8   # compare efforts in one run
python -m evals report evals/runs/<run>  # re-score a run with the current labels
python -m evals run --investigations broken-access-control   # the agents of one investigation
python -m evals prompts                  # list every agent's prompt variants
python -m evals run --models claude-sonnet-5-5 --tasks endpoint_assessment \
  --prompts endpoint_assessment=baseline,strict --repeats 3
```

`run` refuses to start while any selected case fails `check`. It calls each agent directly with the input the
production steps build, writes results as it goes, and summarizes at the end. A run directory contains:

```
evals/runs/<UTC timestamp>/
  matrix.json      # models, efforts, cases, repeats and tasks of the run
  runs.jsonl       # one line per agent task run: status, wall time, call count
  calls.jsonl      # one line per agent call: tokens, requests, tool calls, latency, status
  outputs/<model>/<effort>/<case>/r<repeat>/<task>.json   # raw agent output; <task>--<prompt>.json for a prompt variant
  summary.md       # accuracy, consistency, cost, tokens and latency per model and task
  summary.csv      # the same numbers per model, task and case
  results.json     # everything the report page shows, including agent prompts
  report.html      # evals/report_template.html with results.json embedded
```

`report.html` builds itself from the embedded data, so new models, cases or agent prompts need no page
changes. Each run records every agent's instructions and a short prompt fingerprint, so a prompt change is visible.
To refresh the published page, re-run or re-report, then ask Claude to republish `report.html` to the page's URL.

Every agent call runs through Claude Code (`claude -p`) on the signed-in subscription. `efforts` in
`evals/matrix.yaml` (`efforts: [default]`) or `--effort` lists the efforts to run, and `default` means Claude Code's own.
With more than one, every model runs at each effort and the series are named `model · effort`.
`--workers` sets how many agent tasks run at once (default 4); each one is a separate `claude` process.

Cost is Claude Code's own estimate of what each call would cost on the API at list prices. A subscription is
not billed per token, so read it as plan usage. Runs recorded before this show `n/a`.
Models must be listed in `KNOWN_MODELS` in `spica_advisor/runner.py`; `run` rejects any other name before starting.
Failed runs count as empty predictions, and their tokens still count toward cost.

## Prompt variants

A run can compare prompts instead of, or as well as, models. Each pair of model and prompt is one series in the
summary and on the report page.

```
evals/prompts/<task>/<variant>.yaml
  description: one line shown on the report and cases pages
  instructions: |      # optional; replaces the agent's instructions, defaults to the production ones
    ...
  input: <name>        # optional; a named input builder from TASKS[<task>].inputs, defaults to the production input
```

`baseline` is built in: it is always the prompt the advisor ships with, so a file of that name is rejected. Agents
left out of `--prompts` run with baseline. The report shows each variant's instructions as a diff against baseline.
Input builders are registered in `TASKS[<task>].inputs`; they change what the agent is shown. To ship a winning variant,
copy its instructions into the agent's `prompts.py` and move its input builder into the investigation's steps.

## Case layout

A case is a folder of labels in `evals/expected/` paired with the resources folder of the same name in `resources/`.

```
resources/<case>/            # function/ bucket/ policy/ env-var/, the agents' input
evals/expected/<case>/       # labels, the expected agent output
  sensitive-env-vars.yaml
  endpoint-assessment.yaml
  policy-attachments.yaml
  bucket-acl.yaml
```

Cases are discovered from `evals/expected/`, so other folders in `resources/` are ignored.
`resources/` is git-ignored except `resources/synthetic-*/`, so real exports are never committed. Labels follow the
same rule: only `evals/expected/synthetic-*/` is committed, because real labels name client resources.

## Labels

| File | Agent and its input | Format | Rules enforced by `check` |
|---|---|---|---|
| `sensitive-env-vars.yaml` | Env var sensitiveness classifier, given every env var name | `KEY: low \| medium \| high` | Every env var key in the case, and only those |
| `policy-attachments.yaml` | Policy attachment finder, given every function's source | list of `{function_id, policy_id, policy_name}` | `function_id` (where the policy is attached) must exist; set `policy_id` for a hardcoded id and/or `policy_name` for the env var name when it comes from `process.env` |
| `bucket-acl.yaml` | Bucket ACL evaluator, given one bucket schema at a time | `<bucket _id>: {includes_sensitive_information, read, write}` with `read`/`write` in `applied \| applied_but_in_risk \| not_applied` | Any existing buckets you want scored |

`endpoint-assessment.yaml` belongs to the `endpoint_assessment` task, the endpoint agent, which is given a
batch of public functions at a time, with the code their handlers can run (cut by `spica_advisor/code_slice`) in the prompt. It labels two independent axes per public handler, and code turns
the pair into a report severity (`report_decision` in `spica_advisor/investigations/unauthenticated_endpoints/policy.py`):

```
handlers:
  <function _id>:
    <handler>: {auth: none | authentication | authorization, impact: low | medium | high}
skipped:                    # sign-in, registration and password-reset handlers the agent should not classify
  <function _id>: [<handler>, ...]
```

Only handlers listed here are scored, so the file can start partial; use `{}` for a case without labels. A handler
must be one of its function's public http triggers and appear in its source, and cannot be both labeled and skipped.
`python -m evals run --tasks endpoint_assessment` runs it, and `--investigations unauthenticated-endpoints` runs the
same agent.

A public http trigger is `type: http`, `active: true` and not `options.authorize: true`, the same filter the investigation applies before calling the agent.

Sign-in, registration and password-reset handlers go under `skipped`. A one-time code, signed link or webhook signature
counts as `authentication`, and a captcha alone as `none`. A handler that only forwards to another handler takes that
handler's labels.

## Replacing the dummy data

Every dummy file contains `REPLACE_ME`, and `check` reports each file that still has it.

- **Real cases (`real-*`)**: rename `evals/expected/real-01/` to an exported project name, such as `spica-orchestrator`, and delete the dummy `resources/real-01/`.
  The case then uses the existing `resources/<project>/` export as is.
- **Synthetic cases (`synthetic-*`)**: replace the dummy `resources/synthetic-*/` folders with hand-written resources that target edge cases.
- **Labels**: rewrite every file in `evals/expected/<case>/` for the case's resources and remove the `REPLACE_ME` line.

A case is ready when `python -m evals check <case>` prints `ok`.

## Editing cases on the report page

The published report has a second page, `cases.html`, backed by the artifact's database. It lists every case with its
labels, the full resources of synthetic cases, and an index of names and ids for real cases. Real exports never leave
the machine: their code and env var values stay in `resources/<case>`.

- `python -m evals export-cases <file>` writes the repo's cases in the page's format, for loading them into the page.
- `python -m evals import-cases <file>` applies the page's cases to the repo: it rewrites labels and synthetic
  resources, refuses unsafe paths and empty case lists, and moves cases deleted on the page to `evals/.deleted/`.

The run panel compares either models, with the shipped prompts, or the prompt variants of one model. The page's
"Run benchmark" button saves a `runs/<id>` request and sends a comment to the Claude session watching the
artifact. That session imports the cases, runs `check`, then `run` with the requested models, prompts, agents, cases
and repeats, republishes `report.html` and `cases.html` from the new run, and records progress in `runs/<id>`.
