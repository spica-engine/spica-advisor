# Spica Advisor

Spica Advisor reviews Spica resources like functions, buckets, secrets, environment variables, policies,
and finds potential security issues, improvements, and optimizations. 
It then provides practical suggestions for addressing them.

Every LLM judgment runs through Claude Code (`claude -p`), so runs use a Claude subscription
instead of an API key.

## GitHub Action

Add a workflow to the repository that holds your Spica resources:

```yaml
name: Spica Advisor

on:
  schedule:
    - cron: "0 6 * * 1"
  workflow_dispatch:

permissions:
  contents: read
  issues: write

jobs:
  advise:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: htuna07/spica-advisor@main
        with:
          claude-code-oauth-token: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}
```

Each run writes the report to the job summary and keeps it in one issue labeled
`spica-advisor`. The issue is created when there are findings, updated on later
runs, and closed when a complete run finds nothing. Set `issue: false` to skip it.

Create the token once with `claude setup-token` and store it as the `CLAUDE_CODE_OAUTH_TOKEN` secret.

| Input | Default | Description |
| --- | --- | --- |
| `claude-code-oauth-token` | | Required. Token from `claude setup-token` |
| `model` | `claude-sonnet-5-5` | Claude model to run, one of `KNOWN_MODELS` in `spica_advisor/runner.py` |
| `effort` | Claude Code's default | `low`, `medium`, `high`, `xhigh` or `max` |
| `project-dir` | `.` | Directory holding the Spica resources |
| `output-dir` | `output` | Directory for the JSON and Markdown reports |
| `investigations` | all | Comma-separated subset to run |
| `issue` | `true` | Keep the report in a single issue |
| `github-token` | `github.token` | Token used to manage the issue |

## Running locally

Install [Claude Code](https://docs.claude.com/en/docs/claude-code) and sign in with `claude auth login`,
or set `CLAUDE_CODE_OAUTH_TOKEN`. The model and effort come from the environment or a `.env` file:

| Variable | Default | Description |
| --- | --- | --- |
| `SPICA_ADVISOR_MODEL` | `claude-sonnet-5-5` | Claude model to run |
| `SPICA_ADVISOR_EFFORT` | Claude Code's default | `low`, `medium`, `high`, `xhigh` or `max` |

`ANTHROPIC_API_KEY` is removed from Claude Code's environment, so runs never bill the API.

```
SPICA_ADVISOR_MODEL=claude-opus-5-5 SPICA_ADVISOR_EFFORT=high python main.py --project-dir path/to/spica-project
```
