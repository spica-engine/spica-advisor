import argparse
import logging
from pathlib import Path
from pprint import pformat

from spica_advisor.github import GitHubIssues, append_step_summary, report_metadata, step_summary_path
from spica_advisor.investigation import InvestigationError
from spica_advisor.investigations import INVESTIGATIONS
from spica_advisor.log import LOGGER, configure_logging
from spica_advisor.markdown import Failure, render_report
from spica_advisor.metrics import totals
from spica_advisor.report import write_markdown, write_report
from spica_advisor.runner import ClaudeRunner


def existing_dir(value):
    path = Path(value)
    if not path.is_dir():
        raise argparse.ArgumentTypeError(f"not a directory: {value}")
    return path


def investigation_names(value):
    known = {investigation.name for investigation in INVESTIGATIONS}
    names = [name.strip() for name in value.split(",") if name.strip()]
    if not names:
        return None
    unknown = [name for name in names if name not in known]
    if unknown:
        raise argparse.ArgumentTypeError(
            f"invalid investigation(s): {', '.join(unknown)} "
            f"(choose from {', '.join(sorted(known))})"
        )
    return names


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--log-file", type=Path)
    parser.add_argument(
        "--log-format", choices=("text", "json"), default="text")
    parser.add_argument("--project-dir", type=existing_dir, default=Path("."))
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    parser.add_argument(
        "--investigations",
        type=investigation_names,
        metavar="NAME[,NAME...]",
        help=(
            "comma-separated; runs all investigations when omitted or empty; "
            f"available: {', '.join(investigation.name for investigation in INVESTIGATIONS)}"
        ),
    )
    parser.add_argument(
        "--github-summary",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="append the Markdown report to the GitHub Actions job summary",
    )
    parser.add_argument(
        "--github-issue",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="keep the report in a single GitHub issue labeled spica-advisor",
    )
    return parser.parse_args()


def selected_investigations(names):
    if not names:
        return INVESTIGATIONS
    return [investigation for investigation in INVESTIGATIONS if investigation.name in names]


def run_investigation(investigation, context, output_dir):
    investigation.execute(context)
    write_report(output_dir, investigation.name, context.report)
    if LOGGER.isEnabledFor(logging.DEBUG):
        LOGGER.debug("Full %s report:\n%s",
                     investigation.name, pformat(context.report))
    return context.report


def log_totals(investigation_name, usage):
    LOGGER.info(
        "[%s] %d LLM calls (%d failed), %d requests, %d input tokens (%d cached), "
        "%d output tokens (%d reasoning), %.1fs waiting on LLM",
        investigation_name,
        usage["calls"],
        usage["failed_calls"],
        usage["requests"],
        usage["input_tokens"],
        usage["cached_input_tokens"],
        usage["output_tokens"],
        usage["reasoning_tokens"],
        usage["wall_seconds"],
    )


def run_investigations(investigations, runner, project_dir, output_dir):
    reports = {}
    for investigation in investigations:
        context = investigation.create_context(project_dir, runner)
        first_call = len(runner.calls)
        try:
            reports[investigation.name] = run_investigation(investigation, context, output_dir)
        except InvestigationError as error:
            LOGGER.error("Investigation %s failed: %s", investigation.name, error)
            reports[investigation.name] = Failure(str(error))
        except Exception:
            LOGGER.exception("Investigation %s failed", investigation.name)
            reports[investigation.name] = Failure()
        log_totals(investigation.name, totals(runner.calls[first_call:]))
    return reports


def publish(report, metadata, summary_path, issues):
    try:
        if summary_path:
            append_step_summary(summary_path, report.text)
        if issues:
            issues.sync(report, metadata.run_url)
    except Exception:
        LOGGER.exception("Failed to publish the report to GitHub")
        return False
    return True


def run():
    args = parse_args()
    configure_logging(args.debug, args.log_file, args.log_format)
    try:
        runner = ClaudeRunner.from_env()
        summary_path = step_summary_path() if args.github_summary else None
        issues = GitHubIssues.from_env() if args.github_issue else None
    except Exception:
        LOGGER.exception("Failed to initialize")
        raise SystemExit(1)

    investigations = selected_investigations(args.investigations)
    reports = run_investigations(investigations, runner, args.project_dir, args.output_dir)
    metadata = report_metadata(runner.model, args.project_dir, runner.effort)
    report = render_report([(investigation.section, reports.get(investigation.name)) for investigation in investigations],
                           metadata)
    write_markdown(args.output_dir, report.text)
    published = publish(report, metadata, summary_path, issues)

    failed = [name for name, result in reports.items() if isinstance(result, Failure)]
    if failed:
        LOGGER.error("Failed investigations: %s", ", ".join(failed))
    if failed or not published:
        raise SystemExit(1)
