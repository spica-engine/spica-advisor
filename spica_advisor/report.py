import json
from spica_advisor.log import LOGGER


MARKDOWN_REPORT = "report.md"
RUN_DETAILS = "run.json"


def write_text(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    LOGGER.info("Wrote %s", path)


def write_json(path, data):
    write_text(path, json.dumps(data, indent=2) + "\n")


def write_report(output_dir, investigation_name, report):
    write_json(output_dir / f"{investigation_name}.json", report)


def write_markdown(output_dir, markdown):
    write_text(output_dir / MARKDOWN_REPORT, markdown)


def write_run_details(output_dir, model, effort):
    write_json(output_dir / RUN_DETAILS, {"model": model, "effort": effort})


def read_run_details(output_dir):
    return json.loads((output_dir / RUN_DETAILS).read_text(encoding="utf-8"))


def read_report(output_dir, investigation_name):
    return json.loads((output_dir / f"{investigation_name}.json").read_text(encoding="utf-8"))
