import json
import re
import shutil
from datetime import UTC, datetime
from pathlib import Path

import yaml

from evals.cases import EXPECTED_ROOT, LABEL_FILES, RESOURCES_ROOT
from evals.harness import MATRIX_PATH
from evals.prompts import PROMPTS_ROOT, all_variants
from evals.tasks import TASKS
from evals.validation import IGNORED_DIRS, SCANNED_SUFFIXES
from spica_advisor.investigations.unauthenticated_endpoints.handlers import public_handler_names
from spica_advisor.resources import load_buckets, load_env_vars, load_functions, load_policies
from spica_advisor.runner import KNOWN_MODELS


TRASH_ROOT = Path("evals/.deleted")
CASES_TEMPLATE_PATH = Path(__file__).with_name("cases_template.html")
CASES_DATA_PLACEHOLDER = "__CASES_PAGE_DATA__"
CASE_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
RESOURCE_DIRS = {"function", "bucket", "policy", "env-var"}
REAL = "real"
SYNTHETIC = "synthetic"
LABEL_HELP = {
    "sensitive-env-vars.yaml": "Every env var key in the case: KEY: low | medium | high",
    "unauthenticated-endpoints.yaml": "Every function with a public http trigger, by _id: the handlers with no auth check "
                                      "in the code, each low | medium | high. Use {} when every handler checks auth.",
    "policy-attachments.yaml": "A list of places code gives users a policy: function_id where it happens, plus policy_id "
                               "for a hardcoded id and/or policy_name for the env var name it reads.",
    "bucket-acl.yaml": "Any buckets to score, by _id: includes_sensitive_information (true/false), read and write "
                       "(applied | applied_but_in_risk | not_applied).",
}


def case_kind(project_dir):
    return REAL if project_dir.is_symlink() else SYNTHETIC


def label_texts(expected_dir):
    return {
        file: (expected_dir / file).read_text(encoding="utf-8") if (expected_dir / file).exists() else ""
        for file in LABEL_FILES.values()
    }


def resource_files(project_dir):
    return [
        {"path": path.relative_to(project_dir).as_posix(), "content": path.read_text(encoding="utf-8")}
        for path in sorted(project_dir.rglob("*"))
        if path.is_file() and path.suffix in SCANNED_SUFFIXES and not IGNORED_DIRS.intersection(path.parts)
    ]


def real_case_index(project_dir):
    return {
        "functions": [
            {"_id": function["_id"], "name": function["name"], "public_triggers": public_handler_names(function["schema"])}
            for function in load_functions(project_dir)
        ],
        "buckets": [{"_id": bucket_id, "title": bucket.get("title")} for bucket_id, bucket in load_buckets(project_dir).items()],
        "env_vars": sorted(env_var["name"] for env_var in load_env_vars(project_dir)),
        "policies": [{"_id": policy.get("_id"), "name": policy.get("name")} for policy in load_policies(project_dir)],
    }


def export_case(name, expected_root, resources_root):
    project_dir = resources_root / name
    kind = case_kind(project_dir)
    case = {"name": name, "kind": kind, "labels": label_texts(expected_root / name)}
    if kind == REAL:
        case["index"] = real_case_index(project_dir)
    else:
        case["files"] = resource_files(project_dir) if project_dir.is_dir() else []
    return case


def export_cases(expected_root=EXPECTED_ROOT, resources_root=RESOURCES_ROOT):
    return {
        "cases": [
            export_case(path.name, expected_root, resources_root)
            for path in sorted(expected_root.iterdir())
            if path.is_dir()
        ],
    }


def safe_resource_path(path):
    relative = Path(path)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or len(relative.parts) < 2
        or relative.parts[0] not in RESOURCE_DIRS
        or relative.suffix not in SCANNED_SUFFIXES
    ):
        raise ValueError(f"unsafe resource path: {path!r}")
    return relative


def validate_case(case, resources_root):
    name = case.get("name", "")
    if not CASE_NAME.match(name):
        raise ValueError(f"invalid case name: {name!r}")
    if case.get("kind") not in (REAL, SYNTHETIC):
        raise ValueError(f"{name}: kind must be {REAL!r} or {SYNTHETIC!r}")
    unknown_labels = set(case.get("labels", {})) - set(LABEL_FILES.values())
    if unknown_labels:
        raise ValueError(f"{name}: unknown label files {sorted(unknown_labels)}")
    project_dir = resources_root / name
    if case["kind"] == SYNTHETIC and project_dir.is_symlink():
        raise ValueError(f"{name}: is a linked real export, it cannot be replaced by synthetic resources")
    if case["kind"] == REAL and project_dir.exists() and not project_dir.is_symlink():
        raise ValueError(f"{name}: marked real but resources/{name} is not a linked export")
    for file in case.get("files", []):
        safe_resource_path(file["path"])


def write_labels(expected_dir, labels):
    expected_dir.mkdir(parents=True, exist_ok=True)
    for file in LABEL_FILES.values():
        (expected_dir / file).write_text(labels.get(file, ""), encoding="utf-8")


def write_synthetic_resources(project_dir, files):
    shutil.rmtree(project_dir, ignore_errors=True)
    for file in files:
        path = project_dir / safe_resource_path(file["path"])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(file["content"], encoding="utf-8")


def trash_case(name, expected_root, resources_root, trash_root):
    target = trash_root / f"{name}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    target.mkdir(parents=True)
    shutil.move(expected_root / name, target / "expected")
    project_dir = resources_root / name
    if project_dir.is_symlink() or project_dir.exists():
        shutil.move(project_dir, target / "resources")
    return target


def import_cases(payload, expected_root=EXPECTED_ROOT, resources_root=RESOURCES_ROOT, trash_root=TRASH_ROOT):
    cases = payload.get("cases", [])
    if not cases:
        raise ValueError("refusing to import an empty case list, it would delete every case")
    names = [case.get("name") for case in cases]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise ValueError(f"duplicate case names: {duplicates}")
    for case in cases:
        validate_case(case, resources_root)

    existing = {path.name for path in expected_root.iterdir() if path.is_dir()}
    for case in cases:
        write_labels(expected_root / case["name"], case.get("labels", {}))
        if case["kind"] == SYNTHETIC:
            write_synthetic_resources(resources_root / case["name"], case.get("files", []))
    removed = sorted(existing - set(names))
    for name in removed:
        trash_case(name, expected_root, resources_root, trash_root)
    return {"added": sorted(set(names) - existing), "updated": sorted(set(names) & existing), "removed": removed}


def page_prompts(prompts_root):
    return {
        task: [{"name": variant.name, "description": variant.description, "input": variant.input}
               for variant in variants.values()]
        for task, variants in all_variants(prompts_root).items()
    }


def cases_page_data(results, matrix_path=MATRIX_PATH, prompts_root=PROMPTS_ROOT):
    defaults = yaml.safe_load(matrix_path.read_text(encoding="utf-8"))
    return {
        "models": list(KNOWN_MODELS),
        "prompts": page_prompts(prompts_root),
        "default_models": defaults["models"],
        "default_repeats": defaults["repeats"],
        "tasks": list(TASKS),
        "label_files": LABEL_FILES,
        "label_help": LABEL_HELP,
        "last_run": results["run"],
        "costs": {
            f"{row['model']}|{row['task']}|{row['case']}": row["cost_per_run"]
            for row in results["rows"]
            if row["case"] != "all" and row.get("prompt", "baseline") == "baseline"
        },
    }


def render_cases_page(results, template_path=CASES_TEMPLATE_PATH):
    payload = json.dumps(cases_page_data(results)).replace("</", "<\\/")
    return template_path.read_text(encoding="utf-8").replace(CASES_DATA_PLACEHOLDER, payload)
