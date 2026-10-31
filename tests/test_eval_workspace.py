import pytest

from evals.workspace import cases_page_data, export_cases, import_cases, render_cases_page
from spica_advisor.runner import KNOWN_MODELS


PUBLIC_FUNCTION = """\
_id: fn-1
name: Signup
triggers:
  register:
    type: http
    active: true
    options:
      authorize: false
"""

LABELS = {
    "sensitive-env-vars.yaml": "API_KEY: high\n",
    "unauthenticated-endpoints.yaml": "fn-1:\n  register: high\n",
    "policy-attachments.yaml": "[]\n",
    "bucket-acl.yaml": "{}\n",
}


def write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


@pytest.fixture
def roots(tmp_path):
    expected, resources, trash = tmp_path / "expected", tmp_path / "resources", tmp_path / "trash"
    export_dir = tmp_path / "pentest" / "real-project"
    write(export_dir / "function/Signup/schema.yaml", PUBLIC_FUNCTION)
    write(export_dir / "function/Signup/index.mjs", "const SECRET_CODE = 1;\n")
    write(export_dir / "env-var/API_KEY/schema.yaml", "_id: env-1\nkey: API_KEY\nvalue: real-secret-value\n")
    write(export_dir / "bucket/Users/schema.yaml", "_id: bucket-1\ntitle: Users\n")
    resources.mkdir()
    (resources / "real-project").symlink_to(export_dir)
    write(resources / "synthetic-01/function/Signup/schema.yaml", PUBLIC_FUNCTION)
    write(resources / "synthetic-01/function/Signup/index.mjs", "export function register(req, res) {}\n")
    for case in ("real-project", "synthetic-01"):
        for name, content in LABELS.items():
            write(expected / case / name, content)
    return expected, resources, trash


def test_export_sends_real_cases_as_an_index_without_code_or_values(roots):
    expected, resources, _ = roots

    exported = {case["name"]: case for case in export_cases(expected, resources)["cases"]}

    real = exported["real-project"]
    assert real["kind"] == "real" and "files" not in real
    assert real["index"]["functions"] == [{"_id": "fn-1", "name": "Signup", "public_triggers": ["register"]}]
    assert real["index"]["env_vars"] == ["API_KEY"]
    assert real["labels"]["sensitive-env-vars.yaml"] == "API_KEY: high\n"
    serialized = str(real)
    assert "real-secret-value" not in serialized and "SECRET_CODE" not in serialized


def test_export_sends_synthetic_cases_with_their_files(roots):
    expected, resources, _ = roots

    synthetic = {case["name"]: case for case in export_cases(expected, resources)["cases"]}["synthetic-01"]

    assert synthetic["kind"] == "synthetic"
    assert [file["path"] for file in synthetic["files"]] == [
        "function/Signup/index.mjs", "function/Signup/schema.yaml",
    ]


def test_import_round_trip_applies_edits_and_new_cases(roots):
    expected, resources, trash = roots
    payload = export_cases(expected, resources)
    synthetic = next(case for case in payload["cases"] if case["name"] == "synthetic-01")
    synthetic["labels"]["sensitive-env-vars.yaml"] = "{}\n"
    synthetic["files"] = [{"path": "bucket/Orders/schema.yaml", "content": "_id: b-9\ntitle: Orders\n"}]
    payload["cases"].append({"name": "synthetic-02", "kind": "synthetic", "labels": LABELS, "files": []})

    result = import_cases(payload, expected, resources, trash)

    assert result == {"added": ["synthetic-02"], "updated": ["real-project", "synthetic-01"], "removed": []}
    assert (expected / "synthetic-01/sensitive-env-vars.yaml").read_text() == "{}\n"
    assert sorted(p.relative_to(resources / "synthetic-01").as_posix() for p in (resources / "synthetic-01").rglob("*.yaml")) == [
        "bucket/Orders/schema.yaml",
    ]
    assert (resources / "real-project").is_symlink()
    assert (resources / "real-project/function/Signup/index.mjs").exists()


def test_import_moves_removed_cases_to_trash(roots):
    expected, resources, trash = roots
    payload = export_cases(expected, resources)
    payload["cases"] = [case for case in payload["cases"] if case["name"] != "synthetic-01"]

    result = import_cases(payload, expected, resources, trash)

    assert result["removed"] == ["synthetic-01"]
    assert not (expected / "synthetic-01").exists() and not (resources / "synthetic-01").exists()
    [trashed] = trash.iterdir()
    assert (trashed / "expected/sensitive-env-vars.yaml").exists()
    assert (trashed / "resources/function/Signup/index.mjs").exists()


def test_import_refuses_an_empty_case_list(roots):
    expected, resources, trash = roots

    with pytest.raises(ValueError, match="empty case list"):
        import_cases({"cases": []}, expected, resources, trash)


@pytest.mark.parametrize("path", ["../outside.yaml", "/etc/passwd.yaml", "function/x/run.sh", "secrets/x/schema.yaml", "index.mjs"])
def test_import_rejects_unsafe_resource_paths_before_writing_anything(roots, path):
    expected, resources, trash = roots
    payload = export_cases(expected, resources)
    payload["cases"][1]["files"] = [{"path": path, "content": "x"}]
    payload["cases"][1]["labels"]["sensitive-env-vars.yaml"] = "CHANGED: low\n"

    with pytest.raises(ValueError, match="unsafe resource path"):
        import_cases(payload, expected, resources, trash)

    assert (expected / "synthetic-01/sensitive-env-vars.yaml").read_text() == "API_KEY: high\n"


def test_import_refuses_to_replace_a_real_export_with_synthetic_files(roots):
    expected, resources, trash = roots
    payload = export_cases(expected, resources)
    payload["cases"][0]["kind"] = "synthetic"

    with pytest.raises(ValueError, match="linked real export"):
        import_cases(payload, expected, resources, trash)


@pytest.mark.parametrize("name", ["Bad Name", "../escape", "", "a" * 64])
def test_import_rejects_invalid_case_names(roots, name):
    expected, resources, trash = roots

    with pytest.raises(ValueError, match="invalid case name"):
        import_cases({"cases": [{"name": name, "kind": "synthetic", "labels": {}}]}, expected, resources, trash)


def test_cases_page_embeds_models_defaults_and_costs(tmp_path):
    template = tmp_path / "template.html"
    template.write_text("<script>__CASES_PAGE_DATA__</script>")
    matrix = tmp_path / "matrix.yaml"
    matrix.write_text("models: [claude-sonnet-5-5]\ncases: all\nrepeats: 2\ntasks: all\n")
    results = {"run": "r1", "rows": [
        {"model": "claude-sonnet-5-5", "task": "bucket_acl", "case": "c1", "cost_per_run": 0.5},
        {"model": "claude-sonnet-5-5", "task": "bucket_acl", "case": "all", "cost_per_run": 0.5},
    ]}

    data = cases_page_data(results, matrix)

    assert data["default_models"] == ["claude-sonnet-5-5"] and data["default_repeats"] == 2
    assert data["costs"] == {"claude-sonnet-5-5|bucket_acl|c1": 0.5}
    assert data["models"] == list(KNOWN_MODELS)
    assert render_cases_page(results, template).startswith("<script>{")


def test_cases_page_lists_prompt_variants_and_keeps_baseline_costs(tmp_path):
    matrix = tmp_path / "matrix.yaml"
    matrix.write_text("models: [claude-sonnet-5-5]\ncases: all\nrepeats: 1\ntasks: all\n")
    prompts = tmp_path / "prompts" / "unauthenticated_endpoints"
    prompts.mkdir(parents=True)
    (prompts / "strict.yaml").write_text("description: Stricter.\ninput: source-only\ninstructions: x\n")
    results = {"run": "r1", "rows": [
        {"model": "claude-sonnet-5-5", "prompt": "baseline", "task": "unauthenticated_endpoints", "case": "c1", "cost_per_run": 0.5},
        {"model": "claude-sonnet-5-5", "prompt": "strict", "task": "unauthenticated_endpoints", "case": "c1", "cost_per_run": 0.9},
    ]}

    data = cases_page_data(results, matrix, tmp_path / "prompts")

    assert data["prompts"]["unauthenticated_endpoints"] == [
        {"name": "baseline", "description": "The prompt the advisor ships with.", "input": "default"},
        {"name": "strict", "description": "Stricter.", "input": "source-only"},
    ]
    assert data["prompts"]["bucket_acl"] == [
        {"name": "baseline", "description": "The prompt the advisor ships with.", "input": "default"},
    ]
    assert data["costs"] == {"claude-sonnet-5-5|unauthenticated_endpoints|c1": 0.5}
