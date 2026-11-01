import pytest

from evals.cases import EvalCase, find_cases
from evals.validation import check_case


FUNCTION_SCHEMA = """\
_id: fn-signup
name: Signup
triggers:
  register:
    type: http
    active: true
    options:
      authorize: false
  admin:
    type: http
    active: true
    options:
      authorize: true
"""

PRIVATE_FUNCTION_SCHEMA = """\
_id: fn-private
name: Private
triggers:
  handler:
    type: http
    active: true
    options:
      authorize: true
"""

POLICY_SCHEMA = """\
_id: policy-user
name: User Policy
statement:
  - module: bucket:data
    action: bucket:data:stream
    resource:
      include: [bucket-users]
      exclude: []
"""

LABELS = {
    "sensitive-env-vars.yaml": "API_SECRET: high\n",
    "endpoint-assessment.yaml": "handlers:\n  fn-signup:\n    register: {auth: none, impact: high}\n",
    "policy-attachments.yaml": "- function_id: fn-signup\n  policy_id: policy-user\n",
    "bucket-acl.yaml": (
        "bucket-users:\n"
        "  includes_sensitive_information: true\n"
        "  read: applied\n"
        "  write: not_applied\n"
    ),
}


def new_case(tmp_path, name):
    return EvalCase(name, tmp_path / "resources" / name, tmp_path / "expected" / name)


def write_file(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write(case, relative, content):
    write_file(case.project_dir / relative, content)


def write_label(case, name, content):
    write_file(case.expected_dir / name, content)


@pytest.fixture
def case(tmp_path):
    case = new_case(tmp_path, "demo")
    write(case, "function/Signup/schema.yaml", FUNCTION_SCHEMA)
    write(case, "function/Signup/index.mjs", "export function register(req, res) {}\n")
    write(case, "function/Private/schema.yaml", PRIVATE_FUNCTION_SCHEMA)
    write(case, "policy/User/schema.yaml", POLICY_SCHEMA)
    write(case, "bucket/Users/schema.yaml", "_id: bucket-users\ntitle: Users\n")
    write(case, "bucket/Settings/schema.yaml", "_id: bucket-settings\ntitle: Settings\n")
    write(case, "env-var/API_SECRET/schema.yaml", "_id: env-1\nkey: API_SECRET\n")
    for name, content in LABELS.items():
        write_label(case, name, content)
    return case


def test_consistent_case_has_no_problems(case):
    assert check_case(case) == []


def test_empty_label_files_are_allowed_when_nothing_needs_labels(tmp_path):
    case = new_case(tmp_path, "empty")
    case.project_dir.mkdir(parents=True)
    for name in LABELS:
        write_label(case, name, "")

    assert check_case(case) == []


def test_reports_missing_label_files(case):
    (case.expected_dir / "bucket-acl.yaml").unlink()

    assert check_case(case) == [f"missing label file: {case.expected_dir / 'bucket-acl.yaml'}"]


def test_reports_missing_resources_directory(tmp_path):
    case = new_case(tmp_path, "unexported")
    for name, content in LABELS.items():
        write_label(case, name, content)

    assert check_case(case) == [f"missing resources: {case.project_dir}"]


def test_reports_placeholder_markers_outside_node_modules(case):
    write(case, "function/Signup/index.mjs", "// REPLACE_ME\nexport function register(req, res) {}\n")
    write(case, "function/Signup/node_modules/lib/index.js", "// REPLACE_ME\n")

    write_label(case, "sensitive-env-vars.yaml", "# REPLACE_ME\nAPI_SECRET: high\n")

    assert check_case(case) == [
        f"placeholder: {case.project_dir / 'function/Signup/index.mjs'}",
        f"placeholder: {case.expected_dir / 'sensitive-env-vars.yaml'}",
    ]


def test_reports_invalid_label_values_with_their_file(case):
    write_label(case, "bucket-acl.yaml", (
        "bucket-users:\n"
        "  includes_sensitive_information: true\n"
        "  read: maybe\n"
        "  write: not_applied\n"
    ))

    [problem] = check_case(case)
    assert problem.startswith("bucket-acl.yaml: bucket-users.read:")


def test_reports_unparseable_yaml(case):
    write_label(case, "sensitive-env-vars.yaml", "API_SECRET: [high\n")

    [problem] = check_case(case)
    assert problem.startswith("could not read case:")


def test_every_env_var_needs_exactly_one_label(case):
    write(case, "env-var/LOG_LEVEL/schema.yaml", "_id: env-2\nkey: LOG_LEVEL\n")
    write_label(case, "sensitive-env-vars.yaml", "API_SECRET: high\nTYPO_KEY: low\n")

    assert check_case(case) == [
        "sensitive-env-vars.yaml: missing label for env var LOG_LEVEL",
        "sensitive-env-vars.yaml: unexpected env var TYPO_KEY",
    ]


def test_reports_duplicate_env_var_names(case):
    write(case, "env-var/API_SECRET_COPY/schema.yaml", "_id: env-2\nkey: API_SECRET\n")

    assert check_case(case) == ["env var name is not unique: API_SECRET"]


def test_labeled_triggers_must_exist_in_function_source(case):
    write(case, "function/Signup/index.mjs", "export function signup(req, res) {}\n")

    assert check_case(case) == ["endpoint-assessment.yaml: fn-signup.register not found in function source"]


def test_policy_attachments_must_reference_existing_function(case):
    write_label(case, "policy-attachments.yaml", "- function_id: fn-missing\n  policy_id: policy-not-exported\n")

    assert check_case(case) == ["policy-attachments.yaml: [0] unknown function fn-missing"]


def test_policy_attachment_can_reference_policy_by_env_var_name(case):
    write_label(case, "policy-attachments.yaml", "- function_id: fn-signup\n  policy_name: USER_POLICY_ID\n")

    assert check_case(case) == []


def test_policy_attachment_needs_policy_id_or_name(case):
    write_label(case, "policy-attachments.yaml", "- function_id: fn-signup\n")

    [problem] = check_case(case)
    assert problem.startswith("policy-attachments.yaml: 0:")
    assert "policy_id or policy_name is required" in problem


def test_any_existing_buckets_can_be_labeled(case):
    write_label(case, "bucket-acl.yaml", (
        "bucket-settings:\n"
        "  includes_sensitive_information: false\n"
        "  read: not_applied\n"
        "  write: not_applied\n"
        "bucket-unknown:\n"
        "  includes_sensitive_information: false\n"
        "  read: not_applied\n"
        "  write: not_applied\n"
    ))

    assert check_case(case) == ["bucket-acl.yaml: unexpected bucket bucket-unknown"]


def test_find_cases_pairs_label_directories_with_resources_in_order(tmp_path):
    expected_root = tmp_path / "expected"
    for name in ("synthetic-01", "real-01"):
        (expected_root / name).mkdir(parents=True)
    (expected_root / "README.md").write_text("docs")

    cases = find_cases(expected_root, tmp_path / "resources")

    assert cases == [new_case(tmp_path, "real-01"), new_case(tmp_path, "synthetic-01")]
    assert find_cases(expected_root, tmp_path / "resources", ["synthetic-01"]) == [new_case(tmp_path, "synthetic-01")]


def test_find_cases_rejects_unknown_names(tmp_path):
    (tmp_path / "expected" / "real-01").mkdir(parents=True)

    with pytest.raises(ValueError, match="unknown case"):
        find_cases(tmp_path / "expected", tmp_path / "resources", ["real-99"])
