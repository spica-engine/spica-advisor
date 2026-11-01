import pytest

from spica_advisor.investigations.broken_access_control.markdown import SECTION as ACCESS_SECTION
from spica_advisor.investigations.sensitive_env_vars.markdown import SECTION as ENV_SECTION
from spica_advisor.investigations.unauthenticated_endpoints.markdown import SECTION as ENDPOINT_SECTION
from spica_advisor.markdown import Failure, Links, ReportMetadata, escape, render_report


ENV_REPORT = [
    {"_id": "e1", "name": "LOG_LEVEL", "path": "env-var/LOG_LEVEL",
     "report": {"sensitiveness_level": "medium", "reason": "might reveal internals"}},
    {"_id": "e2", "name": "JWT_SECRET", "path": "env-var/JWT_SECRET",
     "report": {"sensitiveness_level": "high", "reason": "signs | tokens"}},
]
ENDPOINT_REPORT = [
    {"function_id": "f1", "function_name": "Login", "path": "function/Login", "methods": [
        {"name": "resetPassword", "severity": "high", "auth": "none", "auth_reason": "no check",
         "impact": "high", "impact_reason": "updates users | without auth"},
    ]},
]
ACCESS_REPORT = [
    {"policy_id": "p1", "policy_name": "Customer", "path": "policy/Customer", "attachments": [
        {"attachment": {"function_id": "f1", "function_name": "Signup", "path": "function/Signup",
                        "match": "await Auth.policy.attach(\n    user._id,\n    POLICY || fallback\n);"},
         "definition": {"function_id": "f1", "function_name": "Signup", "path": "function/Signup",
                        "match": "const POLICY = process.env.CUSTOMER_POLICY;"}},
        {"attachment": {"function_id": "f2", "function_name": "Import", "path": "function/Import", "match": "x" * 200},
         "definition": {"function_id": "f3", "function_name": "Constants", "path": "function/Constants",
                        "match": "export const POLICY = 'p1';"}},
    ], "affected_statements": [
        {"statement_index": 2, "affected_buckets": [
            {"_id": "b1", "name": "Payment Methods", "path": "bucket/Payment-Methods", "report": {
                "access": "read", "row_level_security_status": "applied_but_in_risk",
                "reason": "filter can be bypassed", "includes_sensitive_information": True}},
        ]},
    ]},
]
GITHUB_METADATA = ReportMetadata(
    model="claude-sonnet-5-5",
    commit="a1b2c3d4e5",
    commit_url="https://github.com/o/r/commit/a1b2c3d4e5",
    run_url="https://github.com/o/r/actions/runs/7",
    source_url="https://github.com/o/r/tree/a1b2c3d4e5/spica",
)


def test_report_counts_findings_and_sorts_rows_by_severity():
    report = render_report([(ENV_SECTION, ENV_REPORT)], ReportMetadata(model="m"))

    assert report.finding_count == 2
    assert report.complete
    assert "| Sensitive env vars | 1 | 1 | 0 |" in report.text
    assert report.text.index("JWT_SECRET") < report.text.index("LOG_LEVEL")


def test_report_links_resources_to_the_scanned_commit():
    report = render_report([(ENDPOINT_SECTION, ENDPOINT_REPORT)], GITHUB_METADATA)

    assert "Commit [`a1b2c3d`](https://github.com/o/r/commit/a1b2c3d4e5)" in report.text
    assert "[Workflow run](https://github.com/o/r/actions/runs/7)" in report.text
    assert ("| 🔴 High | [Login](https://github.com/o/r/tree/a1b2c3d4e5/spica/function/Login) "
            "| `resetPassword` | None: no check | High: updates users \\| without auth |") in report.text


def test_report_shows_paths_when_not_on_github():
    report = render_report([(ACCESS_SECTION, ACCESS_REPORT)], ReportMetadata(model="m"))

    assert ("| 🟠 Medium | Customer (`policy/Customer`) | `statement[2]` "
            "| Payment Methods (`bucket/Payment-Methods`) | Read | Yes | Applied, but at risk "
            "| filter can be bypassed |") in report.text


def test_access_section_lists_where_policies_are_attached_and_defined():
    report = render_report([(ACCESS_SECTION, ACCESS_REPORT)], ReportMetadata(model="m"))

    attachments = report.text.split("#### Where these policies are attached to users\n\n")[1]
    assert attachments.startswith("| Policy | Attached in | Attaching code | Defined in | Defining code |")
    assert ("| Customer (`policy/Customer`) | Signup (`function/Signup`) "
            "| `await Auth.policy.attach( user._id, POLICY \\|\\| fallback );` "
            "| Signup (`function/Signup`) | `const POLICY = process.env.CUSTOMER_POLICY;` |") in attachments
    assert f"| Import (`function/Import`) | `{'x' * 149}…` | Constants (`function/Constants`) |" in attachments


def test_attachments_table_is_omitted_without_attachments():
    access_report = [{**ACCESS_REPORT[0], "attachments": []}]

    report = render_report([(ACCESS_SECTION, access_report)], ReportMetadata(model="m"))

    assert "Where these policies are attached" not in report.text


@pytest.mark.parametrize(("status", "sensitive", "label"), [
    ("not_applied", True, "🔴 High"),
    ("not_applied", False, "🟠 Medium"),
    ("applied_but_in_risk", True, "🟠 Medium"),
    ("applied_but_in_risk", False, "🟡 Low"),
])
def test_access_severity_rises_with_bucket_sensitivity(status, sensitive, label):
    bucket = {"_id": "b1", "name": "B", "path": "bucket/B", "report": {
        "access": "write", "row_level_security_status": status, "reason": "r", "includes_sensitive_information": sensitive}}
    access_report = [{"policy_id": "p1", "policy_name": "P", "path": "policy/P", "attachments": [],
                      "affected_statements": [{"statement_index": 0, "affected_buckets": [bucket]}]}]

    report = render_report([(ACCESS_SECTION, access_report)], ReportMetadata(model="m"))

    assert f"| {label} | P (`policy/P`)" in report.text


def test_failed_investigation_is_not_reported_as_clean():
    report = render_report([(ENV_SECTION, []), (ENDPOINT_SECTION, None)], ReportMetadata(model="m"))

    assert not report.complete
    assert report.finding_count == 0
    assert "No findings.\n\n| Investigation" not in report.text
    assert "| Endpoints without full access control | ⚠️ Failed | – | – |" in report.text
    assert "This investigation failed" in report.text


def test_failed_investigation_shows_its_reason_inside_the_report():
    report = render_report([(ENDPOINT_SECTION, Failure("Function A | B is too large."))], ReportMetadata(model="m"))

    assert "This investigation failed" in report.text
    assert "Reason: Function A \\| B is too large." in report.text
    assert not report.complete


def test_failed_investigation_without_a_reason_shows_no_reason():
    report = render_report([(ENDPOINT_SECTION, Failure())], ReportMetadata(model="m"))

    assert "Reason:" not in report.text


def test_header_shows_effort_only_when_set():
    with_effort = render_report([(ENV_SECTION, [])], ReportMetadata(model="m", effort="high"))
    without_effort = render_report([(ENV_SECTION, [])], ReportMetadata(model="m"))

    assert "Model `m` · Effort `high`" in with_effort.text
    assert "Effort" not in without_effort.text


def test_clean_report_says_so():
    report = render_report([(ENV_SECTION, []), (ENDPOINT_SECTION, [])], ReportMetadata(model="m"))

    assert report.complete
    assert report.text.count("No findings.") == 3


def test_escape_keeps_llm_text_inside_its_table_cell():
    assert escape("`a | b`\n`x[0] < y`") == "`a \\| b` `x[0] < y`"


def test_link_labels_escape_brackets():
    assert Links("https://x").resource("a [b]", "bucket/a") == "[a \\[b\\]](https://x/bucket/a)"


def test_resource_without_path_is_plain_text():
    assert Links("https://github.com/o/r/tree/sha").resource("Name", None) == "Name"
