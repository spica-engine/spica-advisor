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
    assert ("| [Login](https://github.com/o/r/tree/a1b2c3d4e5/spica/function/Login) "
            "| `resetPassword`: updates users \\| without auth | no check |") in report.text


def test_report_shows_plain_names_when_not_on_github():
    report = render_report([(ACCESS_SECTION, ACCESS_REPORT)], ReportMetadata(model="m"))

    assert ("### 🟠 Medium\n\n#### Broken access control\n\n"
            "Policies attached to users that can reach buckets without effective row-level security. "
            "Buckets holding sensitive data rank higher.\n\n"
            "| Policy | Function | Bucket | Why |\n"
            "| --- | --- | --- | --- |\n"
            "| Customer | Signup, Import "
            "| Payment Methods "
            "| filter can be bypassed |") in report.text


def test_access_rows_name_the_functions_that_attach_the_policy():
    attachment = {"attachment": {"function_id": "f1", "function_name": "Signup", "path": "function/Signup", "match": "m"},
                  "definition": {"function_id": "f1", "function_name": "Signup", "path": "function/Signup", "match": "m"}}
    access_report = [{**ACCESS_REPORT[0], "attachments": [attachment, attachment]}]

    report = render_report([(ACCESS_SECTION, access_report)], GITHUB_METADATA)

    assert "| [Customer](https://github.com/o/r/tree/a1b2c3d4e5/spica/policy/Customer) | [Signup](https://github.com/o/r/tree/a1b2c3d4e5/spica/function/Signup) |" in report.text
    assert "Where these policies are attached" not in report.text


def test_access_rows_show_a_dash_without_attachments():
    access_report = [{**ACCESS_REPORT[0], "attachments": []}]

    report = render_report([(ACCESS_SECTION, access_report)], ReportMetadata(model="m"))

    assert "| Customer | – | Payment Methods |" in report.text


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

    assert f"### {label}\n\n#### Broken access control" in report.text


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
    assert report.text.count("No findings.") == 1


def test_escape_keeps_llm_text_inside_its_table_cell():
    assert escape("`a | b`\n`x[0] < y`") == "`a \\| b` `x[0] < y`"


def test_link_labels_escape_brackets():
    assert Links("https://x").resource("a [b]", "bucket/a") == "[a \\[b\\]](https://x/bucket/a)"


def test_resource_without_path_is_plain_text():
    assert Links("https://github.com/o/r/tree/sha").resource("Name", None) == "Name"


def test_access_findings_merge_statements_granting_the_same_access_to_a_bucket_keeping_the_shortest_reason():
    def bucket(status, sensitive, reason):
        return {"_id": "b1", "name": "Services", "path": "bucket/Services", "report": {
            "access": "write", "row_level_security_status": status, "reason": reason, "includes_sensitive_information": sensitive}}

    access_report = [{"policy_id": "p1", "policy_name": "User", "path": "policy/User", "attachments": [], "affected_statements": [
        {"statement_index": 4, "affected_buckets": [bucket("not_applied", True, "write is always true")]},
        {"statement_index": 2, "affected_buckets": [bucket("applied_but_in_risk", False, "admin bypasses the owner check")]},
    ]}]

    report = render_report([(ACCESS_SECTION, access_report)], ReportMetadata(model="m"))

    assert report.finding_count == 1
    assert "| User | – | Services | write is always true |" in report.text


def test_endpoint_methods_with_the_same_missing_check_share_a_row():
    def method(name, impact_reason):
        return {"name": name, "severity": "high", "auth": "none", "auth_reason": "no check on caller",
                "impact": "high", "impact_reason": impact_reason}

    endpoint_report = [{"function_id": "f1", "function_name": "Stripe", "path": "function/Stripe", "methods": [
        method("createCustomer", "creates customer"), method("deleteCustomer", "deletes customer"),
        method("listCards", "creates customer"),
    ]}]

    report = render_report([(ENDPOINT_SECTION, endpoint_report)], ReportMetadata(model="m"))

    assert report.finding_count == 1
    assert "- `createCustomer`: creates customer<br>- `deleteCustomer`: deletes customer<br>- `listCards`: creates customer | no check on caller |" in report.text


def test_findings_are_grouped_under_one_section_per_severity_without_a_severity_column():
    report = render_report([(ENV_SECTION, ENV_REPORT), (ENDPOINT_SECTION, ENDPOINT_REPORT)], ReportMetadata(model="m"))

    assert report.text.index("### 🔴 High") < report.text.index("### 🟠 Medium")
    assert "### 🟡 Low" not in report.text
    assert "| Severity |" not in report.text
    assert report.text.count(ENV_SECTION.description) == 1
    assert report.text.index("#### Sensitive env vars") < report.text.index("#### Endpoints without full access control")


def test_failed_investigations_are_listed_in_their_own_section():
    report = render_report([(ENV_SECTION, ENV_REPORT), (ENDPOINT_SECTION, None)], ReportMetadata(model="m"))

    assert "### ⚠️ Failed investigations\n\n#### Endpoints without full access control\n\n" in report.text
    assert not report.complete


def test_read_and_write_access_to_a_bucket_share_a_row_with_labelled_reasons():
    def bucket(access, status, reason):
        return {"_id": "b1", "name": "Licenses", "path": "bucket/Licenses", "report": {
            "access": access, "row_level_security_status": status, "reason": reason, "includes_sensitive_information": True}}

    access_report = [{"policy_id": "p1", "policy_name": "User", "path": "policy/User", "attachments": [], "affected_statements": [
        {"statement_index": 1, "affected_buckets": [bucket("read", "applied_but_in_risk", "admin bypasses the owner check")]},
        {"statement_index": 2, "affected_buckets": [bucket("write", "not_applied", "write is always true")]},
    ]}]

    report = render_report([(ACCESS_SECTION, access_report)], ReportMetadata(model="m"))

    assert report.finding_count == 1
    assert "| User | – | Licenses | - Read: admin bypasses the owner check<br>- Write: write is always true |" in report.text
    assert "### 🟠 Medium" not in report.text
