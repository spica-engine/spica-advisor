from spica_advisor.investigations import broken_access_control
from spica_advisor.investigations.broken_access_control.context import BrokenAccessControlContext
from spica_advisor.investigations.broken_access_control.models import CodeLocation, Report
from spica_advisor.investigations.broken_access_control.steps import map_findings_to_policies, restore_function_ids


def write_schema(project_dir, folder, content):
    path = project_dir / folder / "schema.yaml"
    path.parent.mkdir(parents=True)
    path.write_text(content, encoding="utf-8")


def test_reports_buckets_without_effective_row_level_security_whatever_their_sensitivity(tmp_path):
    context = BrokenAccessControlContext(project_dir=tmp_path, runner=None)
    context.policies = [{"_id": "p1", "statement": [
        {"module": "bucket:data", "action": "bucket:data:update", "resource": {"include": ["b1", "b2", "b3"]}},
    ]}]
    context.buckets = {bucket_id: {"_id": bucket_id} for bucket_id in ("b1", "b2", "b3")}
    context.bucket_acl_reports = {
        bucket_id: {"includes_sensitive_information": False,
                    "write": {"row_level_security_status": status, "reason": "r"}}
        for bucket_id, status in (("b1", "not_applied"), ("b2", "applied_but_in_risk"), ("b3", "applied"))
    }

    map_findings_to_policies(context)

    [policy] = context.report
    [statement] = policy["affected_statements"]
    assert [bucket["_id"] for bucket in statement["affected_buckets"]] == ["b1", "b2"]


def attachment(function_id, match, definition_match="const POLICY = 'p1';", policy_id=None, policy_name=None):
    return Report(
        attachment=CodeLocation(function_id=function_id, match=match),
        definition=CodeLocation(function_id="f3", match=definition_match),
        policy_id=policy_id,
        policy_name=policy_name,
    )


def test_findings_name_policies_and_buckets_with_their_paths(tmp_path):
    write_schema(tmp_path, "function/Signup", "_id: f1\nname: Signup\n")
    write_schema(tmp_path, "function/Constants", "_id: f3\nname: Constants\n")
    write_schema(tmp_path, "policy/Customer", "_id: p1\nname: Customer Policy\n")
    write_schema(tmp_path, "bucket/Payment-Methods", "_id: b1\ntitle: Payment Methods\n")
    context = BrokenAccessControlContext(project_dir=tmp_path, runner=None)
    context.attachment_reports = [
        attachment("f1", "Auth.policy.attach(id, POLICY)", policy_id="p1"),
        attachment("f1", "Auth.policy.attach(id, POLICY)", policy_name="Customer Policy"),
        attachment("f1", "Auth.policy.attach(id, POLICY)", "const POLICY = process.env.P;", policy_id="p1"),
        attachment("f2", "Auth.policy.attach(id, OTHER)", policy_id="p2"),
    ]
    context.policies = [{"_id": "p1", "name": "Customer Policy", "statement": [
        {"module": "bucket:data", "action": "bucket:data:index", "resource": {"include": ["b1"]}},
    ]}]
    context.buckets = {"b1": {"_id": "b1"}}
    context.bucket_acl_reports = {"b1": {
        "includes_sensitive_information": True,
        "read": {"row_level_security_status": "not_applied", "reason": "no filter"},
        "write": {"row_level_security_status": "applied", "reason": "owner only"},
    }}

    map_findings_to_policies(context)

    assert context.report == [{
        "policy_id": "p1",
        "policy_name": "Customer Policy",
        "path": "policy/Customer/schema.yaml",
        "attachments": [
            {
                "attachment": {"function_id": "f1", "function_name": "Signup", "path": "function/Signup/schema.yaml", "line": None,
                               "match": "Auth.policy.attach(id, POLICY)"},
                "definition": {"function_id": "f3", "function_name": "Constants", "path": "function/Constants/schema.yaml", "line": None,
                               "match": "const POLICY = 'p1';"},
            },
            {
                "attachment": {"function_id": "f1", "function_name": "Signup", "path": "function/Signup/schema.yaml", "line": None,
                               "match": "Auth.policy.attach(id, POLICY)"},
                "definition": {"function_id": "f3", "function_name": "Constants", "path": "function/Constants/schema.yaml", "line": None,
                               "match": "const POLICY = process.env.P;"},
            },
        ],
        "affected_statements": [{"statement_index": 0, "affected_buckets": [{
            "_id": "b1",
            "name": "Payment Methods",
            "path": "bucket/Payment-Methods/schema.yaml",
            "line": None,
            "end_line": None,
            "report": {
                "access": "read",
                "row_level_security_status": "not_applied",
                "reason": "no filter",
                "includes_sensitive_information": True,
            },
        }]}],
    }]


class FailingRunner:
    def run(self, *args, **kwargs):
        raise AssertionError("agent should not run")


def test_function_file_names_are_mapped_back_to_function_ids():
    functions = [{"_id": "fn/1", "name": "Orders"}, {"_id": "f3", "name": "Config"}]
    reports = [attachment("fn_1.js", "m"), attachment("f3", "m")]

    restore_function_ids(reports, functions)

    assert [(report.attachment.function_id, report.definition.function_id) for report in reports] == [
        ("fn/1", "f3"), ("f3", "f3")]


def test_skips_agents_when_project_has_no_functions(tmp_path):
    write_schema(tmp_path, "policy/Customer", "_id: p1\nname: Customer\n")
    write_schema(tmp_path, "bucket/Orders", "_id: b1\ntitle: Orders\n")

    assert broken_access_control.build().run(tmp_path, FailingRunner()) == []


def test_attachment_line_is_the_first_line_containing_the_quoted_code(tmp_path):
    from spica_advisor.investigations.broken_access_control.steps import match_line

    (tmp_path / "function" / "Signup").mkdir(parents=True)
    (tmp_path / "function" / "Signup" / "index.mjs").write_text(
        "export default async () => {\n  await Auth.policy.attach(\n    user._id,\n    POLICY\n  );\n};\n", encoding="utf-8")
    path = "function/Signup/index.mjs"

    assert match_line(tmp_path, path, "  await Auth.policy.attach(\n    user._id,") == 2
    assert match_line(tmp_path, path, "somethingElse()") is None
    assert match_line(tmp_path, None, "Auth.policy.attach(") is None
    assert match_line(tmp_path, path, "  \n") is None
