import re
from collections.abc import Iterable

from spica_advisor.function_files import restore_function_ids as restore_ids
from spica_advisor.investigations.broken_access_control.agents import BUCKET_ACL_AGENT, POLICY_ATTACHMENT_AGENT
from spica_advisor.investigations.broken_access_control.context import BrokenAccessControlContext
from spica_advisor.investigations.broken_access_control.prompts import ATTACHMENT_INPUT, bucket_acl_input
from spica_advisor.log import LOGGER
from spica_advisor.resources import load_buckets, load_functions, load_policies, resource_locations


READ_ACTIONS = {"bucket:data:stream", "bucket:data:index", "bucket:data:show"}
WRITE_ACTIONS = {"bucket:data:create", "bucket:data:update", "bucket:data:delete"}


def clean(value):
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def acl_rule_for_action(action):
    if action in READ_ACTIONS:
        return "read"
    if action in WRITE_ACTIONS:
        return "write"
    return None


def affected_bucket_ids(statement, buckets):
    resource = statement.get("resource", {})
    include = resource.get("include", [])
    exclude = set(resource.get("exclude", []))
    if "*" in include:
        return [bucket_id for bucket_id in buckets if bucket_id not in exclude]
    return [bucket_id for bucket_id in include if bucket_id in buckets and bucket_id not in exclude]


def bucket_data_statements(policy) -> Iterable[tuple[int, dict, str]]:
    for statement_index, statement in enumerate(policy.get("statement", [])):
        acl_rule = acl_rule_for_action(statement.get("action"))
        if statement.get("module") == "bucket:data" and acl_rule:
            yield statement_index, statement, acl_rule


def matches_report(policy, report):
    return bool(
        (report.policy_id and policy.get("_id") == report.policy_id)
        or (report.policy_name and clean(policy.get("name")) == clean(report.policy_name))
    )


def code_location(location, function_locations):
    function = function_locations.get(location.function_id, {})
    return {
        "function_id": location.function_id,
        "function_name": function.get("name"),
        "path": function.get("path"),
        "match": location.match,
    }


def policy_attachments(policy, attachment_reports, function_locations):
    unique_reports = {
        (report.attachment.function_id, report.attachment.match,
         report.definition.function_id, report.definition.match): report
        for report in attachment_reports
        if matches_report(policy, report)
    }
    return [
        {
            "attachment": code_location(report.attachment, function_locations),
            "definition": code_location(report.definition, function_locations),
        }
        for report in unique_reports.values()
    ]


def restore_function_ids(reports, functions):
    restore_ids([location for report in reports for location in (report.attachment, report.definition)], functions)


def read_functions(context: BrokenAccessControlContext):
    context.functions = load_functions(context.project_dir)
    LOGGER.debug("Discovered %d functions", len(context.functions))


def find_policy_attachments(context: BrokenAccessControlContext):
    if not context.functions:
        return
    response = context.runner.run(
        POLICY_ATTACHMENT_AGENT,
        ATTACHMENT_INPUT,
        functions=context.functions,
    )
    restore_function_ids(response.reports, context.functions)
    context.attachment_reports = response.reports
    attaching_function_ids = {report.attachment.function_id for report in context.attachment_reports}
    LOGGER.info("Found %d functions that attach policies to users", len(attaching_function_ids))


def load_relevant_policies(context: BrokenAccessControlContext):
    policies = load_policies(context.project_dir)
    context.policies = [
        policy for policy in policies
        if any(matches_report(policy, report) for report in context.attachment_reports)
        and any(statement.get("module") == "bucket:data" for statement in policy.get("statement", []))
    ]
    LOGGER.debug("Loaded %d policies; %d are relevant", len(policies), len(context.policies))
    LOGGER.info("Found %d policies that have access to buckets", len(context.policies))


def find_bucket_accesses(context: BrokenAccessControlContext):
    context.buckets = load_buckets(context.project_dir)
    context.bucket_ids = list(dict.fromkeys(
        bucket_id
        for policy in context.policies
        for _, statement, _ in bucket_data_statements(policy)
        for bucket_id in affected_bucket_ids(statement, context.buckets)
    ))
    LOGGER.info("Found %d buckets accessed by relevant policies", len(context.bucket_ids))


def evaluate_bucket_rules(context: BrokenAccessControlContext):
    context.bucket_acl_reports = {
        bucket_id: context.runner.run(BUCKET_ACL_AGENT, bucket_acl_input(context.buckets[bucket_id])).model_dump()
        for bucket_id in context.bucket_ids
    }


def map_findings_to_policies(context: BrokenAccessControlContext):
    policy_locations = resource_locations(context.project_dir, "policy")
    bucket_locations = resource_locations(context.project_dir, "bucket")
    function_locations = resource_locations(context.project_dir, "function")
    report = []
    risky_bucket_ids = set()
    for policy in context.policies:
        affected_statements = []
        for statement_index, statement, acl_rule in bucket_data_statements(policy):
            affected_buckets = []
            for bucket_id in affected_bucket_ids(statement, context.buckets):
                bucket_report = context.bucket_acl_reports[bucket_id]
                access_report = {
                    "access": acl_rule,
                    "row_level_security_status": bucket_report[acl_rule]["row_level_security_status"],
                    "reason": bucket_report[acl_rule]["reason"],
                    "includes_sensitive_information": bucket_report["includes_sensitive_information"],
                }
                if access_report["row_level_security_status"] != "applied":
                    bucket_location = bucket_locations.get(bucket_id, {})
                    affected_buckets.append({
                        "_id": bucket_id,
                        "name": bucket_location.get("name"),
                        "path": bucket_location.get("path"),
                        "report": access_report,
                    })
                    risky_bucket_ids.add(bucket_id)

            if affected_buckets:
                affected_statements.append({
                    "statement_index": statement_index,
                    "affected_buckets": affected_buckets,
                })

        if affected_statements:
            policy_location = policy_locations.get(policy.get("_id"), {})
            report.append({
                "policy_id": policy.get("_id"),
                "policy_name": policy_location.get("name"),
                "path": policy_location.get("path"),
                "attachments": policy_attachments(policy, context.attachment_reports, function_locations),
                "affected_statements": affected_statements,
            })

    LOGGER.info("Found %d buckets with ACL issues", len(risky_bucket_ids))
    context.report = report
