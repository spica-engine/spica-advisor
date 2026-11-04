from spica_advisor.markdown import Row, Section, escape


SEVERITIES = {
    ("not_applied", True): "high",
    ("not_applied", False): "medium",
    ("applied_but_in_risk", True): "medium",
    ("applied_but_in_risk", False): "low",
}
SEVERITY_ORDER = ("high", "medium", "low")
READ_OF_NON_SENSITIVE_DATA = ("read", "not_applied", False)


def severity(access_report):
    status = access_report["row_level_security_status"]
    sensitive = access_report["includes_sensitive_information"]
    if (access_report["access"], status, sensitive) == READ_OF_NON_SENSITIVE_DATA:
        return "low"
    return SEVERITIES[status, sensitive]


def attached_functions(policy, links):
    functions = {
        (attached["path"], attached.get("line")): attached["function_name"]
        for attached in (attachment["attachment"] for attachment in policy["attachments"])
    }
    return ", ".join(links.resource(name, path, line) for (path, line), name in functions.items()) or "–"


def findings(report):
    grouped = {}
    for policy in report:
        for statement in policy["affected_statements"]:
            for bucket in statement["affected_buckets"]:
                key = (policy["policy_name"], policy["path"], bucket["name"], bucket["path"], bucket.get("line"), bucket.get("end_line"))
                grouped.setdefault(key, []).append((statement["statement_index"], bucket["report"]))
    return grouped


def reasons(granted):
    by_access = {}
    for _, access_report in granted:
        by_access.setdefault(access_report["access"], []).append(access_report["reason"])
    shortest = {access: min(texts, key=len) for access, texts in by_access.items()}
    if len(shortest) == 1:
        return escape(next(iter(shortest.values())))
    return "<br>".join(f"- {access.capitalize()}: {escape(reason)}" for access, reason in sorted(shortest.items()))


def rows(report, links):
    functions = {policy["path"]: attached_functions(policy, links) for policy in report}
    return [
        Row(min((severity(r) for _, r in granted), key=SEVERITY_ORDER.index), (
            links.resource(policy_name, policy_path),
            functions[policy_path],
            links.resource(bucket_name, bucket_path, bucket_line, bucket_end_line),
            reasons(granted),
        ))
        for (policy_name, policy_path, bucket_name, bucket_path, bucket_line, bucket_end_line), granted in findings(report).items()
    ]


SECTION = Section(
    title="Broken access control",
    description=(
        "Policies attached to users that can reach buckets without effective row-level security. "
        "Buckets holding sensitive data rank higher."
    ),
    columns=("Policy", "Attached by", "Bucket", "Why"),
    rows=rows,
)
