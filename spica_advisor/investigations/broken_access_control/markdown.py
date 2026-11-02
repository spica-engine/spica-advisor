from spica_advisor.markdown import Row, Section, code, escape, table


SEVERITIES = {
    ("not_applied", True): "high",
    ("not_applied", False): "medium",
    ("applied_but_in_risk", True): "medium",
    ("applied_but_in_risk", False): "low",
}
SEVERITY_ORDER = ("high", "medium", "low")
MAX_SNIPPET_CHARS = 150
ATTACHMENT_COLUMNS = ("Policy", "Attached in", "Attaching code", "Defined in", "Defining code")


def severity(access_report):
    return SEVERITIES[access_report["row_level_security_status"], access_report["includes_sensitive_information"]]


def snippet(text):
    line = " ".join(text.split())
    return line if len(line) <= MAX_SNIPPET_CHARS else line[:MAX_SNIPPET_CHARS - 1] + "…"


def code_cells(location, links):
    return links.resource(location["function_name"], location["path"]), escape(code(snippet(location["match"])))


def attachments_table(report, links):
    rows = [
        [
            links.resource(policy["policy_name"], policy["path"]),
            *code_cells(attachment["attachment"], links),
            *code_cells(attachment["definition"], links),
        ]
        for policy in report
        for attachment in policy["attachments"]
    ]
    if not rows:
        return ""
    return "### Where these policies are attached to users\n\n" + table(ATTACHMENT_COLUMNS, rows)


def findings(report):
    grouped = {}
    for policy in report:
        for statement in policy["affected_statements"]:
            for bucket in statement["affected_buckets"]:
                key = (policy["policy_name"], policy["path"], bucket["name"], bucket["path"])
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
    return [
        Row(min((severity(r) for _, r in granted), key=SEVERITY_ORDER.index), (
            links.resource(policy_name, policy_path),
            links.resource(bucket_name, bucket_path),
            reasons(granted),
        ))
        for (policy_name, policy_path, bucket_name, bucket_path), granted in findings(report).items()
    ]


SECTION = Section(
    title="Broken access control",
    description=(
        "Policies attached to users that can reach buckets without effective row-level security. "
        "Buckets holding sensitive data rank higher."
    ),
    columns=("Policy", "Bucket", "Why"),
    rows=rows,
    appendix=attachments_table,
)
