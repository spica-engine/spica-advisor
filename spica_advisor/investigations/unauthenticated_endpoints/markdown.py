from spica_advisor.markdown import Row, Section, code, escape


AUTH_LABELS = {"none": "None", "authentication": "Authentication only", "authorization": "Authorization"}


def rows(report, links):
    return [
        Row(method["severity"], (
            links.resource(function["function_name"], function["path"]),
            code(method["name"]),
            f"{AUTH_LABELS[method['auth']]}: {escape(method['auth_reason'])}",
            f"{method['impact'].capitalize()}: {escape(method['impact_reason'])}",
        ))
        for function in report
        for method in function["methods"]
    ]


SECTION = Section(
    title="Endpoints without full access control",
    description="Public HTTP functions with methods that have no authentication check, or that only check who the caller is. "
                "Severity combines the missing check with what the method can do.",
    columns=("Function", "Method", "Authentication", "Impact"),
    rows=rows,
)
