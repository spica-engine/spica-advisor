from spica_advisor.markdown import Row, Section, code, escape


def rows(report, links):
    return [
        Row(method["risk_level"], (
            links.resource(function["function_name"], function["path"]),
            code(method["name"]),
            escape(method["reason"]),
        ))
        for function in report
        for method in function["methods"]
    ]


SECTION = Section(
    title="Unauthenticated endpoints",
    description="Public HTTP functions with methods that run without an authentication check, or that only check who the caller is.",
    columns=("Function", "Method", "Why"),
    rows=rows,
)
