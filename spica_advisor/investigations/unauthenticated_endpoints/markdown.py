from spica_advisor.markdown import Row, Section, code, escape


def bullet_list(texts):
    unique = list(dict.fromkeys(escape(text) for text in texts))
    return unique[0] if len(unique) == 1 else "<br>".join(f"- {text}" for text in unique)


def findings(report):
    grouped = {}
    for function in report:
        for method in function["methods"]:
            key = (function["function_name"], function["path"], method["severity"], method["auth"])
            grouped.setdefault(key, []).append(method)
    return grouped


def rows(report, links):
    return [
        Row(severity, (
            links.resource(function_name, path),
            ", ".join(code(method["name"]) for method in methods),
            bullet_list(method["auth_reason"] for method in methods),
            bullet_list(method["impact_reason"] for method in methods),
        ))
        for (function_name, path, severity, auth), methods in findings(report).items()
    ]


SECTION = Section(
    title="Endpoints without full access control",
    description="Public HTTP functions with methods that have no authentication check, or that only check who the caller is. "
                "Severity combines the missing check with what the method can do.",
    columns=("Function", "Method", "Authentication", "Impact"),
    rows=rows,
)
