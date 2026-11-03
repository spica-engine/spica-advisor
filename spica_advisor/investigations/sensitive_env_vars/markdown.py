from spica_advisor.markdown import Row, Section, escape


def rows(report, links):
    return [
        Row(entry["report"]["sensitiveness_level"], (
            links.resource(entry["name"], entry["path"], entry.get("line")),
            escape(entry["report"]["reason"]),
        ))
        for entry in report
    ]


SECTION = Section(
    title="Sensitive env vars",
    description="Environment variables whose values look sensitive. Consider moving them to Spica secrets.",
    columns=("Env var", "Why"),
    rows=rows,
)
