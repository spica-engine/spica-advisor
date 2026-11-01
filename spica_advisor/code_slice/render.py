from spica_advisor.code_slice.module import VISIBLE_KINDS


OMITTED = "// … omitted"


def render_module(module, indexes, judged):
    role = "judged function" if judged else "imported by the code above"
    lines = [f'=== Spica function "{module.name}" (function_id: {module.function_id}), {role} ===']
    previous = -1
    for index in sorted(indexes):
        if any(module.statements[skipped].kind in VISIBLE_KINDS for skipped in range(previous + 1, index)):
            lines.append(OMITTED)
        lines.append(module.statement_text(index))
        previous = index
    if any(statement.kind in VISIBLE_KINDS for statement in module.statements[previous + 1:]):
        lines.append(OMITTED)
    return "\n".join(lines)


def render(modules, included, notes, judged_ids):
    ordered = sorted(included, key=lambda function_id: function_id not in judged_ids)
    sections = [render_module(modules[function_id], included[function_id], function_id in judged_ids)
                for function_id in ordered]
    if notes:
        sections.append("Notes:\n" + "\n".join(f"- {note}" for note in notes))
    return "\n\n".join(sections)
