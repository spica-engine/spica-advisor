import re


def function_file_name(function):
    return re.sub(r"[^\w.-]", "_", str(function["_id"])) + ".js"


def restore_function_ids(items, functions):
    ids_by_file_name = {function_file_name(function): function["_id"] for function in functions}
    for item in items:
        item.function_id = ids_by_file_name.get(item.function_id, item.function_id)


def write_function_files(functions, folder):
    for function in functions:
        (folder / function_file_name(function)).write_text(function["content"], encoding="utf-8")
    listing = "\n".join(
        f"- {function_file_name(function)}: function_id {function['_id']}, name {function['name']}"
        for function in functions
    )
    return f"Each function's source is a file in the current directory:\n{listing}"
