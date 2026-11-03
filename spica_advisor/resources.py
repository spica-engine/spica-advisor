import re
from pathlib import Path

import yaml


FUNCTION_EXTENSIONS = ("mjs", "js", "ts")
RESOURCE_NAME_KEYS = {"bucket": "title", "env-var": "key", "function": "name", "policy": "name"}


def read_schema(schema_path):
    with open(schema_path, encoding="utf-8") as file:
        return yaml.safe_load(file)


def load_schemas(path):
    schemas = []
    for schema_path in Path(path).rglob("schema.yaml"):
        schema = read_schema(schema_path)
        if schema:
            schemas.append(schema)
    return schemas


def function_entry_file(folder):
    for extension in FUNCTION_EXTENSIONS:
        entry = folder / f"index.{extension}"
        if entry.is_file():
            return entry
    return folder / "schema.yaml"


def line_number(text, offset):
    return text.count("\n", 0, offset) + 1


def acl_lines(text):
    start = re.search(r"^acl:", text, re.M)
    if not start:
        return {}
    following = re.search(r"^\S", text[start.end():], re.M)
    block_end = start.end() + following.start() if following else len(text)
    return {"line": line_number(text, start.start()), "end_line": line_number(text, len(text[:block_end].rstrip()) - 1)}


def key_line(text):
    key = re.search(r"^key:", text, re.M)
    return {"line": line_number(text, key.start())} if key else {}


def anchor_lines(kind, schema_path):
    text = schema_path.read_text(encoding="utf-8")
    if kind == "bucket":
        return acl_lines(text)
    if kind == "env-var":
        return key_line(text)
    return {}


def resource_locations(project_dir, kind):
    locations = {}
    for schema_path in (project_dir / kind).rglob("schema.yaml"):
        schema = read_schema(schema_path)
        if schema and schema.get("_id"):
            file = function_entry_file(schema_path.parent) if kind == "function" else schema_path
            locations[schema["_id"]] = {
                "name": schema.get(RESOURCE_NAME_KEYS[kind]),
                "path": file.relative_to(project_dir).as_posix(),
                **anchor_lines(kind, schema_path),
            }
    return locations


def read_function_source(folder):
    return "\n".join(
        path.read_text(encoding="utf-8")
        for extension in FUNCTION_EXTENSIONS
        for path in sorted(folder.glob(f"*.{extension}"))
    )


def load_functions(project_dir):
    definitions = []
    for schema_path in (project_dir / "function").rglob("schema.yaml"):
        schema = read_schema(schema_path)
        if schema:
            definitions.append({
                "_id": schema.get("_id"),
                "name": schema.get("name"),
                "schema": schema,
                "content": read_function_source(schema_path.parent),
            })
    return definitions


def load_policies(project_dir):
    return load_schemas(project_dir / "policy")


def load_env_vars(project_dir):
    return [
        {"_id": env_var.get("_id"), "name": env_var.get("key")}
        for env_var in load_schemas(project_dir / "env-var")
    ]


def load_buckets(project_dir):
    return {
        bucket["_id"]: bucket
        for bucket in load_schemas(project_dir / "bucket")
        if bucket.get("_id")
    }
