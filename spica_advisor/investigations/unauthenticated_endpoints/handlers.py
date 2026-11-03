import re


DEFAULT_EXPORT = "default"
DECLARED_EXPORT = re.compile(r"\bexport\s+(?:async\s+)?(?:function\s*\*?|const|let|var|class)\s+(\w+)")
EXPORT_LIST = re.compile(r"\bexport\s*\{([^}]*)\}")
DEFAULT_EXPORT_DECLARATION = re.compile(r"\bexport\s+default\b")


def is_public_endpoint(trigger):
    return (
        trigger.get("type") == "http"
        and trigger.get("active") is True
        and not (trigger.get("options") or {}).get("authorize")
    )


def has_public_endpoint(schema):
    return any(is_public_endpoint(trigger) for trigger in (schema.get("triggers") or {}).values())


def public_handler_names(schema):
    return sorted(name for name, trigger in (schema.get("triggers") or {}).items() if is_public_endpoint(trigger))


def exported_names(source):
    names = set(DECLARED_EXPORT.findall(source))
    for exports in EXPORT_LIST.findall(source):
        # "handler as alias" exports the alias, which is the name Spica looks up.
        names.update(item.split()[-1] for item in exports.split(",") if item.strip())
    if DEFAULT_EXPORT_DECLARATION.search(source):
        names.add(DEFAULT_EXPORT)
    return names


def handler_line(source, name):
    if name == DEFAULT_EXPORT:
        match = DEFAULT_EXPORT_DECLARATION.search(source)
    else:
        match = next(
            (m for m in DECLARED_EXPORT.finditer(source) if m.group(1) == name),
            None,
        ) or next(
            (m for m in EXPORT_LIST.finditer(source) if name in (item.split()[-1] for item in m.group(1).split(",") if item.strip())),
            None,
        )
    return source.count("\n", 0, match.start()) + 1 if match else None


def served_handler_names(function):
    # A trigger whose handler is not exported runs no code, so it is not an endpoint.
    exported = exported_names(function["content"])
    return [name for name in public_handler_names(function["schema"]) if name in exported]
