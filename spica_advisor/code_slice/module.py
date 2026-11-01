from dataclasses import dataclass, field

import tree_sitter_typescript
from tree_sitter import Language, Parser

from spica_advisor.code_slice.references import declared_names, text


# The TypeScript grammar also parses plain JavaScript, so one parser covers every function file.
PARSER = Parser(Language(tree_sitter_typescript.language_typescript()))

DECLARATION_NODES = {
    "function_declaration", "generator_function_declaration", "class_declaration", "abstract_class_declaration",
    "lexical_declaration", "variable_declaration", "enum_declaration",
}
NEVER_RUN_NODES = {"interface_declaration", "type_alias_declaration", "ambient_declaration", "empty_statement"}
SKIPPED_NODES = {"comment", "hash_bang_line"}

IMPORT = "import"
DECLARATION = "declaration"
DEFAULT_EXPORT = "default-export"
RE_EXPORT = "re-export"
EXPORT_LIST = "export-list"
LOAD = "load"
IGNORED = "ignored"
# Statements of these kinds are the ones a reader needs to see to know code was cut out.
VISIBLE_KINDS = {IMPORT, DECLARATION, DEFAULT_EXPORT, RE_EXPORT, LOAD}


@dataclass(frozen=True)
class Statement:
    node: object
    kind: str
    specifier: str | None = None


@dataclass(frozen=True)
class ImportBinding:
    statement: int
    specifier: str
    imported: str


@dataclass(frozen=True)
class LocalExport:
    name: str


@dataclass(frozen=True)
class DefaultExport:
    statement: int


@dataclass(frozen=True)
class ReExport:
    statement: int
    specifier: str
    name: str


@dataclass
class Module:
    function_id: str
    name: str
    source: bytes
    has_errors: bool = False
    statements: list[Statement] = field(default_factory=list)
    defined_by: dict[str, int] = field(default_factory=dict)
    imports: dict[str, ImportBinding] = field(default_factory=dict)
    exports: dict = field(default_factory=dict)
    star_exports: list[tuple[int, str]] = field(default_factory=list)

    def statement_text(self, index):
        node = self.statements[index].node
        return self.source[node.start_byte:node.end_byte].decode()


def specifier_of(node):
    source = node.child_by_field_name("source")
    return text(source)[1:-1] if source is not None else None


def index_import(module, node, index):
    specifier = specifier_of(node)
    clause = next((child for child in node.children if child.type == "import_clause"), None)
    if any(child.type == "type" for child in node.children):
        return Statement(node, IGNORED)
    if clause is None:
        return Statement(node, LOAD, specifier)
    for child in clause.children:
        if child.type == "identifier":
            module.imports[text(child)] = ImportBinding(index, specifier, "default")
        elif child.type == "namespace_import":
            local = next(grandchild for grandchild in child.children if grandchild.type == "identifier")
            module.imports[text(local)] = ImportBinding(index, specifier, "*")
        elif child.type == "named_imports":
            for item in (grandchild for grandchild in child.children if grandchild.type == "import_specifier"):
                name = text(item.child_by_field_name("name"))
                alias = item.child_by_field_name("alias")
                module.imports[text(alias) if alias is not None else name] = ImportBinding(index, specifier, name)
    return Statement(node, IMPORT, specifier)


def export_specifiers(node):
    clause = next((child for child in node.children if child.type == "export_clause"), None)
    for item in (clause.children if clause is not None else []):
        if item.type == "export_specifier":
            alias = item.child_by_field_name("alias")
            name = text(item.child_by_field_name("name"))
            yield name, text(alias) if alias is not None else name


def index_export(module, node, index):
    specifier = specifier_of(node)
    declaration = node.child_by_field_name("declaration")
    is_default = any(child.type == "default" for child in node.children)
    if specifier is not None:
        namespace = next((child for child in node.children if child.type == "namespace_export"), None)
        for name, exported in export_specifiers(node):
            module.exports[exported] = ReExport(index, specifier, name)
        if namespace is not None:
            alias = next(child for child in namespace.children if child.type == "identifier")
            module.exports[text(alias)] = ReExport(index, specifier, "*")
        elif not any(child.type == "export_clause" for child in node.children):
            module.star_exports.append((index, specifier))
        return Statement(node, RE_EXPORT, specifier)
    if any(child.type == "export_clause" for child in node.children):
        for name, exported in export_specifiers(node):
            module.exports[exported] = LocalExport(name)
        return Statement(node, EXPORT_LIST)
    if declaration is not None and declaration.type in DECLARATION_NODES:
        names = sorted(declared_names(declaration))
        for name in names:
            module.defined_by[name] = index
            module.exports[name] = LocalExport(name)
        if is_default and names:
            module.exports["default"] = LocalExport(names[0])
        return Statement(node, DECLARATION)
    if is_default:
        module.exports["default"] = DefaultExport(index)
        return Statement(node, DEFAULT_EXPORT)
    return Statement(node, IGNORED)


def index_statement(module, node):
    index = len(module.statements)
    if node.type == "import_statement":
        return index_import(module, node, index)
    if node.type == "export_statement":
        return index_export(module, node, index)
    if node.type in DECLARATION_NODES:
        for name in declared_names(node):
            module.defined_by[name] = index
        return Statement(node, DECLARATION)
    if node.type in NEVER_RUN_NODES:
        return Statement(node, IGNORED)
    return Statement(node, LOAD)


def index_module(function_id, name, source):
    data = source.encode()
    root = PARSER.parse(data).root_node
    module = Module(function_id, name, data, has_errors=root.has_error)
    for node in root.children:
        if node.type not in SKIPPED_NODES:
            module.statements.append(index_statement(module, node))
    return module
