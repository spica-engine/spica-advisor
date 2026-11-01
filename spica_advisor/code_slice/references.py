from dataclasses import dataclass


FUNCTION_NODES = {
    "function_declaration", "function_expression", "function", "generator_function",
    "generator_function_declaration", "arrow_function", "method_definition",
}
NAMED_FUNCTION_EXPRESSIONS = {"function_expression", "function", "generator_function"}
BLOCK_NODES = {"statement_block", "switch_body", "for_statement", "for_in_statement", "catch_clause"}
BLOCK_DECLARATIONS = {"function_declaration", "generator_function_declaration", "class_declaration"}
REFERENCE_NODES = {"identifier", "shorthand_property_identifier"}


@dataclass(frozen=True)
class Reference:
    # `member` is set when a name is only used as `name.member`, which lets a namespace import resolve to one export.
    name: str
    member: str | None = None


def text(node):
    return node.text.decode()


def pattern_names(node):
    if node is None:
        return set()
    kind = node.type
    if kind in ("identifier", "shorthand_property_identifier_pattern"):
        return {text(node)}
    if kind in ("formal_parameters", "object_pattern", "array_pattern", "rest_pattern"):
        return set().union(*(pattern_names(child) for child in node.children))
    if kind in ("required_parameter", "optional_parameter"):
        return pattern_names(node.child_by_field_name("pattern"))
    if kind in ("assignment_pattern", "object_assignment_pattern"):
        return pattern_names(node.child_by_field_name("left"))
    if kind == "pair_pattern":
        return pattern_names(node.child_by_field_name("value"))
    return set()


def declared_names(node):
    kind = node.type
    if kind in ("lexical_declaration", "variable_declaration"):
        return set().union(*(
            pattern_names(declarator.child_by_field_name("name"))
            for declarator in node.children if declarator.type == "variable_declarator"
        ))
    name = node.child_by_field_name("name")
    return {text(name)} if name is not None else set()


def hoisted_names(node):
    # `var` is function-scoped, so it is bound everywhere in the function body except in nested functions.
    if node is None:
        return set()
    names = declared_names(node) if node.type == "variable_declaration" else set()
    for child in node.children:
        if child.type not in FUNCTION_NODES:
            names |= hoisted_names(child)
    return names


def block_names(node):
    kind = node.type
    if kind == "for_statement":
        initializer = node.child_by_field_name("initializer")
        return declared_names(initializer) if initializer is not None and initializer.type == "lexical_declaration" else set()
    if kind == "for_in_statement":
        keyword = node.child_by_field_name("kind")
        return pattern_names(node.child_by_field_name("left")) if keyword is not None and text(keyword) != "var" else set()
    if kind == "catch_clause":
        return pattern_names(node.child_by_field_name("parameter"))
    statements = [grandchild for child in node.children for grandchild in (
        child.children if child.type in ("switch_case", "switch_default") else [child]
    )]
    return set().union(set(), *(
        declared_names(statement) for statement in statements
        if statement.type == "lexical_declaration" or statement.type in BLOCK_DECLARATIONS
    ))


def function_names(node):
    names = pattern_names(node.child_by_field_name("parameters")) | pattern_names(node.child_by_field_name("parameter"))
    name = node.child_by_field_name("name")
    if node.type in NAMED_FUNCTION_EXPRESSIONS and name is not None:
        names.add(text(name))
    return names | hoisted_names(node.child_by_field_name("body"))


def static_member(node):
    owner = node.child_by_field_name("object")
    if owner is None or owner.type != "identifier":
        return None
    if node.type == "member_expression":
        member = node.child_by_field_name("property")
        return (text(owner), text(member)) if member is not None and member.type == "property_identifier" else None
    index = node.child_by_field_name("index")
    if index is not None and index.type == "string":
        return text(owner), text(index)[1:-1]
    return None


def walk(node, scopes, found):
    kind = node.type
    if kind in REFERENCE_NODES:
        if not any(text(node) in scope for scope in scopes):
            found[Reference(text(node))] = None
        return
    if kind in ("member_expression", "subscript_expression"):
        member = static_member(node)
        if member and not any(member[0] in scope for scope in scopes):
            found[Reference(*member)] = None
            return
    if kind in FUNCTION_NODES:
        scopes = [*scopes, function_names(node)]
    elif kind in BLOCK_NODES:
        scopes = [*scopes, block_names(node)]
    for child in node.children:
        walk(child, scopes, found)


def free_references(node):
    found = {}
    walk(node, [], found)
    return list(found)
