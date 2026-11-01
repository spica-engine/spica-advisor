import pytest

from spica_advisor.code_slice import CodeIndex


def function(name, content):
    return {"_id": f"id-{name}", "name": name, "content": content.strip("\n")}


def cut(functions, judged, handlers):
    index = CodeIndex(functions)
    return index.render(index.cut(f"id-{judged}", handlers), {f"id-{judged}"})


def sections(text):
    return {
        part.splitlines()[0].split('"')[1]: part.splitlines()[1:]
        for part in text.split("\n\n=== ") if part
    } if text.startswith("===") else {}


def only(content, handlers=("handler",), name="Main"):
    return cut([function(name, content)], name, list(handlers))


def test_keeps_the_handler_and_what_it_uses_and_marks_what_was_left_out():
    text = only("""
import { helper } from "axios";
const LIMIT = 5;
const UNUSED = 6;
function used(x) { return x + LIMIT; }
function dead() { return UNUSED; }
export function handler(req, res) { return res.json(used(helper)); }
export function other() { return dead(); }
""")

    assert text == """=== Spica function "Main" (function_id: id-Main), judged function ===
import { helper } from "axios";
const LIMIT = 5;
// … omitted
function used(x) { return x + LIMIT; }
// … omitted
export function handler(req, res) { return res.json(used(helper)); }
// … omitted"""


def test_a_file_that_is_entirely_used_has_no_omission_markers():
    text = only("export function handler() { return 1; }\n")

    assert "omitted" not in text


def test_code_that_runs_when_the_file_loads_is_kept_with_what_it_uses():
    text = only("""
import * as Bucket from "@spica-devkit/bucket";
const KEY = process.env.API_KEY;
Bucket.initialize({ apikey: KEY });
export function handler() { return 1; }
""")

    assert "Bucket.initialize({ apikey: KEY });" in text
    assert "const KEY = process.env.API_KEY;" in text
    assert 'import * as Bucket from "@spica-devkit/bucket";' in text


def test_parameters_and_inner_declarations_hide_top_level_names():
    text = only("""
function helper() { return "top level"; }
function run(helper) { return helper(); }
export function handler() { return run(() => 1); }
""")

    assert "return run(" in text and "function run(helper)" in text
    assert 'return "top level"' not in text


def test_a_block_scoped_name_only_hides_the_top_level_name_inside_its_block():
    text = only("""
function helper() { return "top level"; }
export function handler() {
  { const helper = 1; }
  return helper();
}
""")

    assert 'return "top level"' in text


def test_destructured_and_catch_names_hide_top_level_names():
    text = only("""
const status = "top level";
export function handler({ status }) { try { return status; } catch (error) { return error; } }
""")

    assert "top level" not in text


def test_var_is_visible_across_the_whole_function():
    text = only("""
function helper() { return "top level"; }
export function handler(flag) { if (flag) { var helper = 1; } return helper; }
""")

    assert "top level" not in text


@pytest.mark.parametrize("source", [
    "function inner(req) {}\nexport { inner as handler };",
    "const inner = (req) => {};\nexport { inner as handler };",
    "export const handler = wrap(inner);\nfunction inner(req) {}\nfunction wrap(f) { return f; }",
    "export function handler(req) { return inner(); }\nfunction inner() {}",
])
def test_every_export_form_reaches_the_handler_declaration(source):
    text = only(source + "\nfunction unrelated() {}")

    assert "unrelated" not in text
    assert "inner" in text


def test_default_exports_are_reached_by_the_name_default():
    text = only("function unrelated() {}\nexport default async function (req, res) { return 1; }", ["default"])

    assert "export default async function (req, res) { return 1; }" in text
    assert "unrelated" not in text


def test_a_default_export_that_wraps_a_local_function_keeps_the_function():
    text = only("function inner() {}\nfunction unrelated() {}\nexport default wrap(inner);", ["default"])

    assert "function inner() {}" in text and "unrelated" not in text


def test_a_class_is_kept_whole_with_its_parent():
    text = only("""
class Base { check() {} }
class Service extends Base { run() { return this.check(); } }
class Unused {}
export function handler() { return new Service().run(); }
""")

    assert "class Base" in text and "class Service extends Base" in text and "class Unused" not in text


def test_imports_from_packages_are_kept_as_one_line_and_not_followed():
    text = cut([function("Main", 'import axios from "axios";\nexport function handler() { return axios.get("x"); }')],
               "Main", ["handler"])

    assert text.count("=== Spica function") == 1
    assert 'import axios from "axios";' in text


def test_only_the_used_exports_of_another_function_are_included():
    functions = [
        function("Main", 'import { check, unused } from "@spica-fn/Helper";\nexport function handler(req) { return check(req); }'),
        function("Helper", """
import axios from "axios";
const KEY = "k";
export function check(req) { return axios.get(KEY); }
export function unused() { return 1; }
"""),
    ]

    parts = sections(cut(functions, "Main", ["handler"]))

    assert parts["Helper"] == [
        'import axios from "axios";',
        'const KEY = "k";',
        'export function check(req) { return axios.get(KEY); }',
        '// … omitted',
    ]


def test_a_namespace_import_used_by_member_includes_only_that_export():
    functions = [
        function("Main", 'import * as Helper from "@spica-fn/Helper";\nexport function handler() { return Helper.check(); }'),
        function("Helper", "export function check() {}\nexport function unused() {}"),
    ]

    text = cut(functions, "Main", ["handler"])

    assert "export function check() {}" in text and "unused" not in text


def test_a_namespace_import_used_as_a_value_includes_every_export_and_says_so():
    functions = [
        function("Main", 'import * as Helper from "@spica-fn/Helper";\nexport function handler() { return use(Helper); }\nfunction use() {}'),
        function("Helper", "export function check() {}\nexport function other() {}"),
    ]

    text = cut(functions, "Main", ["handler"])

    assert "export function check() {}" in text and "export function other() {}" in text
    assert "uses `Helper` from @spica-fn/Helper as a whole" in text


def test_default_imports_resolve_to_the_default_export():
    functions = [
        function("Main", 'import guard from "@spica-fn/Guard";\nexport function handler(req) { return guard(req); }'),
        function("Guard", "export default function guard(req) { return req.token; }\nexport function unused() {}"),
    ]

    text = cut(functions, "Main", ["handler"])

    assert "export default function guard(req)" in text and "unused" not in text


def test_an_import_of_an_unknown_function_or_missing_export_is_noted():
    functions = [
        function("Main", 'import { a } from "@spica-fn/Missing";\nimport { b } from "@spica-fn/Helper";\nexport function handler() { return a() + b(); }'),
        function("Helper", "export function c() {}"),
    ]

    text = cut(functions, "Main", ["handler"])

    assert "Main imports @spica-fn/Missing, which is not a function in this project" in text
    assert "Helper has no export named `b`" in text


def test_circular_imports_end_and_keep_each_function_once():
    functions = [
        function("A", 'import { b } from "@spica-fn/B";\nexport function handler() { return b(); }\nexport function a() { return 1; }'),
        function("B", 'import { a } from "@spica-fn/A";\nexport function b() { return a(); }'),
    ]

    text = cut(functions, "A", ["handler"])

    assert text.count("export function handler()") == 1
    assert text.count("export function a()") == 1
    assert text.count("export function b()") == 1


def test_a_helper_shared_by_two_paths_is_kept_once():
    functions = [
        function("Main", 'import { left } from "@spica-fn/Left";\nimport { right } from "@spica-fn/Right";\nexport function handler() { return left() + right(); }'),
        function("Left", 'import { shared } from "@spica-fn/Shared";\nexport function left() { return shared(); }'),
        function("Right", 'import { shared } from "@spica-fn/Shared";\nexport function right() { return shared(); }'),
        function("Shared", "export function shared() { return 1; }"),
    ]

    text = cut(functions, "Main", ["handler"])

    assert text.count("export function shared()") == 1
    assert text.count("=== Spica function") == 4


def test_different_methods_and_aliases_of_one_function_are_each_kept_once():
    functions = [
        function("Main", """
import { one as first, two } from "@spica-fn/Helper";
import { one as again } from "@spica-fn/Helper";
export function handler() { return first() + again() + two(); }
"""),
        function("Helper", "export function one() {}\nexport function two() {}\nexport function three() {}"),
    ]

    parts = sections(cut(functions, "Main", ["handler"]))

    assert parts["Helper"][:2] == ["export function one() {}", "export function two() {}"]
    assert "three" not in "\n".join(parts["Helper"])


def test_re_exports_are_followed_to_the_defining_function():
    functions = [
        function("Main", 'import { check } from "@spica-fn/Index";\nexport function handler() { return check(); }'),
        function("Index", 'export { check } from "@spica-fn/Impl";\nexport { other } from "@spica-fn/Impl";'),
        function("Impl", "export function check() {}\nexport function other() {}"),
    ]

    text = cut(functions, "Main", ["handler"])

    assert "export function check() {}" in text and "other() {}" not in text


def test_star_re_exports_that_form_a_cycle_end():
    functions = [
        function("Main", 'import { check } from "@spica-fn/A";\nexport function handler() { return check(); }'),
        function("A", 'export * from "@spica-fn/B";'),
        function("B", 'export * from "@spica-fn/A";\nexport function check() {}'),
    ]

    text = cut(functions, "Main", ["handler"])

    assert "export function check() {}" in text


def test_a_star_re_export_cycle_without_the_name_is_noted_instead_of_looping():
    functions = [
        function("Main", 'import { nope } from "@spica-fn/A";\nexport function handler() { return nope(); }'),
        function("A", 'export * from "@spica-fn/B";'),
        function("B", 'export * from "@spica-fn/A";'),
    ]

    assert "A has no export named `nope`" in cut(functions, "Main", ["handler"])


def test_several_handlers_share_one_slice():
    text = only("""
function shared() {}
function onlyA() {}
function onlyB() {}
function unused() {}
export function a() { shared(); onlyA(); }
export function b() { shared(); onlyB(); }
""", ["a", "b"])

    assert text.count("function shared() {}") == 1
    assert "onlyA() {}" in text and "onlyB() {}" in text and "unused" not in text


def test_typescript_syntax_and_non_ascii_text_are_kept_exactly():
    text = only("""
type Reply = { ok: boolean };
const GREETING: string = "héllo → wörld";
export async function handler(req: Request, res: Response): Promise<Reply> { return { ok: GREETING.length > 0 }; }
""")

    assert 'const GREETING: string = "héllo → wörld";' in text
    assert "export async function handler(req: Request, res: Response): Promise<Reply>" in text
    assert "type Reply" not in text


def test_the_judged_function_comes_first_and_is_labelled():
    functions = [
        function("Main", 'import { a } from "@spica-fn/Helper";\nexport function handler() { return a(); }'),
        function("Helper", "export function a() {}"),
    ]

    headers = [line for line in cut(functions, "Main", ["handler"]).splitlines() if line.startswith("===")]

    assert headers == [
        '=== Spica function "Main" (function_id: id-Main), judged function ===',
        '=== Spica function "Helper" (function_id: id-Helper), imported by the code above ===',
    ]


def test_a_handler_the_file_does_not_export_is_noted():
    assert "Main has no export named `ghost`" in only("export function handler() {}", ["ghost"])


def test_the_same_input_always_gives_the_same_text():
    source = "import { b } from '@spica-fn/B';\nexport function handler() { return b(); }"
    functions = [function("A", source), function("B", "export function b() {}\nexport function c() {}")]

    assert cut(functions, "A", ["handler"]) == cut(functions, "A", ["handler"])


def test_the_cuts_of_several_functions_are_merged_and_the_shared_code_is_sent_once():
    functions = [
        function("One", 'import { shared, a } from "@spica-fn/Shared";\nexport function handler() { return shared() + a(); }'),
        function("Two", 'import { shared, b } from "@spica-fn/Shared";\nexport function handler() { return shared() + b(); }'),
        function("Shared", "export function shared() {}\nexport function a() {}\nexport function b() {}\nexport function c() {}"),
    ]
    index = CodeIndex(functions)
    merged = index.cut("id-One", ["handler"]).union(index.cut("id-Two", ["handler"]))

    text = index.render(merged, {"id-One", "id-Two"})

    assert text.count("export function shared() {}") == 1
    assert "export function a() {}" in text and "export function b() {}" in text and "function c()" not in text
    assert [line.split('"')[1] for line in text.splitlines() if line.startswith("===")] == ["One", "Two", "Shared"]
    assert text.count("judged function") == 2


def test_merging_cuts_keeps_the_notes_of_both_without_repeats():
    functions = [
        function("One", 'import { x } from "@spica-fn/Gone";\nexport function handler() { return x(); }'),
        function("Two", 'import { x } from "@spica-fn/Gone";\nexport function handler() { return x(); }'),
    ]
    index = CodeIndex(functions)

    merged = index.cut("id-One", ["handler"]).union(index.cut("id-Two", ["handler"]))

    assert merged.notes == (
        "One imports @spica-fn/Gone, which is not a function in this project",
        "Two imports @spica-fn/Gone, which is not a function in this project",
    )
