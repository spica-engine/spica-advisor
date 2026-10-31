import pytest

from spica_advisor import resources
from spica_advisor.investigations import unauthenticated_endpoints
from spica_advisor.investigations.unauthenticated_endpoints import prompts
from spica_advisor.investigations.unauthenticated_endpoints.agents import ENDPOINT_RISK_AGENT
from spica_advisor.investigations.unauthenticated_endpoints.handlers import exported_names
from spica_advisor.investigations.unauthenticated_endpoints.models import (
    FunctionRisk,
    FunctionRiskResponse,
    MethodRisk,
)


def write_function(root, project, function_id, triggers, content):
    folder = root / project / "function" / function_id
    folder.mkdir(parents=True)
    (folder / "schema.yaml").write_text(
        f"_id: {function_id}\nname: {function_id}\ntriggers:\n{triggers}",
        encoding="utf-8",
    )
    (folder / "index.mjs").write_text(content, encoding="utf-8")


PUBLIC_HTTP = """  handler:
    type: http
    active: true
    options:
      method: Get
      path: /public
      authorize: false
"""

PUBLIC_HTTP_WITHOUT_AUTHORIZE = """  handler:
    type: http
    active: true
    options:
      method: Get
      path: /public
"""

AUTHORIZED_HTTP = """  handler:
    type: http
    active: true
    options:
      method: Get
      path: /private
      authorize: true
"""

INACTIVE_HTTP = """  handler:
    type: http
    active: false
    options:
      method: Get
      path: /inactive
"""

SCHEDULE = """  handler:
    type: schedule
    active: true
    options:
      frequency: "* * * * *"
"""


class FakeRunner:
    def __init__(self, response):
        self.response = response
        self.agents = []
        self.prompts = []

    def run(self, agent, prompt, functions=()):
        self.agents.append(agent)
        self.prompts.append(prompt)
        self.functions = functions
        return self.response


def test_load_functions_includes_id_schema_and_content(tmp_path):
    write_function(tmp_path, "demo", "fn-1", PUBLIC_HTTP, "export function handler() {}")

    [definition] = resources.load_functions(tmp_path / "demo")

    assert definition["_id"] == "fn-1"
    assert definition["name"] == "fn-1"
    assert definition["schema"]["triggers"]["handler"]["type"] == "http"
    assert definition["content"] == "export function handler() {}"


def test_sends_only_public_functions_without_schema_to_agent(tmp_path):
    write_function(tmp_path, "demo", "public", PUBLIC_HTTP, "export function handler(req, res) {} // public source")
    write_function(tmp_path, "demo", "no-authorize", PUBLIC_HTTP_WITHOUT_AUTHORIZE, "export function handler(req, res) {} // no authorize source")
    write_function(tmp_path, "demo", "authorized", AUTHORIZED_HTTP, "export function handler(req, res) {} // authorized source")
    write_function(tmp_path, "demo", "inactive", INACTIVE_HTTP, "export function handler(req, res) {} // inactive source")
    write_function(tmp_path, "demo", "scheduled", SCHEDULE, "export function handler(req, res) {} // scheduled source")
    runner = FakeRunner(FunctionRiskResponse(functions=[]))

    unauthenticated_endpoints.build().run(tmp_path / "demo", runner)

    assert runner.agents == [ENDPOINT_RISK_AGENT]
    [prompt] = runner.prompts
    assert "// public source" in prompt
    assert "// no authorize source" in prompt
    assert "// authorized source" not in prompt
    assert "// inactive source" not in prompt
    assert "// scheduled source" not in prompt
    assert "/public" not in prompt


def test_reports_risks_of_served_handlers_grouped_by_function(tmp_path):
    write_function(tmp_path, "demo", "fn-1", PUBLIC_HTTP, "export function handler(req, res) {}")
    write_function(tmp_path, "demo", "fn-2", PUBLIC_HTTP, "export function handler(req, res) {}")
    runner = FakeRunner(FunctionRiskResponse(functions=[
        FunctionRisk(function_id="fn-1", methods=[
            MethodRisk(name="handler", risk_level="high", reason="writes bucket"),
            MethodRisk(name="health", risk_level="low", reason="returns OK"),
        ]),
        FunctionRisk(function_id="fn-2", methods=[]),
        FunctionRisk(function_id="unknown", methods=[
            MethodRisk(name="other", risk_level="low", reason="hallucinated"),
        ]),
    ]))

    report = unauthenticated_endpoints.build().run(tmp_path / "demo", runner)

    assert report == [
        {
            "function_id": "fn-1",
            "function_name": "fn-1",
            "path": "function/fn-1",
            "methods": [
                {"name": "handler", "risk_level": "high", "reason": "writes bucket"},
            ],
        },
    ]


def test_skips_agent_when_no_public_functions(tmp_path):
    write_function(tmp_path, "demo", "authorized", AUTHORIZED_HTTP, "export function handler(req, res) {} // authorized source")
    runner = FakeRunner(response=None)

    assert unauthenticated_endpoints.build().run(tmp_path / "demo", runner) == []
    assert runner.prompts == []


class SequenceRunner:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.prompts = []

    def run(self, agent, prompt, functions=()):
        self.prompts.append(prompt)
        return next(self.responses)


def risk(function_id):
    return FunctionRisk(function_id=function_id, methods=[
        MethodRisk(name="handler", risk_level="medium", reason="no auth"),
    ])


def test_splits_large_inputs_into_batches_and_merges_their_risks(tmp_path, monkeypatch):
    monkeypatch.setattr(prompts, "MAX_BATCH_CHARS", 400)
    for function_id in ("fn-1", "fn-2", "fn-3"):
        write_function(tmp_path, "demo", function_id, PUBLIC_HTTP, f"export function handler(req, res) {{}} // {function_id} " + "x" * 100)
    runner = SequenceRunner([
        FunctionRiskResponse(functions=[risk("fn-1"), risk("fn-2")]),
        FunctionRiskResponse(functions=[risk("fn-3")]),
    ])

    report = unauthenticated_endpoints.build().run(tmp_path / "demo", runner)

    assert [prompt.count("function_id:") for prompt in runner.prompts] == [2, 1]
    assert sorted(entry["function_id"] for entry in report) == ["fn-1", "fn-2", "fn-3"]


def test_oversized_function_gets_its_own_batch(monkeypatch):
    monkeypatch.setattr(prompts, "MAX_BATCH_CHARS", 100)
    small = {"_id": "small", "content": "x", "handlers": ["handler"]}
    large = {"_id": "large", "content": "x" * 500, "handlers": ["handler"]}

    assert prompts.batch_by_size([small, large, small]) == [[small], [large], [small]]


def test_prompt_lists_each_function_s_served_handlers(tmp_path):
    triggers = PUBLIC_HTTP + PUBLIC_HTTP.replace("handler", "default").replace("/public", "/") + PUBLIC_HTTP.replace("handler", "missing")
    write_function(tmp_path, "demo", "fn-1", triggers, "export default () => {}\nexport function handler(req, res) {}")
    runner = FakeRunner(FunctionRiskResponse(functions=[]))

    unauthenticated_endpoints.build().run(tmp_path / "demo", runner)

    [prompt] = runner.prompts
    assert "function_id: fn-1\nhttp_handlers: default (the default export), handler\n" in prompt


def test_skips_functions_whose_public_triggers_have_no_exported_handler(tmp_path):
    write_function(tmp_path, "demo", "fn-library", PUBLIC_HTTP.replace("handler", "default"), "export const KEY = 1;")
    write_function(tmp_path, "demo", "fn-api", PUBLIC_HTTP, "export function handler(req, res) {}")
    runner = FakeRunner(FunctionRiskResponse(functions=[]))

    unauthenticated_endpoints.build().run(tmp_path / "demo", runner)

    [prompt] = runner.prompts
    assert "fn-library" not in prompt
    assert "function_id: fn-api" in prompt


def test_skips_agent_when_no_public_trigger_has_a_handler(tmp_path):
    write_function(tmp_path, "demo", "fn-library", PUBLIC_HTTP.replace("handler", "default"), "export const KEY = 1;")
    runner = FakeRunner(response=None)

    assert unauthenticated_endpoints.build().run(tmp_path / "demo", runner) == []
    assert runner.prompts == []


@pytest.mark.parametrize(("source", "names"), [
    ("export async function create(req, res) {}", {"create"}),
    ("export function* stream() {}\nexport const list = async (req, res) => {}", {"stream", "list"}),
    ("function a() {}\nfunction b() {}\nexport { a, b as renamed }", {"a", "renamed"}),
    ("export default async function (req, res) {}", {"default"}),
    ("const handler = () => {};\nexport { handler as default };", {"default"}),
    ("function create(req, res) {}", set()),
])
def test_exported_names_cover_the_esm_export_forms(source, names):
    assert exported_names(source) == names


def test_files_input_gives_the_agent_every_function_and_the_public_handlers_as_starting_points(tmp_path):
    from evals.inputs import endpoint_calls_with_files

    write_function(tmp_path, "demo", "fn-api", PUBLIC_HTTP + PUBLIC_HTTP.replace("handler", "default").replace("/public", "/"),
                   "export default () => {}\nexport function handler(req, res) { return requireAuth(req); }")
    write_function(tmp_path, "demo", "fn-helpers", AUTHORIZED_HTTP, "export function requireAuth(req) {}")
    runner = FakeRunner(FunctionRiskResponse(functions=[]))

    context = unauthenticated_endpoints.build().create_context(tmp_path / "demo", runner)
    for step_name, step in context_steps_until_analysis(context):
        step(context)

    [call] = endpoint_calls_with_files(context)

    assert call.prompt == ("Judge these handlers.\nfunction_id: fn-api\nhttp_handlers: default, handler\n"
                           "`default` is the default export of the file.")
    assert sorted(function["_id"] for function in call.functions) == ["fn-api", "fn-helpers"]


def context_steps_until_analysis(context):
    from spica_advisor.investigations.unauthenticated_endpoints import steps

    return [("read", steps.read_functions), ("find", steps.find_public_functions), ("prepare", steps.prepare_for_analysis)]


def test_file_names_in_the_answer_are_mapped_back_to_function_ids(tmp_path):
    write_function(tmp_path, "demo", "fn-1", PUBLIC_HTTP, "export function handler(req, res) {}")
    runner = FakeRunner(FunctionRiskResponse(functions=[risk("fn-1.js")]))

    report = unauthenticated_endpoints.build().run(tmp_path / "demo", runner)

    assert [entry["function_id"] for entry in report] == ["fn-1"]
