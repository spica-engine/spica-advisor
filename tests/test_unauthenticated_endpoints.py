import pytest

from spica_advisor import resources
from spica_advisor.investigations import unauthenticated_endpoints
from spica_advisor.investigations.unauthenticated_endpoints import steps
from spica_advisor.investigations.unauthenticated_endpoints.agents import ENDPOINT_ASSESSMENT_AGENT
from spica_advisor.investigations.unauthenticated_endpoints.handlers import exported_names
from spica_advisor.investigations.unauthenticated_endpoints.models import (
    EndpointAssessmentResponse,
    FunctionAssessment,
    HandlerAssessment,
    SkippedHandler,
)
from spica_advisor.investigations.unauthenticated_endpoints.policy import SEVERITY_MATRIX


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
        self.functions = []

    def run(self, agent, prompt, functions=()):
        self.agents.append(agent)
        self.prompts.append(prompt)
        self.functions.append(functions)
        return self.response


class SequenceRunner(FakeRunner):
    def __init__(self, responses):
        super().__init__(None)
        self.responses = iter(responses)

    def run(self, agent, prompt, functions=()):
        super().run(agent, prompt, functions)
        return next(self.responses)


NO_FINDINGS = EndpointAssessmentResponse(functions=[], skipped=[])


def handler(name, auth, impact, auth_reason="no check", impact_reason="writes bucket"):
    return HandlerAssessment(name=name, auth_reason=auth_reason, auth=auth, impact_reason=impact_reason, impact=impact)


def assessment(function_id, *handlers):
    return FunctionAssessment(function_id=function_id, handlers=list(handlers))


def test_load_functions_includes_id_schema_and_content(tmp_path):
    write_function(tmp_path, "demo", "fn-1", PUBLIC_HTTP, "export function handler() {}")

    [definition] = resources.load_functions(tmp_path / "demo")

    assert definition["_id"] == "fn-1"
    assert definition["name"] == "fn-1"
    assert definition["schema"]["triggers"]["handler"]["type"] == "http"
    assert definition["content"] == "export function handler() {}"


def test_asks_the_agent_about_public_functions_only_but_lets_it_read_every_function(tmp_path):
    write_function(tmp_path, "demo", "public", PUBLIC_HTTP, "export function handler(req, res) {}")
    write_function(tmp_path, "demo", "no-authorize", PUBLIC_HTTP_WITHOUT_AUTHORIZE, "export function handler(req, res) {}")
    write_function(tmp_path, "demo", "authorized", AUTHORIZED_HTTP, "export function handler(req, res) {}")
    write_function(tmp_path, "demo", "inactive", INACTIVE_HTTP, "export function handler(req, res) {}")
    write_function(tmp_path, "demo", "scheduled", SCHEDULE, "export function handler(req, res) {}")
    runner = FakeRunner(NO_FINDINGS)

    unauthenticated_endpoints.build().run(tmp_path / "demo", runner)

    assert runner.agents == [ENDPOINT_ASSESSMENT_AGENT] * 2
    assert sorted(prompt.splitlines()[1] for prompt in runner.prompts) == ["function_id: no-authorize", "function_id: public"]
    assert all(
        sorted(function["_id"] for function in functions) == ["authorized", "inactive", "no-authorize", "public", "scheduled"]
        for functions in runner.functions
    )


def test_reports_a_severity_decided_by_the_policy_for_served_handlers_grouped_by_function(tmp_path):
    names = ["handler", "health", "confirm", "update", "remove"]
    write_function(tmp_path, "demo", "fn-1", "".join(PUBLIC_HTTP.replace("handler", name) for name in names),
                   "\n".join(f"export function {name}(req, res) {{}}" for name in names))
    write_function(tmp_path, "demo", "fn-2", PUBLIC_HTTP, "export function handler(req, res) {}")
    runner = SequenceRunner([
        EndpointAssessmentResponse(functions=[
            assessment("fn-1",
                       handler("handler", "none", "high"),
                       handler("health", "none", "low", impact_reason="returns OK"),
                       handler("confirm", "authentication", "high", auth_reason="token only"),
                       handler("update", "authentication", "medium"),
                       handler("remove", "authorization", "high")),
            assessment("unknown", handler("other", "none", "high")),
        ], skipped=[]),
        EndpointAssessmentResponse(functions=[assessment("fn-2", handler("handler", "authorization", "high"))], skipped=[]),
    ])

    report = unauthenticated_endpoints.build().run(tmp_path / "demo", runner)

    assert report == [
        {
            "function_id": "fn-1",
            "function_name": "fn-1",
            "path": "function/fn-1",
            "methods": [
                {"name": "handler", "severity": "high", "auth": "none", "auth_reason": "no check",
                 "impact": "high", "impact_reason": "writes bucket"},
                {"name": "health", "severity": "low", "auth": "none", "auth_reason": "no check",
                 "impact": "low", "impact_reason": "returns OK"},
                {"name": "confirm", "severity": "medium", "auth": "authentication", "auth_reason": "token only",
                 "impact": "high", "impact_reason": "writes bucket"},
                {"name": "update", "severity": "low", "auth": "authentication", "auth_reason": "no check",
                 "impact": "medium", "impact_reason": "writes bucket"},
            ],
        },
    ]


def test_skips_agent_when_no_public_functions(tmp_path):
    write_function(tmp_path, "demo", "authorized", AUTHORIZED_HTTP, "export function handler(req, res) {}")
    runner = FakeRunner(response=None)

    assert unauthenticated_endpoints.build().run(tmp_path / "demo", runner) == []
    assert runner.prompts == []


def test_skipped_handlers_are_never_reported(tmp_path):
    write_function(tmp_path, "demo", "fn-1", PUBLIC_HTTP, "export function handler(req, res) {}")
    runner = FakeRunner(EndpointAssessmentResponse(
        functions=[assessment("fn-1")],
        skipped=[SkippedHandler(function_id="fn-1", name="handler", reason="sign-in")],
    ))

    assert unauthenticated_endpoints.build().run(tmp_path / "demo", runner) == []


def test_each_public_function_gets_its_own_call_and_the_findings_are_merged(tmp_path):
    for function_id in ("fn-1", "fn-2", "fn-3"):
        write_function(tmp_path, "demo", function_id, PUBLIC_HTTP, "export function handler(req, res) {}")
    runner = SequenceRunner([
        EndpointAssessmentResponse(functions=[assessment(function_id, handler("handler", "none", "medium"))], skipped=[])
        for function_id in ("fn-1", "fn-2", "fn-3")
    ])

    report = unauthenticated_endpoints.build().run(tmp_path / "demo", runner)

    assert [prompt.count("function_id:") for prompt in runner.prompts] == [1, 1, 1]
    assert sorted(entry["function_id"] for entry in report) == ["fn-1", "fn-2", "fn-3"]


def test_prompt_lists_the_served_handlers_and_points_out_the_default_export(tmp_path):
    triggers = PUBLIC_HTTP + PUBLIC_HTTP.replace("handler", "default").replace("/public", "/") + PUBLIC_HTTP.replace("handler", "missing")
    write_function(tmp_path, "demo", "fn-1", triggers, "export default () => {}\nexport function handler(req, res) {}")
    runner = FakeRunner(NO_FINDINGS)

    unauthenticated_endpoints.build().run(tmp_path / "demo", runner)

    assert runner.prompts == [
        "Judge these handlers.\nfunction_id: fn-1\nhttp_handlers: default, handler\n"
        "`default` is the default export of the file."
    ]


def test_skips_functions_whose_public_triggers_have_no_exported_handler(tmp_path):
    write_function(tmp_path, "demo", "fn-library", PUBLIC_HTTP.replace("handler", "default"), "export const KEY = 1;")
    write_function(tmp_path, "demo", "fn-api", PUBLIC_HTTP, "export function handler(req, res) {}")
    runner = FakeRunner(NO_FINDINGS)

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


def test_file_names_in_the_answer_are_mapped_back_to_function_ids(tmp_path):
    write_function(tmp_path, "demo", "fn-1", PUBLIC_HTTP, "export function handler(req, res) {}")
    runner = FakeRunner(EndpointAssessmentResponse(
        functions=[assessment("fn-1.js", handler("handler", "none", "high"))],
        skipped=[SkippedHandler(function_id="fn-1.js", name="login", reason="sign-in")],
    ))
    context = unauthenticated_endpoints.build().create_context(tmp_path / "demo", runner)

    for step in (steps.read_functions, steps.find_public_functions, steps.prepare_for_analysis, steps.analyze_endpoints):
        step(context)

    assert [item.function_id for item in context.assessments] == ["fn-1"]
    assert [item.function_id for item in context.skipped_handlers] == ["fn-1"]


def test_severity_matrix_maps_every_auth_and_impact_pair():
    assert SEVERITY_MATRIX == {
        "none": {"low": "low", "medium": "medium", "high": "high"},
        "authentication": {"low": "none", "medium": "low", "high": "medium"},
        "authorization": {"low": "none", "medium": "none", "high": "none"},
    }
