import pytest

from spica_advisor import resources
from spica_advisor.investigation import InvestigationError
from spica_advisor.investigations import unauthenticated_endpoints
from spica_advisor.investigations.unauthenticated_endpoints import batches
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


def judged_ids(runner):
    return sorted(line for prompt in runner.prompts for line in prompt.splitlines() if line.startswith("function_id:"))


def test_asks_the_agent_about_public_functions_only_and_gives_it_their_code_instead_of_tools(tmp_path):
    write_function(tmp_path, "demo", "public", PUBLIC_HTTP, "export function handler(req, res) {} // public source")
    write_function(tmp_path, "demo", "no-authorize", PUBLIC_HTTP_WITHOUT_AUTHORIZE, "export function handler(req, res) {} // no authorize source")
    write_function(tmp_path, "demo", "authorized", AUTHORIZED_HTTP, "export function handler(req, res) {} // authorized source")
    write_function(tmp_path, "demo", "inactive", INACTIVE_HTTP, "export function handler(req, res) {} // inactive source")
    write_function(tmp_path, "demo", "scheduled", SCHEDULE, "export function handler(req, res) {} // scheduled source")
    runner = FakeRunner(NO_FINDINGS)

    unauthenticated_endpoints.build().run(tmp_path / "demo", runner)

    assert runner.agents == [ENDPOINT_ASSESSMENT_AGENT]
    assert judged_ids(runner) == ["function_id: no-authorize", "function_id: public"]
    assert runner.functions == [()]
    [prompt] = runner.prompts
    assert "// public source" in prompt and "// no authorize source" in prompt
    assert "authorized source" not in prompt and "inactive source" not in prompt
    assert "scheduled source" not in prompt


def test_the_prompt_carries_the_code_of_imported_functions_but_only_what_is_used(tmp_path):
    write_function(tmp_path, "demo", "Main", PUBLIC_HTTP,
                   'import { check } from "@spica-fn/Helper";\nexport function handler(req, res) { return check(req); }')
    write_function(tmp_path, "demo", "Helper", AUTHORIZED_HTTP,
                   "export function check(req) { return req.token; }\nexport function unrelated() { return 1; }")
    runner = FakeRunner(NO_FINDINGS)

    unauthenticated_endpoints.build().run(tmp_path / "demo", runner)

    [prompt] = runner.prompts
    assert "export function check(req) { return req.token; }" in prompt
    assert "unrelated" not in prompt


def write_sharing_functions(tmp_path, names):
    write_function(tmp_path, "demo", "Shared", AUTHORIZED_HTTP, "export function check(req) { return req.token; }")
    for name in names:
        write_function(tmp_path, "demo", name, PUBLIC_HTTP,
                       f'import {{ check }} from "@spica-fn/Shared";\nexport function handler(req, res) {{ return check(req); }} // {name} ' + "x" * 200)


def test_functions_that_fit_together_share_one_prompt_with_the_shared_code_once(tmp_path):
    write_sharing_functions(tmp_path, ["fn-1", "fn-2", "fn-3"])
    runner = FakeRunner(NO_FINDINGS)

    unauthenticated_endpoints.build().run(tmp_path / "demo", runner)

    [prompt] = runner.prompts
    assert judged_ids(runner) == ["function_id: fn-1", "function_id: fn-2", "function_id: fn-3"]
    assert prompt.count("export function check(req) { return req.token; }") == 1


def test_functions_that_do_not_fit_together_are_split_and_each_prompt_stays_under_the_limit(tmp_path, monkeypatch):
    write_sharing_functions(tmp_path, ["fn-1", "fn-2", "fn-3"])
    everything = FakeRunner(NO_FINDINGS)
    unauthenticated_endpoints.build().run(tmp_path / "demo", everything)
    limit = len(everything.prompts[0]) - 1
    monkeypatch.setattr(batches, "MAX_PROMPT_CHARS", limit)
    runner = SequenceRunner([NO_FINDINGS, NO_FINDINGS])

    unauthenticated_endpoints.build().run(tmp_path / "demo", runner)

    assert len(runner.prompts) == 2
    assert all(len(prompt) <= limit for prompt in runner.prompts)
    assert judged_ids(runner) == ["function_id: fn-1", "function_id: fn-2", "function_id: fn-3"]


def test_findings_of_every_batch_are_merged_in_the_report(tmp_path, monkeypatch):
    write_sharing_functions(tmp_path, ["fn-1", "fn-2"])
    monkeypatch.setattr(batches, "MAX_PROMPT_CHARS", 700)
    runner = SequenceRunner([
        EndpointAssessmentResponse(functions=[assessment(function_id, handler("handler", "none", "medium"))], skipped=[])
        for function_id in ("fn-1", "fn-2")
    ])

    report = unauthenticated_endpoints.build().run(tmp_path / "demo", runner)

    assert len(runner.prompts) == 2
    assert sorted(entry["function_id"] for entry in report) == ["fn-1", "fn-2"]


def test_a_function_alone_above_the_size_limit_fails_the_investigation_with_a_reason(tmp_path, monkeypatch):
    monkeypatch.setattr(batches, "MAX_PROMPT_CHARS", 300)
    write_function(tmp_path, "demo", "Big", PUBLIC_HTTP, "export function handler(req, res) { return '" + "x" * 400 + "'; }")
    runner = FakeRunner(NO_FINDINGS)

    with pytest.raises(InvestigationError, match=r"function Big \(Big\).*above the 300 limit"):
        unauthenticated_endpoints.build().run(tmp_path / "demo", runner)

    assert runner.prompts == []


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


def test_prompt_lists_the_served_handlers_and_points_out_the_default_export(tmp_path):
    triggers = PUBLIC_HTTP + PUBLIC_HTTP.replace("handler", "default").replace("/public", "/") + PUBLIC_HTTP.replace("handler", "missing")
    write_function(tmp_path, "demo", "fn-1", triggers, "export default () => {}\nexport function handler(req, res) {}")
    runner = FakeRunner(NO_FINDINGS)

    unauthenticated_endpoints.build().run(tmp_path / "demo", runner)

    assert runner.prompts == [
        "Judge these handlers.\nfunction_id: fn-1\nhttp_handlers: default, handler\n"
        "`default` is the default export of the file.\n\nCode:\n"
        '=== Spica function "fn-1" (function_id: fn-1), judged function ===\n'
        "export default () => {}\nexport function handler(req, res) {}"
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



def test_severity_matrix_maps_every_auth_and_impact_pair():
    assert SEVERITY_MATRIX == {
        "none": {"low": "low", "medium": "medium", "high": "high"},
        "authentication": {"low": "none", "medium": "low", "high": "medium"},
        "authorization": {"low": "none", "medium": "none", "high": "none"},
    }
