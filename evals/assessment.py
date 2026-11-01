from typing import Literal

from pydantic import BaseModel

from evals.inputs import endpoint_calls_with_files
from spica_advisor.agent import Agent
from spica_advisor.function_files import restore_function_ids
from spica_advisor.investigations.unauthenticated_endpoints import steps
from spica_advisor.investigations.unauthenticated_endpoints.context import UnauthenticatedEndpointsContext


AuthLevel = Literal["none", "authentication", "authorization"]
Impact = Literal["low", "medium", "high"]
NOT_REPORTED = "none"

ASSESSMENT_INSTRUCTIONS = """
Classify the authentication and the impact of each public HTTP handler I give you.
Judge only the handlers listed in http_handlers. Ignore every other export. The
source of every function is a file, and the listing maps each file to its function_id.
Do not classify obvious sign-in, registration and password-reset handlers. List each
one in `skipped` with its name and a short reason instead.

Auth, for each handler:
1- Look for an auth check that runs BEFORE the handler reads or writes anything.
   It can be inside the handler, a call to another function in the file, a function
   imported from another Spica function (`@spica-fn/<name>`; open its file from the
   listing), or a wrapper that takes the handler as an argument. Follow only calls that
   could perform auth. Stop at npm and devkit imports and judge them by name.
2- auth is one of:
   - none: no check at all, or only a captcha
   - authentication: verifies who the caller is, for example a token or session, but
     checks no permission, role or ownership. A one-time code, signed link or webhook
     signature also counts
   - authorization: verifies who the caller is AND checks a permission, role or ownership
     for the action. Returning only records that belong to the caller counts as an
     ownership check, when the caller's identity comes from the verified token and never
     from request parameters.

Impact, for each handler, as if every caller were allowed to call it:
3- impact is one of:
   - high: writes or deletes data; sends data to real targets such as emails or third-party
     services; reads personal or sensitive data; installs or runs code or system commands
   - medium: reads public data, such as public configuration, maintenance mode or blogs;
     reads internal data without returning it; sends data to a test or non-critical target
   - low: returns an empty object or fixed dummy data, only logs to the console, does only
     calculations or validation on the request, or does nothing
4- Follow only the calls that change data or return data, and stop at npm and devkit
   imports.

Write each reason as a few words. Return one entry per given function with its
function_id from the listing, never the file name. For each handler, use the name
exactly as it appears in http_handlers.
Also return `skipped`: one entry per skipped handler with its function_id, handler
name and reason.
"""


class HandlerAssessment(BaseModel):
    name: str
    auth_reason: str
    auth: AuthLevel
    impact_reason: str
    impact: Impact


class FunctionAssessment(BaseModel):
    function_id: str
    handlers: list[HandlerAssessment]


class SkippedHandler(BaseModel):
    function_id: str
    name: str
    reason: str


class EndpointAssessmentResponse(BaseModel):
    functions: list[FunctionAssessment]
    skipped: list[SkippedHandler]


ENDPOINT_ASSESSMENT_AGENT = Agent(
    name="Endpoint auth and impact assessor",
    instructions=ASSESSMENT_INSTRUCTIONS,
    output_type=EndpointAssessmentResponse,
)


# The reporting policy lives in code, so changing it needs no new agent run.
def report_decision(auth, impact):
    if auth == "none":
        return impact
    if auth == "authentication" and impact == "high":
        return "low"
    return NOT_REPORTED


def predict_endpoint_assessment(case, labels, runner, build_input=None):
    context = UnauthenticatedEndpointsContext(project_dir=case.project_dir, runner=runner)
    for step in (steps.read_functions, steps.find_public_functions, steps.prepare_for_analysis):
        step(context)
    merged = {"functions": [], "skipped": []}
    for call in (build_input or endpoint_calls_with_files)(context):
        response = runner.run(ENDPOINT_ASSESSMENT_AGENT, call.prompt, functions=call.functions)
        restore_function_ids([*response.functions, *response.skipped], context.functions)
        merged["functions"] += [function.model_dump() for function in response.functions]
        merged["skipped"] += [skipped.model_dump() for skipped in response.skipped]
    return merged
