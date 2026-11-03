from dataclasses import dataclass

from spica_advisor.code_slice import CodeIndex
from spica_advisor.investigations.unauthenticated_endpoints.agents import ENDPOINT_ASSESSMENT_AGENT
from spica_advisor.investigations.unauthenticated_endpoints.batches import Packer
from spica_advisor.investigations.unauthenticated_endpoints.context import UnauthenticatedEndpointsContext
from spica_advisor.investigations.unauthenticated_endpoints.handlers import handler_line, has_public_endpoint, served_handler_names
from spica_advisor.investigations.unauthenticated_endpoints.policy import NOT_REPORTED, report_decision
from spica_advisor.log import LOGGER
from spica_advisor.resources import load_functions, resource_locations


@dataclass(frozen=True)
class EndpointCall:
    prompt: str
    functions: tuple = ()


def read_functions(context: UnauthenticatedEndpointsContext):
    context.functions = load_functions(context.project_dir)
    LOGGER.info("Discovered %d functions", len(context.functions))


def find_public_functions(context: UnauthenticatedEndpointsContext):
    context.public_functions = [
        function for function in context.functions
        if has_public_endpoint(function["schema"])
    ]
    LOGGER.info("Found %d functions with public endpoints", len(context.public_functions))


def prepare_for_analysis(context: UnauthenticatedEndpointsContext):
    context.code_index = CodeIndex(context.functions)
    context.analysis_inputs = []
    for function in context.public_functions:
        handlers = served_handler_names(function)
        if handlers:
            context.analysis_inputs.append({
                "_id": function["_id"], "name": function["name"], "content": function["content"], "handlers": handlers,
            })
    skipped = len(context.public_functions) - len(context.analysis_inputs)
    if skipped:
        LOGGER.info("Skipped %d functions whose public triggers have no exported handler", skipped)


def endpoint_calls(context: UnauthenticatedEndpointsContext):
    if not context.analysis_inputs:
        return []
    return [EndpointCall(prompt) for prompt in Packer(context.code_index, context.analysis_inputs).pack(context.analysis_inputs)]


def analyze_endpoints(context: UnauthenticatedEndpointsContext, build_calls=endpoint_calls):
    calls = build_calls(context)
    if len(calls) > 1:
        LOGGER.info("Analyzing %d functions in %d calls", len(context.analysis_inputs), len(calls))
    for call in calls:
        response = context.runner.run(ENDPOINT_ASSESSMENT_AGENT, call.prompt, functions=call.functions)
        context.assessments.extend(response.functions)
        context.skipped_handlers.extend(response.skipped)


def reported_method(handler, source):
    severity = report_decision(handler.auth, handler.impact)
    if severity == NOT_REPORTED:
        return None
    return {
        "name": handler.name,
        "line": handler_line(source, handler.name),
        "severity": severity,
        "auth": handler.auth,
        "auth_reason": handler.auth_reason,
        "impact": handler.impact,
        "impact_reason": handler.impact_reason,
    }


def function_report(assessment, location, handler_names, source):
    methods = [reported_method(handler, source) for handler in assessment.handlers if handler.name in handler_names]
    return {
        "function_id": assessment.function_id,
        "function_name": location.get("name"),
        "path": location.get("path"),
        "methods": [method for method in methods if method],
    }


def entry_source(project_dir, location):
    path = location.get("path")
    return (project_dir / path).read_text(encoding="utf-8") if path else ""


def report_unauthenticated_endpoints(context: UnauthenticatedEndpointsContext):
    handlers = {function["_id"]: set(function["handlers"]) for function in context.analysis_inputs}
    locations = resource_locations(context.project_dir, "function")
    reports = [
        function_report(assessment, locations.get(assessment.function_id, {}), handlers[assessment.function_id],
                        entry_source(context.project_dir, locations.get(assessment.function_id, {})))
        for assessment in context.assessments
        if assessment.function_id in handlers
    ]
    context.report = [report for report in reports if report["methods"]]
    method_count = sum(len(function["methods"]) for function in context.report)
    LOGGER.info("Found %d unauthenticated endpoints in %d functions", method_count, len(context.report))
