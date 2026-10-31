from spica_advisor.investigations.unauthenticated_endpoints.handlers import DEFAULT_EXPORT
from spica_advisor.investigations.unauthenticated_endpoints.prompts import batch_by_size
from spica_advisor.investigations.unauthenticated_endpoints.steps import EndpointCall


def format_source_only(function):
    return f"""function_id: {function["_id"]}
```
{function["content"]}
```"""


def endpoint_prompts_without_handler_names(context):
    # Rebuilds the input the endpoint agent had before it was given handler names, for the legacy variant.
    functions = [{"_id": function["_id"], "content": function["content"]} for function in context.public_functions]
    return [
        EndpointCall("Functions:\n" + "\n\n".join(format_source_only(function) for function in batch))
        for batch in batch_by_size(functions, format_source_only)
    ]


def file_call_prompt(function):
    lines = ["Judge these handlers.", f"function_id: {function['_id']}", f"http_handlers: {', '.join(function['handlers'])}"]
    if DEFAULT_EXPORT in function["handlers"]:
        lines.append("`default` is the default export of the file.")
    return "\n".join(lines)


def endpoint_calls_with_files(context):
    # Every function is a file, so the agent can follow a handler into helpers that have no public endpoint.
    return [EndpointCall(file_call_prompt(function), tuple(context.functions)) for function in context.analysis_inputs]
