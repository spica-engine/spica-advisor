from spica_advisor.investigations.unauthenticated_endpoints.handlers import DEFAULT_EXPORT


ENDPOINT_ASSESSMENT_INSTRUCTIONS = """
Classify the authentication and the impact of each public HTTP handler I give you.
Judge only the handlers listed in http_handlers for each function_id. Ignore every
other export. The code I give you is cut down to what those handlers can run: their
declarations, the helpers they call, the globals they use, the code that runs when the
file loads, and the imports they need. `// … omitted` marks code that was left out.
Every Spica function has one section, and code imported from another Spica function
(`@spica-fn/<name>`) is in that function's section, which several handlers can share.
Do not classify obvious sign-in, registration and password-reset handlers. List each
one in `skipped` with its name and a short reason instead.

Auth, for each handler:
1- Look for an auth check that runs BEFORE the handler reads or writes anything.
   It can be inside the handler, a call to another function in the file, a function
   imported from another Spica function (`@spica-fn/<name>`; its code is in its own
   section), or a wrapper that takes the handler as an argument. Follow only calls that
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
function_id. For each handler, use the name exactly as it appears in http_handlers.
Also return `skipped`: one entry per skipped handler with its function_id, handler
name and reason.
"""


# About 125k tokens, which leaves room in the model's context for the instructions and the answer.
MAX_PROMPT_CHARS = 500_000


def function_listing(function):
    lines = [f"function_id: {function['_id']}", f"http_handlers: {', '.join(function['handlers'])}"]
    if DEFAULT_EXPORT in function["handlers"]:
        lines.append("`default` is the default export of the file.")
    return "\n".join(lines)


def handler_call_prompt(functions, code):
    listing = "\n\n".join(function_listing(function) for function in functions)
    return f"Judge these handlers.\n{listing}\n\nCode:\n{code}"
