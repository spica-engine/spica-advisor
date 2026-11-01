# Endpoint auth and impact (draft)

A draft for an endpoint agent that labels two independent axes per handler. Code, not the agent,
decides what to report. Nothing loads this file.

## Prompt

```
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
     for the action

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
```

## Output model

The prompt does not describe the output format. The runner passes this model to Claude Code as a
JSON schema, so the field names, the allowed values and the field order come from here.

```python
AuthLevel = Literal["none", "authentication", "authorization"]
Impact = Literal["low", "medium", "high"]

class HandlerAssessment(BaseModel):
    name: str
    auth_reason: str      # reason before label, so the model reasons first
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
```
