NOT_REPORTED = "none"


# The reporting policy lives in code, so changing it needs no new agent run.
def report_decision(auth, impact):
    if auth == "none":
        return impact
    if auth == "authentication" and impact == "high":
        return "low"
    return NOT_REPORTED
