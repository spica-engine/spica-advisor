NOT_REPORTED = "none"

# Severity of a handler by its authentication level (row) and impact (column). The policy lives in code,
# so changing it needs no new agent run.
SEVERITY_MATRIX = {
    "none": {"low": "low", "medium": "medium", "high": "high"},
    "authentication": {"low": NOT_REPORTED, "medium": "low", "high": "medium"},
    "authorization": {"low": NOT_REPORTED, "medium": NOT_REPORTED, "high": NOT_REPORTED},
}


def report_decision(auth, impact):
    return SEVERITY_MATRIX[auth][impact]
