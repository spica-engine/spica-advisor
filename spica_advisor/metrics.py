from dataclasses import dataclass


OK_STATUS = "ok"
SUMMED_FIELDS = (
    "wall_seconds",
    "requests",
    "tool_calls",
    "input_tokens",
    "cached_input_tokens",
    "cache_write_tokens",
    "output_tokens",
    "reasoning_tokens",
)


@dataclass(frozen=True)
class CallRecord:
    agent: str
    model: str
    status: str
    wall_seconds: float
    requests: int
    tool_calls: int
    input_tokens: int
    cached_input_tokens: int
    cache_write_tokens: int
    output_tokens: int
    reasoning_tokens: int
    cost_usd: float | None = None


def totals(calls):
    costs = [call.cost_usd for call in calls if call.cost_usd is not None]
    return {
        "calls": len(calls),
        "failed_calls": sum(call.status != OK_STATUS for call in calls),
        **{name: round(sum(getattr(call, name) for call in calls), 3) for name in SUMMED_FIELDS},
        "cost_usd": round(sum(costs), 6) if costs else None,
    }
