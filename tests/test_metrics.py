from spica_advisor.metrics import CallRecord, totals


def call(cost_usd, status="ok"):
    return CallRecord(
        agent="a", model="m", status=status, wall_seconds=1.0, requests=1, tool_calls=0, input_tokens=10,
        cached_input_tokens=0, cache_write_tokens=0, output_tokens=5, reasoning_tokens=0, cost_usd=cost_usd,
    )


def test_totals_add_up_the_cost_of_every_call():
    usage = totals([call(0.25), call(0.5, status="error"), call(None)])

    assert usage["cost_usd"] == 0.75
    assert usage["calls"] == 3 and usage["failed_calls"] == 1


def test_totals_report_no_cost_when_no_call_reported_one():
    assert totals([call(None)])["cost_usd"] is None
    assert totals([])["cost_usd"] is None
