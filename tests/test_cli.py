import sys
from types import SimpleNamespace

from spica_advisor.cli import parse_args, run_investigations
from spica_advisor.investigation import InvestigationBuilder, InvestigationContext, InvestigationError
from spica_advisor.investigations.sensitive_env_vars.markdown import SECTION as ENV_SECTION
from spica_advisor.markdown import Failure


def parse(monkeypatch, *argv):
    monkeypatch.setattr(sys, "argv", ["spica-advisor", *argv])
    return parse_args()


def test_empty_investigations_runs_all(monkeypatch):
    assert parse(monkeypatch, "--investigations", "").investigations is None


def failing_investigation(name, error):
    def step(context):
        raise error

    return (InvestigationBuilder(name).with_context(InvestigationContext).with_section(ENV_SECTION)
            .step("fail", step).build())


def test_an_investigation_error_keeps_its_reason_for_the_report(tmp_path):
    investigation = failing_investigation("env", InvestigationError("The code is too large."))

    reports = run_investigations([investigation], SimpleNamespace(calls=[]), tmp_path, tmp_path)

    assert reports == {"env": Failure("The code is too large.")}


def test_an_unexpected_error_fails_the_investigation_without_leaking_its_message(tmp_path):
    investigation = failing_investigation("env", RuntimeError("secret detail"))

    reports = run_investigations([investigation], SimpleNamespace(calls=[]), tmp_path, tmp_path)

    assert reports == {"env": Failure()}
