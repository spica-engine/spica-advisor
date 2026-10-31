import pytest

from evals.cli import investigation_tasks
from evals.tasks import INVESTIGATION_TASKS, TASKS
from spica_advisor.investigations import INVESTIGATIONS


def test_investigation_names_match_the_production_ones():
    assert set(INVESTIGATION_TASKS) == {investigation.name for investigation in INVESTIGATIONS}


def test_every_agent_task_belongs_to_exactly_one_investigation():
    tasks = [task for names in INVESTIGATION_TASKS.values() for task in names]

    assert sorted(tasks) == sorted(TASKS)


def test_investigations_expand_to_their_agents_without_duplicates():
    assert investigation_tasks(["broken-access-control", "sensitive-env-vars", "broken-access-control"]) == [
        "policy_attachments", "bucket_acl", "sensitive_env_vars"]
