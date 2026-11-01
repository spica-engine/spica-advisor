from collections.abc import Callable
from dataclasses import dataclass, field

from spica_advisor.agent import Agent
from spica_advisor.investigations.broken_access_control.agents import BUCKET_ACL_AGENT, POLICY_ATTACHMENT_AGENT
from spica_advisor.investigations.broken_access_control.context import BrokenAccessControlContext
from spica_advisor.investigations.broken_access_control.prompts import bucket_acl_input
from spica_advisor.investigations.broken_access_control.steps import find_policy_attachments
from spica_advisor.investigations.broken_access_control.steps import read_functions as read_all_functions
from spica_advisor.investigations.sensitive_env_vars.agents import SENSITIVENESS_AGENT
from spica_advisor.investigations.sensitive_env_vars.context import SensitiveEnvVarsContext
from spica_advisor.investigations.sensitive_env_vars.steps import assess_sensitiveness, read_env_vars
from spica_advisor.investigations.unauthenticated_endpoints.agents import ENDPOINT_ASSESSMENT_AGENT
from spica_advisor.investigations.unauthenticated_endpoints.context import UnauthenticatedEndpointsContext
from spica_advisor.investigations.unauthenticated_endpoints.steps import (
    analyze_endpoints,
    find_public_functions,
    prepare_for_analysis,
)
from spica_advisor.investigations.unauthenticated_endpoints.steps import read_functions as read_endpoint_functions
from spica_advisor.log import LOGGER
from spica_advisor.resources import load_buckets, load_env_vars, load_functions


DEFAULT_INPUT = "default"


@dataclass(frozen=True)
class AgentTask:
    name: str
    agent: Agent
    has_input: Callable
    predict: Callable
    inputs: dict[str, Callable] = field(default_factory=dict)

    def input_builder(self, name):
        return None if name == DEFAULT_INPUT else self.inputs[name]


def predict_sensitive_env_vars(case, labels, runner, build_input=None):
    context = SensitiveEnvVarsContext(project_dir=case.project_dir, runner=runner)
    read_env_vars(context)
    assess_sensitiveness(context)
    return context.sensitiveness_reports


def predict_endpoint_assessment(case, labels, runner, build_input=None):
    context = UnauthenticatedEndpointsContext(project_dir=case.project_dir, runner=runner)
    for step in (read_endpoint_functions, find_public_functions, prepare_for_analysis):
        step(context)
    analyze_endpoints(context, *([build_input] if build_input else []))
    return {
        "functions": [assessment.model_dump() for assessment in context.assessments],
        "skipped": [skipped.model_dump() for skipped in context.skipped_handlers],
    }


def predict_policy_attachments(case, labels, runner, build_input=None):
    context = BrokenAccessControlContext(project_dir=case.project_dir, runner=runner)
    read_all_functions(context)
    find_policy_attachments(context)
    return [report.model_dump() for report in context.attachment_reports]


def predict_bucket_acl(case, labels, runner, build_input=None):
    buckets = load_buckets(case.project_dir)
    predictions = {}
    # One failed call should not discard the other buckets' answers; the runner still records the failure.
    for bucket_id in labels.bucket_acl:
        try:
            predictions[bucket_id] = runner.run(BUCKET_ACL_AGENT, bucket_acl_input(buckets[bucket_id])).model_dump()
        except Exception:
            LOGGER.exception("Bucket ACL evaluation failed for %s", bucket_id)
    return predictions


TASKS = {
    task.name: task
    for task in (
        AgentTask(
            name="sensitive_env_vars",
            agent=SENSITIVENESS_AGENT,
            has_input=lambda case, labels: bool(load_env_vars(case.project_dir)),
            predict=predict_sensitive_env_vars,
        ),
        AgentTask(
            name="endpoint_assessment",
            agent=ENDPOINT_ASSESSMENT_AGENT,
            has_input=lambda case, labels: bool(labels.endpoint_assessment.handlers or labels.endpoint_assessment.skipped),
            predict=predict_endpoint_assessment,
        ),
        AgentTask(
            name="policy_attachments",
            agent=POLICY_ATTACHMENT_AGENT,
            has_input=lambda case, labels: bool(load_functions(case.project_dir)),
            predict=predict_policy_attachments,
        ),
        AgentTask(
            name="bucket_acl",
            agent=BUCKET_ACL_AGENT,
            has_input=lambda case, labels: bool(labels.bucket_acl),
            predict=predict_bucket_acl,
        ),
    )
}


INVESTIGATION_TASKS = {
    "sensitive-env-vars": ["sensitive_env_vars"],
    "unauthenticated-endpoints": ["endpoint_assessment"],
    "broken-access-control": ["policy_attachments", "bucket_acl"],
}
