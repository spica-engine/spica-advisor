from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, model_validator

from spica_advisor.investigations.broken_access_control.models import RowLevelSecurityStatus
from spica_advisor.investigations.sensitive_env_vars.models import SensitivenessLevel
from spica_advisor.investigations.unauthenticated_endpoints.models import AuthLevel, RiskLevel


EXPECTED_ROOT = Path("evals/expected")
RESOURCES_ROOT = Path("resources")
LABEL_FILES = {
    "sensitive_env_vars": "sensitive-env-vars.yaml",
    "endpoint_assessment": "endpoint-assessment.yaml",
    "policy_attachments": "policy-attachments.yaml",
    "bucket_acl": "bucket-acl.yaml",
}


class Label(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PolicyAttachmentLabel(Label):
    function_id: str
    policy_id: str | None = None
    policy_name: str | None = None

    @model_validator(mode="after")
    def require_policy_reference(self):
        if not (self.policy_id or self.policy_name):
            raise ValueError("policy_id or policy_name is required")
        return self


class BucketAclLabel(Label):
    includes_sensitive_information: bool
    read: RowLevelSecurityStatus
    write: RowLevelSecurityStatus


class HandlerLabel(Label):
    auth: AuthLevel
    impact: RiskLevel


class EndpointAssessmentLabels(Label):
    handlers: dict[str, dict[str, HandlerLabel]] = {}
    skipped: dict[str, list[str]] = {}


class CaseLabels(Label):
    sensitive_env_vars: dict[str, SensitivenessLevel] = {}
    policy_attachments: list[PolicyAttachmentLabel] = []
    bucket_acl: dict[str, BucketAclLabel] = {}
    endpoint_assessment: EndpointAssessmentLabels = EndpointAssessmentLabels()


@dataclass(frozen=True)
class EvalCase:
    name: str
    project_dir: Path
    expected_dir: Path

    def label_path(self, field):
        return self.expected_dir / LABEL_FILES[field]

    def load_labels(self) -> CaseLabels:
        labels = {
            field: data
            for field in LABEL_FILES
            if (data := yaml.safe_load(self.label_path(field).read_text(encoding="utf-8"))) is not None
        }
        return CaseLabels.model_validate(labels)


def find_cases(expected_root, resources_root, names=None):
    cases = {
        path.name: EvalCase(path.name, Path(resources_root) / path.name, path)
        for path in sorted(Path(expected_root).iterdir())
        if path.is_dir()
    }
    if not names:
        return list(cases.values())
    unknown = [name for name in names if name not in cases]
    if unknown:
        raise ValueError(f"unknown case(s): {', '.join(unknown)} (available: {', '.join(cases)})")
    return [cases[name] for name in names]
