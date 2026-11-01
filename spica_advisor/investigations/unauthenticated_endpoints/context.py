from dataclasses import dataclass, field

from spica_advisor.code_slice import CodeIndex
from spica_advisor.investigation import InvestigationContext
from spica_advisor.investigations.unauthenticated_endpoints.models import FunctionAssessment, SkippedHandler


@dataclass
class UnauthenticatedEndpointsContext(InvestigationContext):
    functions: list[dict] = field(default_factory=list)
    public_functions: list[dict] = field(default_factory=list)
    analysis_inputs: list[dict] = field(default_factory=list)
    code_index: CodeIndex | None = None
    assessments: list[FunctionAssessment] = field(default_factory=list)
    skipped_handlers: list[SkippedHandler] = field(default_factory=list)
