from typing import Literal

from pydantic import BaseModel


AuthLevel = Literal["none", "authentication", "authorization"]
RiskLevel = Literal["low", "medium", "high"]


class HandlerAssessment(BaseModel):
    name: str
    auth_reason: str
    auth: AuthLevel
    impact_reason: str
    impact: RiskLevel


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
