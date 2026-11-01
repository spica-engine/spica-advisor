from spica_advisor.agent import Agent
from spica_advisor.investigations.unauthenticated_endpoints.models import EndpointAssessmentResponse
from spica_advisor.investigations.unauthenticated_endpoints.prompts import ENDPOINT_ASSESSMENT_INSTRUCTIONS


ENDPOINT_ASSESSMENT_AGENT = Agent(
    name="Endpoint auth and impact assessor",
    instructions=ENDPOINT_ASSESSMENT_INSTRUCTIONS,
    output_type=EndpointAssessmentResponse,
)
