from spica_advisor.investigations.sensitive_env_vars.agents import SENSITIVENESS_AGENT
from spica_advisor.investigations.sensitive_env_vars.context import SensitiveEnvVarsContext
from spica_advisor.investigations.sensitive_env_vars.prompts import sensitiveness_input
from spica_advisor.log import LOGGER
from spica_advisor.resources import load_env_vars, resource_locations


REPORTED_LEVELS = {"medium", "high"}


def read_env_vars(context: SensitiveEnvVarsContext):
    context.env_vars = load_env_vars(context.project_dir)
    LOGGER.info("Discovered %d env vars", len(context.env_vars))


def assess_sensitiveness(context: SensitiveEnvVarsContext):
    if not context.env_vars:
        return
    names = [env_var["name"] for env_var in context.env_vars]
    response = context.runner.run(SENSITIVENESS_AGENT, sensitiveness_input(names))
    context.sensitiveness_reports = {
        assessment.name: assessment.model_dump(exclude={"name"})
        for assessment in response.env_vars
    }


def env_var_report(env_var_id, location, report):
    return {"_id": env_var_id, "name": location.get("name"), "path": location.get("path"),
            "line": location.get("line"), "report": report}


def report_sensitive_env_vars(context: SensitiveEnvVarsContext):
    locations = resource_locations(context.project_dir, "env-var")
    context.report = [
        env_var_report(env_var["_id"], locations.get(env_var["_id"], {}), report)
        for env_var in context.env_vars
        if (report := context.sensitiveness_reports.get(env_var["name"]))
        and report["sensitiveness_level"] in REPORTED_LEVELS
    ]
    LOGGER.info("Found %d sensitive env vars", len(context.report))
