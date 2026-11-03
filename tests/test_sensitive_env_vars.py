from spica_advisor import resources
from spica_advisor.investigations import sensitive_env_vars
from spica_advisor.investigations.sensitive_env_vars.agents import SENSITIVENESS_AGENT
from spica_advisor.investigations.sensitive_env_vars.models import (
    EnvVarSensitiveness,
    SensitivenessResponse,
)


def write_env_var(root, project, env_id, key):
    folder = root / project / "env-var" / key
    folder.mkdir(parents=True)
    (folder / "schema.yaml").write_text(
        f"_id: {env_id}\nkey: {key}\nvalue: super-secret-value\n",
        encoding="utf-8",
    )


class FakeRunner:
    def __init__(self, response):
        self.response = response
        self.agents = []
        self.prompts = []

    def run(self, agent, prompt):
        self.agents.append(agent)
        self.prompts.append(prompt)
        return self.response


def test_load_env_vars_omits_values(tmp_path):
    write_env_var(tmp_path, "demo", "id-1", "API_KEY")

    assert resources.load_env_vars(tmp_path / "demo") == [{"_id": "id-1", "name": "API_KEY"}]


def test_reports_only_medium_and_high_env_vars(tmp_path):
    write_env_var(tmp_path, "demo", "id-1", "API_KEY")
    write_env_var(tmp_path, "demo", "id-2", "ADMIN_EMAIL")
    write_env_var(tmp_path, "demo", "id-3", "LOG_LEVEL")
    runner = FakeRunner(SensitivenessResponse(env_vars=[
        EnvVarSensitiveness(name="API_KEY", sensitiveness_level="high", reason="credential"),
        EnvVarSensitiveness(name="ADMIN_EMAIL", sensitiveness_level="medium", reason="personal data"),
        EnvVarSensitiveness(name="LOG_LEVEL", sensitiveness_level="low", reason="config"),
    ]))

    report = sensitive_env_vars.build().run(tmp_path / "demo", runner)

    assert sorted(report, key=lambda entry: entry["_id"]) == [
        {
            "_id": "id-1",
            "name": "API_KEY",
            "path": "env-var/API_KEY/schema.yaml", "line": 2,
            "report": {"sensitiveness_level": "high", "reason": "credential"},
        },
        {
            "_id": "id-2",
            "name": "ADMIN_EMAIL",
            "path": "env-var/ADMIN_EMAIL/schema.yaml", "line": 2,
            "report": {"sensitiveness_level": "medium", "reason": "personal data"},
        },
    ]
    assert runner.agents == [SENSITIVENESS_AGENT]
    assert "super-secret-value" not in runner.prompts[0]


def test_skips_agent_when_no_env_vars(tmp_path):
    runner = FakeRunner(response=None)

    assert sensitive_env_vars.build().run(tmp_path / "demo", runner) == []
    assert runner.prompts == []
