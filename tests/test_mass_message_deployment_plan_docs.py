from __future__ import annotations

import unittest
from pathlib import Path


class TestMassMessageDeploymentPlanDocs(unittest.TestCase):
    def test_deployment_plan_requires_schema_first_and_flag_staging(self):
        content = Path("docs/mass-message-deployment-rollout-plan.md").read_text(encoding="utf-8")
        self.assertIn("Schema rollout **before API/worker usage**", content)
        self.assertIn("MESSAGING_MASS_SEND_ENABLED=false", content)
        self.assertIn("MESSAGING_MASS_SEND_KILL_SWITCH=true", content)

    def test_deployment_plan_includes_canary_success_and_rollback_conditions(self):
        content = Path("docs/mass-message-deployment-rollout-plan.md").read_text(encoding="utf-8")
        self.assertIn("Canary rollout phases", content)
        self.assertIn("Success criteria", content)
        self.assertIn("Go / No-Go gates", content)
        self.assertIn("No-Go / rollback conditions", content)
        self.assertIn("export MESSAGING_MASS_SEND_KILL_SWITCH=true", content)


if __name__ == "__main__":
    unittest.main()
