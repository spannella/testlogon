from __future__ import annotations

import unittest
from pathlib import Path


class TestMessagingComplianceRolloutFlags(unittest.TestCase):
    def test_rollout_doc_includes_compliance_flags_and_rollback_drill(self):
        text = Path("docs/messaging-message-controls-rollout.md").read_text(encoding="utf-8")
        self.assertIn("MESSAGING_COMPLIANCE_ARCHIVE_ENABLED", text)
        self.assertIn("MESSAGING_COMPLIANCE_ARCHIVE_ENFORCE_WRITE_SUCCESS", text)
        self.assertIn("MESSAGING_COMPLIANCE_EXPORT_ENABLED", text)
        self.assertIn("MESSAGING_COMPLIANCE_LEGAL_HOLD_ENABLED", text)
        self.assertIn("Staging rollback drill validation", text)


if __name__ == "__main__":
    unittest.main()
