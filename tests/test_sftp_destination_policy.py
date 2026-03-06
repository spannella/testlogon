import unittest
from unittest.mock import patch

from fastapi import HTTPException

from app.services import sftp_destination_policy as policy


class TestSftpDestinationPolicy(unittest.TestCase):
    def test_allowlist_policy_blocks_and_audits_disallowed_host(self):
        fake_settings = type("Cfg", (), {
            "filemgr_sftp_destination_policy_mode": "allowlist",
            "filemgr_sftp_allowed_destinations": "*.allowed.example.com,10.0.0.0/24",
        })()
        with (
            patch.object(policy, "S", fake_settings),
            patch.object(policy, "audit_event") as audit,
        ):
            with self.assertRaises(HTTPException) as ctx:
                policy.enforce_sftp_destination_policy(host="bad.example.net", owner="u1", mount_id="m1", stage="mount_create")

        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail["code"], "sftp_destination_not_allowed")
        self.assertEqual(audit.call_args.args[0], "filemgr_sftp_destination_policy_denied")

    def test_allowlist_accepts_matching_domain_and_cidr(self):
        fake_settings = type("Cfg", (), {
            "filemgr_sftp_destination_policy_mode": "allowlist",
            "filemgr_sftp_allowed_destinations": "*.allowed.example.com,10.0.0.0/24",
        })()
        with (
            patch.object(policy, "S", fake_settings),
            patch.object(policy, "audit_event") as audit,
        ):
            policy.enforce_sftp_destination_policy(host="node.allowed.example.com", owner="u1", mount_id="m1", stage="connection")
            policy.enforce_sftp_destination_policy(host="10.0.0.42", owner="u1", mount_id="m1", stage="connection")
        audit.assert_not_called()


if __name__ == "__main__":
    unittest.main()
