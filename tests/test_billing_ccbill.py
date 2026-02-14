import unittest
from unittest import mock

from app.services import billing_ccbill as bc


class BillingCcbillTests(unittest.TestCase):
    def test_compute_due(self) -> None:
        balance = {
            "owed_settled_cents": 1500,
            "owed_pending_cents": 500,
            "payments_settled_cents": 300,
            "payments_pending_cents": 200,
        }

        due = bc.compute_due(balance)

        self.assertEqual(due["due_settled_cents"], 1200)
        self.assertEqual(due["due_if_all_settles_cents"], 1500)

    def test_cents_to_dollars_rounding(self) -> None:
        self.assertEqual(bc._cents_to_dollars(105), 1.05)
        self.assertEqual(bc._cents_to_dollars(1999), 19.99)
        self.assertEqual(bc._cents_to_dollars(1), 0.01)

    def test_webhook_remote_ip_allowed_by_default(self) -> None:
        # Defaults to disabled IP enforcement, so any IP should pass.
        self.assertTrue(bc.webhook_remote_ip_allowed("203.0.113.10"))


    def test_verify_mode_defaults_to_local_in_dev(self) -> None:
        with mock.patch("app.services.billing_ccbill.S", new=type("Stub", (), {"ccbill_webhook_verify_mode":"", "dev_mode":True})()):
            self.assertEqual(bc.ccbill_webhook_verify_mode(), "local")

    def test_verify_mode_defaults_to_strict_outside_dev(self) -> None:
        with mock.patch("app.services.billing_ccbill.S", new=type("Stub", (), {"ccbill_webhook_verify_mode":"", "dev_mode":False})()):
            self.assertEqual(bc.ccbill_webhook_verify_mode(), "ip+sig")

    def test_signature_required_when_secret_missing_in_strict_mode(self) -> None:
        with mock.patch("app.services.billing_ccbill.ccbill_webhook_verify_mode", return_value="ip+sig"), \
             mock.patch("app.services.billing_ccbill._webhook_signature_secret_for_mode", return_value=""):
            self.assertFalse(bc.verify_ccbill_webhook_signature(b"{}", "anything"))


if __name__ == "__main__":
    unittest.main()
