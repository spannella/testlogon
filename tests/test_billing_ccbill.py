import unittest

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


if __name__ == "__main__":
    unittest.main()
