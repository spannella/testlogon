import unittest
from unittest.mock import patch

from app.routers import admin_usage


class TestAdminUsageRoutes(unittest.TestCase):
    def test_finalize_period_route(self):
        with (
            patch.object(admin_usage, "finalize_billing_period_admin", return_value={"period_id": "2026-02", "finalized_count": 2, "snapshots": [{"version": 1}]}) as fn,
            patch.object(admin_usage, "audit_event") as audit,
        ):
            resp = admin_usage.finalize_billing_period(admin_usage.FinalizePeriodIn(period_id="2026-02"), req=None, admin_user="admin")
        self.assertEqual(resp["period_id"], "2026-02")
        fn.assert_called_once_with(period_id="2026-02", user_id=None)
        audit.assert_called_once()

    def test_recompute_route(self):
        with (
            patch.object(admin_usage, "recompute_usage_aggregates_admin", return_value={"applied": True, "events_scanned": 5, "mismatches": 1}) as fn,
            patch.object(admin_usage, "audit_event") as audit,
        ):
            resp = admin_usage.recompute_usage(
                admin_usage.RecomputeUsageIn(scope="user", user_id="u1", period_id="2026-02", apply=True),
                req=None,
                admin_user="admin",
            )
        self.assertTrue(resp["applied"])
        fn.assert_called_once_with(scope="user", period_id="2026-02", user_id="u1", apply=True)
        audit.assert_called_once()

    def test_user_detail_route(self):
        with patch.object(admin_usage, "get_admin_user_usage_detail", return_value={"user_id": "u1"}) as fn:
            resp = admin_usage.admin_user_usage_detail("u1", period_id="2026-02", top_n=5, admin_user="admin")
        self.assertEqual(resp["user_id"], "u1")
        fn.assert_called_once_with("u1", period_id="2026-02", top_n=5, include_resource_paths=False)

    def test_generate_invoice_lines_route(self):
        with (
            patch.object(admin_usage, "generate_invoice_line_items_for_snapshot_admin", return_value={"total_amount_cents": 12, "pricing_catalog_version": "v1"}) as fn,
            patch.object(admin_usage, "audit_event") as audit,
        ):
            resp = admin_usage.generate_invoice_lines(
                admin_usage.GenerateInvoiceLinesIn(user_id="u1", period_id="2026-02", snapshot_version=1),
                req=None,
                admin_user="admin",
            )
        self.assertEqual(resp["total_amount_cents"], 12)
        fn.assert_called_once_with(
            user_id="u1",
            period_id="2026-02",
            snapshot_version=1,
            pricing_catalog_version=None,
        )
        audit.assert_called_once()

    def test_create_billing_adjustment_route(self):
        with (
            patch.object(admin_usage, "create_billing_adjustment_admin", return_value={"ok": True, "amount_cents": -50, "adjustment_id": "a1"}) as fn,
            patch.object(admin_usage, "audit_event") as audit,
        ):
            resp = admin_usage.create_billing_adjustment(
                admin_usage.CreateBillingAdjustmentIn(
                    user_id="u1",
                    period_id="2026-02",
                    snapshot_version=1,
                    adjustment_type="credit",
                    amount_cents=50,
                    reason="support credit",
                ),
                req=None,
                admin_user="admin",
            )
        self.assertTrue(resp["ok"])
        fn.assert_called_once_with(
            user_id="u1",
            period_id="2026-02",
            snapshot_version=1,
            adjustment_type="credit",
            amount_cents=50,
            reason="support credit",
            reference_id=None,
        )
        audit.assert_called_once()

    def test_require_admin_user_enforced(self):
        with patch.object(admin_usage, "S") as settings:
            settings.filemgr_admin_users = "alice,bob"
            with self.assertRaises(Exception):
                admin_usage._require_admin_user("charlie")
            self.assertEqual(admin_usage._require_admin_user("alice"), "alice")


if __name__ == "__main__":
    unittest.main()
