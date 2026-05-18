import unittest
from types import SimpleNamespace
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
        detail = {
            "user_id": "u1",
            "summary": {
                "upload": {"used_bytes": 10},
                "download": {"used_bytes": 5},
                "storage": {"used_bytes": 2},
                "message_send": {"used_count": 7},
                "post_publish": {"used_count": 3},
                "messaging_upload_bytes_total": 11,
                "messaging_download_bytes_total": 12,
                "newsfeed_upload_bytes_total": 13,
                "newsfeed_download_bytes_total": 14,
            },
            "snapshots": [{"upload_bytes_total": 10, "message_send_count_total": 7, "newsfeed_upload_bytes_total": 13}],
        }
        with patch.object(admin_usage, "get_admin_user_usage_detail", return_value=detail) as fn:
            resp = admin_usage.admin_user_usage_detail("u1", period_id="2026-02", top_n=5, admin_user="admin")
        self.assertEqual(resp["user_id"], "u1")
        self.assertEqual(resp["source_family"], "all")
        self.assertEqual(resp["surface_segments"]["messaging"]["message_send_count_total"], 7)
        fn.assert_called_once_with("u1", period_id="2026-02", top_n=5, include_resource_paths=False)

    def test_user_detail_route_source_family_filter(self):
        detail = {
            "user_id": "u1",
            "summary": {
                "upload": {"used_bytes": 10},
                "download": {"used_bytes": 5},
                "storage": {"used_bytes": 2},
                "message_send": {"used_count": 7},
                "post_publish": {"used_count": 3},
                "messaging_upload_bytes_total": 11,
                "messaging_download_bytes_total": 12,
                "newsfeed_upload_bytes_total": 13,
                "newsfeed_download_bytes_total": 14,
            },
            "snapshots": [{"upload_bytes_total": 10, "download_bytes_total": 5, "storage_bytes_peak": 2, "message_send_count_total": 7, "post_publish_count_total": 3, "messaging_upload_bytes_total": 11, "messaging_download_bytes_total": 12, "newsfeed_upload_bytes_total": 13, "newsfeed_download_bytes_total": 14}],
        }
        with patch.object(admin_usage, "get_admin_user_usage_detail", return_value=detail):
            resp = admin_usage.admin_user_usage_detail("u1", source_family="messaging", admin_user="admin")
        self.assertEqual(resp["source_family"], "messaging")
        self.assertEqual(resp["summary_surface"]["message_send_count_total"], 7)
        self.assertEqual(resp["summary_surface"]["upload_bytes_total"], 11)
        self.assertEqual(resp["snapshots"][0]["upload_bytes_total"], 0)
        self.assertEqual(resp["snapshots"][0]["message_send_count_total"], 7)

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


    def test_generate_api_usage_invoice_lines_route(self):
        with (
            patch.object(admin_usage, "_api_usage_table", return_value="tbl"),
            patch.object(admin_usage, "generate_api_invoice_line_items_for_snapshot", return_value={"total_amount_micros": 120, "invoice_sk": "API_USAGE#INVOICE#2026-02#V0001"}) as fn,
            patch.object(admin_usage, "audit_event") as audit,
        ):
            resp = admin_usage.generate_api_usage_invoice_lines(
                admin_usage.GenerateApiInvoiceLinesIn(user_sub="u1", period_id="2026-02", snapshot_version=1, include_key_sublines=True),
                req=None,
                admin_user="admin",
            )
        self.assertEqual(resp["total_amount_micros"], 120)
        fn.assert_called_once_with("tbl", user_sub="u1", period_id="2026-02", snapshot_version=1, include_key_sublines=True)
        audit.assert_called_once()

    def test_create_api_usage_adjustment_route(self):
        with (
            patch.object(admin_usage, "_api_usage_table", return_value="tbl"),
            patch.object(admin_usage, "create_api_billing_adjustment", return_value={"ok": True, "signed_amount_micros": -50, "adjustment_id": "adj_1"}) as fn,
            patch.object(admin_usage, "audit_event") as audit,
        ):
            resp = admin_usage.create_api_usage_billing_adjustment(
                admin_usage.CreateApiBillingAdjustmentIn(
                    user_sub="u1",
                    period_id="2026-02",
                    snapshot_version=1,
                    adjustment_type="credit",
                    amount_micros=50,
                    reason="support",
                ),
                req=None,
                admin_user="admin",
            )
        self.assertTrue(resp["ok"])
        fn.assert_called_once_with("tbl", user_sub="u1", period_id="2026-02", snapshot_version=1, adjustment_type="credit", amount_micros=50, reason="support", reference_id=None)
        audit.assert_called_once()

    def test_export_api_usage_reconciliation_route(self):
        with (
            patch.object(admin_usage, "_api_usage_table", return_value="tbl"),
            patch.object(admin_usage, "export_api_billing_reconciliation_report", return_value={"variance_vs_snapshot_micros": 0}) as fn,
        ):
            resp = admin_usage.export_api_usage_reconciliation(user_sub="u1", period_id="2026-02", snapshot_version=1, admin_user="admin")
        self.assertEqual(resp["variance_vs_snapshot_micros"], 0)
        fn.assert_called_once_with("tbl", user_sub="u1", period_id="2026-02", snapshot_version=1)

    def test_run_api_usage_shadow_validation_route(self):
        with (
            patch.object(admin_usage, "_api_usage_table", return_value="tbl"),
            patch.object(admin_usage, "run_api_billing_shadow_validation", return_value={"within_threshold": True, "variance_vs_expected_micros": 0}) as fn,
            patch.object(admin_usage, "audit_event") as audit,
        ):
            resp = admin_usage.run_api_usage_shadow_validation(
                admin_usage.RunApiBillingShadowValidationIn(
                    user_sub="u1",
                    period_id="2026-02",
                    snapshot_version=1,
                    expected_total_micros=100,
                    variance_threshold_micros=5,
                    sample_expected_by_route={"GET:/ui/api_keys": 100},
                    cycle_id="cycle-1",
                ),
                req=None,
                admin_user="admin",
            )
        self.assertTrue(resp["within_threshold"])
        fn.assert_called_once_with(
            "tbl",
            user_sub="u1",
            period_id="2026-02",
            snapshot_version=1,
            expected_total_micros=100,
            variance_threshold_micros=5,
            sample_expected_by_route={"GET:/ui/api_keys": 100},
            cycle_id="cycle-1",
        )
        audit.assert_called_once()

    def test_create_api_usage_cutover_signoff_route(self):
        with (
            patch.object(admin_usage, "_api_usage_table", return_value="tbl"),
            patch.object(admin_usage, "record_api_billing_cutover_signoff", return_value={"ok": True, "signoff_sk": "API_USAGE#CUTOVER_SIGNOFF#2026-02#V0001"}) as fn,
            patch.object(admin_usage, "audit_event") as audit,
        ):
            resp = admin_usage.create_api_usage_cutover_signoff(
                admin_usage.ApiBillingCutoverSignoffIn(
                    user_sub="u1",
                    period_id="2026-02",
                    snapshot_version=1,
                    shadow_report_sk="API_USAGE#SHADOW_BILLING#2026-02#V0001#cycle-1",
                    product_approved_by="prod.user",
                    finance_approved_by="fin.user",
                    engineering_approved_by="eng.user",
                    cutover_criteria="shadow variance under threshold",
                    rollback_criteria="rollback on drift",
                ),
                req=None,
                admin_user="admin",
            )
        self.assertTrue(resp["ok"])
        fn.assert_called_once_with(
            "tbl",
            user_sub="u1",
            period_id="2026-02",
            snapshot_version=1,
            shadow_report_sk="API_USAGE#SHADOW_BILLING#2026-02#V0001#cycle-1",
            product_approved_by="prod.user",
            finance_approved_by="fin.user",
            engineering_approved_by="eng.user",
            cutover_criteria="shadow variance under threshold",
            rollback_criteria="rollback on drift",
        )
        audit.assert_called_once()

    def test_admin_api_keys_rollout_state_includes_registry_drift_threshold_fields(self):
        req = SimpleNamespace(
            app=SimpleNamespace(
                state=SimpleNamespace(
                    api_key_registry_drift={
                        "stale_route_count": 3,
                        "stale_route_preview": ["GET:/missing"],
                        "unregistered_live_route_count": 2,
                        "unregistered_live_route_preview": ["GET:/v1/fs/unknown"],
                        "warn_threshold": 1,
                        "warn_threshold_exceeded": True,
                        "status": "critical",
                    }
                )
            )
        )
        with (
            patch.object(admin_usage, "get_api_key_rollout_state", return_value={"dual_credential_mode": "prefer_api_key", "products": {}}),
            patch.object(admin_usage, "audit_event") as audit,
        ):
            out = admin_usage.admin_api_keys_rollout_state(req=req, include_subjects=False, admin_user="admin")
        self.assertEqual(out["registry_drift"]["stale_route_count"], 3)
        self.assertEqual(out["registry_drift"]["unregistered_live_route_count"], 2)
        self.assertEqual(out["registry_drift"]["warn_threshold"], 1)
        self.assertTrue(out["registry_drift"]["warn_threshold_exceeded"])
        self.assertEqual(out["registry_drift"]["status"], "critical")
        audit.assert_called_once()

    def test_admin_api_keys_rollout_state_defaults_registry_drift_threshold_fields(self):
        req = SimpleNamespace(
            app=SimpleNamespace(
                state=SimpleNamespace(
                    api_key_registry_drift={
                        "stale_route_count": 0,
                        "stale_route_preview": [],
                    }
                )
            )
        )
        with patch.object(admin_usage, "get_api_key_rollout_state", return_value={"dual_credential_mode": "prefer_api_key", "products": {}}):
            out = admin_usage.admin_api_keys_rollout_state(req=req, include_subjects=False, admin_user="admin")
        self.assertEqual(out["registry_drift"]["warn_threshold"], 0)
        self.assertFalse(out["registry_drift"]["warn_threshold_exceeded"])
        self.assertEqual(out["registry_drift"]["unregistered_live_route_count"], 0)
        self.assertEqual(out["registry_drift"]["status"], "ok")

    def test_admin_api_keys_rollout_state_blocks_include_subjects_without_explicit_enable(self):
        req = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(api_key_registry_drift={})))
        with (
            patch.object(admin_usage, "S", SimpleNamespace(api_key_rollout_state_allow_subjects=False)),
            patch.object(admin_usage, "audit_event") as audit,
        ):
            with self.assertRaises(admin_usage.HTTPException) as exc:
                admin_usage.admin_api_keys_rollout_state(req=req, include_subjects=True, admin_user="admin")
        self.assertEqual(exc.exception.status_code, 403)
        self.assertIn("include_subjects is disabled", str(exc.exception.detail))
        audit.assert_called_once()

    def test_admin_api_keys_rollout_state_allows_include_subjects_when_enabled(self):
        req = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(api_key_registry_drift={})))
        with (
            patch.object(admin_usage, "S", SimpleNamespace(api_key_rollout_state_allow_subjects=True)),
            patch.object(admin_usage, "get_api_key_rollout_state", return_value={"dual_credential_mode": "prefer_api_key", "products": {}}) as get_state,
            patch.object(admin_usage, "audit_event"),
        ):
            admin_usage.admin_api_keys_rollout_state(req=req, include_subjects=True, admin_user="admin")
        get_state.assert_called_once_with(include_subjects=True)


if __name__ == "__main__":
    unittest.main()
