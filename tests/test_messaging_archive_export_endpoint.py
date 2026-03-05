from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from app.routers import messaging


class _InMemoryExportsTable:
    def __init__(self):
        self.items = {}

    def put_item(self, *, Item):
        self.items[Item["export_id"]] = dict(Item)

    def get_item(self, *, Key):
        item = self.items.get(Key["export_id"])
        return {"Item": dict(item)} if item else {}

    def update_item(self, *, Key, UpdateExpression, ExpressionAttributeNames=None, ExpressionAttributeValues=None):
        item = self.items.setdefault(Key["export_id"], {"export_id": Key["export_id"]})
        expr = UpdateExpression.replace("SET", "").strip()
        for assignment in expr.split(","):
            lhs, rhs = assignment.strip().split("=", 1)
            lhs = lhs.strip()
            rhs = rhs.strip()
            if ExpressionAttributeNames and lhs in ExpressionAttributeNames:
                lhs = ExpressionAttributeNames[lhs]
            item[lhs] = ExpressionAttributeValues[rhs]

    def query(self, *, IndexName, KeyConditionExpression, ScanIndexForward=False, Limit=50):
        _ = IndexName, KeyConditionExpression
        rows = list(self.items.values())
        rows.sort(key=lambda x: int(x.get("created_at", 0) or 0), reverse=not ScanIndexForward)
        return {"Items": rows[:Limit]}


class TestMessagingArchiveExportEndpoint(unittest.TestCase):
    def test_create_export_rejects_when_feature_disabled(self):
        actor = SimpleNamespace(sub="admin-1")
        with patch.object(messaging, "_messaging_compliance_export_enabled", return_value=False):
            with self.assertRaises(HTTPException) as ctx:
                messaging.create_compliance_archive_export(
                    messaging.ComplianceArchiveExportCreateIn(case_id="CASE-1", from_ts=0, to_ts=100),
                    actor=actor,
                )
        self.assertEqual(ctx.exception.status_code, 403)

    def test_create_export_persists_and_completes(self):
        table = _InMemoryExportsTable()
        actor = SimpleNamespace(sub="admin-1")
        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = Path(tmp) / "manifest.json"
            records_path = Path(tmp) / "records.jsonl"
            manifest_path.write_text("{}", encoding="utf-8")
            records_path.write_text("", encoding="utf-8")

            fake_artifact = SimpleNamespace(
                artifact_dir=tmp,
                manifest_path=str(manifest_path),
                records_path=str(records_path),
                record_count=0,
            )

            with (
                patch.object(messaging, "_messaging_compliance_export_enabled", return_value=True),
                patch.object(messaging, "T", SimpleNamespace(message_compliance_exports=table)),
                patch.object(messaging, "new_id", return_value="abc"),
                patch.object(messaging, "now_ts", side_effect=[100, 101, 102, 103]),
                patch.object(messaging, "build_case_export_bundle", return_value=fake_artifact),
                patch.object(messaging, "record_messaging_archive_export_outcome") as export_metric,
                patch.object(messaging, "audit_event") as audit_mock,
            ):
                out = messaging.create_compliance_archive_export(
                    messaging.ComplianceArchiveExportCreateIn(case_id="CASE-1", from_ts=0, to_ts=100),
                    actor=actor,
                )

        self.assertEqual(out.export_id, "exp_abc")
        self.assertEqual(out.status, "completed")
        self.assertEqual(table.items["exp_abc"]["status"], "completed")
        export_metric.assert_called_once_with(outcome="success")
        audit_mock.assert_called_once()

    def test_create_export_records_failure_metric_on_builder_error(self):
        table = _InMemoryExportsTable()
        actor = SimpleNamespace(sub="admin-1")
        with (
            patch.object(messaging, "_messaging_compliance_export_enabled", return_value=True),
            patch.object(messaging, "T", SimpleNamespace(message_compliance_exports=table)),
            patch.object(messaging, "new_id", return_value="abc"),
            patch.object(messaging, "now_ts", return_value=100),
            patch.object(messaging, "build_case_export_bundle", side_effect=RuntimeError("boom")),
            patch.object(messaging, "record_messaging_archive_export_outcome") as export_metric,
            patch.object(messaging, "audit_event"),
        ):
            with self.assertRaises(HTTPException):
                messaging.create_compliance_archive_export(
                    messaging.ComplianceArchiveExportCreateIn(case_id="CASE-1", from_ts=0, to_ts=100),
                    actor=actor,
                )
        export_metric.assert_called_once_with(outcome="failure")

    def test_get_export_rejects_when_feature_disabled(self):
        table = _InMemoryExportsTable()
        table.items["exp_1"] = {
            "export_id": "exp_1",
            "case_id": "CASE-1",
            "tenant_id": "default",
            "status": "completed",
            "created_at": 1,
            "updated_at": 1,
            "requested_by_user_id": "u1",
            "expires_at": 100,
        }
        actor = SimpleNamespace(sub="admin-1")
        with (
            patch.object(messaging, "T", SimpleNamespace(message_compliance_exports=table)),
            patch.object(messaging, "_messaging_compliance_export_enabled", return_value=False),
        ):
            with self.assertRaises(HTTPException) as ctx:
                messaging.get_compliance_archive_export("exp_1", actor=actor)
        self.assertEqual(ctx.exception.status_code, 403)

    def test_manifest_access_denies_expired_artifacts(self):
        table = _InMemoryExportsTable()
        table.items["exp_1"] = {
            "export_id": "exp_1",
            "status": "completed",
            "manifest_path": "/tmp/x.json",
            "records_path": "/tmp/x.jsonl",
            "expires_at": 10,
            "created_at": 1,
            "updated_at": 1,
            "requested_by_user_id": "admin",
            "case_id": "CASE-1",
            "tenant_id": "default",
        }
        actor = SimpleNamespace(sub="admin-1")
        with (
            patch.object(messaging, "_messaging_compliance_export_enabled", return_value=True),
            patch.object(messaging, "T", SimpleNamespace(message_compliance_exports=table)),
            patch.object(messaging, "now_ts", return_value=11),
        ):
            with self.assertRaises(HTTPException) as ctx:
                messaging.get_compliance_archive_export_manifest("exp_1", actor=actor)
        self.assertEqual(ctx.exception.status_code, 410)

    def test_list_exports_by_case(self):
        table = _InMemoryExportsTable()
        table.items["exp_1"] = {
            "export_id": "exp_1",
            "case_id": "CASE-1",
            "tenant_id": "default",
            "status": "completed",
            "created_at": 2,
            "updated_at": 3,
            "requested_by_user_id": "u1",
            "expires_at": 100,
            "record_count": 2,
        }
        actor = SimpleNamespace(sub="admin-1")
        with (
            patch.object(messaging, "_messaging_compliance_export_enabled", return_value=True),
            patch.object(messaging, "T", SimpleNamespace(message_compliance_exports=table)),
        ):
            out = messaging.list_compliance_archive_exports("CASE-1", actor=actor)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].export_id, "exp_1")


if __name__ == "__main__":
    unittest.main()
