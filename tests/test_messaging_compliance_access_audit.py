from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from app.auth.roles import AdminProfile, AdminProfileType, AdminScope, Role
from app.routers import messaging


class _Req:
    def __init__(self, path: str):
        self.scope = {"route": SimpleNamespace(path=path)}
        self.url = SimpleNamespace(path=path)
        self.headers = {}
        self.client = SimpleNamespace(host="127.0.0.1")


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


class TestMessagingComplianceAccessAndAudit(unittest.TestCase):
    def test_legal_hold_operator_denies_non_admin(self):
        actor = SimpleNamespace(sub="user-1", role=Role.USER, admin_profile=AdminProfile())
        with self.assertRaises(HTTPException) as ctx:
            asyncio.run(messaging.require_legal_hold_operator(user=actor, request=_Req("/messaging/conversations/c1/legal-holds")))
        self.assertEqual(ctx.exception.status_code, 403)

    def test_compliance_query_operator_denies_admin_without_scope(self):
        actor = SimpleNamespace(
            sub="admin-1",
            role=Role.ADMIN,
            admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.BILLING_SUPPORT,)),
        )
        with self.assertRaises(HTTPException) as ctx:
            asyncio.run(messaging.require_compliance_query_operator(user=actor, request=_Req("/messaging/compliance/archive/events")))
        self.assertEqual(ctx.exception.status_code, 403)

    def test_compliance_export_operator_allows_scoped_admin(self):
        actor = SimpleNamespace(
            sub="admin-1",
            role=Role.ADMIN,
            admin_profile=AdminProfile(type=AdminProfileType.GENERAL, scopes=[AdminScope.CONTENT_MODERATION]),
        )
        out = asyncio.run(messaging.require_compliance_export_operator(user=actor, request=_Req("/messaging/compliance/archive/exports")))
        self.assertEqual(out.sub, "admin-1")

    def test_archive_query_forces_internal_tenant_scope(self):
        actor = SimpleNamespace(sub="admin-1")
        with patch.object(messaging, "query_archive_records") as query_mock:
            query_mock.return_value = SimpleNamespace(items=[], next_offset=None, total_matches=0)
            _ = messaging.query_compliance_archive_events(actor=actor)

        self.assertEqual(query_mock.call_args.kwargs["tenant_id"], "default")

    def test_legal_hold_create_audit_has_immutable_identifiers(self):
        actor = SimpleNamespace(sub="admin-1")
        with (
            patch.object(messaging, "_messaging_compliance_legal_hold_enabled", return_value=True),
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "_get_message_or_404", return_value={"message_id": "m1"}),
            patch.object(messaging, "now_ts", return_value=100),
            patch.object(messaging, "new_id", return_value="h1"),
            patch.object(messaging.T.message_legal_holds, "put_item"),
            patch.object(messaging, "audit_event") as audit_mock,
        ):
            messaging.create_message_legal_hold(
                "c1",
                messaging.LegalHoldCreateIn(case_id="CASE-1", reason="Preserve", message_id="m1"),
                actor=actor,
            )

        audit_mock.assert_called_once()
        _, kwargs = audit_mock.call_args
        self.assertEqual(kwargs["outcome"], "success")
        self.assertEqual(kwargs["conversation_id"], "c1")
        self.assertEqual(kwargs["hold_id"], "lh_h1")
        self.assertEqual(kwargs["case_id"], "CASE-1")

    def test_legal_hold_release_audit_has_hold_id(self):
        actor = SimpleNamespace(sub="admin-1")
        hold_item = {
            "hold_id": "lh_h1",
            "conversation_id": "c1",
            "tenant_id": "default",
            "message_id": "m1",
            "case_id": "CASE-1",
            "reason": "x",
            "created_at": 50,
            "created_by_user_id": "admin-0",
        }
        with (
            patch.object(messaging, "_messaging_compliance_legal_hold_enabled", return_value=True),
            patch.object(messaging, "require_participant_active"),
            patch.object(messaging, "now_ts", return_value=120),
            patch.object(messaging.T.message_legal_holds, "get_item", return_value={"Item": hold_item}),
            patch.object(messaging.T.message_legal_holds, "update_item"),
            patch.object(messaging, "audit_event") as audit_mock,
        ):
            messaging.release_message_legal_hold("c1", "lh_h1", messaging.LegalHoldReleaseIn(reason="closed"), actor=actor)

        audit_mock.assert_called_once()
        _, kwargs = audit_mock.call_args
        self.assertEqual(kwargs["outcome"], "success")
        self.assertEqual(kwargs["conversation_id"], "c1")
        self.assertEqual(kwargs["hold_id"], "lh_h1")

    def test_export_create_audit_contains_export_id_and_case_id(self):
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
                patch.object(messaging, "record_messaging_archive_export_outcome"),
                patch.object(messaging, "audit_event") as audit_mock,
            ):
                messaging.create_compliance_archive_export(
                    messaging.ComplianceArchiveExportCreateIn(case_id="CASE-1", from_ts=0, to_ts=100),
                    actor=actor,
                )

        self.assertEqual(audit_mock.call_count, 1)
        event_name = audit_mock.call_args.args[0]
        _, kwargs = audit_mock.call_args
        self.assertEqual(event_name, "messaging_compliance_export_created")
        self.assertEqual(kwargs["outcome"], "success")
        self.assertEqual(kwargs["export_id"], "exp_abc")
        self.assertEqual(kwargs["case_id"], "CASE-1")


if __name__ == "__main__":
    unittest.main()
