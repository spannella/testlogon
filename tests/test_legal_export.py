"""Hermetic offline tests for the LEX workstream (Legal & DSAR export).

Covers:
  * LEX-006 — legal-hold model/service: place/release/expiry, is_user_on_hold
    O(1) GSI lookup, multiple holds per user.
  * LEX-007 — deletion blocked while held, re-enabled on release (flag-gated;
    OFF = no-op).
  * LEX-009 — intake validation (required fields → ValueError → 400).
  * LEX-010 — scoped sealed builder honours data_types, redacts secrets,
    signed manifest verifies & fails on tamper.
  * LEX-011/012 — _require_legal rejects ADMIN/USER; ROOT permitted; every
    action emits an audit_event.

No real AWS / no network: moto in-memory tables bound onto the frozen ``T``
handles via ``object.__setattr__`` (restored on teardown); ``S`` flags flipped
via ``object.__setattr__``; the S3 client and audit-adapter event source are
patched. Route-handler coroutines/sync functions are called directly (the env's
TestClient is broken).
"""
from __future__ import annotations

import asyncio
import unittest
from unittest.mock import MagicMock, patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover
    mock_aws = None

from app.auth.roles import Role
from app.core.settings import S
from app.core.tables import T


def _simple_table(ddb, name):
    return ddb.create_table(
        TableName=name,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _legal_holds_table(ddb):
    return ddb.create_table(
        TableName="legal_holds",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "gsi1pk", "AttributeType": "S"},
            {"AttributeName": "gsi1sk", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByUser",
                "KeySchema": [
                    {"AttributeName": "gsi1pk", "KeyType": "HASH"},
                    {"AttributeName": "gsi1sk", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _user_keyed_table(ddb, name):
    return ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "user_sub", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "user_sub", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )


def _user_sk_table(ddb, name):
    return ddb.create_table(
        TableName=name,
        KeySchema=[
            {"AttributeName": "user_sub", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "user_sub", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _billing_table(ddb):
    return _simple_table(ddb, "billing")


def _alerts_table(ddb):
    return ddb.create_table(
        TableName="alerts",
        KeySchema=[
            {"AttributeName": "user_sub", "KeyType": "HASH"},
            {"AttributeName": "alert_id", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "user_sub", "AttributeType": "S"},
            {"AttributeName": "alert_id", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto not installed")
class LegalExportTests(unittest.TestCase):
    def setUp(self):
        self._moto = mock_aws()
        self._moto.start()
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self._holds = _legal_holds_table(ddb)
        self._exports = _simple_table(ddb, "legal_exports")
        self._profile = _user_keyed_table(ddb, "profiles")
        self._addresses = ddb.create_table(
            TableName="addresses",
            KeySchema=[
                {"AttributeName": "user_sub", "KeyType": "HASH"},
                {"AttributeName": "address_id", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "user_sub", "AttributeType": "S"},
                {"AttributeName": "address_id", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        self._billing = _billing_table(ddb)
        self._alerts = _alerts_table(ddb)
        self._data_requests = _simple_table(ddb, "data_requests")

        self._saved = {}
        for attr, tbl in [
            ("legal_holds", self._holds),
            ("legal_exports", self._exports),
            ("profile", self._profile),
            ("addresses", self._addresses),
            ("billing", self._billing),
            ("alerts", self._alerts),
            ("data_requests", self._data_requests),
        ]:
            self._saved[attr] = getattr(T, attr)
            object.__setattr__(T, attr, tbl)

        self._saved_flag = S.legal_export_enabled
        object.__setattr__(S, "legal_export_enabled", True)
        self._saved_subs = S.legal_export_authorized_subs
        object.__setattr__(S, "legal_export_authorized_subs", "")
        self._saved_dev = S.dev_mode
        object.__setattr__(S, "dev_mode", True)

    def tearDown(self):
        for attr, tbl in self._saved.items():
            object.__setattr__(T, attr, tbl)
        object.__setattr__(S, "legal_export_enabled", self._saved_flag)
        object.__setattr__(S, "legal_export_authorized_subs", self._saved_subs)
        object.__setattr__(S, "dev_mode", self._saved_dev)
        self._moto.stop()

    # ----- LEX-006: legal-hold service -----

    def test_place_and_is_user_on_hold_o1(self):
        from app.services import legal_hold as lh

        self.assertFalse(lh.is_user_on_hold("u_alice"))
        item = lh.place_hold(user_sub="u_alice", reason="subpoena", created_by="root")
        self.assertEqual(item["status"], "active")
        self.assertTrue(lh.is_user_on_hold("u_alice"))
        # GSI keys present on active hold
        self.assertEqual(item["gsi1pk"], "USER#u_alice")

    def test_release_stops_blocking(self):
        from app.services import legal_hold as lh

        item = lh.place_hold(user_sub="u_bob", reason="matter", created_by="root")
        self.assertTrue(lh.is_user_on_hold("u_bob"))
        released = lh.release_hold(item["hold_id"], released_by="root")
        self.assertEqual(released["status"], "released")
        self.assertFalse(lh.is_user_on_hold("u_bob"))
        # META row preserved (not deleted)
        self.assertIsNotNone(lh.get_hold(item["hold_id"]))

    def test_multiple_holds_and_expiry(self):
        from app.services import legal_hold as lh

        lh.place_hold(user_sub="u_x", reason="a", created_by="root")
        lh.place_hold(user_sub="u_x", reason="b", created_by="root")
        self.assertEqual(len(lh.list_holds_for_user("u_x")), 2)
        self.assertTrue(lh.is_user_on_hold("u_x"))
        # Expired hold is not live
        expired = lh.place_hold(user_sub="u_exp", reason="old", created_by="root", expires_at=1)
        self.assertFalse(lh.is_user_on_hold("u_exp"))
        self.assertFalse(lh._hold_is_live(expired))

    def test_place_hold_requires_fields(self):
        from app.services import legal_hold as lh

        with self.assertRaises(ValueError):
            lh.place_hold(user_sub="", reason="x", created_by="root")
        with self.assertRaises(ValueError):
            lh.place_hold(user_sub="u", reason="", created_by="root")

    # ----- LEX-007: deletion blocked while held (flag-gated) -----

    def test_deletion_blocked_while_held(self):
        from app.services import legal_hold as lh
        from app.services import gdpr_service

        # Seed a data_requests row so process_deletion can update status.
        T.data_requests.put_item(
            Item={"pk": "USER#u_held", "sk": "REQUEST#r1", "request_id": "r1", "status": "pending"}
        )
        lh.place_hold(user_sub="u_held", reason="hold", created_by="root")

        with patch.object(gdpr_service, "_write_audit"):
            result = gdpr_service.process_deletion("u_held", "r1")
        self.assertTrue(result.get("blocked"))
        self.assertEqual(result.get("reason"), "legal_hold")

    def test_deletion_no_op_when_flag_off(self):
        # With the flag OFF, process_deletion must NOT consult the hold service.
        from app.services import gdpr_service

        object.__setattr__(S, "legal_export_enabled", False)
        with patch("app.services.legal_hold.is_user_on_hold") as m:
            # delete_user_data is heavy; stub it so we only assert the guard path.
            with patch("app.services.account.delete_user_data", return_value={}):
                with patch.object(gdpr_service, "_write_audit"):
                    T.data_requests.put_item(
                        Item={"pk": "USER#u2", "sk": "REQUEST#r2", "request_id": "r2", "status": "pending"}
                    )
                    try:
                        gdpr_service.process_deletion("u2", "r2")
                    except Exception:
                        pass
            m.assert_not_called()

    # ----- LEX-009: intake validation -----

    def test_intake_requires_fields(self):
        from app.services import legal_export as le

        with self.assertRaises(ValueError):
            le.create_intake(matter_ref="", requesting_authority="FBI",
                             requested_by="root", legal_basis="warrant",
                             target_user_subs=["u"])
        with self.assertRaises(ValueError):
            le.create_intake(matter_ref="M1", requesting_authority="",
                             requested_by="root", legal_basis="warrant",
                             target_user_subs=["u"])
        with self.assertRaises(ValueError):
            le.create_intake(matter_ref="M1", requesting_authority="FBI",
                             requested_by="root", legal_basis="",
                             target_user_subs=["u"])
        with self.assertRaises(ValueError):
            le.create_intake(matter_ref="M1", requesting_authority="FBI",
                             requested_by="root", legal_basis="warrant",
                             target_user_subs=[])
        with self.assertRaises(ValueError):
            le.create_intake(matter_ref="M1", requesting_authority="FBI",
                             requested_by="root", legal_basis="warrant",
                             target_user_subs=["u"], data_types=["bogus"])

    # ----- LEX-010: scoped sealed builder + signed manifest -----

    def _seed_user_data(self, user_sub):
        T.profile.put_item(Item={"user_sub": user_sub, "email": f"{user_sub}@x.com",
                                 "session_token": "SECRET_TOKEN"})
        T.addresses.put_item(Item={"user_sub": user_sub, "address_id": "a1",
                                   "city": "NYC"})
        T.billing.put_item(Item={"pk": f"USER#{user_sub}", "sk": "PM#1",
                                 "card_number": "4242424242424242", "brand": "visa",
                                 "created_at": 1000})
        T.alerts.put_item(Item={"user_sub": user_sub, "alert_id": "al1",
                                "event": "login", "ts": 1000})

    def test_scoped_builder_redaction_and_signature(self):
        from app.services import legal_export as le

        self._seed_user_data("u_target")
        intake = le.create_intake(
            matter_ref="M-100", requesting_authority="State PD",
            requested_by="root", legal_basis="subpoena",
            target_user_subs=["u_target"],
            data_types=["profile", "addresses", "billing", "alerts"],
        )
        built = le.build_legal_package(intake)
        manifest = built["manifest"]

        # Manifest signature verifies
        self.assertTrue(le.verify_manifest_signature(manifest))

        # Tamper detection: altering a file's sha breaks the signature check
        tampered = dict(manifest)
        tampered_files = [dict(f) for f in tampered["files"]]
        tampered_files[0] = {**tampered_files[0], "sha256": "deadbeef"}
        tampered["files"] = tampered_files
        self.assertFalse(le.verify_manifest_signature(tampered))

        # Redaction: no secrets appear anywhere in the ZIP payload
        import io, zipfile
        zf = zipfile.ZipFile(io.BytesIO(built["zip_bytes"]))
        blob = b"".join(zf.read(n) for n in zf.namelist())
        self.assertNotIn(b"4242424242424242", blob)
        self.assertNotIn(b"SECRET_TOKEN", blob)
        # contains expected files
        names = zf.namelist()
        self.assertIn("manifest.json", names)
        self.assertIn("README.txt", names)
        self.assertTrue(any("users/u_target/profile.json" == n for n in names))

    def test_data_type_filter_excludes_out_of_scope(self):
        from app.services import legal_export as le

        self._seed_user_data("u_scope")
        intake = le.create_intake(
            matter_ref="M-200", requesting_authority="X", requested_by="root",
            legal_basis="warrant", target_user_subs=["u_scope"],
            data_types=["profile"],
        )
        built = le.build_legal_package(intake)
        import io, zipfile
        names = zipfile.ZipFile(io.BytesIO(built["zip_bytes"])).namelist()
        self.assertTrue(any("profile.json" in n for n in names))
        self.assertFalse(any("billing.json" in n for n in names))
        self.assertFalse(any("alerts.json" in n for n in names))

    def test_generate_uploads_and_completes(self):
        from app.services import legal_export as le

        self._seed_user_data("u_gen")
        intake = le.create_intake(
            matter_ref="M-300", requesting_authority="X", requested_by="root",
            legal_basis="warrant", target_user_subs=["u_gen"],
            data_types=["profile"],
        )
        fake_s3 = MagicMock()
        with patch("app.core.aws_clients.s3_client", return_value=fake_s3):
            updated = le.generate_package(intake["legal_export_id"])
        self.assertEqual(updated["status"], "completed")
        self.assertTrue(updated["package_sha256"])
        fake_s3.put_object.assert_called_once()
        _, kwargs = fake_s3.put_object.call_args
        self.assertEqual(kwargs["ServerSideEncryption"], "AES256")

    # ----- LEX-011/012: access control + audit -----

    def _ctx(self, role, sub="actor1"):
        return {"user_sub": sub, "role": role}

    def test_require_legal_rejects_admin_and_user(self):
        from app.routers import legal_export as router

        with self.assertRaises(Exception) as a:
            router._require_legal(self._ctx(Role.ADMIN))
        self.assertEqual(getattr(a.exception, "status_code", None), 403)

        with self.assertRaises(Exception) as u:
            router._require_legal(self._ctx(Role.USER))
        self.assertEqual(getattr(u.exception, "status_code", None), 403)

        # ROOT is permitted
        self.assertEqual(router._require_legal(self._ctx(Role.ROOT, "rootsub")), "rootsub")

    def test_require_legal_allowlist(self):
        from app.routers import legal_export as router

        object.__setattr__(S, "legal_export_authorized_subs", "legalguy, other")
        self.assertEqual(router._require_legal(self._ctx(Role.USER, "legalguy")), "legalguy")
        with self.assertRaises(Exception):
            router._require_legal(self._ctx(Role.USER, "nobody"))

    def test_flag_off_returns_404(self):
        from app.routers import legal_export as router

        object.__setattr__(S, "legal_export_enabled", False)
        with self.assertRaises(Exception) as e:
            router._require_legal(self._ctx(Role.ROOT))
        self.assertEqual(getattr(e.exception, "status_code", None), 404)

    def test_endpoints_emit_audit_events(self):
        from app.routers import legal_export as router

        self._seed_user_data("u_audit")
        events = []
        with patch.object(router, "audit_event", side_effect=lambda *a, **k: events.append((a, k))):
            ctx = self._ctx(Role.ROOT, "rootsub")
            # place hold
            hold = router.place_hold(router.PlaceHoldIn(user_sub="u_audit", reason="r"), ctx)
            # intake
            intake = router.create_export(router.LegalExportIntakeIn(
                matter_ref="M-9", requesting_authority="A", legal_basis="warrant",
                target_user_subs=["u_audit"], data_types=["profile"],
            ), ctx)
            # generate
            with patch("app.core.aws_clients.s3_client", return_value=MagicMock()):
                router.generate_export(intake["legal_export_id"], ctx)
            # download (presign returns a url)
            with patch.object(router.legal_export_svc, "get_download_url", return_value="http://x/y"):
                resp = router.download_export(intake["legal_export_id"], ctx)
        self.assertEqual(resp.status_code, 302)
        emitted = [a[0] for (a, k) in events]
        self.assertIn("legal_hold.placed", emitted)
        self.assertIn("legal_export.intake_created", emitted)
        self.assertIn("legal_export.generated", emitted)
        self.assertIn("legal_export.downloaded", emitted)


if __name__ == "__main__":
    unittest.main()
