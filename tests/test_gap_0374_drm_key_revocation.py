"""Offline regression tests for GAP-0374 (VOD-010 §4.3 / §6.5-6.7).

GAP-0374 — there were NO admin DRM key revocation endpoints in
``app/routers/vod_drm.py`` (only the GET key-serve + GET info handlers). A
compromised AES-128 DRM key could not be invalidated without redeploying.

The fix adds:
  - POST /v1/vod/drm/keys/revoke           (admin-only) — revoke one key
  - POST /v1/vod/drm/keys/{asset_id}/revoke-all (admin-only) — revoke all
revocation records persisted to a new ContentKeys DynamoDB table, plus a
serve-time check in GET /key/{key_id} that returns 410 for a revoked key.

Fully offline / hermetic:
  - A real in-memory ContentKeys table is created with moto (no real AWS) and
    ``vod_drm_keys.T`` is patched to point at it (the router calls service
    helpers, which use that handle).
  - The FastAPI TestClient is unusable in this repo, so the sync route handlers
    are called directly with a fake admin auth context.
  - The entitlement-token verification is stubbed so the GET serve path is
    reachable without minting a real signed token.
  - Frozen ``S`` is mutated via ``object.__setattr__`` and restored on cleanup.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None

from fastapi import HTTPException


def _make_content_keys_table(ddb):
    """Create the ContentKeys table mirroring scripts/local-ddb-init.py."""
    return ddb.create_table(
        TableName="ContentKeys",
        KeySchema=[{"AttributeName": "key_id", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "key_id", "AttributeType": "S"},
            {"AttributeName": "asset_id", "AttributeType": "S"},
            {"AttributeName": "tenant_id", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByAssetCreatedAt",
                "KeySchema": [
                    {"AttributeName": "asset_id", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "ByTenantCreatedAt",
                "KeySchema": [
                    {"AttributeName": "tenant_id", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


ASSET = "asset_abc"
TENANT = "tenant_t1"


def _admin_ctx():
    return SimpleNamespace(sub="admin_sub", role="ROOT", admin_profile=None)


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestDrmKeyRevocationGap0374(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_content_keys_table(ddb)

        from app.services import vod_drm_keys
        from app.routers import vod_drm
        from app.core.settings import S

        self.vod_drm_keys = vod_drm_keys
        self.vod_drm = vod_drm
        self.S = S

        # Bind the service's table handle to the moto table.
        self.stack.enter_context(
            patch.object(vod_drm_keys, "T", SimpleNamespace(content_keys=self.table))
        )

        # Ensure DRM is enabled + a deterministic key root for derivation.
        for attr, val in (("vod_drm_enabled", True), ("vod_drm_key_root", "test-root-secret")):
            old = getattr(S, attr)
            object.__setattr__(S, attr, val)
            self.addCleanup(lambda a=attr, o=old: object.__setattr__(S, a, o))

        # Stub entitlement verification so the GET serve path is reachable.
        def _fake_validate(*, token, expected_audience):
            return {"asset_id": ASSET, "tenant_id": TENANT}

        self.stack.enter_context(
            patch.object(vod_drm, "validate_playback_entitlement", _fake_validate)
        )

        self.key_id = vod_drm_keys.derive_key_id(ASSET, TENANT)

    # ---- helper: call the serve handler, return (status, body) ----
    def _serve(self, key_id):
        try:
            resp = self.vod_drm.get_decryption_key(
                key_id=key_id, asset=ASSET, token="tok", tenant=TENANT
            )
            return 200, resp
        except HTTPException as exc:
            return exc.status_code, exc.detail

    # ---- Test 1: admin can revoke; non-admin is blocked ----
    def test_admin_revoke_writes_record_and_non_admin_blocked(self):
        # Serve works before revocation.
        status, _ = self._serve(self.key_id)
        self.assertEqual(status, 200, "key should serve before revocation")

        # Admin revoke writes a record.
        body = self.vod_drm.RevokeKeyIn(
            key_id=self.key_id, asset_id=ASSET, tenant_id=TENANT, reason="leaked"
        )
        result = self.vod_drm.revoke_drm_key(body=body, actor=_admin_ctx())
        self.assertTrue(result["revoked"])
        self.assertEqual(result["key_id"], self.key_id)

        item = self.table.get_item(Key={"key_id": self.key_id}).get("Item")
        self.assertIsNotNone(item, "revocation record must be persisted")
        self.assertTrue(item["revoked"])
        self.assertEqual(item["revoked_by"], "admin_sub")

        # Non-admin (USER) is rejected by the admin dependency (403).
        # The dependency runs as part of the route; emulate by invoking the
        # underlying gate directly.
        from app.auth.policy import require_roles
        from app.auth.roles import Role

        with self.assertRaises(HTTPException) as cm:
            require_roles(SimpleNamespace(role="USER", admin_profile=None), {Role.ADMIN, Role.ROOT})
        self.assertEqual(cm.exception.status_code, 403)

    # ---- Test 2: after revoke, GET key is refused (410) ----
    def test_serve_refused_after_revoke(self):
        status, _ = self._serve(self.key_id)
        self.assertEqual(status, 200)

        body = self.vod_drm.RevokeKeyIn(key_id=self.key_id, asset_id=ASSET, tenant_id=TENANT)
        self.vod_drm.revoke_drm_key(body=body, actor=_admin_ctx())

        status, detail = self._serve(self.key_id)
        self.assertEqual(status, 410, "revoked key must no longer serve")
        self.assertEqual(detail["code"], "key_revoked")

    # ---- Test 3: revoke-all revokes every key for the asset ----
    def test_revoke_all_revokes_every_key_for_asset(self):
        # A different rotation slot yields a different key_id for the same asset.
        other_key_id = self.vod_drm_keys.derive_key_id(ASSET, TENANT, key_slot=5)
        self.assertNotEqual(other_key_id, self.key_id)

        # Both serve before revoke-all (validate_key_id only checks slot 0, so we
        # check the asset-wide marker directly via is_key_revoked for the slot-5
        # key; the slot-0 key uses the full serve path).
        status, _ = self._serve(self.key_id)
        self.assertEqual(status, 200)
        self.assertFalse(self.vod_drm_keys.is_key_revoked(other_key_id, ASSET, TENANT))

        body = self.vod_drm.RevokeAllIn(tenant_id=TENANT, reason="rotate-all")
        result = self.vod_drm.revoke_all_drm_keys(asset_id=ASSET, body=body, actor=_admin_ctx())
        self.assertTrue(result["revoked_all"])

        # Asset-wide marker persisted.
        self.assertTrue(self.vod_drm_keys.is_asset_revoked(ASSET, TENANT))

        # The slot-0 key is now refused at serve time.
        status, detail = self._serve(self.key_id)
        self.assertEqual(status, 410)
        self.assertEqual(detail["code"], "key_revoked")

        # Any other derived key (slot 5) for the same asset is also revoked.
        self.assertTrue(self.vod_drm_keys.is_key_revoked(other_key_id, ASSET, TENANT))

        # A key for a DIFFERENT asset is unaffected.
        self.assertFalse(self.vod_drm_keys.is_asset_revoked("other_asset", TENANT))

    # ---- Test 4: revoke by (asset_id, tenant_id) without key_id ----
    def test_revoke_by_asset_tenant_derives_key_id(self):
        body = self.vod_drm.RevokeKeyIn(asset_id=ASSET, tenant_id=TENANT)
        result = self.vod_drm.revoke_drm_key(body=body, actor=_admin_ctx())
        self.assertEqual(result["key_id"], self.key_id)
        status, detail = self._serve(self.key_id)
        self.assertEqual(status, 410)

    def test_revoke_missing_identity_400(self):
        body = self.vod_drm.RevokeKeyIn()
        with self.assertRaises(HTTPException) as cm:
            self.vod_drm.revoke_drm_key(body=body, actor=_admin_ctx())
        self.assertEqual(cm.exception.status_code, 400)


if __name__ == "__main__":
    unittest.main()
