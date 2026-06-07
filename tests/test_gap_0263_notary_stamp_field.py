"""Offline regression test for GAP-0263 (KYC-007): ``notary_stamp`` field metadata.

The ``SignatureFieldType.NOTARY_STAMP`` enum value already existed, but the
signature packet *store* layer
(``app/services/signature_packet_store.py``) never persisted the notary-specific
metadata (``stamp_image_ref``, ``stamp_number``, ``stamp_expiry``, ``stamped_at``)
as discrete DynamoDB attributes. ``upsert_packet_field`` / ``fill_packet_field``
silently dropped that data, so a ``notary_stamp`` field was stored without any
stamp credentials — a compliance gap for high-risk KYC cases.

This test creates a draft packet, upserts a ``notary_stamp`` field with stamp
metadata, and fills it, asserting the metadata round-trips through DynamoDB. It
also exercises the S3-backed stamp-image upload helper and the past-expiry guard.

FAILS BEFORE FIX:
  * ``upsert_packet_field`` / ``fill_packet_field`` raise ``TypeError`` on the new
    keyword arguments (the parameters did not exist), and the stamp metadata was
    never written.

PASSES AFTER FIX:
  * stamp metadata is persisted and read back; past expiry is rejected;
    ``upload_stamp_image`` stores the image in S3 (moto) and returns its key.

Hermetic / offline:
  * A real in-memory DynamoDB table is created with moto (NO real AWS). The exact
    frozen ``T`` handles are patched via ``object.__setattr__``. The module-level
    ``_s3`` client is monkeypatched to a moto-backed client so no real S3 call is
    ever made. ``S.signature_pdf_enabled`` is enabled via ``object.__setattr__``
    (Settings ``S`` is frozen).
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_packets_table(ddb):
    return ddb.create_table(
        TableName="signature_packets",
        KeySchema=[{"AttributeName": "packet_id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "packet_id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_fields_table(ddb):
    return ddb.create_table(
        TableName="signature_packet_fields",
        KeySchema=[
            {"AttributeName": "packet_id", "KeyType": "HASH"},
            {"AttributeName": "field_id", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "packet_id", "AttributeType": "S"},
            {"AttributeName": "field_id", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestNotaryStampFieldGap0263(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())

        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.packets = _make_packets_table(ddb)
        self.fields = _make_fields_table(ddb)

        from app.core.settings import S
        from app.core.tables import T
        from app.services import signature_packet_store as store

        self.store = store
        self.T = T

        # Enable the signature feature flag (frozen Settings — use __setattr__).
        prev_flag = getattr(S, "signature_pdf_enabled", False)
        object.__setattr__(S, "signature_pdf_enabled", True)
        self.addCleanup(lambda: object.__setattr__(S, "signature_pdf_enabled", prev_flag))

        # Patch the exact frozen table handles (T is frozen — use __setattr__).
        prev_packets = T.signature_packets
        prev_fields = T.signature_packet_fields
        object.__setattr__(T, "signature_packets", self.packets)
        object.__setattr__(T, "signature_packet_fields", self.fields)
        self.addCleanup(lambda: object.__setattr__(T, "signature_packets", prev_packets))
        self.addCleanup(lambda: object.__setattr__(T, "signature_packet_fields", prev_fields))

        # Monkeypatch the module-level S3 client to a moto-backed client so no
        # real AWS S3 call leaks out.
        self._moto_s3 = boto3.client("s3", region_name="us-east-1")
        self._moto_s3.create_bucket(Bucket=store.STAMP_IMAGE_BUCKET)
        prev_s3 = store._s3
        store._s3 = self._moto_s3
        self.addCleanup(lambda: setattr(store, "_s3", prev_s3))

    def _make_draft_packet(self) -> str:
        from app.services.signature_packet_domain import SignaturePacketStatus

        packet_id = "sp_notarytest"
        self.packets.put_item(
            Item={
                "packet_id": packet_id,
                "owner_user_id": "owner_sub",
                "status": SignaturePacketStatus.DRAFT.value,
            }
        )
        return packet_id

    def test_upsert_notary_stamp_persists_metadata(self):
        from app.services.signature_packet_domain import SignatureFieldType

        packet_id = self._make_draft_packet()
        item = self.store.upsert_packet_field(
            packet_id=packet_id,
            field_id="notary_1",
            page=1,
            x=0.0,
            y=0.0,
            width=100.0,
            height=100.0,
            field_type=SignatureFieldType.NOTARY_STAMP,
            assigned_signer_id="admin_sub",
            required=True,
            stamp_number="NP-12345",
            stamp_expiry="2099-12-31",
            stamp_image_ref="kyc/stamps/sp_notarytest/notary_1/stamp.png",
        )
        self.assertEqual(item["field_type"], "notary_stamp")
        self.assertEqual(item["stamp_number"], "NP-12345")
        self.assertEqual(item["stamp_expiry"], "2099-12-31")
        self.assertEqual(item["stamp_image_ref"], "kyc/stamps/sp_notarytest/notary_1/stamp.png")

        # Round-trips through DynamoDB.
        stored = self.store.get_packet_field(packet_id, "notary_1")
        self.assertEqual(stored["stamp_number"], "NP-12345")
        self.assertEqual(stored["stamp_expiry"], "2099-12-31")
        self.assertEqual(stored["stamp_image_ref"], "kyc/stamps/sp_notarytest/notary_1/stamp.png")

    def test_upsert_notary_stamp_rejects_past_expiry(self):
        from app.services.signature_packet_domain import SignatureFieldType

        packet_id = self._make_draft_packet()
        with self.assertRaisesRegex(ValueError, "stamp_expiry is in the past"):
            self.store.upsert_packet_field(
                packet_id=packet_id,
                field_id="notary_exp",
                page=1,
                x=0.0,
                y=0.0,
                width=100.0,
                height=100.0,
                field_type=SignatureFieldType.NOTARY_STAMP,
                assigned_signer_id="admin_sub",
                required=True,
                stamp_number="NP-00001",
                stamp_expiry="2000-01-01",
            )

    def test_non_notary_field_unaffected(self):
        """Backward compatibility: a plain TEXT field stores no stamp metadata."""
        from app.services.signature_packet_domain import SignatureFieldType

        packet_id = self._make_draft_packet()
        item = self.store.upsert_packet_field(
            packet_id=packet_id,
            field_id="text_1",
            page=1,
            x=0.0,
            y=0.0,
            width=50.0,
            height=20.0,
            field_type=SignatureFieldType.TEXT,
            assigned_signer_id="admin_sub",
            required=False,
            # Even if stamp params are passed for a non-notary field, they are ignored.
            stamp_number="NP-IGNORED",
        )
        self.assertEqual(item["field_type"], "text")
        self.assertNotIn("stamp_number", item)
        self.assertNotIn("stamp_expiry", item)
        self.assertNotIn("stamp_image_ref", item)

    def test_fill_notary_stamp_writes_discrete_metadata(self):
        from app.services.signature_packet_domain import (
            SignatureFieldType,
            SignaturePacketStatus,
        )

        packet_id = self._make_draft_packet()
        self.store.upsert_packet_field(
            packet_id=packet_id,
            field_id="notary_fill",
            page=1,
            x=0.0,
            y=0.0,
            width=100.0,
            height=100.0,
            field_type=SignatureFieldType.NOTARY_STAMP,
            assigned_signer_id="admin_sub",
            required=True,
        )
        # Move the packet out of DRAFT so fill is allowed (fill only blocks COMPLETED).
        self.packets.update_item(
            Key={"packet_id": packet_id},
            UpdateExpression="SET #s = :sent",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":sent": SignaturePacketStatus.SENT.value},
        )

        result = self.store.fill_packet_field(
            packet_id=packet_id,
            field_id="notary_fill",
            value="notary:NP-12345",
            filled_by_signer_id="admin_sub",
            capture_mode="notary_stamp",
            stamp_image_ref="kyc/stamps/sp_notarytest/notary_fill/stamp.png",
            stamp_number="NP-12345",
            stamp_expiry="2099-12-31",
        )
        self.assertEqual(result["stamp_image_ref"], "kyc/stamps/sp_notarytest/notary_fill/stamp.png")
        self.assertEqual(result["stamp_number"], "NP-12345")
        self.assertEqual(result["stamp_expiry"], "2099-12-31")
        self.assertTrue(result.get("stamped_at"))

    def test_upload_stamp_image_uses_s3_and_returns_key(self):
        packet_id = self._make_draft_packet()
        key = self.store.upload_stamp_image(
            packet_id=packet_id,
            field_id="notary_1",
            image_bytes=b"\x89PNG-fake-stamp",
        )
        self.assertEqual(key, f"kyc/stamps/{packet_id}/notary_1/stamp.png")
        # Object actually exists in the (moto) bucket.
        obj = self._moto_s3.get_object(Bucket=self.store.STAMP_IMAGE_BUCKET, Key=key)
        self.assertEqual(obj["Body"].read(), b"\x89PNG-fake-stamp")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
