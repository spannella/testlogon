from __future__ import annotations

import json
import unittest
from pathlib import Path

from pydantic import ValidationError

from app.services.messaging_compliance_archive_schema import (
    ARCHIVE_EVENT_SCHEMA_VERSION,
    ARCHIVE_EVENT_TAXONOMY,
    MessagingArchiveEvent,
    build_archive_event,
    canonical_serialize_payload,
    compute_payload_hash,
)


class TestMessagingComplianceArchiveSchema(unittest.TestCase):
    def test_canonical_serialization_and_hash_are_deterministic(self):
        payload_a = {"b": 2, "a": 1, "nested": {"z": 9, "x": 1}}
        payload_b = {"nested": {"x": 1, "z": 9}, "a": 1, "b": 2}

        self.assertEqual(canonical_serialize_payload(payload_a), canonical_serialize_payload(payload_b))
        self.assertEqual(compute_payload_hash(payload_a), compute_payload_hash(payload_b))


    def test_canonical_serialization_matches_expected_exact_json(self):
        payload = {
            "z": [3, 2, 1],
            "a": {"emoji": "🙂", "text": "héllo"},
            "m": True,
        }
        canonical = canonical_serialize_payload(payload)
        self.assertEqual(
            canonical,
            '{"a":{"emoji":"🙂","text":"héllo"},"m":true,"z":[3,2,1]}',
        )
        self.assertEqual(
            compute_payload_hash(payload),
            "3fe03639313d202f8e147f34a4985574e3ee24e985d7c2df2e7541ac7f9ebf4e",
        )

    def test_canonical_hash_is_stable_across_equivalent_payload_construction_orders(self):
        payload_1 = {
            "alpha": {"x": 1, "y": ["b", "a"]},
            "beta": "value",
            "gamma": 42,
        }
        payload_2 = {
            "gamma": 42,
            "beta": "value",
            "alpha": {"y": ["b", "a"], "x": 1},
        }
        self.assertEqual(compute_payload_hash(payload_1), compute_payload_hash(payload_2))

    def test_build_archive_event_sets_valid_payload_hash(self):
        evt = build_archive_event(
            event_id="evt_1",
            event_ts=1700000000,
            tenant_id="t1",
            conversation_id="c1",
            message_id="m1",
            actor_user_id="u1",
            effective_user_id="u1",
            event_type="message.sent",
            payload={"text": "hello", "meta": {"lang": "en"}},
            prev_hash="0" * 64,
        )

        self.assertEqual(evt.schema_version, ARCHIVE_EVENT_SCHEMA_VERSION)
        self.assertEqual(evt.payload_hash, compute_payload_hash(evt.payload))

    def test_payload_hash_mismatch_is_rejected(self):
        with self.assertRaises(ValidationError):
            MessagingArchiveEvent(
                schema_version=1,
                event_id="evt_2",
                event_ts=1700000001,
                tenant_id="t1",
                conversation_id="c1",
                message_id="m2",
                actor_user_id="u1",
                effective_user_id="u1",
                event_type="message.sent",
                payload={"text": "hello"},
                payload_hash="f" * 64,
                prev_hash="0" * 64,
            )

    def test_event_type_outside_taxonomy_is_rejected(self):
        with self.assertRaises(ValidationError):
            build_archive_event(
                event_id="evt_3",
                event_ts=1700000002,
                tenant_id="t1",
                conversation_id="c1",
                message_id="m3",
                actor_user_id="u1",
                effective_user_id="u1",
                event_type="message.unknown",
                payload={"text": "nope"},
                prev_hash="0" * 64,
            )

    def test_json_schema_file_is_versioned_and_taxonomy_aligned(self):
        schema_path = Path("docs/messaging-compliance-archive-event-schema-v1.json")
        self.assertTrue(schema_path.exists())

        schema_doc = json.loads(schema_path.read_text())
        self.assertEqual(schema_doc["properties"]["schema_version"]["const"], ARCHIVE_EVENT_SCHEMA_VERSION)
        self.assertEqual(tuple(schema_doc["properties"]["event_type"]["enum"]), ARCHIVE_EVENT_TAXONOMY)


if __name__ == "__main__":
    unittest.main()
