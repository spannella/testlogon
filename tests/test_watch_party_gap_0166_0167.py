"""Regression tests for GAP-0166 and GAP-0167 (watch party hardening).

GAP-0166 — watch-party SSE must not share the broadcast-session namespace.
    Before the fix, ``watch_party`` published/subscribed against the shared
    ``_BROADCAST_SUBSCRIBERS`` dict in ``broadcast_sse`` using the raw
    ``party_id``, which collides with broadcast ``session_id`` keys. The new
    ``watch_party_sse`` wrappers prefix every key with ``"wp:"`` so the two
    namespaces are isolated.

GAP-0167 — ``participant_count`` must never go below zero.
    Before the fix, ``_update_participant_count`` issued an unconditional
    ``SET participant_count = participant_count + :d``; a decrement at 0 drove
    the counter negative. The fix adds a ``ConditionExpression`` floor guard so
    a spurious decrement at the floor is a no-op.

Fully offline. GAP-0166 uses in-process queues only. GAP-0167 uses moto-backed
DynamoDB (conditional-expression semantics match production). No real AWS.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover
    mock_aws = None


# ---------------------------------------------------------------------------
# GAP-0166: SSE namespace isolation
# ---------------------------------------------------------------------------

class TestWatchPartySseNamespaceGap0166(unittest.TestCase):
    def setUp(self):
        # Reset the shared in-memory subscriber dict for isolation.
        from app.services import broadcast_sse

        broadcast_sse._BROADCAST_SUBSCRIBERS.clear()
        self.addCleanup(broadcast_sse._BROADCAST_SUBSCRIBERS.clear)

    def test_watch_party_event_does_not_bleed_into_broadcast(self):
        """A watch-party publish must not reach a broadcast subscriber on the
        same logical ID.

        FAILS BEFORE FIX: both keys are identical, so the broadcast queue
        receives the watch-party event.
        """
        from app.services.broadcast_sse import broadcast_sse_subscribe
        from app.services.watch_party_sse import wp_sse_publish, wp_sse_subscribe, wp_sse_unsubscribe

        shared_id = "collide_id_123"

        broadcast_q = broadcast_sse_subscribe(shared_id)
        party_q = wp_sse_subscribe(shared_id)

        wp_sse_publish(shared_id, {"_type": "participant_joined", "user_sub": "u1"})

        self.assertFalse(party_q.empty(), "watch-party queue should have the event")
        self.assertTrue(
            broadcast_q.empty(),
            "GAP-0166: broadcast queue received a watch-party event — namespace collision",
        )

        wp_sse_unsubscribe(shared_id, party_q)

    def test_broadcast_event_does_not_bleed_into_watch_party(self):
        """A broadcast publish must not reach a watch-party subscriber."""
        from app.services.broadcast_sse import broadcast_sse_publish, broadcast_sse_subscribe
        from app.services.watch_party_sse import wp_sse_subscribe, wp_sse_unsubscribe

        shared_id = "collide_id_456"

        broadcast_q = broadcast_sse_subscribe(shared_id)
        party_q = wp_sse_subscribe(shared_id)

        broadcast_sse_publish(shared_id, {"_type": "stream_started"})

        self.assertFalse(broadcast_q.empty(), "broadcast queue should have the event")
        self.assertTrue(
            party_q.empty(),
            "GAP-0166: watch-party queue received a broadcast event — namespace collision",
        )

        wp_sse_unsubscribe(shared_id, party_q)


# ---------------------------------------------------------------------------
# GAP-0167: participant_count floor guard
# ---------------------------------------------------------------------------

def _watch_parties_table(ddb):
    return ddb.create_table(
        TableName="watch_parties",
        KeySchema=[{"AttributeName": "party_id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "party_id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestParticipantCountFloorGap0167(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _watch_parties_table(ddb)

        from app.services import watch_party

        self.stack.enter_context(
            patch.object(watch_party, "T", SimpleNamespace(watch_parties=self.table))
        )

    def _count(self, party_id: str) -> int:
        item = self.table.get_item(Key={"party_id": party_id})["Item"]
        return int(item["participant_count"])

    def test_decrement_at_zero_is_no_op(self):
        """Decrementing when count is already 0 must not go negative.

        FAILS BEFORE FIX: the unconditional update drives the count to -1.
        """
        from app.services.watch_party import _update_participant_count

        party_id = "wp_floor_001"
        self.table.put_item(
            Item={"party_id": party_id, "participant_count": 0, "updated_at": 0}
        )

        _update_participant_count(party_id, -1)

        self.assertEqual(
            self._count(party_id),
            0,
            "GAP-0167: participant_count must stay at 0, not go negative",
        )

    def test_decrement_from_positive_still_works(self):
        """Normal decrement from a positive count must still apply."""
        from app.services.watch_party import _update_participant_count

        party_id = "wp_floor_002"
        self.table.put_item(
            Item={"party_id": party_id, "participant_count": 3, "updated_at": 0}
        )

        _update_participant_count(party_id, -1)

        self.assertEqual(self._count(party_id), 2)

    def test_increment_still_works(self):
        """Increment path is unguarded and must still apply."""
        from app.services.watch_party import _update_participant_count

        party_id = "wp_floor_003"
        self.table.put_item(
            Item={"party_id": party_id, "participant_count": 1, "updated_at": 0}
        )

        _update_participant_count(party_id, 1)

        self.assertEqual(self._count(party_id), 2)

    def test_double_decrement_at_one_floors_at_zero(self):
        """Two decrements on a count of 1 must leave the count at 0, not -1."""
        from app.services.watch_party import _update_participant_count

        party_id = "wp_floor_004"
        self.table.put_item(
            Item={"party_id": party_id, "participant_count": 1, "updated_at": 0}
        )

        _update_participant_count(party_id, -1)
        _update_participant_count(party_id, -1)

        self.assertEqual(self._count(party_id), 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
