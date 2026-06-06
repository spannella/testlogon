"""Offline regression test for GAP-0313 (MSG-004).

`presence_heartbeat` in ``app/routers/messaging.py`` gates an expensive SSE
fan-out (`_fanout_presence_update`) on a per-user cooldown
(``PRESENCE_SSE_COOLDOWN_SEC`` = 60s). The original implementation did a
read-then-write: it read the prior presence item, computed
``prev_last_seen = ... if prev_item else 0``, did a plain ``put_item`` (NO
ConditionExpression), and fired the fan-out whenever
``ts - prev_last_seen >= PRESENCE_SSE_COOLDOWN_SEC``.

That was vulnerable to:
  (a) cold start / TTL-expired item → ``prev_last_seen = 0`` →
      ``ts - 0 >= 60`` is always true → restart flood; and
  (b) multi-worker: each worker reads stale state and fires its own
      cooldown-less burst (the read + put are not atomic).

The fix makes the cooldown atomic: a conditional ``UpdateItem`` updates a
dedicated ``last_sse_at`` attribute only when
``attribute_not_exists(last_sse_at) OR last_sse_at <= ts - cooldown``, and the
fan-out fires ONLY when that conditional write succeeds. ``last_seen_at`` keeps
updating on every heartbeat (TTL / presence freshness) regardless.

Fully offline: a real in-memory DynamoDB presence table is created with moto
(no real AWS) and bound to the exact ``messaging.tbl_presence`` handle the code
uses. ``_fanout_presence_update`` is patched to a counter so we can assert how
many times the fan-out fires. The (sync) route handler is called directly (the
FastAPI TestClient is unusable in this repo).
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None

import app.routers.messaging as messaging


def _make_presence_table(ddb):
    """Mirror the UserPresence table from scripts/local-ddb-init.py (hash=user_id)."""
    return ddb.create_table(
        TableName="UserPresence_test",
        KeySchema=[{"AttributeName": "user_id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "user_id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto not installed")
class PresenceCooldownAtomicTest(unittest.TestCase):
    USER = "u_alice"

    def setUp(self):
        self._stack = ExitStack()
        self.addCleanup(self._stack.close)

        self._aws = self._stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_presence_table(ddb)

        # Bind moto table to the EXACT module-level handle the code uses.
        self._stack.enter_context(
            patch.object(messaging, "tbl_presence", self.table)
        )

        # Count fan-out calls; never touch the real (DDB-heavy) fan-out.
        self.fanout_calls: list[tuple] = []
        self._stack.enter_context(
            patch.object(
                messaging,
                "_fanout_presence_update",
                side_effect=lambda *a, **k: self.fanout_calls.append((a, k)),
            )
        )

        # Stub collaborators irrelevant to the cooldown gate.
        self._stack.enter_context(
            patch.object(messaging, "_enforce_messaging_internal_entitlement", lambda **k: None)
        )
        self._stack.enter_context(
            patch.object(messaging, "_handle_helpdesk_presence_event", lambda **k: {"action": "none"})
        )
        self._stack.enter_context(
            patch.object(messaging, "audit_event", lambda *a, **k: None)
        )

        # Controllable clock.
        self._now = {"t": 1_000_000}
        self._stack.enter_context(
            patch.object(messaging, "now_ts", lambda: self._now["t"])
        )

    def _beat(self):
        inp = messaging.PresenceHeartbeatIn(device="web", status="online")
        return messaging.presence_heartbeat(inp=inp, request=None, x_request_id=None, user_id=self.USER)

    # ---- tests ----

    def test_cold_start_single_heartbeat_fires_once(self):
        out = self._beat()
        self.assertTrue(out["ok"])
        self.assertEqual(len(self.fanout_calls), 1, "cold-start heartbeat should fan out exactly once")

    def test_two_back_to_back_heartbeats_fire_only_once(self):
        # Two sequential beats within the cooldown window: after the fix the
        # atomic conditional write lets only the first fan out.
        self._beat()
        self._now["t"] += 1  # still well within the 60s cooldown
        self._beat()
        self.assertEqual(
            len(self.fanout_calls), 1,
            "second heartbeat within cooldown window must NOT fan out again",
        )

    def test_heartbeat_after_cooldown_fires_again(self):
        self._beat()
        self.assertEqual(len(self.fanout_calls), 1)
        # Advance past the cooldown window.
        self._now["t"] += messaging.PRESENCE_SSE_COOLDOWN_SEC + 1
        self._beat()
        self.assertEqual(
            len(self.fanout_calls), 2,
            "heartbeat after cooldown window should fan out again",
        )

    def test_stale_last_seen_but_recent_sse_does_not_reflood(self):
        # Deterministic multi-worker / cold-start discriminator.
        #
        # Seed a presence row whose `last_seen_at` is STALE (older than the
        # cooldown) but whose `last_sse_at` is RECENT (a fan-out just fired).
        # This is exactly the cross-worker state: one worker already fanned out
        # (advancing last_sse_at) while last_seen_at lags. The OLD read-then-put
        # code gated on `last_seen_at` only — ts - stale_last_seen >= 60 → it
        # would (wrongly) re-fan-out. The fix gates on `last_sse_at`, so this
        # beat is correctly suppressed.
        now = self._now["t"]
        self.table.put_item(
            Item={
                "user_id": self.USER,
                "last_seen_at": now - (messaging.PRESENCE_SSE_COOLDOWN_SEC + 5),
                "last_sse_at": now - 2,  # a fan-out fired 2s ago
                "status": "online",
                "ttl": now + messaging.PRESENCE_TTL_SEC,
            }
        )
        self._beat()
        self.assertEqual(
            len(self.fanout_calls), 0,
            "a recent SSE (last_sse_at) must suppress fan-out even when "
            "last_seen_at is stale",
        )

    def test_last_seen_updates_every_beat_even_when_no_fanout(self):
        # last_seen_at must stay fresh (TTL/presence freshness) on the
        # cooldown-suppressed beat, even though no fan-out fires.
        self._beat()
        self._now["t"] += 5
        self._beat()
        self.assertEqual(len(self.fanout_calls), 1)  # cooldown suppressed 2nd

        item = self.table.get_item(Key={"user_id": self.USER}).get("Item")
        self.assertIsNotNone(item)
        self.assertEqual(int(item["last_seen_at"]), self._now["t"], "last_seen_at must update every beat")
        self.assertEqual(int(item["ttl"]), self._now["t"] + messaging.PRESENCE_TTL_SEC)
        # last_sse_at stays at the time of the beat that actually fanned out.
        self.assertEqual(int(item["last_sse_at"]), self._now["t"] - 5)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
