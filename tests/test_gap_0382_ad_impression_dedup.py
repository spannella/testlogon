"""Offline regression test for GAP-0382 (VOD-018 §6.2).

`app/services/ad_placement.record_ad_impression` wrote every call unconditionally
to the AdImpressions table with a timestamp-bearing sort key and, on
``event_type=="complete"``, credited the creator via ``_credit_ad_revenue`` every
single time. Because ``now_ts()`` returns integer SECONDS, a single authenticated
user could POST ``event_type=complete`` repeatedly (different seconds) and inflate
creator ad revenue without bound.

The fix adds a DDB conditional write (``attribute_not_exists(pk)``) keyed on
``AD_DEDUP#{date}#USER#{user}#VIDEO#{video}#SLOT#{slot}`` so revenue is credited
exactly ONCE per (user, video, slot, calendar day). Duplicate ``complete`` events
record the impression but do NOT re-credit.

Hermetic: a real in-memory DynamoDB AdImpressions table is created with moto and
bound to the EXACT frozen ``ad_placement.T`` handle via ``object.__setattr__``
(restored on cleanup). ``_credit_ad_revenue`` is patched to a counting spy so the
test asserts on credit COUNT without exercising the billing/ledger path.

FAILS BEFORE FIX: every ``complete`` calls ``_credit_ad_revenue`` → count > 1.
PASSES AFTER FIX: duplicate ``complete`` events are deduped → count stays 1.
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


def _make_ad_impressions_table(ddb):
    """Mirror the AdImpressions TableDef in scripts/local-ddb-init.py."""
    return ddb.create_table(
        TableName="AdImpressions",
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


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestAdImpressionDedupGap0382(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_ad_impressions_table(ddb)

        from app.services import ad_placement

        self.ad_placement = ad_placement

        # Bind the frozen T.ad_impressions handle to the moto table, restore after.
        self._orig_table = ad_placement.T.ad_impressions
        object.__setattr__(ad_placement.T, "ad_impressions", self.table)
        self.addCleanup(
            lambda: object.__setattr__(
                ad_placement.T, "ad_impressions", self._orig_table
            )
        )

        # Disable fraud detection so the path is purely the dedup/credit logic.
        # S is a frozen dataclass → use object.__setattr__ and restore on cleanup.
        self._orig_fraud = getattr(
            ad_placement.S, "ad_fraud_detection_enabled", True
        )
        object.__setattr__(ad_placement.S, "ad_fraud_detection_enabled", False)
        self.addCleanup(
            lambda: object.__setattr__(
                ad_placement.S, "ad_fraud_detection_enabled", self._orig_fraud
            )
        )

        # Don't hit the real video_metadata counter / get_video; we only care
        # about the credit count, which we spy on directly.
        self._credit_calls = []

        def _fake_credit(*, video_id, event_id, ts):
            self._credit_calls.append((video_id, event_id, ts))

        self.stack.enter_context(
            patch.object(ad_placement, "_credit_ad_revenue", _fake_credit)
        )
        # video_metadata is also a frozen handle pointing at no-such-table here;
        # the counter update is best-effort (try/except) so it harmlessly fails.

    def _record(self, *, video_id, user_id, slot_index, slot_type="pre_roll"):
        return self.ad_placement.record_ad_impression(
            video_id=video_id,
            user_id=user_id,
            slot_type=slot_type,
            slot_index=slot_index,
            creative_id="dev_ad_preroll_15s",
            event_type="complete",
        )

    def test_complete_credits_once_per_user_video_slot_day(self):
        """First complete credits; second identical complete (same day) does NOT."""
        r1 = self._record(video_id="v1", user_id="bob", slot_index=0)
        self.assertTrue(r1["ok"])
        self.assertEqual(len(self._credit_calls), 1, "first complete must credit")

        # Identical complete, same day → deduped, no second credit.
        r2 = self._record(video_id="v1", user_id="bob", slot_index=0)
        self.assertTrue(r2["ok"], "API still returns ok on a duplicate")
        self.assertEqual(
            len(self._credit_calls), 1,
            "duplicate complete must NOT credit again (GAP-0382 dedup)",
        )

        # A third identical complete is still deduped.
        self._record(video_id="v1", user_id="bob", slot_index=0)
        self.assertEqual(len(self._credit_calls), 1)

    def test_different_user_slot_video_each_credited(self):
        """Distinct (user|slot|video) tuples each get an independent credit."""
        self._record(video_id="v1", user_id="alice", slot_index=0)
        self.assertEqual(len(self._credit_calls), 1)

        # Different user, same video/slot → credited.
        self._record(video_id="v1", user_id="bob", slot_index=0)
        self.assertEqual(len(self._credit_calls), 2)

        # Same user, different slot → credited.
        self._record(video_id="v1", user_id="bob", slot_index=1)
        self.assertEqual(len(self._credit_calls), 3)

        # Same user/slot, different video → credited.
        self._record(video_id="v2", user_id="bob", slot_index=1)
        self.assertEqual(len(self._credit_calls), 4)

    def test_different_day_resets_dedup(self):
        """A complete on a later UTC day re-credits the same user/video/slot."""
        # ts for 2026-01-01 and 2026-01-02 (UTC midnights).
        day1 = 1767225600  # 2026-01-01T00:00:00Z
        day2 = 1767312000  # 2026-01-02T00:00:00Z

        with patch.object(self.ad_placement, "now_ts", return_value=day1):
            self._record(video_id="v1", user_id="bob", slot_index=0)
        self.assertEqual(len(self._credit_calls), 1)

        # Same day again → deduped.
        with patch.object(self.ad_placement, "now_ts", return_value=day1 + 30):
            self._record(video_id="v1", user_id="bob", slot_index=0)
        self.assertEqual(len(self._credit_calls), 1)

        # Next day → credited again.
        with patch.object(self.ad_placement, "now_ts", return_value=day2):
            self._record(video_id="v1", user_id="bob", slot_index=0)
        self.assertEqual(len(self._credit_calls), 2)


if __name__ == "__main__":
    unittest.main()
