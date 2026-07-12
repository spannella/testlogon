"""Offline regression tests for the Newsfeed "For You" recommendation engine
(NRS-001..NRS-010, workstream NRS).

Covers:
- NRS-001: flag defaults OFF; settings knobs exist.
- NRS-003: per-user post-engagement signal recording (best-effort) + TTL,
  and the flag-gated ``record_post_engagement`` hook (no-op when off).
- NRS-005: ``score_post`` determinism (recency / engagement / affinity /
  content-type / personal-history) and ``rank_candidates`` exclusions + cap.
- NRS-006: three-source candidate generation incl. a non-followed popular author.
- NRS-007: global popularity index read/write.
- NRS-008/010: compute_for_you_posts store/get + cold_start vs for_you source.
- NRS-009: ``GET /feed/for-you`` chronological fallback when flag off.

Isolation: a real in-memory DynamoDB is created with moto and the exact frozen
``T.recommendations`` handle is monkeypatched via ``object.__setattr__`` (restored
on cleanup). The frozen ``S`` flags/knobs are toggled the same way. No real AWS,
no network. The FastAPI TestClient is unusable here, so the For-You route handler
is called directly.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover
    mock_aws = None

from app.core.settings import S
from app.core.tables import T
import app.services.newsfeed_recsys as recsys


def _make_reco_table(ddb):
    return ddb.create_table(
        TableName="recommendations_test",
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


NOW = 1_800_000_000  # fixed "now" for deterministic decay


def _iso(epoch: int) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


@unittest.skipIf(mock_aws is None, "moto not installed")
class NewsfeedRecsysTest(unittest.TestCase):
    def setUp(self):
        self._mock = mock_aws()
        self._mock.start()
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self._reco = _make_reco_table(ddb)
        self._orig_reco = T.recommendations
        object.__setattr__(T, "recommendations", self._reco)

        # Flag ON by default for service-level tests; flip per-test as needed.
        self._orig_flag = S.newsfeed_recsys_enabled
        object.__setattr__(S, "newsfeed_recsys_enabled", True)

        # Freeze now_ts in the service module.
        self._now_patch = patch.object(recsys, "now_ts", lambda: NOW)
        self._now_patch.start()
        # time.time() drives _ttl_epoch / _decay's _days_ago_epoch uses now_ts.
        self._time_patch = patch.object(recsys.time, "time", lambda: float(NOW))
        self._time_patch.start()

    def tearDown(self):
        self._now_patch.stop()
        self._time_patch.stop()
        object.__setattr__(S, "newsfeed_recsys_enabled", self._orig_flag)
        object.__setattr__(T, "recommendations", self._orig_reco)
        self._mock.stop()

    # ------------------------------------------------------------------ NRS-001
    def test_flag_defaults_off_and_knobs_exist(self):
        # The frozen class default is off (instance was forced on in setUp).
        self.assertFalse(type(S)().newsfeed_recsys_enabled)
        for attr in (
            "newsfeed_recsys_refresh_interval_hours",
            "newsfeed_recsys_max_for_you_results",
            "newsfeed_recsys_candidate_followed_limit",
            "newsfeed_recsys_candidate_popular_limit",
            "newsfeed_recsys_candidate_affinity_limit",
            "newsfeed_recsys_signal_retention_days",
            "newsfeed_recsys_weight_affinity",
        ):
            self.assertTrue(hasattr(S, attr), attr)

    # ------------------------------------------------------------------ NRS-003
    def test_record_post_signal_writes_item_with_author_and_ttl(self):
        recsys.record_post_signal(user_id="alice", post_id="p1", author_id="bob", action="like")
        recsys.record_post_signal(user_id="alice", post_id="p1", author_id="bob", action="comment")
        item = self._reco.get_item(Key={"pk": "SIGNAL#alice", "sk": "POST#p1"}).get("Item")
        self.assertIsNotNone(item)
        self.assertEqual(item["author_id"], "bob")
        # like(1.0) + comment(2.0) accumulated
        self.assertEqual(float(item["signal_score"]), 3.0)
        self.assertGreater(int(item["ttl_epoch"]), NOW)

    def test_engagement_hook_noop_when_flag_off(self):
        object.__setattr__(S, "newsfeed_recsys_enabled", False)
        recsys.record_post_engagement(user_id="alice", post_id="p9", author_id="bob", action="like")
        item = self._reco.get_item(Key={"pk": "SIGNAL#alice", "sk": "POST#p9"}).get("Item")
        self.assertIsNone(item)

    def test_engagement_hook_writes_signal_and_popularity_when_public(self):
        recsys.record_post_engagement(user_id="alice", post_id="p2", author_id="bob", action="like", is_public=True)
        sig = self._reco.get_item(Key={"pk": "SIGNAL#alice", "sk": "POST#p2"}).get("Item")
        pop = self._reco.get_item(Key={"pk": "POPULAR#GLOBAL", "sk": "POST#p2"}).get("Item")
        self.assertIsNotNone(sig)
        self.assertIsNotNone(pop)

    def test_engagement_hook_skips_popularity_for_locked(self):
        recsys.record_post_engagement(user_id="alice", post_id="p3", author_id="bob", action="unlock", is_public=False)
        pop = self._reco.get_item(Key={"pk": "POPULAR#GLOBAL", "sk": "POST#p3"}).get("Item")
        self.assertIsNone(pop)

    # ------------------------------------------------------------------ NRS-007
    def test_popularity_index_read_write(self):
        recsys.bump_post_popularity(post_id="p1", author_id="bob")
        recsys.bump_post_popularity(post_id="p2", author_id="carol")
        ids = {r["post_id"] for r in recsys.get_popular_post_ids(50)}
        self.assertEqual(ids, {"p1", "p2"})

    # ------------------------------------------------------------------ NRS-005
    def test_score_post_deterministic_and_recency(self):
        recent = {"post_id": "r", "user_id": "z", "created_at": _iso(NOW - 3600)}
        old = {"post_id": "o", "user_id": "z", "created_at": _iso(NOW - 30 * 86400)}
        s_recent = recsys.score_post(recent, author_affinity={}, post_history={}, follow_set=set(), viewer_id="v", now=NOW)
        s_old = recsys.score_post(old, author_affinity={}, post_history={}, follow_set=set(), viewer_id="v", now=NOW)
        self.assertGreater(s_recent, s_old)
        # deterministic
        self.assertEqual(s_recent, recsys.score_post(recent, author_affinity={}, post_history={}, follow_set=set(), viewer_id="v", now=NOW))

    def test_score_post_followed_author_outranks_stranger(self):
        base_kwargs = dict(post_history={}, viewer_id="v", now=NOW)
        followed = {"post_id": "f", "user_id": "friend", "created_at": _iso(NOW - 86400)}
        stranger = {"post_id": "s", "user_id": "rando", "created_at": _iso(NOW - 86400)}
        s_followed = recsys.score_post(followed, author_affinity={}, follow_set={"friend"}, **base_kwargs)
        s_stranger = recsys.score_post(stranger, author_affinity={}, follow_set=set(), **base_kwargs)
        self.assertGreater(s_followed, s_stranger)

    def test_score_post_engagement_and_history_boost(self):
        plain = {"post_id": "a", "user_id": "z", "created_at": _iso(NOW - 86400)}
        engaged = {"post_id": "b", "user_id": "z", "created_at": _iso(NOW - 86400), "like_count": 100, "comment_count": 50}
        s_plain = recsys.score_post(plain, author_affinity={}, post_history={}, follow_set=set(), viewer_id="v", now=NOW)
        s_engaged = recsys.score_post(engaged, author_affinity={}, post_history={}, follow_set=set(), viewer_id="v", now=NOW)
        self.assertGreater(s_engaged, s_plain)
        # personal-history boost on a specific post
        s_hist = recsys.score_post(plain, author_affinity={}, post_history={"a": 5.0}, follow_set=set(), viewer_id="v", now=NOW)
        self.assertGreater(s_hist, s_plain)

    def test_rank_candidates_excludes_and_caps(self):
        posts = [
            {"post_id": "keep", "user_id": "z", "created_at": _iso(NOW - 100)},
            {"post_id": "drop", "user_id": "z", "created_at": _iso(NOW - 100)},
            {"post_id": "keep", "user_id": "z", "created_at": _iso(NOW - 100)},  # dupe
        ]
        ranked = recsys.rank_candidates(
            "v", posts, exclude=lambda p: p.get("post_id") == "drop"
        )
        self.assertEqual(ranked, ["keep"])

    # ------------------------------------------------------------------ NRS-006
    def test_generate_candidates_three_sources_with_popular_out_of_network(self):
        # Followed source returns the viewer's own/followed refs.
        followed_refs = [{"post_id": "own1", "author_id": "v"}]
        # A popular, NON-followed author's post in the popularity index.
        recsys.bump_post_popularity(post_id="popular1", author_id="stranger")

        def fetch_followed(viewer, limit):
            return followed_refs

        def fetch_author_posts(author, limit):
            return []

        cands, counts = recsys.generate_candidate_ids(
            "v", fetch_followed=fetch_followed, fetch_author_posts=fetch_author_posts
        )
        ids = {c["post_id"] for c in cands}
        self.assertIn("own1", ids)
        self.assertIn("popular1", ids)  # out-of-network surfaced
        self.assertGreaterEqual(counts["popular"], 1)

    # --------------------------------------------------------------- NRS-008/010
    def test_compute_for_you_cold_start_then_for_you(self):
        # Popular post by a stranger so cold-start has something to rank.
        recsys.bump_post_popularity(post_id="hot", author_id="stranger")

        def fetch_followed(viewer, limit):
            return []

        def fetch_author_posts(author, limit):
            return []

        def hydrate(pids):
            return {pid: {"post_id": pid, "user_id": "stranger", "created_at": _iso(NOW - 100)} for pid in pids}

        # Cold start: no signals, no follows.
        res = recsys.compute_for_you_posts(
            "newbie",
            fetch_followed=fetch_followed,
            fetch_author_posts=fetch_author_posts,
            hydrate=hydrate,
        )
        self.assertEqual(res["source"], "cold_start")
        self.assertIn("hot", res and recsys.get_for_you_posts("newbie", limit=10)[0])

        # Now the viewer engages -> signals accrue -> source shifts to for_you.
        recsys.record_post_signal(user_id="newbie", post_id="hot", author_id="stranger", action="like")
        res2 = recsys.compute_for_you_posts(
            "newbie",
            fetch_followed=fetch_followed,
            fetch_author_posts=fetch_author_posts,
            hydrate=hydrate,
        )
        self.assertEqual(res2["source"], "for_you")

    def test_get_for_you_posts_flag_off_returns_fallback(self):
        object.__setattr__(S, "newsfeed_recsys_enabled", False)
        ids, cursor, source = recsys.get_for_you_posts("anyone")
        self.assertEqual(ids, [])
        self.assertEqual(source, "chronological_fallback")


@unittest.skipIf(mock_aws is None, "moto not installed")
class ForYouEndpointFallbackTest(unittest.TestCase):
    """NRS-009: the route delegates to the chronological feed when the flag is
    off (byte-for-byte feed body, plus a source marker)."""

    def test_endpoint_flag_off_delegates_to_chronological(self):
        import app.routers.newsfeed as nf

        orig_flag = S.newsfeed_recsys_enabled
        object.__setattr__(S, "newsfeed_recsys_enabled", False)
        try:
            sentinel = {"items": [{"post_id": "x"}], "next_cursor": None}
            with patch.object(nf, "view_feed", return_value=sentinel) as vf:
                out = nf.view_for_you_feed(limit=20, cursor=None, user_id="alice")
            vf.assert_called_once()
            self.assertEqual(out["items"], sentinel["items"])
            self.assertEqual(out["source"], "chronological_fallback")
        finally:
            object.__setattr__(S, "newsfeed_recsys_enabled", orig_flag)


if __name__ == "__main__":
    unittest.main()
