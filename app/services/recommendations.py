"""Content recommendation engine (DISC-001).

Provides personalized "For You" feeds, similar-video suggestions,
and creator recommendations using DynamoDB-native collaborative
filtering.  No external ML infrastructure required.

Data layout (all in the ``recommendations`` table):
- ``RECO#{user_id}`` / ``FOR_YOU``  -- pre-computed video ids
- ``RECO#{user_id}`` / ``CREATOR_SUGGEST`` -- pre-computed creator ids
- ``SIMILAR#{video_id}`` / ``VIDEOS`` -- similar videos
- ``SIGNAL#{user_id}`` / ``VIDEO#{video_id}`` -- per-user engagement signals
"""

from __future__ import annotations

import asyncio
import logging
import math
import time
from decimal import Decimal
from typing import Any, Dict, List, Optional, Set, Tuple

from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Signal weights (Section 6.1 of the spec)
# ---------------------------------------------------------------------------
WEIGHT_WATCH_HIGH = 5.0    # watch > 80%
WEIGHT_WATCH_MED = 3.0     # watch 40-80%
WEIGHT_WATCH_LOW = 1.0     # watch < 40%
WEIGHT_LIKE = 4.0
WEIGHT_SUBSCRIBE = 3.0
WEIGHT_PURCHASE = 6.0

DECAY_FACTOR = 0.95  # per-day recency decay

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ttl_epoch(seconds_from_now: int) -> int:
    return int(time.time()) + seconds_from_now


def _signal_ttl() -> int:
    return _ttl_epoch(S.reco_signal_retention_days * 86400)


def _reco_ttl() -> int:
    """24-hour TTL for pre-computed recommendations."""
    return _ttl_epoch(86400)


def _similar_ttl() -> int:
    """48-hour TTL for similar-video lists."""
    return _ttl_epoch(172800)


def _days_ago(ts: int) -> float:
    diff = time.time() - ts
    return max(diff / 86400.0, 0.0)


def _decay(score: float, last_viewed_at: int) -> float:
    days = _days_ago(last_viewed_at)
    return score * (DECAY_FACTOR ** days)


def _to_int(val: Any) -> int:
    if val is None:
        return 0
    return int(val)


def _to_float(val: Any) -> float:
    if val is None:
        return 0.0
    return float(val)


# ---------------------------------------------------------------------------
# Signal recording
# ---------------------------------------------------------------------------

def record_signal(
    *,
    user_id: str,
    video_id: str,
    watch_pct: int | None = None,
    liked: bool | None = None,
) -> Dict[str, Any]:
    """Record or update an engagement signal for user+video."""
    now = now_ts()
    pk = f"SIGNAL#{user_id}"
    sk = f"VIDEO#{video_id}"

    # Upsert: always store latest timestamp
    update_parts = [
        "last_viewed_at = :now",
        "ttl_epoch = :ttl",
    ]
    values: Dict[str, Any] = {
        ":now": now,
        ":ttl": _signal_ttl(),
    }

    if watch_pct is not None:
        update_parts.append("view_count = if_not_exists(view_count, :zero) + :one")
        values[":zero"] = 0
        values[":one"] = 1

    if liked is not None:
        update_parts.append("liked = :liked")
        values[":liked"] = liked

    try:
        resp = T.recommendations.update_item(
            Key={"pk": pk, "sk": sk},
            UpdateExpression="SET " + ", ".join(update_parts),
            ExpressionAttributeValues=values,
            ReturnValues="ALL_NEW",
        )
        item = resp.get("Attributes", {})

        # Set watch_pct separately, keeping the max value
        if watch_pct is not None:
            current_wp = _to_int(item.get("watch_pct", 0))
            new_wp = max(watch_pct, current_wp)
            T.recommendations.update_item(
                Key={"pk": pk, "sk": sk},
                UpdateExpression="SET watch_pct = :wp",
                ExpressionAttributeValues={":wp": new_wp},
            )

        return {"ok": True, "pk": pk, "sk": sk}
    except Exception:
        logger.exception("Failed to record signal for %s/%s", user_id, video_id)
        return {"ok": False}


# ---------------------------------------------------------------------------
# User signal retrieval
# ---------------------------------------------------------------------------

def get_user_signals(user_id: str, limit: int = 500) -> List[Dict[str, Any]]:
    """Return all engagement signals for a user."""
    items: List[Dict[str, Any]] = []
    last_key = None
    while len(items) < limit:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": Key("pk").eq(f"SIGNAL#{user_id}"),
            "Limit": min(limit - len(items), 100),
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.recommendations.query(**kwargs)
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return items


def compute_affinity_scores(signals: List[Dict[str, Any]]) -> Dict[str, float]:
    """Compute weighted affinity scores per video from raw signals."""
    scores: Dict[str, float] = {}
    for sig in signals:
        sk = sig.get("sk", "")
        if not sk.startswith("VIDEO#"):
            continue
        vid = sk[6:]  # strip "VIDEO#"
        wp = _to_int(sig.get("watch_pct", 0))
        liked = sig.get("liked", False)
        last_viewed = _to_int(sig.get("last_viewed_at", 0))

        if wp > 80:
            score = WEIGHT_WATCH_HIGH
        elif wp > 40:
            score = WEIGHT_WATCH_MED
        else:
            score = WEIGHT_WATCH_LOW

        if liked:
            score += WEIGHT_LIKE

        score = _decay(score, last_viewed)
        scores[vid] = score
    return scores


# ---------------------------------------------------------------------------
# For You computation
# ---------------------------------------------------------------------------

def compute_for_you(user_id: str) -> List[str]:
    """Compute personalized For You video recommendations.

    Algorithm:
    1. Build user affinity scores from signals
    2. Find similar users via co-viewing patterns
    3. Collect unseen high-affinity videos from similar users
    4. Rank and store results
    """
    signals = get_user_signals(user_id)
    if not signals:
        return []

    affinities = compute_affinity_scores(signals)
    watched_ids = set(affinities.keys())

    # Find high-affinity videos (score > 3.0)
    high_affinity_vids = [vid for vid, score in affinities.items() if score > 3.0]
    if not high_affinity_vids:
        high_affinity_vids = sorted(affinities.keys(), key=lambda v: affinities[v], reverse=True)[:10]

    # Step 2: find similar users by co-viewing
    user_overlap: Dict[str, int] = {}
    for vid in high_affinity_vids[:10]:  # cap to bound computation
        try:
            resp = T.video_views.query(
                IndexName="ByVideoViewedAt",
                KeyConditionExpression=Key("video_id").eq(vid),
                Limit=100,
            )
            for item in resp.get("Items", []):
                other_uid = item.get("user_id", "")
                if other_uid and other_uid != user_id:
                    user_overlap[other_uid] = user_overlap.get(other_uid, 0) + 1
        except Exception:
            logger.debug("Failed to query VideoViews for %s", vid)

    # Filter to users sharing 2+ high-affinity videos
    similar_users = sorted(
        [(uid, count) for uid, count in user_overlap.items() if count >= 2],
        key=lambda x: x[1],
        reverse=True,
    )[:S.reco_max_similar_users]

    if not similar_users:
        return []

    # Step 3: collect unseen videos from similar users
    candidate_scores: Dict[str, float] = {}
    for sim_uid, overlap_count in similar_users:
        sim_weight = overlap_count / max(len(high_affinity_vids), 1)
        sim_signals = get_user_signals(sim_uid, limit=100)
        sim_affinities = compute_affinity_scores(sim_signals)
        for vid, sim_score in sim_affinities.items():
            if vid not in watched_ids and sim_score > 2.0:
                candidate_scores[vid] = candidate_scores.get(vid, 0.0) + (sim_score * sim_weight)

    # Step 4: Apply new-video boost
    now = now_ts()
    boost_cutoff = now - (S.reco_new_video_boost_hours * 3600)
    for vid in list(candidate_scores.keys()):
        try:
            meta = T.video_metadata.get_item(Key={"video_id": vid}).get("Item")
            if meta:
                # Only include published public videos
                if meta.get("status") != "published" or meta.get("visibility") != "public":
                    del candidate_scores[vid]
                    continue
                created = _to_int(meta.get("created_at", 0))
                if created > boost_cutoff:
                    candidate_scores[vid] *= 2.0  # new video boost
        except Exception:
            pass

    # Rank and cap
    ranked = sorted(candidate_scores.items(), key=lambda x: x[1], reverse=True)
    video_ids = [vid for vid, _score in ranked[:S.reco_max_for_you_results]]

    # Store pre-computed results
    if video_ids:
        _store_for_you(user_id, video_ids)

    return video_ids


def _store_for_you(user_id: str, video_ids: List[str]) -> None:
    now = now_ts()
    T.recommendations.put_item(Item={
        "pk": f"RECO#{user_id}",
        "sk": "FOR_YOU",
        "video_ids": video_ids,
        "computed_at": now,
        "ttl_epoch": _reco_ttl(),
        "version": 1,
    })


def get_for_you(user_id: str, *, limit: int = 24, offset: int = 0) -> Tuple[List[str], str | None, str]:
    """Fetch pre-computed For You list.

    Returns (video_ids, next_cursor, source).
    """
    if not S.recommendations_enabled:
        return [], None, "trending_fallback"

    try:
        resp = T.recommendations.get_item(
            Key={"pk": f"RECO#{user_id}", "sk": "FOR_YOU"},
        )
    except Exception:
        logger.exception("Failed to fetch FOR_YOU for %s", user_id)
        return [], None, "trending_fallback"

    item = resp.get("Item")
    if not item or not item.get("video_ids"):
        return [], None, "trending_fallback"

    all_ids = item["video_ids"]
    page = all_ids[offset : offset + limit]
    next_offset = offset + limit if offset + limit < len(all_ids) else None
    next_cursor = str(next_offset) if next_offset is not None else None
    return page, next_cursor, "for_you"


# ---------------------------------------------------------------------------
# Similar videos
# ---------------------------------------------------------------------------

def compute_similar_videos(video_id: str) -> List[str]:
    """Compute similar videos based on co-view patterns."""
    # Find users who watched this video with watch_pct > 40%
    viewers: List[str] = []
    try:
        resp = T.video_views.query(
            IndexName="ByVideoViewedAt",
            KeyConditionExpression=Key("video_id").eq(video_id),
            Limit=200,
        )
        for item in resp.get("Items", []):
            uid = item.get("user_id", "")
            if uid:
                viewers.append(uid)
    except Exception:
        logger.debug("Failed to query viewers for %s", video_id)
        return []

    if not viewers:
        return []

    # For each viewer, find other videos they watched
    coview_counts: Dict[str, int] = {}
    for uid in viewers[:50]:
        try:
            sigs = get_user_signals(uid, limit=50)
            for sig in sigs:
                sk = sig.get("sk", "")
                if not sk.startswith("VIDEO#"):
                    continue
                other_vid = sk[6:]
                if other_vid != video_id:
                    coview_counts[other_vid] = coview_counts.get(other_vid, 0) + 1
        except Exception:
            pass

    # Filter to published/public videos and rank
    ranked_candidates = sorted(coview_counts.items(), key=lambda x: x[1], reverse=True)
    similar_ids: List[str] = []
    for vid, _count in ranked_candidates:
        if len(similar_ids) >= S.reco_max_similar_videos:
            break
        try:
            meta = T.video_metadata.get_item(Key={"video_id": vid}).get("Item")
            if meta and meta.get("status") == "published" and meta.get("visibility") == "public":
                similar_ids.append(vid)
        except Exception:
            similar_ids.append(vid)

    # Store
    if similar_ids:
        _store_similar(video_id, similar_ids)

    return similar_ids


def _store_similar(video_id: str, similar_ids: List[str]) -> None:
    now = now_ts()
    T.recommendations.put_item(Item={
        "pk": f"SIMILAR#{video_id}",
        "sk": "VIDEOS",
        "similar_video_ids": similar_ids,
        "computed_at": now,
        "ttl_epoch": _similar_ttl(),
    })


def get_similar(video_id: str, *, limit: int = 8) -> Tuple[List[str], str]:
    """Fetch pre-computed similar videos.

    Returns (video_ids, source).
    """
    if not S.recommendations_enabled:
        return [], "category_fallback"

    try:
        resp = T.recommendations.get_item(
            Key={"pk": f"SIMILAR#{video_id}", "sk": "VIDEOS"},
        )
    except Exception:
        return [], "category_fallback"

    item = resp.get("Item")
    if not item or not item.get("similar_video_ids"):
        return [], "category_fallback"

    ids = item["similar_video_ids"][:limit]
    return ids, "collaborative_filtering"


# ---------------------------------------------------------------------------
# Creator suggestions
# ---------------------------------------------------------------------------

def compute_creator_suggestions(user_id: str) -> List[str]:
    """Compute creator suggestions based on subscription overlap."""
    from app.services.social import get_following

    # Get user's followed creators
    following, _ = get_following(user_id, limit=100)
    following_ids = {f.get("target_user_id") or f.get("user_id", "") for f in following}
    following_ids.discard("")

    if not following_ids:
        return []

    # For each followed creator, find their other followers, then
    # find who those followers also follow.
    candidate_scores: Dict[str, int] = {}
    for fid in list(following_ids)[:20]:
        # Find followers of this creator
        try:
            from app.services.social import get_followers
            followers, _ = get_followers(fid, limit=50)
            for follower in followers:
                other_uid = follower.get("user_id", "")
                if not other_uid or other_uid == user_id:
                    continue
                # Get who this follower also follows
                other_following, _ = get_following(other_uid, limit=50)
                for of in other_following:
                    cid = of.get("target_user_id") or of.get("user_id", "")
                    if cid and cid != user_id and cid not in following_ids:
                        candidate_scores[cid] = candidate_scores.get(cid, 0) + 1
        except Exception:
            pass

    ranked = sorted(candidate_scores.items(), key=lambda x: x[1], reverse=True)
    creator_ids = [cid for cid, _score in ranked[:S.reco_max_creator_suggestions]]

    if creator_ids:
        _store_creator_suggestions(user_id, creator_ids)

    return creator_ids


def _store_creator_suggestions(user_id: str, creator_ids: List[str]) -> None:
    now = now_ts()
    T.recommendations.put_item(Item={
        "pk": f"RECO#{user_id}",
        "sk": "CREATOR_SUGGEST",
        "creator_ids": creator_ids,
        "computed_at": now,
        "ttl_epoch": _reco_ttl(),
        "version": 1,
    })


def get_creator_suggestions(user_id: str, *, limit: int = 10) -> Tuple[List[str], str]:
    """Fetch pre-computed creator suggestions.

    Returns (creator_ids, source).
    """
    if not S.recommendations_enabled:
        return [], "subscription_overlap"

    try:
        resp = T.recommendations.get_item(
            Key={"pk": f"RECO#{user_id}", "sk": "CREATOR_SUGGEST"},
        )
    except Exception:
        return [], "subscription_overlap"

    item = resp.get("Item")
    if not item or not item.get("creator_ids"):
        return [], "subscription_overlap"

    return item["creator_ids"][:limit], "subscription_overlap"


# ---------------------------------------------------------------------------
# Refresh (background or on-demand)
# ---------------------------------------------------------------------------

def refresh_user_recommendations(user_id: str) -> Dict[str, Any]:
    """Recompute all recommendations for a single user."""
    t0 = time.time()
    for_you = compute_for_you(user_id)
    creators = compute_creator_suggestions(user_id)
    duration = time.time() - t0
    return {
        "user_id": user_id,
        "for_you_count": len(for_you),
        "creator_count": len(creators),
        "duration_seconds": round(duration, 2),
    }


def _list_all_signal_users() -> List[str]:
    """Return the set of user_ids that have at least one engagement signal."""
    user_ids: Set[str] = set()
    kwargs: Dict[str, Any] = {
        "FilterExpression": Attr("pk").begins_with("SIGNAL#"),
        "ProjectionExpression": "pk",
    }
    while True:
        resp = T.recommendations.scan(**kwargs)
        for item in resp.get("Items", []):
            pk = item.get("pk", "")
            if pk.startswith("SIGNAL#"):
                user_ids.add(pk[len("SIGNAL#"):])
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return list(user_ids)


def refresh_all_users() -> Dict[str, Any]:
    """Recompute recommendations for every user that has engagement signals."""
    user_ids = _list_all_signal_users()
    t0 = time.time()
    processed = 0
    errors = 0
    for uid in user_ids:
        try:
            refresh_user_recommendations(uid)
            processed += 1
        except Exception:
            logger.exception("reco: refresh_all_users: error for user %s", uid)
            errors += 1
    duration = time.time() - t0
    logger.info(
        "reco: refresh_all_users complete: %d users, %d errors, %.1fs",
        processed, errors, duration,
    )
    return {
        "users_processed": processed,
        "errors": errors,
        "duration_seconds": round(duration, 2),
    }


async def _reco_refresh_loop() -> None:
    """Background loop: periodically recompute recommendations for all users."""
    interval_seconds = max(1, S.reco_refresh_interval_hours * 3600)
    await asyncio.sleep(60)  # brief startup delay past the boot window
    while True:
        try:
            await asyncio.get_event_loop().run_in_executor(None, refresh_all_users)
        except asyncio.CancelledError:  # pragma: no cover - shutdown path
            break
        except Exception:
            logger.exception("reco: background refresh loop error")
        await asyncio.sleep(interval_seconds)


def start_reco_refresh_task() -> None:
    """Startup handler: schedule the recommendation refresh background loop."""
    if not S.recommendations_enabled:
        logger.info(
            "reco refresh disabled (recommendations_enabled=False)"
        )
        return
    asyncio.ensure_future(_reco_refresh_loop())
