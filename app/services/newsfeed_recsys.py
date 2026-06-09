"""Newsfeed "For You" recommendation engine (NRS-001..NRS-010).

Turns the reverse-chronological own+following newsfeed (``GET /feed``) into a
ranked "For You" experience, reusing the DynamoDB-native collaborative-filtering
patterns already proven for videos in ``app/services/recommendations.py``.

FLAG: every behavior here is gated behind ``S.newsfeed_recsys_enabled`` (env
``NEWSFEED_RECSYS_ENABLED``, default ``false``).  With the flag off, the For-You
endpoint delegates to the existing chronological feed unchanged.

==============================================================================
NRS-002 — Ranking signals + scoring model (design note)
==============================================================================
Signals, each derived from data already on the post item / existing services:

* recency        — ``post["created_at"]`` (ISO string; parsed via
                    ``newsfeed_feed_query.parse_filter_dt``).  Per-day exponential
                    decay reusing the video approach (``DECAY_FACTOR=0.95``).
* engagement     — ``like_count`` + ``comment_count`` + sum(``reactions_counts``)
                    + (``tip_total_cents``/100), normalized by post age in days
                    (velocity = engagement / max(age_days, ~1hr)).
* author affinity— viewer follows (``social.get_following``) give a flat boost;
                    per-author engagement counters from NRS-003 signals add more.
* content type   — has-media (``newsfeed_feed_query.post_has_media``), locked
                    posts (``post["locked"]``), video posts get small weights.
* personal hist. — viewer's prior signal on THIS post (``SIGNAL#{viewer}`` /
                    ``POST#{post_id}``) is a strong boost (they engaged before).

Score pseudocode (implemented in ``score_post``)::

    recency_score   = decay(1.0, created_epoch)                 # 0..1
    velocity        = engagement_total / max(age_days, 1/24)
    engagement_score= log1p(velocity)
    affinity_score  = (1.0 if author in follow_set else 0.0)
                      + author_affinity_counter(viewer_signals, author)
    content_score   = (has_media?+1) + (video?+1) - (locked?+0.5)
    history_score   = viewer_signal_weight_on_post
    score = wR*recency + wE*engagement + wA*affinity
            + wC*content + wH*history

Exclusion parity with the chronological feed loop
(``app/routers/newsfeed.py:5302-5328``) — handled in ``rank_candidates`` via a
caller-supplied exclusion callback so the router keeps owning block/snooze/hide/
moderation/unpublished/locked-visibility checks.

==============================================================================
Data layout (all in the existing ``recommendations`` table, pk/sk)
==============================================================================
* ``SIGNAL#{user_id}`` / ``POST#{post_id}``  -- per-user post engagement signal
    (namespaced sk so video ``VIDEO#`` signals never collide), carries
    ``author_id`` + weighted ``signal_score`` + ``last_engaged_at`` + ``ttl_epoch``.
* ``RECO#{user_id}``  / ``FOR_YOU_POSTS``     -- pre-computed ordered post_ids
    (namespaced sk so the video ``FOR_YOU`` row is untouched), 24h TTL.
* ``POPULAR#GLOBAL``  / ``{score:020d}#{post_id}`` -- sparse global popularity
    index (NRS-007).  Rows carry a TTL; only public published posts are written.

Hot-partition note (NRS-007): popularity rows are upserted best-effort on each
engagement; the single ``POPULAR#GLOBAL`` partition is acceptable for the feed
scale here (reads take the top-N by sk desc).  A time-bucketed ``POPULAR#{hour}``
scheme is the documented next step if write volume grows.
"""

from __future__ import annotations

import logging
import math
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from boto3.dynamodb.conditions import Attr, Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.newsfeed_feed_query import (
    parse_filter_dt,
    post_has_media,
    sort_posts_deterministically,
)

logger = logging.getLogger(__name__)

# Engagement weight per signal type (how much a single action contributes to the
# per-user/per-author affinity counters).
SIGNAL_WEIGHTS: Dict[str, float] = {
    "like": 1.0,
    "reaction": 1.0,
    "comment": 2.0,
    "tip": 4.0,
    "unlock": 5.0,
    "follow": 3.0,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ttl_epoch(seconds_from_now: int) -> int:
    return int(time.time()) + seconds_from_now


def _signal_ttl() -> int:
    return _ttl_epoch(S.newsfeed_recsys_signal_retention_days * 86400)


def _reco_ttl() -> int:
    return _ttl_epoch(86400)


def _popular_ttl() -> int:
    return _ttl_epoch(86400)


def _to_int(val: Any) -> int:
    if val is None:
        return 0
    try:
        return int(val)
    except (TypeError, ValueError):
        return 0


def _to_float(val: Any) -> float:
    if val is None:
        return 0.0
    try:
        return float(val)
    except (TypeError, ValueError):
        return 0.0


def _post_created_epoch(post: Dict[str, Any]) -> int:
    """Best-effort epoch seconds for a post's created_at (ISO string or int)."""
    raw = post.get("created_at")
    if raw is None:
        return 0
    if isinstance(raw, (int, float)):
        return int(raw)
    try:
        dt = parse_filter_dt(str(raw))
        if dt is not None:
            return int(dt.timestamp())
    except Exception:
        pass
    return 0


def _days_ago_epoch(epoch: int, now: int) -> float:
    if epoch <= 0:
        return 36500.0  # treat unknown timestamps as very old
    return max((now - epoch) / 86400.0, 0.0)


def _decay(score: float, epoch: int, now: int) -> float:
    days = _days_ago_epoch(epoch, now)
    return score * (S.newsfeed_recsys_engagement_decay_factor ** days)


def _reactions_total(post: Dict[str, Any]) -> int:
    counts = post.get("reactions_counts") or {}
    if isinstance(counts, dict):
        return sum(_to_int(v) for v in counts.values())
    return 0


# ---------------------------------------------------------------------------
# NRS-003 — Post-engagement signal recording
# ---------------------------------------------------------------------------

def record_post_signal(
    *,
    user_id: str,
    post_id: str,
    author_id: str,
    action: str,
) -> Dict[str, Any]:
    """Record/update a post-engagement signal (best-effort, never raises).

    Stored at ``SIGNAL#{user_id}`` / ``POST#{post_id}``.  Accumulates a weighted
    ``signal_score``, tracks ``author_id`` + ``last_engaged_at`` and carries a TTL.
    """
    weight = SIGNAL_WEIGHTS.get(action, 1.0)
    now = now_ts()
    try:
        T.recommendations.update_item(
            Key={"pk": f"SIGNAL#{user_id}", "sk": f"POST#{post_id}"},
            UpdateExpression=(
                "SET signal_score = if_not_exists(signal_score, :z) + :w, "
                "author_id = :aid, last_engaged_at = :now, ttl_epoch = :ttl, "
                "last_action = :act, post_id = :pid"
            ),
            ExpressionAttributeValues={
                ":z": 0,
                ":w": int(weight) if weight == int(weight) else weight,
                ":aid": author_id or "",
                ":now": now,
                ":ttl": _signal_ttl(),
                ":act": action,
                ":pid": post_id,
            },
        )
        return {"ok": True}
    except Exception:
        logger.debug("record_post_signal failed for %s/%s", user_id, post_id, exc_info=True)
        return {"ok": False}


def record_post_engagement(
    *,
    user_id: str,
    post_id: str,
    author_id: str,
    action: str,
    is_public: bool = True,
) -> None:
    """Fire-and-forget hook for engagement write sites.

    Records the per-user signal AND bumps the global popularity index.  Both are
    wrapped so a DDB failure can never change the 2xx outcome of the request.
    Entirely gated on the feature flag (no-op when disabled) so wiring it into
    like/comment/tip/unlock has zero effect until For-You is turned on.
    """
    if not S.newsfeed_recsys_enabled:
        return
    try:
        record_post_signal(user_id=user_id, post_id=post_id, author_id=author_id, action=action)
    except Exception:
        logger.debug("record_post_engagement signal hook failed", exc_info=True)
    if is_public:
        try:
            bump_post_popularity(post_id=post_id, author_id=author_id)
        except Exception:
            logger.debug("record_post_engagement popularity hook failed", exc_info=True)


def get_user_post_signals(user_id: str, limit: int = 500) -> List[Dict[str, Any]]:
    """Return all post-engagement signals for a user (sk begins_with POST#)."""
    items: List[Dict[str, Any]] = []
    last_key = None
    while len(items) < limit:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": (
                Key("pk").eq(f"SIGNAL#{user_id}") & Key("sk").begins_with("POST#")
            ),
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


def author_affinity_from_signals(signals: List[Dict[str, Any]]) -> Dict[str, float]:
    """Roll up per-author affinity from raw post signals (recency-decayed)."""
    now = now_ts()
    scores: Dict[str, float] = {}
    for sig in signals:
        author = sig.get("author_id") or ""
        if not author:
            continue
        raw = _to_float(sig.get("signal_score", 0.0))
        last = _to_int(sig.get("last_engaged_at", 0))
        scores[author] = scores.get(author, 0.0) + _decay(raw, last, now)
    return scores


def post_history_from_signals(signals: List[Dict[str, Any]]) -> Dict[str, float]:
    """Map post_id -> decayed signal score (viewer's prior engagement)."""
    now = now_ts()
    out: Dict[str, float] = {}
    for sig in signals:
        sk = str(sig.get("sk", ""))
        if not sk.startswith("POST#"):
            continue
        pid = sk[len("POST#"):]
        out[pid] = _decay(_to_float(sig.get("signal_score", 0.0)), _to_int(sig.get("last_engaged_at", 0)), now)
    return out


# ---------------------------------------------------------------------------
# NRS-007 — Global popularity index
# ---------------------------------------------------------------------------

def _velocity_score(post: Dict[str, Any], now: int) -> float:
    engagement = (
        _to_int(post.get("like_count"))
        + _to_int(post.get("comment_count"))
        + _reactions_total(post)
        + _to_int(post.get("tip_total_cents")) / 100.0
    )
    age_days = max(_days_ago_epoch(_post_created_epoch(post), now), 1.0 / 24.0)
    return engagement / age_days


def bump_post_popularity(*, post_id: str, author_id: str, like_count: int = 0, comment_count: int = 0) -> None:
    """Upsert a popularity marker for a post (best-effort).

    Writes a single ``POPULAR#GLOBAL`` / ``POST#{post_id}`` marker carrying the
    author + a TTL.  The actual velocity ranking is computed at read time from the
    live post item, so this marker only needs to record candidacy + recency.
    """
    if not post_id:
        return
    try:
        T.recommendations.put_item(Item={
            "pk": "POPULAR#GLOBAL",
            "sk": f"POST#{post_id}",
            "post_id": post_id,
            "author_id": author_id or "",
            "marked_at": now_ts(),
            "ttl_epoch": _popular_ttl(),
        })
    except Exception:
        logger.debug("bump_post_popularity failed for %s", post_id, exc_info=True)


def get_popular_post_ids(limit: int = 100) -> List[Dict[str, str]]:
    """Return candidate popular posts as ``[{"post_id","author_id"}, ...]``.

    Candidacy only — public/locked/published exclusions are enforced at the
    candidate-hydration / ranking stage against the live post item.
    """
    out: List[Dict[str, str]] = []
    last_key = None
    try:
        while len(out) < limit:
            kwargs: Dict[str, Any] = {
                "KeyConditionExpression": Key("pk").eq("POPULAR#GLOBAL") & Key("sk").begins_with("POST#"),
                "Limit": min(limit - len(out), 100),
                "ScanIndexForward": False,
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = T.recommendations.query(**kwargs)
            for it in resp.get("Items", []):
                pid = it.get("post_id")
                if pid:
                    out.append({"post_id": str(pid), "author_id": str(it.get("author_id") or "")})
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
    except Exception:
        logger.debug("get_popular_post_ids query failed", exc_info=True)
    return out[:limit]


# ---------------------------------------------------------------------------
# NRS-005 — Scoring
# ---------------------------------------------------------------------------

def score_post(
    post: Dict[str, Any],
    *,
    author_affinity: Dict[str, float],
    post_history: Dict[str, float],
    follow_set: Set[str],
    viewer_id: str,
    now: int,
) -> float:
    """Pure, deterministic post score.  No I/O.

    ``author_affinity`` / ``post_history`` are pre-computed from the viewer's
    signals (NRS-003); ``follow_set`` are the viewer's followings.
    """
    author = str(post.get("user_id") or "")
    post_id = str(post.get("post_id") or "")
    created = _post_created_epoch(post)

    recency_score = _decay(1.0, created, now)

    velocity = _velocity_score(post, now)
    engagement_score = math.log1p(max(velocity, 0.0))

    affinity_score = (1.0 if author in follow_set else 0.0) + author_affinity.get(author, 0.0)

    content_score = 0.0
    if post_has_media(post):
        content_score += 1.0
    if post.get("kind") == "video" or post.get("video_id"):
        content_score += 1.0
    if post.get("locked"):
        content_score -= 0.5

    history_score = post_history.get(post_id, 0.0)

    return (
        S.newsfeed_recsys_weight_recency * recency_score
        + S.newsfeed_recsys_weight_engagement * engagement_score
        + S.newsfeed_recsys_weight_affinity * affinity_score
        + S.newsfeed_recsys_weight_content_type * content_score
        + S.newsfeed_recsys_weight_personal_history * history_score
    )


def rank_candidates(
    viewer_id: str,
    candidates: List[Dict[str, Any]],
    *,
    author_affinity: Optional[Dict[str, float]] = None,
    post_history: Optional[Dict[str, float]] = None,
    follow_set: Optional[Set[str]] = None,
    exclude: Optional[Callable[[Dict[str, Any]], bool]] = None,
) -> List[str]:
    """Score + order candidate posts, applying exclusions, dedupe, and cap.

    ``exclude(post) -> True`` drops a post (router supplies block/snooze/hide/
    moderation/unpublished/locked-visibility parity).  Tie-break is stable:
    score desc, then (created_at, post_id) desc via ``sort_posts_deterministically``.
    """
    author_affinity = author_affinity or {}
    post_history = post_history or {}
    follow_set = follow_set or set()
    now = now_ts()

    seen: Set[str] = set()
    scored: List[Tuple[float, Dict[str, Any]]] = []
    for post in candidates:
        pid = str(post.get("post_id") or "")
        if not pid or pid in seen:
            continue
        if exclude is not None:
            try:
                if exclude(post):
                    continue
            except Exception:
                logger.debug("rank_candidates exclude callback raised for %s", pid, exc_info=True)
                continue
        seen.add(pid)
        s = score_post(
            post,
            author_affinity=author_affinity,
            post_history=post_history,
            follow_set=follow_set,
            viewer_id=viewer_id,
            now=now,
        )
        scored.append((s, post))

    # Stable ordering: bucket by score, then deterministic within ties.
    def _key(item: Tuple[float, Dict[str, Any]]):
        s, p = item
        return (s, str(p.get("created_at") or ""), str(p.get("post_id") or ""))

    scored.sort(key=_key, reverse=True)
    cap = S.newsfeed_recsys_max_for_you_results
    return [str(p.get("post_id")) for _s, p in scored[:cap]]


# ---------------------------------------------------------------------------
# NRS-006 — Candidate generation (followed + popular + affinity)
# ---------------------------------------------------------------------------

def generate_candidate_ids(
    viewer_id: str,
    *,
    fetch_followed: Callable[[str, int], List[Dict[str, str]]],
    fetch_author_posts: Callable[[str, int], List[Dict[str, str]]],
) -> Tuple[List[Dict[str, str]], Dict[str, int]]:
    """Build a deduped candidate pool from three sources.

    Collaborators are injected so the service stays hermetically testable:
      * ``fetch_followed(viewer_id, limit)``  -> recent followed-author refs.
      * ``fetch_author_posts(author_id, limit)`` -> recent posts by an author.
    Popular candidates come from the local popularity index (NRS-007).

    Returns ``(candidates, per_source_counts)`` where each candidate is
    ``{"post_id","author_id"}``.  Counts feed NRS-004 metrics.
    """
    from app.services.social import get_following

    pool: Dict[str, Dict[str, str]] = {}
    counts = {"followed": 0, "popular": 0, "affinity": 0}

    # 1) Followed authors (existing fan-out refs).
    try:
        followed = fetch_followed(viewer_id, S.newsfeed_recsys_candidate_followed_limit)
        for ref in followed:
            pid = str(ref.get("post_id") or "")
            if pid:
                pool.setdefault(pid, {"post_id": pid, "author_id": str(ref.get("author_id") or "")})
                counts["followed"] += 1
    except Exception:
        logger.debug("candidate gen: followed source failed", exc_info=True)

    # 2) Popular (out-of-network).
    try:
        for ref in get_popular_post_ids(S.newsfeed_recsys_candidate_popular_limit):
            pid = ref["post_id"]
            if pid not in pool:
                pool[pid] = {"post_id": pid, "author_id": ref.get("author_id", "")}
                counts["popular"] += 1
    except Exception:
        logger.debug("candidate gen: popular source failed", exc_info=True)

    # 3) Affinity (collaborative): authors the viewer engaged with + followings,
    #    pull their recent posts.
    try:
        signals = get_user_post_signals(viewer_id, limit=200)
        aff = author_affinity_from_signals(signals)
        affinity_authors = [a for a, _ in sorted(aff.items(), key=lambda x: x[1], reverse=True)][:20]
        try:
            following, _ = get_following(viewer_id, limit=50)
            for f in following:
                aid = f.get("target_user_id") or f.get("user_id") or ""
                if aid:
                    affinity_authors.append(aid)
        except Exception:
            logger.debug("candidate gen: get_following failed", exc_info=True)

        added = 0
        for author in dict.fromkeys(affinity_authors):
            if added >= S.newsfeed_recsys_candidate_affinity_limit:
                break
            try:
                for ref in fetch_author_posts(author, 10):
                    pid = str(ref.get("post_id") or "")
                    if pid and pid not in pool:
                        pool[pid] = {"post_id": pid, "author_id": str(ref.get("author_id") or author)}
                        counts["affinity"] += 1
                        added += 1
                        if added >= S.newsfeed_recsys_candidate_affinity_limit:
                            break
            except Exception:
                logger.debug("candidate gen: author posts failed for %s", author, exc_info=True)
    except Exception:
        logger.debug("candidate gen: affinity source failed", exc_info=True)

    return list(pool.values()), counts


# ---------------------------------------------------------------------------
# NRS-008 — Pre-compute + store + refresh
# ---------------------------------------------------------------------------

def store_for_you_posts(viewer_id: str, post_ids: List[str]) -> None:
    T.recommendations.put_item(Item={
        "pk": f"RECO#{viewer_id}",
        "sk": "FOR_YOU_POSTS",
        "post_ids": post_ids,
        "computed_at": now_ts(),
        "ttl_epoch": _reco_ttl(),
        "version": 1,
    })


def get_for_you_posts(viewer_id: str, *, limit: int = 20, offset: int = 0) -> Tuple[List[str], Optional[str], str]:
    """Read the pre-computed For-You row.

    Returns ``(post_ids, next_cursor, source)`` where source is ``for_you`` when a
    non-empty stored row exists, else ``chronological_fallback``.
    """
    if not S.newsfeed_recsys_enabled:
        return [], None, "chronological_fallback"
    try:
        resp = T.recommendations.get_item(Key={"pk": f"RECO#{viewer_id}", "sk": "FOR_YOU_POSTS"})
    except Exception:
        logger.debug("get_for_you_posts failed for %s", viewer_id, exc_info=True)
        return [], None, "chronological_fallback"
    item = resp.get("Item")
    if not item or not item.get("post_ids"):
        return [], None, "chronological_fallback"
    all_ids = list(item["post_ids"])
    page = all_ids[offset:offset + limit]
    next_offset = offset + limit if offset + limit < len(all_ids) else None
    return page, (str(next_offset) if next_offset is not None else None), "for_you"


def compute_for_you_posts(
    viewer_id: str,
    *,
    fetch_followed: Callable[[str, int], List[Dict[str, str]]],
    fetch_author_posts: Callable[[str, int], List[Dict[str, str]]],
    hydrate: Callable[[List[str]], Dict[str, Dict[str, Any]]],
    follow_set: Optional[Set[str]] = None,
    exclude: Optional[Callable[[Dict[str, Any]], bool]] = None,
) -> Dict[str, Any]:
    """Candidate gen -> hydrate -> rank -> store.  Returns a summary + source.

    ``hydrate(post_ids)`` returns ``{post_id: post_item}`` (router supplies a
    batch_get_item-backed hydrator).  Source is ``for_you`` when the viewer has
    signals/follows, else ``cold_start`` (NRS-010) when ranking is driven purely
    by popularity.
    """
    candidates, counts = generate_candidate_ids(
        viewer_id,
        fetch_followed=fetch_followed,
        fetch_author_posts=fetch_author_posts,
    )

    signals = get_user_post_signals(viewer_id, limit=500)
    author_affinity = author_affinity_from_signals(signals)
    post_history = post_history_from_signals(signals)
    follow_set = follow_set or set()

    # Cold start: no signals AND no follows -> popularity-driven.
    is_cold = (not signals) and (not follow_set)

    pids = [c["post_id"] for c in candidates]
    posts_by_id = hydrate(pids) if pids else {}
    candidate_posts = [posts_by_id[p] for p in pids if p in posts_by_id]

    ranked = rank_candidates(
        viewer_id,
        candidate_posts,
        author_affinity=author_affinity,
        post_history=post_history,
        follow_set=follow_set,
        exclude=exclude,
    )

    store_for_you_posts(viewer_id, ranked)

    source = "cold_start" if is_cold else "for_you"
    return {
        "viewer_id": viewer_id,
        "ranked_count": len(ranked),
        "candidate_counts": counts,
        "source": source,
    }


async def _newsfeed_recsys_refresh_loop() -> None:
    """Background loop: periodically recompute For-You rows for all signal users."""
    import asyncio

    from app.metrics import record_newsfeed_recsys_refresh

    interval_seconds = max(1, S.newsfeed_recsys_refresh_interval_hours * 3600)
    await asyncio.sleep(60)  # brief startup delay past the boot window
    while True:
        try:
            from app.routers.newsfeed import recompute_for_you_all_users

            await asyncio.get_event_loop().run_in_executor(None, recompute_for_you_all_users)
            record_newsfeed_recsys_refresh(outcome="success")
        except asyncio.CancelledError:  # pragma: no cover - shutdown path
            break
        except Exception:
            logger.exception("newsfeed recsys: background refresh loop error")
            try:
                record_newsfeed_recsys_refresh(outcome="error")
            except Exception:
                pass
        await asyncio.sleep(interval_seconds)


def start_newsfeed_recsys_refresh_task() -> None:
    """Startup handler: schedule the For-You refresh loop (gated on flag)."""
    import asyncio

    if not S.newsfeed_recsys_enabled:
        logger.info("newsfeed recsys refresh disabled (newsfeed_recsys_enabled=False)")
        return
    asyncio.ensure_future(_newsfeed_recsys_refresh_loop())


def list_post_signal_users() -> List[str]:
    """User_ids that have at least one POST# engagement signal (for refresh-all)."""
    user_ids: Set[str] = set()
    kwargs: Dict[str, Any] = {
        "FilterExpression": Attr("pk").begins_with("SIGNAL#") & Attr("sk").begins_with("POST#"),
        "ProjectionExpression": "pk",
    }
    try:
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
    except Exception:
        logger.debug("list_post_signal_users scan failed", exc_info=True)
    return list(user_ids)
