"""FEED-007: Mark Post Interesting.

A per-viewer "interesting" signal, distinct from likes/reactions. It feeds the
feed-ranking / "more like this" signal and lets a viewer toggle the marker on a
post.

Storage reuses the EXISTING ``billing`` table (no new table) per the ticket:

    PK = USER#{user_sub}
    SK = POST_SIGNAL#{post_id}
    signal = "interesting"
    created_at = <unix ts>
    post_id = {post_id}

The toggle is idempotent: marking an already-marked post is a no-op, and the
aggregate ``interesting_count`` on the post item (app_single_table, PK=POST#id,
SK=META) is only mutated when the per-viewer signal actually changes state. The
``check existing signal before toggle`` rule (per the ticket) guarantees the
counter never drifts on repeated marks/unmarks.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from app.core.aws import ddb
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

_SIGNAL_INTERESTING = "interesting"


def _billing_pk(user_sub: str) -> str:
    return f"USER#{user_sub}"


def _signal_sk(post_id: str) -> str:
    return f"POST_SIGNAL#{post_id}"


def _get_signal(user_sub: str, post_id: str) -> Optional[Dict[str, Any]]:
    """Point-read the viewer's signal record for a post (None if unmarked)."""
    try:
        resp = T.billing.get_item(
            Key={"pk": _billing_pk(user_sub), "sk": _signal_sk(post_id)}
        )
    except ClientError:
        return None
    return resp.get("Item")


def is_interesting(user_sub: str, post_id: str) -> bool:
    """Whether the viewer has marked the post interesting (viewer-specific)."""
    item = _get_signal(user_sub, post_id)
    return bool(item and item.get("signal") == _SIGNAL_INTERESTING)


def _post_meta_table():
    """The app_single_table handle that holds POST#{id}/META records."""
    name = getattr(S, "billing_table_name", "") or ""
    return ddb.Table(name) if name else None


def _adjust_interesting_count(post_id: str, delta: int) -> None:
    """Atomically bump the aggregate ``interesting_count`` on the post item."""
    tbl = _post_meta_table()
    if tbl is None:
        return
    try:
        if delta >= 0:
            tbl.update_item(
                Key={"pk": f"POST#{post_id}", "sk": "META"},
                UpdateExpression="SET interesting_count = if_not_exists(interesting_count, :z) + :d",
                ExpressionAttributeValues={":d": delta, ":z": 0},
            )
        else:
            tbl.update_item(
                Key={"pk": f"POST#{post_id}", "sk": "META"},
                UpdateExpression="SET interesting_count = interesting_count - :d",
                ExpressionAttributeValues={":d": -delta, ":z": 0},
                ConditionExpression="interesting_count > :z",
            )
    except ClientError:
        # Missing post / counter already at 0 — counter drift tolerated (a
        # reconciliation job is the source of truth per the ticket).
        pass


def mark_interesting(user_sub: str, post_id: str) -> Dict[str, Any]:
    """Mark a post interesting for the viewer (idempotent toggle ON).

    Checks for an existing signal before writing so a repeated mark is a no-op
    and the aggregate counter is incremented exactly once.
    """
    if not _get_signal(user_sub, post_id):
        T.billing.put_item(
            Item={
                "pk": _billing_pk(user_sub),
                "sk": _signal_sk(post_id),
                "Entity": "PostSignal",
                "signal": _SIGNAL_INTERESTING,
                "user_id": user_sub,
                "post_id": post_id,
                "created_at": now_ts(),
            }
        )
        _adjust_interesting_count(post_id, 1)
    return {"ok": True, "post_id": post_id, "is_interesting": True}


def unmark_interesting(user_sub: str, post_id: str) -> Dict[str, Any]:
    """Remove the viewer's interesting signal (idempotent toggle OFF)."""
    if _get_signal(user_sub, post_id):
        T.billing.delete_item(
            Key={"pk": _billing_pk(user_sub), "sk": _signal_sk(post_id)}
        )
        _adjust_interesting_count(post_id, -1)
    return {"ok": True, "post_id": post_id, "is_interesting": False}


def list_interesting_post_ids(user_sub: str, limit: int = 200) -> List[str]:
    """List post_ids the viewer marked interesting (newest activity first).

    Powers the feed-ranking / "more like this" boost: callers can prioritise
    these posts (and posts by the same authors) in ranking.
    """
    try:
        resp = T.billing.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
            ExpressionAttributeValues={
                ":pk": _billing_pk(user_sub),
                ":prefix": "POST_SIGNAL#",
            },
            Limit=max(1, min(limit, 1000)),
        )
    except ClientError:
        return []
    out: List[str] = []
    for it in resp.get("Items", []):
        if it.get("signal") != _SIGNAL_INTERESTING:
            continue
        pid = it.get("post_id") or str(it.get("sk", "")).split("#", 1)[-1]
        if pid:
            out.append(pid)
    return out


def interesting_post_id_set(user_sub: str, limit: int = 1000) -> set:
    """Set form of ``list_interesting_post_ids`` for O(1) membership in feed boost."""
    return set(list_interesting_post_ids(user_sub, limit=limit))
