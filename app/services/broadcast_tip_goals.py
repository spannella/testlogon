"""Broadcast tip goal service -- CRUD and progress tracking (BCAST-013)."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.broadcast_sse import broadcast_sse_publish

logger = logging.getLogger(__name__)


def create_goal(
    *,
    session_id: str,
    label: str,
    target_cents: int,
    sort_order: int = 0,
    actor: str,
) -> Dict[str, Any]:
    """Create a tip goal for a broadcast session.

    Raises 409 if the session already has max goals.
    """
    existing = list_goals(session_id)
    max_goals = S.broadcast_max_goals_per_session
    if len(existing) >= max_goals:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "MAX_GOALS_REACHED",
                "message": f"Maximum {max_goals} goals per session.",
            },
        )

    goal_id = f"goal_{uuid4().hex[:12]}"
    ts = now_ts()
    item: Dict[str, Any] = {
        "session_id": session_id,
        "goal_id": goal_id,
        "label": label,
        "target_cents": target_cents,
        "current_cents": 0,
        "reached": False,
        "sort_order": sort_order,
        "created_at": ts,
        "created_by": actor,
    }
    T.broadcast_tip_goals.put_item(Item=item)

    out = _goal_out(item)
    broadcast_sse_publish(session_id, {"_type": "goal:created", **out})
    return out


def list_goals(session_id: str) -> List[Dict[str, Any]]:
    """List all goals for a session, ordered by sort_order then created_at."""
    resp = T.broadcast_tip_goals.query(
        KeyConditionExpression=Key("session_id").eq(session_id),
    )
    items = resp.get("Items", [])
    items.sort(key=lambda g: (int(g.get("sort_order", 0)), int(g.get("created_at", 0))))
    return [_goal_out(item) for item in items]


def get_goal(session_id: str, goal_id: str) -> Dict[str, Any]:
    """Get a single goal by session_id and goal_id."""
    resp = T.broadcast_tip_goals.get_item(
        Key={"session_id": session_id, "goal_id": goal_id},
    )
    item = resp.get("Item")
    if not item:
        raise HTTPException(404, {"code": "GOAL_NOT_FOUND", "message": "Tip goal not found."})
    return _goal_out(item)


def delete_goal(session_id: str, goal_id: str) -> bool:
    """Delete a tip goal."""
    _ = get_goal(session_id, goal_id)  # 404 if not found
    T.broadcast_tip_goals.delete_item(
        Key={"session_id": session_id, "goal_id": goal_id},
    )
    broadcast_sse_publish(session_id, {
        "_type": "goal:deleted",
        "session_id": session_id,
        "goal_id": goal_id,
    })
    return True


def advance_goal_progress(session_id: str, tip_amount_cents: int) -> List[Dict[str, Any]]:
    """Distribute a tip amount across active (non-reached) goals.

    Goals are filled in sort_order. Each goal receives tip amount up to its
    remaining capacity. Overflow spills to the next goal. Once a goal reaches
    its target, it is marked as reached and a goal:reached SSE event fires.
    """
    goals = T.broadcast_tip_goals.query(
        KeyConditionExpression=Key("session_id").eq(session_id),
    ).get("Items", [])

    if not goals:
        return []

    goals.sort(key=lambda g: (int(g.get("sort_order", 0)), int(g.get("created_at", 0))))

    remaining = tip_amount_cents
    updated: List[Dict[str, Any]] = []

    for goal in goals:
        if remaining <= 0:
            updated.append(_goal_out(goal))
            continue
        if goal.get("reached"):
            updated.append(_goal_out(goal))
            continue

        current = int(goal.get("current_cents", 0))
        target = int(goal.get("target_cents", 0))
        capacity = max(0, target - current)

        if capacity <= 0:
            _mark_goal_reached(session_id, goal["goal_id"], current)
            goal["reached"] = True
            goal["current_cents"] = current
            updated.append(_goal_out(goal))
            continue

        applied = min(remaining, capacity)
        new_current = current + applied
        remaining -= applied
        reached_now = new_current >= target

        # Atomic update
        update_parts = ["current_cents = current_cents + :amt"]
        expr_vals: Dict[str, Any] = {":amt": applied}
        if reached_now:
            update_parts.append("reached = :t")
            update_parts.append("reached_at = :ts")
            expr_vals[":t"] = True
            expr_vals[":ts"] = now_ts()

        T.broadcast_tip_goals.update_item(
            Key={"session_id": session_id, "goal_id": goal["goal_id"]},
            UpdateExpression="SET " + ", ".join(update_parts),
            ExpressionAttributeValues=expr_vals,
        )

        goal["current_cents"] = new_current
        goal["reached"] = reached_now
        if reached_now:
            goal["reached_at"] = now_ts()
        goal_out = _goal_out(goal)
        updated.append(goal_out)

        # Publish progress SSE event
        broadcast_sse_publish(session_id, {
            "_type": "goal:progress",
            **goal_out,
            "tip_applied_cents": applied,
        })

        # Publish reached event if threshold crossed
        if reached_now:
            broadcast_sse_publish(session_id, {
                "_type": "goal:reached",
                **goal_out,
            })

    return updated


def _mark_goal_reached(session_id: str, goal_id: str, current_cents: int) -> None:
    """Mark a goal as reached (idempotent)."""
    T.broadcast_tip_goals.update_item(
        Key={"session_id": session_id, "goal_id": goal_id},
        UpdateExpression="SET reached = :t, reached_at = :ts",
        ExpressionAttributeValues={":t": True, ":ts": now_ts()},
    )


def _goal_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert DDB goal item to output dict."""
    return {
        "goal_id": item.get("goal_id", ""),
        "session_id": item.get("session_id", ""),
        "label": item.get("label", ""),
        "target_cents": int(item.get("target_cents", 0)),
        "current_cents": int(item.get("current_cents", 0)),
        "reached": bool(item.get("reached", False)),
        "reached_at": int(item["reached_at"]) if item.get("reached_at") else None,
        "sort_order": int(item.get("sort_order", 0)),
        "created_at": int(item.get("created_at", 0)),
    }
