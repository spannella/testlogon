"""Agent Fleet Management (AGENT-004).

Fleet-level operations: aggregate status, bulk start/stop,
worker templates (save/list/delete/create-from).
"""

from __future__ import annotations

import logging
from decimal import Decimal
from typing import Any, Dict, List, Optional
from uuid import uuid4

from app.core.tables import T
from app.core.time import now_ts
from app.services.agent_worker_provisioner import (
    _item_to_worker,
    create_worker,
    list_workers,
    start_worker,
    stop_worker,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Fleet status
# ---------------------------------------------------------------------------


def fleet_status(user_id: str) -> Dict[str, Any]:
    """Get aggregate fleet metrics for a user.

    Returns total workers, counts by status, queue depth, and worker summaries.
    """
    workers = list_workers(user_id)

    status_counts: Dict[str, int] = {
        "ready": 0,
        "running": 0,
        "stopped": 0,
        "error": 0,
        "provisioning": 0,
    }
    for w in workers:
        s = w.get("worker_status", "unknown")
        if s in status_counts:
            status_counts[s] += 1

    # Queue depth: count agent-eligible tickets
    queue_depth = _count_eligible_tickets(user_id)

    return {
        "total_workers": len(workers),
        "status_counts": status_counts,
        "queue_depth": queue_depth,
        "workers": [_worker_summary(w) for w in workers],
    }


def fleet_capacity(user_id: str) -> Dict[str, Any]:
    """Get capacity metrics: queue depth by type vs workers by type/state."""
    workers = list_workers(user_id)

    workers_by_type: Dict[str, int] = {}
    workers_by_state: Dict[str, int] = {}
    for w in workers:
        at = w.get("agent_type", "unknown")
        workers_by_type[at] = workers_by_type.get(at, 0) + 1
        ws = w.get("worker_status", "unknown")
        workers_by_state[ws] = workers_by_state.get(ws, 0) + 1

    queue_by_type = _count_eligible_by_type(user_id)

    # Simple recommendation
    recommended_action = ""
    total_queue = sum(queue_by_type.values())
    active = workers_by_state.get("ready", 0) + workers_by_state.get("running", 0)
    if total_queue > active and active > 0:
        recommended_action = f"Consider adding more workers -- {total_queue} tickets queued, only {active} active workers."
    elif total_queue > 0 and active == 0:
        recommended_action = "Start or create workers to begin processing queued tickets."

    return {
        "queue_by_type": queue_by_type,
        "workers_by_type": workers_by_type,
        "workers_by_state": workers_by_state,
        "recommended_action": recommended_action,
    }


# ---------------------------------------------------------------------------
# Bulk actions
# ---------------------------------------------------------------------------


def bulk_start(user_id: str) -> Dict[str, Any]:
    """Start all stopped workers. Returns count started."""
    workers = list_workers(user_id, status="stopped")
    started = 0
    errors: List[Dict[str, str]] = []
    for w in workers:
        try:
            start_worker(user_id, w["worker_id"])
            started += 1
        except Exception as e:
            errors.append({"worker_id": w["worker_id"], "error": str(e)})
    logger.info(
        "fleet.bulk.start user_id=%s count=%d errors=%d",
        user_id, started, len(errors),
    )
    return {"count": started, "errors": errors}


def bulk_stop(user_id: str) -> Dict[str, Any]:
    """Stop all running/ready workers. Returns count stopped."""
    workers = list_workers(user_id)
    stoppable = [w for w in workers if w.get("worker_status") in ("ready", "running")]
    stopped = 0
    errors: List[Dict[str, str]] = []
    for w in stoppable:
        try:
            stop_worker(user_id, w["worker_id"])
            stopped += 1
        except Exception as e:
            errors.append({"worker_id": w["worker_id"], "error": str(e)})
    logger.info(
        "fleet.bulk.stop user_id=%s count=%d errors=%d",
        user_id, stopped, len(errors),
    )
    return {"count": stopped, "errors": errors}


# ---------------------------------------------------------------------------
# Worker templates
# ---------------------------------------------------------------------------


def save_template(
    user_id: str,
    *,
    label: str,
    agent_type: str,
    tool: str,
    compute_type: str,
    instance_type: str,
    llm_key_id: str,
    repo_url: str = "",
    branch_convention: str = "",
    idle_timeout_seconds: int = 7200,
    ticket_filter: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Save a worker configuration as a reusable template."""
    template_id = uuid4().hex
    ts = now_ts()
    item: Dict[str, Any] = {
        "pk": f"USER#{user_id}",
        "sk": f"TEMPLATE#{template_id}",
        "template_id": template_id,
        "label": label,
        "agent_type": agent_type,
        "tool": tool,
        "compute_type": compute_type,
        "instance_type": instance_type,
        "llm_key_id": llm_key_id,
        "repo_url": repo_url,
        "branch_convention": branch_convention,
        "idle_timeout_seconds": idle_timeout_seconds,
        "ticket_filter": ticket_filter or {},
        "created_at": ts,
    }
    T.agent_workers.put_item(Item=item)
    logger.info(
        "fleet.template.created user_id=%s template_id=%s agent_type=%s",
        user_id, template_id, agent_type,
    )
    return _template_out(item)


def list_templates(user_id: str) -> List[Dict[str, Any]]:
    """List saved worker templates for a user."""
    resp = T.agent_workers.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
        ExpressionAttributeValues={
            ":pk": f"USER#{user_id}",
            ":prefix": "TEMPLATE#",
        },
    )
    return [_template_out(item) for item in resp.get("Items", [])]


def get_template(user_id: str, template_id: str) -> Optional[Dict[str, Any]]:
    """Get a single template by ID."""
    resp = T.agent_workers.get_item(
        Key={"pk": f"USER#{user_id}", "sk": f"TEMPLATE#{template_id}"}
    )
    item = resp.get("Item")
    return _template_out(item) if item else None


def delete_template(user_id: str, template_id: str) -> None:
    """Delete a worker template."""
    T.agent_workers.delete_item(
        Key={"pk": f"USER#{user_id}", "sk": f"TEMPLATE#{template_id}"}
    )
    logger.info(
        "fleet.template.deleted user_id=%s template_id=%s",
        user_id, template_id,
    )


def create_worker_from_template(
    user_id: str,
    template_id: str,
    label: str = "",
) -> Dict[str, Any]:
    """Create a new worker using a saved template's configuration."""
    tmpl = get_template(user_id, template_id)
    if not tmpl:
        raise ValueError("Template not found")

    return create_worker(
        user_id=user_id,
        label=label or f"{tmpl['label']} (copy)",
        agent_type=tmpl["agent_type"],
        tool=tmpl["tool"],
        compute_type=tmpl["compute_type"],
        instance_type=tmpl["instance_type"],
        llm_key_id=tmpl["llm_key_id"],
        repo_url=tmpl.get("repo_url", ""),
        branch_convention=tmpl.get("branch_convention", ""),
        idle_timeout_seconds=tmpl.get("idle_timeout_seconds", 7200),
        template_id=template_id,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _worker_summary(w: Dict[str, Any]) -> Dict[str, Any]:
    """Build a worker summary dict for fleet status."""
    uptime = 0
    if w.get("started_at") and w.get("worker_status") in ("ready", "running"):
        uptime = max(0, now_ts() - int(w["started_at"]))
    return {
        "worker_id": w.get("worker_id", ""),
        "label": w.get("label", ""),
        "agent_type": w.get("agent_type", ""),
        "tool": w.get("tool", ""),
        "worker_status": w.get("worker_status", "unknown"),
        "agent_state": w.get("agent_state", "idle"),
        "current_ticket_id": w.get("current_ticket_id", ""),
        "current_ticket_title": w.get("current_ticket_title", ""),
        "uptime_seconds": uptime,
        "estimated_cost_cents": w.get("estimated_cost_cents", 0),
        "tickets_completed": w.get("tickets_completed", 0),
    }


def _template_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a DDB template item to a clean dict."""
    tf = item.get("ticket_filter")
    if isinstance(tf, dict):
        tf = {k: (int(v) if isinstance(v, Decimal) else v) for k, v in tf.items()}
    return {
        "template_id": item.get("template_id", ""),
        "label": item.get("label", ""),
        "agent_type": item.get("agent_type", ""),
        "tool": item.get("tool", ""),
        "compute_type": item.get("compute_type", ""),
        "instance_type": item.get("instance_type", ""),
        "llm_key_id": item.get("llm_key_id", ""),
        "repo_url": item.get("repo_url", ""),
        "branch_convention": item.get("branch_convention", ""),
        "idle_timeout_seconds": int(item.get("idle_timeout_seconds", 7200))
        if isinstance(item.get("idle_timeout_seconds"), Decimal)
        else item.get("idle_timeout_seconds", 7200),
        "ticket_filter": tf if tf else {},
        "created_at": int(item.get("created_at", 0))
        if isinstance(item.get("created_at"), Decimal)
        else item.get("created_at", 0),
    }


def _count_eligible_tickets(user_id: str) -> int:
    """Count agent-eligible unclaimed tickets.

    Queries the tickets table for items with agent_eligible='yes' that have
    no current agent claim.
    """
    try:
        total = 0
        kwargs: dict = {
            "FilterExpression": "agent_eligible = :yes AND attribute_not_exists(agent_claimed_by)",
            "ExpressionAttributeValues": {":yes": "yes"},
            "Select": "COUNT",
        }
        while True:
            resp = T.tickets.scan(**kwargs)
            total += resp.get("Count", 0)
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
            kwargs["ExclusiveStartKey"] = last_key
        return total
    except Exception:
        logger.debug("fleet._count_eligible_tickets failed, returning 0")
        return 0


def _count_eligible_by_type(user_id: str) -> Dict[str, int]:
    """Count eligible tickets grouped by type."""
    try:
        by_type: Dict[str, int] = {}
        kwargs: dict = {
            "FilterExpression": "agent_eligible = :yes AND attribute_not_exists(agent_claimed_by)",
            "ExpressionAttributeValues": {":yes": "yes"},
        }
        while True:
            resp = T.tickets.scan(**kwargs)
            for item in resp.get("Items", []):
                t = item.get("type", "untyped")
                by_type[t] = by_type.get(t, 0) + 1
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
            kwargs["ExclusiveStartKey"] = last_key
        return by_type
    except Exception:
        logger.debug("fleet._count_eligible_by_type failed, returning empty")
        return {}
