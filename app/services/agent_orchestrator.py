"""Agent Orchestrator -- Core Agent Loop (AGENT-003).

Drives autonomous ticket processing: query -> claim -> inject ->
monitor -> complete -> loop. Manages agent state machine and
heartbeat monitoring.
"""

from __future__ import annotations

import asyncio
import json
import logging
from decimal import Decimal
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


def _ddb_lowlevel_client() -> Any:
    """Return a low-level DynamoDB client for ``transact_write_items``.

    The boto3 *resource*-attached client (``Table.meta.client``) applies the
    high-level resource transforms, which mangle the explicitly attribute-typed
    items required by ``transact_write_items`` (observed against both moto and
    DynamoDB Local: ``Invalid attribute value type`` / unhashable dict). A
    fresh low-level client built from the same endpoint/region/credentials as
    the project ``ddb`` resource avoids that and keeps dev/prod parity
    (SECOPS-007) -- it inherits the local-stack endpoint in dev and real AWS
    config in prod from the shared resource meta. Resolved lazily so test
    patches of the resource take effect.
    """
    from app.core.aws import ddb  # local import: honors monkeypatched resource

    meta = ddb.meta.client.meta
    creds = getattr(ddb.meta.client._request_signer, "_credentials", None)
    kwargs: Dict[str, Any] = {
        "region_name": meta.region_name,
        "endpoint_url": meta.endpoint_url,
    }
    if creds is not None:
        kwargs["aws_access_key_id"] = creds.access_key
        kwargs["aws_secret_access_key"] = creds.secret_key
        if creds.token:
            kwargs["aws_session_token"] = creds.token
    return boto3.client("dynamodb", **kwargs)

# ---------------------------------------------------------------------------
# Agent state transitions
# ---------------------------------------------------------------------------

VALID_TRANSITIONS: Dict[str, set] = {
    "idle": {"claiming", "paused"},
    "claiming": {"working", "idle", "error"},
    "working": {"awaiting_feedback", "completing", "paused", "error", "idle"},
    "awaiting_feedback": {"working", "paused", "error", "idle"},
    "completing": {"idle", "error"},
    "paused": {"idle", "working"},
    "error": {"idle"},
}

# In-memory set of running agent loops (worker_id -> True)
_running_loops: Dict[str, bool] = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _coerce_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert DDB Decimals to ints in a flat dict."""
    out: Dict[str, Any] = {}
    for k, v in item.items():
        if k in ("pk", "sk"):
            continue
        if isinstance(v, Decimal):
            out[k] = int(v)
        elif isinstance(v, dict):
            out[k] = {kk: (int(vv) if isinstance(vv, Decimal) else vv) for kk, vv in v.items()}
        elif isinstance(v, list):
            coerced = []
            for entry in v:
                if isinstance(entry, dict):
                    coerced.append(
                        {kk: (int(vv) if isinstance(vv, Decimal) else vv) for kk, vv in entry.items()}
                    )
                elif isinstance(entry, Decimal):
                    coerced.append(int(entry))
                else:
                    coerced.append(entry)
            out[k] = coerced
        else:
            out[k] = v
    return out


def _get_worker_item(user_id: str, worker_id: str) -> Optional[Dict[str, Any]]:
    """Fetch raw worker item from DDB."""
    resp = T.agent_workers.get_item(
        Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"}
    )
    return resp.get("Item")


# Control sentinels the terminal monitoring loop scans for as agent state
# transitions. They MUST NOT appear verbatim in user-controlled ticket content
# (GAP-0082: prompt injection — a forged token would fire a false completion or
# freeze the worker awaiting non-existent feedback).
_SIGNAL_TOKENS = (
    "[AGENT_COMPLETE]",
    "[AGENT_FEEDBACK_NEEDED]",
)

# Max length for any single injected user-controlled field. Caps the blast
# radius of oversized ticket content flooding the injected context.
_TICKET_FIELD_MAX_LEN = 4000


def _sanitize_ticket_field(value: Any) -> str:
    """Neutralize agent signal tokens in user-supplied ticket content.

    Replaces the literal control sentinels with a visually similar but
    non-functional fullwidth-bracket form so they render clearly to a human
    reviewer yet are never matched by the monitoring loop. Also caps the field
    length. Applied to every user-controlled field before it is interpolated
    into the agent context (defense at read-time; runs identically in dev and
    prod per SECOPS-007).
    """
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    for token in _SIGNAL_TOKENS:
        safe = token.replace("[", "［").replace("]", "］")
        text = text.replace(token, safe)
    if len(text) > _TICKET_FIELD_MAX_LEN:
        text = text[:_TICKET_FIELD_MAX_LEN] + "… [truncated]"
    return text


# ---------------------------------------------------------------------------
# State Machine
# ---------------------------------------------------------------------------

def transition_agent_state(
    user_id: str,
    worker_id: str,
    new_state: str,
) -> Dict[str, Any]:
    """Transition agent state with validation.

    Enforces valid state transitions. Updates DDB atomically
    with condition expression to prevent race conditions.
    """
    worker = _get_worker_item(user_id, worker_id)
    if not worker:
        raise ValueError("Worker not found")

    current = worker.get("agent_state", "idle")
    allowed = VALID_TRANSITIONS.get(current, set())
    if new_state not in allowed:
        raise ValueError(
            f"Cannot transition from {current} to {new_state}. "
            f"Allowed transitions from {current}: {sorted(allowed)}"
        )

    ts = now_ts()
    try:
        T.agent_workers.update_item(
            Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"},
            UpdateExpression="SET agent_state = :ns, heartbeat_at = :hb, last_activity_at = :la",
            ConditionExpression="attribute_not_exists(agent_state) OR agent_state = :current",
            ExpressionAttributeValues={
                ":ns": new_state,
                ":hb": ts,
                ":la": ts,
                ":current": current,
            },
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise ValueError("Agent state changed concurrently. Refresh and try again.")
        raise

    logger.info(
        "agent.state.transition worker_id=%s from=%s to=%s",
        worker_id, current, new_state,
    )
    updated = _get_worker_item(user_id, worker_id) or worker
    return _coerce_item(updated)


# ---------------------------------------------------------------------------
# Ticket Finding
# ---------------------------------------------------------------------------

def get_eligible_tickets(
    user_id: str,
    worker_id: str,
) -> Dict[str, Any]:
    """Find all eligible tickets for this worker based on its ticket_filter.

    Queries the tickets table for items matching:
    - agent_eligible == "yes"
    - status in ("open")
    - agent_worker_id is empty (not claimed by another agent)
    - matches worker's ticket_filter (types, tags, space_ids, priorities)
    """
    worker = _get_worker_item(user_id, worker_id)
    if not worker:
        return {"tickets": [], "count": 0, "filter_applied": None}

    ticket_filter = worker.get("ticket_filter") or {}
    filter_types = ticket_filter.get("types", [])
    filter_tags = ticket_filter.get("tags", [])
    filter_space_ids = ticket_filter.get("space_ids", [])
    filter_priorities = ticket_filter.get("priorities", [])

    # Scan tickets table for agent-eligible, unclaimed tickets
    # In production this would use a GSI; for dev/test a scan is fine
    scan_kwargs: Dict[str, Any] = {}
    items: List[Dict[str, Any]] = []
    while True:
        resp = T.tickets.scan(**scan_kwargs)
        for item in resp.get("Items", []):
            # Must be a ticket META item
            if not str(item.get("sk", "")).startswith("META"):
                continue
            if item.get("agent_eligible") != "yes":
                continue
            # Must not already be claimed
            awid = item.get("agent_worker_id", "")
            if awid and awid != "":
                continue
            # Status must be open
            status = item.get("status", "")
            if status not in ("open",):
                continue
            items.append(item)
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
        scan_kwargs["ExclusiveStartKey"] = last_key

    # Apply worker's ticket_filter
    filtered: List[Dict[str, Any]] = []
    for item in items:
        if filter_types:
            ticket_type = item.get("type", item.get("category", ""))
            if ticket_type not in filter_types:
                continue
        if filter_tags:
            ticket_tags = item.get("tags", [])
            if isinstance(ticket_tags, str):
                ticket_tags = [ticket_tags]
            if not any(t in filter_tags for t in ticket_tags):
                continue
        if filter_space_ids:
            space_id = item.get("space_id", "")
            if space_id not in filter_space_ids:
                continue
        if filter_priorities:
            priority = item.get("priority", "medium")
            if priority not in filter_priorities:
                continue
        filtered.append(item)

    # Sort by priority (critical > high > medium > low)
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    filtered.sort(key=lambda t: priority_order.get(t.get("priority", "medium"), 2))

    tickets_out = []
    for t in filtered:
        tickets_out.append({
            "ticket_id": t.get("ticket_id", ""),
            "title": t.get("subject", t.get("title", "")),
            "priority": t.get("priority", "medium"),
            "type": t.get("type", t.get("category", "")),
            "tags": t.get("tags", []),
            "space_id": t.get("space_id", ""),
            "created_at": int(t.get("created_at", 0) if t.get("created_at") is not None else 0),
        })

    tf_out = None
    if ticket_filter:
        tf_out = {
            "types": filter_types,
            "tags": filter_tags,
            "space_ids": filter_space_ids,
            "priorities": filter_priorities,
        }

    return {
        "tickets": tickets_out,
        "count": len(tickets_out),
        "filter_applied": tf_out,
    }


def find_next_ticket(
    user_id: str,
    worker_id: str,
) -> Optional[Dict[str, Any]]:
    """Find the next eligible ticket for this worker.

    Returns the highest-priority unassigned ticket, or None.
    """
    result = get_eligible_tickets(user_id, worker_id)
    tickets = result.get("tickets", [])
    return tickets[0] if tickets else None


# ---------------------------------------------------------------------------
# Ticket Claiming
# ---------------------------------------------------------------------------

def claim_ticket(
    user_id: str,
    worker_id: str,
    ticket_id: str,
) -> Dict[str, Any]:
    """Claim a ticket for a worker using optimistic locking.

    Uses DynamoDB conditional write to ensure only one agent
    can claim a ticket. If claim fails, raises ValueError.
    """
    ts = now_ts()

    # The claim record + the ticket-META update must commit atomically.
    # GAP-0081: two sequential writes left an orphaned AGENT_CLAIM# record if
    # the process crashed (SIGKILL/OOM) or write-2 failed for a reason other
    # than ClientError (the old compensating delete only fired on ClientError).
    # TransactWriteItems is all-or-nothing: a crash before/within the call
    # commits neither write, and concurrent claimers can never both win.
    claim_item = {
        "pk": f"AGENT_CLAIM#{ticket_id}",
        "sk": f"CLAIM#{worker_id}",
        "worker_id": worker_id,
        "user_id": user_id,
        "claimed_at": ts,
        "status": "active",
        "checkpoint": "",
    }

    # table_name resolves through the _FloatSafeTable proxy's __getattr__
    # delegation to the wrapped boto3 Table. The low-level client is built
    # fresh (see _ddb_lowlevel_client) because the resource-attached client
    # cannot handle transact_write_items' typed items. Identical code path in
    # dev (DynamoDB Local) and prod (SECOPS-007); both support transactions.
    client = _ddb_lowlevel_client()
    table_name = T.tickets.table_name

    try:
        client.transact_write_items(
            TransactItems=[
                {
                    "Put": {
                        "TableName": table_name,
                        "Item": {
                            "pk": {"S": f"AGENT_CLAIM#{ticket_id}"},
                            "sk": {"S": f"CLAIM#{worker_id}"},
                            "worker_id": {"S": worker_id},
                            "user_id": {"S": user_id},
                            "claimed_at": {"N": str(ts)},
                            "status": {"S": "active"},
                            "checkpoint": {"S": ""},
                        },
                        "ConditionExpression": "attribute_not_exists(pk)",
                    }
                },
                {
                    "Update": {
                        "TableName": table_name,
                        "Key": {
                            "pk": {"S": f"TICKET#{ticket_id}"},
                            "sk": {"S": "META"},
                        },
                        "UpdateExpression": (
                            "SET agent_worker_id = :wid, agent_claimed_at = :ts, "
                            "agent_state = :as_val"
                        ),
                        "ConditionExpression": (
                            "attribute_not_exists(agent_worker_id) "
                            "OR agent_worker_id = :empty"
                        ),
                        "ExpressionAttributeValues": {
                            ":wid": {"S": worker_id},
                            ":ts": {"N": str(ts)},
                            ":as_val": {"S": "claimed"},
                            ":empty": {"S": ""},
                        },
                    }
                },
            ]
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        # A failed condition on either item means another worker already holds
        # the claim or the ticket META. The transaction committed nothing, so
        # there is no orphaned claim record to roll back.
        if code in ("TransactionCanceledException", "ConditionalCheckFailedException"):
            raise ValueError(f"Ticket {ticket_id} already claimed by another agent")
        raise

    # 3. Get ticket title for denormalization
    ticket_item = T.tickets.get_item(
        Key={"pk": f"TICKET#{ticket_id}", "sk": "META"}
    ).get("Item", {})
    ticket_title = ticket_item.get("subject", ticket_item.get("title", ""))

    # 4. Update worker with current ticket and transition to working
    T.agent_workers.update_item(
        Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"},
        UpdateExpression=(
            "SET current_ticket_id = :tid, current_ticket_title = :ttl, "
            "agent_state = :as_val, heartbeat_at = :hb, last_activity_at = :la"
        ),
        ExpressionAttributeValues={
            ":tid": ticket_id,
            ":ttl": ticket_title,
            ":as_val": "working",
            ":hb": ts,
            ":la": ts,
        },
    )

    logger.info(
        "agent.ticket.claimed worker_id=%s ticket_id=%s title=%s",
        worker_id, ticket_id, ticket_title,
    )
    return _coerce_item(claim_item)


def release_ticket(
    user_id: str,
    worker_id: str,
    ticket_id: str,
    *,
    reason: str = "released",
) -> None:
    """Release a claimed ticket back to the queue.

    Clears the claim lock and resets ticket's agent fields.
    """
    ts = now_ts()

    # Update claim record status
    try:
        T.tickets.update_item(
            Key={"pk": f"AGENT_CLAIM#{ticket_id}", "sk": f"CLAIM#{worker_id}"},
            UpdateExpression="SET #st = :st",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":st": reason},
        )
    except ClientError:
        pass  # Claim record may not exist

    # Clear ticket's agent_worker_id
    try:
        T.tickets.update_item(
            Key={"pk": f"TICKET#{ticket_id}", "sk": "META"},
            UpdateExpression=(
                "SET agent_worker_id = :empty, agent_claimed_at = :zero, "
                "agent_state = :empty"
            ),
            ExpressionAttributeValues={
                ":empty": "",
                ":zero": 0,
            },
        )
    except ClientError:
        pass

    # Reset worker's current_ticket_id and agent_state to idle
    T.agent_workers.update_item(
        Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"},
        UpdateExpression=(
            "SET current_ticket_id = :empty, current_ticket_title = :empty, "
            "agent_state = :idle, last_activity_at = :la"
        ),
        ExpressionAttributeValues={
            ":empty": "",
            ":idle": "idle",
            ":la": ts,
        },
    )

    logger.info(
        "agent.ticket.released worker_id=%s ticket_id=%s reason=%s",
        worker_id, ticket_id, reason,
    )


def complete_ticket(
    user_id: str,
    worker_id: str,
    ticket_id: str,
    *,
    summary: str = "",
    pr_url: str = "",
) -> None:
    """Mark a ticket as completed by the agent.

    Updates claim, ticket status, and worker counters.
    """
    ts = now_ts()

    # 1. Update claim status to "completed"
    try:
        T.tickets.update_item(
            Key={"pk": f"AGENT_CLAIM#{ticket_id}", "sk": f"CLAIM#{worker_id}"},
            UpdateExpression="SET #st = :st",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={":st": "completed"},
        )
    except ClientError:
        pass

    # 2. Update ticket agent fields
    try:
        T.tickets.update_item(
            Key={"pk": f"TICKET#{ticket_id}", "sk": "META"},
            UpdateExpression=(
                "SET agent_state = :done, agent_worker_id = :empty"
            ),
            ExpressionAttributeValues={
                ":done": "completed",
                ":empty": "",
            },
        )
    except ClientError:
        pass

    # 3. Increment worker's tickets_completed and clear current ticket
    T.agent_workers.update_item(
        Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"},
        UpdateExpression=(
            "SET current_ticket_id = :empty, current_ticket_title = :empty, "
            "agent_state = :idle, last_activity_at = :la "
            "ADD tickets_completed :one"
        ),
        ExpressionAttributeValues={
            ":empty": "",
            ":idle": "idle",
            ":la": ts,
            ":one": 1,
        },
    )

    logger.info(
        "agent.ticket.completed worker_id=%s ticket_id=%s summary=%s",
        worker_id, ticket_id, summary,
    )


# ---------------------------------------------------------------------------
# Checkpoint System
# ---------------------------------------------------------------------------

def save_checkpoint(
    user_id: str,
    worker_id: str,
    ticket_id: str,
    checkpoint_data: Dict[str, Any],
) -> None:
    """Save a checkpoint for crash recovery."""
    serialized = json.dumps(checkpoint_data)
    if len(serialized) > 65536:
        raise ValueError("Checkpoint data exceeds 64KB limit.")

    T.tickets.update_item(
        Key={"pk": f"AGENT_CLAIM#{ticket_id}", "sk": f"CLAIM#{worker_id}"},
        UpdateExpression="SET checkpoint = :cp",
        ExpressionAttributeValues={":cp": serialized},
    )

    # Also store checkpoint on the ticket itself
    try:
        T.tickets.update_item(
            Key={"pk": f"TICKET#{ticket_id}", "sk": "META"},
            UpdateExpression="SET agent_checkpoint = :cp",
            ExpressionAttributeValues={":cp": serialized},
        )
    except ClientError:
        pass

    logger.debug(
        "agent.checkpoint.saved worker_id=%s ticket_id=%s size=%d",
        worker_id, ticket_id, len(serialized),
    )


def resume_from_checkpoint(
    user_id: str,
    worker_id: str,
) -> Optional[Dict[str, Any]]:
    """Check if the worker has an in-progress ticket to resume.

    Called on worker restart. Returns checkpoint data if found.
    """
    worker = _get_worker_item(user_id, worker_id)
    if not worker or not worker.get("current_ticket_id"):
        return None

    ticket_id = worker["current_ticket_id"]
    claim = T.tickets.get_item(
        Key={"pk": f"AGENT_CLAIM#{ticket_id}", "sk": f"CLAIM#{worker_id}"}
    ).get("Item")
    if claim and claim.get("status") == "active":
        checkpoint_str = claim.get("checkpoint", "")
        return {
            "ticket_id": ticket_id,
            "checkpoint": json.loads(checkpoint_str) if checkpoint_str else {},
            "claimed_at": int(claim.get("claimed_at", 0) if claim.get("claimed_at") is not None else 0),
        }
    return None


def get_checkpoint(
    user_id: str,
    worker_id: str,
) -> Optional[Dict[str, Any]]:
    """Get the current checkpoint data for the worker."""
    worker = _get_worker_item(user_id, worker_id)
    if not worker or not worker.get("current_ticket_id"):
        return None

    ticket_id = worker["current_ticket_id"]
    claim = T.tickets.get_item(
        Key={"pk": f"AGENT_CLAIM#{ticket_id}", "sk": f"CLAIM#{worker_id}"}
    ).get("Item")
    if not claim:
        return None

    checkpoint_str = claim.get("checkpoint", "")
    return {
        "ticket_id": ticket_id,
        "checkpoint": json.loads(checkpoint_str) if checkpoint_str else {},
        "claimed_at": int(claim.get("claimed_at", 0) if claim.get("claimed_at") is not None else 0),
    }


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------

def record_heartbeat(user_id: str, worker_id: str) -> int:
    """Record a heartbeat from a worker agent. Returns the timestamp."""
    ts = now_ts()
    T.agent_workers.update_item(
        Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"},
        UpdateExpression="SET heartbeat_at = :hb, last_activity_at = :la",
        ExpressionAttributeValues={":hb": ts, ":la": ts},
    )
    return ts


def check_stale_heartbeats(
    user_id: str,
    threshold_seconds: int = 120,
) -> List[Dict[str, Any]]:
    """Find workers with missed heartbeats for a specific user.

    Returns list of workers where now - heartbeat_at > threshold.
    """
    ts = now_ts()
    cutoff = ts - threshold_seconds

    resp = T.agent_workers.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
        ExpressionAttributeValues={":pk": f"USER#{user_id}", ":prefix": "WORKER#"},
    )

    stale = []
    for item in resp.get("Items", []):
        state = item.get("agent_state", "idle")
        if state not in ("working", "awaiting_feedback"):
            continue
        hb = int(item.get("heartbeat_at", 0) or 0)
        if hb > 0 and hb < cutoff:
            stale.append(_coerce_item(item))
    return stale


# ---------------------------------------------------------------------------
# Context Injection
# ---------------------------------------------------------------------------

def inject_ticket_context(
    user_id: str,
    worker_id: str,
    ticket_id: str,
) -> str:
    """Build the context injection text for a ticket.

    Generates a formatted prompt that will be pasted into
    the agent's terminal session.
    """
    ticket = T.tickets.get_item(
        Key={"pk": f"TICKET#{ticket_id}", "sk": "META"}
    ).get("Item")
    if not ticket:
        raise ValueError(f"Ticket {ticket_id} not found")

    # Sanitize user-controlled fields before interpolation so a malicious
    # ticket cannot forge the agent control sentinels (GAP-0082). The
    # [AGENT_COMPLETE] / [AGENT_FEEDBACK_NEEDED] literals in the INSTRUCTIONS
    # block below are platform-authored and intentionally kept verbatim.
    subject = _sanitize_ticket_field(
        ticket.get("subject", ticket.get("title", "Untitled"))
    )
    description = _sanitize_ticket_field(ticket.get("description", ""))
    acceptance = _sanitize_ticket_field(
        ticket.get("acceptance_criteria", "None specified")
    )

    context = f"""--- TICKET: {subject} ---
ID: {ticket_id}
Priority: {ticket.get('priority', 'medium')}
Status: {ticket.get('status', 'open')}
Type: {ticket.get('type', ticket.get('category', 'task'))}

DESCRIPTION:
{description}

ACCEPTANCE CRITERIA:
{acceptance}

INSTRUCTIONS:
1. Create a feature branch: agent/{worker_id}/{ticket_id}
2. Implement the changes described above
3. Run tests to verify your changes
4. Commit with a descriptive message referencing {ticket_id}
5. When complete, output: [AGENT_COMPLETE]
6. If you need human input, output: [AGENT_FEEDBACK_NEEDED] followed by your question
---"""
    return context


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

def get_agent_status(user_id: str, worker_id: str) -> Optional[Dict[str, Any]]:
    """Get comprehensive agent status for display."""
    worker = _get_worker_item(user_id, worker_id)
    if not worker:
        return None

    ticket_filter = worker.get("ticket_filter")
    tf_out = None
    if ticket_filter and isinstance(ticket_filter, dict):
        tf_out = {
            "types": ticket_filter.get("types", []),
            "tags": ticket_filter.get("tags", []),
            "space_ids": ticket_filter.get("space_ids", []),
            "priorities": ticket_filter.get("priorities", []),
        }

    return {
        "worker_id": worker_id,
        "agent_state": worker.get("agent_state", "idle"),
        "current_ticket_id": worker.get("current_ticket_id", ""),
        "current_ticket_title": worker.get("current_ticket_title", ""),
        "tickets_completed": int(worker.get("tickets_completed", 0) or 0),
        "tickets_failed": int(worker.get("tickets_failed", 0) or 0),
        "heartbeat_at": int(worker.get("heartbeat_at", 0) or 0),
        "last_activity_at": int(worker.get("last_activity_at", 0) or 0),
        "ticket_filter": tf_out,
        "loop_running": worker_id in _running_loops,
    }


# ---------------------------------------------------------------------------
# Ticket Filter
# ---------------------------------------------------------------------------

def update_ticket_filter(
    user_id: str,
    worker_id: str,
    ticket_filter: Dict[str, Any],
) -> Dict[str, Any]:
    """Update the worker's ticket filter configuration."""
    worker = _get_worker_item(user_id, worker_id)
    if not worker:
        raise ValueError("Worker not found")

    tf = {
        "types": ticket_filter.get("types", []),
        "tags": ticket_filter.get("tags", []),
        "space_ids": ticket_filter.get("space_ids", []),
        "priorities": ticket_filter.get("priorities", []),
    }

    T.agent_workers.update_item(
        Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"},
        UpdateExpression="SET ticket_filter = :tf",
        ExpressionAttributeValues={":tf": tf},
    )

    return {"ok": True, "ticket_filter": tf}


# ---------------------------------------------------------------------------
# Agent Loop Control
# ---------------------------------------------------------------------------

# Default poll interval between loop iterations (seconds). Overridable for
# tests via monkeypatching this module-level constant.
AGENT_LOOP_POLL_INTERVAL_SECONDS = 30


async def _dispatch_ticket(
    user_id: str,
    worker_id: str,
    ticket: Dict[str, Any],
    context: str,
) -> None:
    """Dispatch a claimed ticket to the agent execution layer.

    This is intentionally a safe no-op stub. Real agent execution
    (terminal session injection / Claude invocation, AGENT-004/006) is
    flag-gated and must NOT be triggered from this loop until wired up
    deliberately. The loop's responsibility here is limited to discovering
    and claiming eligible tickets; actual work dispatch is a follow-on.
    """
    logger.info(
        "agent.loop.ticket_dispatched worker_id=%s ticket_id=%s (no-op stub)",
        worker_id,
        ticket.get("ticket_id", ""),
    )


async def run_agent_loop(user_id: str, worker_id: str) -> None:
    """Autonomous agent loop: poll for eligible tickets and work them.

    Runs as an asyncio background task until the worker_id is removed from
    ``_running_loops`` (by ``stop_agent_loop``) or the worker record
    disappears. Each iteration honours pause/error state, refreshes the
    heartbeat, finds the next eligible ticket, claims it atomically
    (tolerating claim races), injects context, and hands off to the
    (currently no-op) dispatch stub.

    NOTE (SECOPS-007 / AGENT-003): ``_running_loops`` is an in-process dict.
    This is correct ONLY for single-process deployments (uvicorn
    ``--workers 1``, as required in dev by the moto constraint). For
    multi-process / multi-instance deployments a distributed lock
    (e.g. a DynamoDB conditional write or SQS visibility timeout) must
    replace this dict before horizontal scaling.
    """
    logger.info("agent.loop.running worker_id=%s user_id=%s", worker_id, user_id)
    try:
        while worker_id in _running_loops:
            poll_interval = AGENT_LOOP_POLL_INTERVAL_SECONDS

            # 1. Re-fetch worker state -- honour pause/stop/error signals.
            worker = _get_worker_item(user_id, worker_id)
            if not worker:
                logger.warning("agent.loop.worker_missing worker_id=%s", worker_id)
                break
            state = worker.get("agent_state", "idle")
            if state in ("paused", "error", "working", "claiming", "completing"):
                # Already busy (or paused/error) -- don't start new work.
                await asyncio.sleep(poll_interval)
                continue

            # 2. Refresh heartbeat (best-effort).
            try:
                T.agent_workers.update_item(
                    Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"},
                    UpdateExpression="SET heartbeat_at = :hb",
                    ExpressionAttributeValues={":hb": now_ts()},
                )
            except Exception:
                logger.warning("agent.loop.heartbeat_failed worker_id=%s", worker_id)

            # 3. Find next eligible ticket.
            ticket = find_next_ticket(user_id, worker_id)
            if not ticket:
                await asyncio.sleep(poll_interval)
                continue

            ticket_id = ticket["ticket_id"]

            # 4. Claim it (atomic -- tolerate races with other workers).
            try:
                transition_agent_state(user_id, worker_id, "claiming")
                claim_ticket(user_id, worker_id, ticket_id)
            except ValueError as exc:
                logger.info(
                    "agent.loop.claim_lost worker_id=%s ticket_id=%s reason=%s",
                    worker_id, ticket_id, exc,
                )
                try:
                    transition_agent_state(user_id, worker_id, "idle")
                except ValueError:
                    pass
                await asyncio.sleep(poll_interval)
                continue

            # 5. Inject context and hand off to the dispatch stub.
            try:
                context = inject_ticket_context(user_id, worker_id, ticket_id)
                logger.info(
                    "agent.loop.ticket_claimed worker_id=%s ticket_id=%s",
                    worker_id, ticket_id,
                )
                await _dispatch_ticket(user_id, worker_id, ticket, context)
            except Exception:
                logger.exception(
                    "agent.loop.dispatch_error worker_id=%s ticket_id=%s",
                    worker_id, ticket_id,
                )
                try:
                    release_ticket(user_id, worker_id, ticket_id, reason="error")
                except Exception:
                    pass

            await asyncio.sleep(poll_interval)
    finally:
        _running_loops.pop(worker_id, None)
        logger.info("agent.loop.exited worker_id=%s", worker_id)


def start_agent_loop(user_id: str, worker_id: str) -> Dict[str, Any]:
    """Mark the agent loop as started and schedule the background coroutine.

    Schedules ``run_agent_loop`` on the running asyncio event loop. The
    FastAPI/uvicorn endpoint that calls this is ``async def`` and therefore
    runs on the event loop, so ``asyncio.create_task`` is safe. If no event
    loop is running (e.g. a purely synchronous caller/test), the loop flag
    is still set but no task is scheduled -- callers in that case are
    responsible for awaiting ``run_agent_loop`` directly.
    """
    worker = _get_worker_item(user_id, worker_id)
    if not worker:
        raise ValueError("Worker not found")

    if worker_id in _running_loops:
        raise ValueError("Agent loop is already running for this worker.")

    # Initialize agent_state to idle if not set
    current_state = worker.get("agent_state", "")
    ts = now_ts()
    if not current_state or current_state in ("", "error"):
        T.agent_workers.update_item(
            Key={"pk": f"USER#{user_id}", "sk": f"WORKER#{worker_id}"},
            UpdateExpression="SET agent_state = :idle, heartbeat_at = :hb, last_activity_at = :la",
            ExpressionAttributeValues={":idle": "idle", ":hb": ts, ":la": ts},
        )

    _running_loops[worker_id] = True

    # Schedule the autonomous loop on the running event loop, if any.
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop is not None:
        task = loop.create_task(run_agent_loop(user_id, worker_id))
        # asyncio.create_task swallows exceptions that are never awaited;
        # surface any uncaught error from the loop coroutine.
        task.add_done_callback(
            lambda t: (
                t.exception()
                and logger.error(
                    "agent.loop.uncaught_exception worker_id=%s",
                    worker_id,
                    exc_info=t.exception(),
                )
            )
            if not t.cancelled()
            else None
        )

    logger.info("agent.loop.started worker_id=%s user_id=%s", worker_id, user_id)

    return {
        "ok": True,
        "worker_id": worker_id,
        "agent_state": worker.get("agent_state", "idle") if current_state else "idle",
        "message": "Agent loop started. Will begin picking up eligible tickets.",
    }


def stop_agent_loop(user_id: str, worker_id: str) -> Dict[str, Any]:
    """Stop the agent loop."""
    worker = _get_worker_item(user_id, worker_id)
    if not worker:
        raise ValueError("Worker not found")

    _running_loops.pop(worker_id, None)

    # If agent is in idle/paused/error, keep current state.
    # Don't force transition, just mark loop as stopped.
    logger.info("agent.loop.stopped worker_id=%s", worker_id)

    return {
        "ok": True,
        "worker_id": worker_id,
        "agent_state": worker.get("agent_state", "idle"),
        "message": "Agent loop stopped. Ticket retained if in progress.",
    }


def is_loop_running(worker_id: str) -> bool:
    """Check if the agent loop is running for a worker."""
    return worker_id in _running_loops


# ---------------------------------------------------------------------------
# Worker initialization helper (for E2E tests / AGENT-002 stub)
# ---------------------------------------------------------------------------

def ensure_worker_exists(
    user_id: str,
    worker_id: str,
    *,
    label: str = "Test Worker",
    agent_type: str = "coder",
) -> Dict[str, Any]:
    """Create a worker record if it doesn't already exist.

    Used by E2E tests when AGENT-002 is not deployed.
    """
    existing = _get_worker_item(user_id, worker_id)
    if existing:
        return _coerce_item(existing)

    ts = now_ts()
    item = {
        "pk": f"USER#{user_id}",
        "sk": f"WORKER#{worker_id}",
        "worker_id": worker_id,
        "user_id": user_id,
        "label": label,
        "agent_type": agent_type,
        "worker_status": "ready",
        "agent_state": "idle",
        "current_ticket_id": "",
        "current_ticket_title": "",
        "tickets_completed": 0,
        "tickets_failed": 0,
        "heartbeat_at": 0,
        "last_activity_at": ts,
        "created_at": ts,
        "ticket_filter": {},
    }
    T.agent_workers.put_item(Item=item)
    return _coerce_item(item)
