"""DMCA claims service layer (MOD-002).

Manages the full lifecycle of DMCA takedown claims: filing, counter-notices,
resolution, repeat infringer tracking, and background waiting-period expiry.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import write_alert
from app.services.dmca_content_operations import (
    hide_content_for_dmca,
    resolve_content_from_url,
    resolve_content_owner,
    restore_content_after_dmca,
)
from app.services.moderation_audit_log import write_moderation_audit_event
from app.services.moderation_policy_engine import apply_ban

logger = logging.getLogger(__name__)

DMCA_STRIKE_THRESHOLD = S.dmca_strike_threshold
DMCA_STRIKE_LOOKBACK_DAYS = S.dmca_strike_lookback_days
DMCA_WAITING_PERIOD_DAYS = 14

_DMCA_STATUS_TRANSITIONS: Dict[str, set] = {
    "filed": {"content_removed"},
    "content_removed": {"counter_notice_filed", "withdrawn", "resolved"},
    "counter_notice_filed": {"waiting_period"},
    "waiting_period": {"resolved", "escalated"},
    "escalated": {"resolved"},
    "withdrawn": set(),
    "resolved": set(),
}


def _coerce_int(val: Any, default: int = 0) -> int:
    try:
        return int(str(val))
    except (TypeError, ValueError):
        return default


def _claim_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a raw DDB item to a public claim dict."""
    return {
        "claim_id": item.get("claim_id", ""),
        "status": item.get("status", ""),
        "claimant_name": item.get("claimant_name", ""),
        "claimant_email": item.get("claimant_email", ""),
        "content_url": item.get("content_url", ""),
        "content_type": item.get("content_type", ""),
        "content_id": item.get("content_id", ""),
        "target_user_id": item.get("target_user_id", ""),
        "original_work_description": item.get("original_work_description", ""),
        "created_at": _coerce_int(item.get("created_at")),
        "updated_at": _coerce_int(item.get("updated_at")),
        "content_removed_at": _coerce_int(item.get("content_removed_at")) or None,
        "counter_notice_filed_at": _coerce_int(item.get("counter_notice_filed_at")) or None,
        "waiting_period_expires_at": _coerce_int(item.get("waiting_period_expires_at")) or None,
        "resolved_at": _coerce_int(item.get("resolved_at")) or None,
        "resolution": item.get("resolution") or None,
        "strike_number": _coerce_int(item.get("strike_number")),
    }


# ---------------------------------------------------------------------------
# Core operations
# ---------------------------------------------------------------------------

def _check_claimant_rate_limit(claimant_email: str) -> None:
    """Enforce a per-claimant daily cap on DMCA filings.

    Queries the ``ByClaimantCreatedAt`` GSI (partition=claimant_email,
    sort=created_at) for claims filed in the last 24h. If the count is at or
    above ``S.dmca_max_claims_per_claimant_per_day``, raises HTTP 429.
    """
    if not claimant_email:
        return
    cap = int(S.dmca_max_claims_per_claimant_per_day)
    if cap <= 0:
        return

    since = now_ts() - 86400
    count = 0
    exclusive_start_key = None

    while True:
        kwargs: Dict[str, Any] = {
            "IndexName": "ByClaimantCreatedAt",
            "KeyConditionExpression": (
                Key("claimant_email").eq(claimant_email) & Key("created_at").gte(since)
            ),
            "Select": "COUNT",
        }
        if exclusive_start_key:
            kwargs["ExclusiveStartKey"] = exclusive_start_key

        resp = T.dmca_claims.query(**kwargs)
        count += int(resp.get("Count", 0))

        if count >= cap:
            raise HTTPException(
                status_code=429,
                detail=(
                    f"DMCA claim rate limit exceeded: a maximum of {cap} claims "
                    "per claimant per 24 hours is allowed."
                ),
            )

        exclusive_start_key = resp.get("LastEvaluatedKey")
        if not exclusive_start_key:
            break


def file_dmca_claim(inp: Dict[str, Any], claimant_user_id: str) -> Dict[str, Any]:
    """File a new DMCA takedown claim.

    Steps:
    1. Create the claim record (status=filed).
    2. Resolve content URL to type/id if not provided.
    3. Hide the content immediately (status -> content_removed).
    4. Calculate strike number for target user.
    5. If strikes >= threshold, apply repeat-infringer ban.
    6. Notify the content creator.
    7. Write audit log entry.
    """
    # Enforce per-claimant daily filing cap before any writes.
    _check_claimant_rate_limit(inp["claimant_email"])

    ts = now_ts()
    claim_id = f"dmca_{uuid4().hex}"

    content_type = inp.get("content_type", "other")
    content_id = inp.get("content_id", "")
    content_url = inp.get("content_url", "")

    # Resolve content from URL if content_id not provided
    if not content_id and content_url:
        resolved_type, resolved_id = resolve_content_from_url(content_url)
        if resolved_id:
            content_type = resolved_type
            content_id = resolved_id

    # Resolve target user from content owner
    target_user_id = ""
    if content_id:
        target_user_id = resolve_content_owner(content_type, content_id)
    if not target_user_id:
        target_user_id = inp.get("target_user_id", "")

    item: Dict[str, Any] = {
        "claim_id": claim_id,
        "entity_type": "dmca_claim",
        "status": "filed",
        "claimant_name": inp["claimant_name"],
        "claimant_email": inp["claimant_email"],
        "claimant_address": inp.get("claimant_address", ""),
        "claimant_phone": inp.get("claimant_phone", ""),
        "claimant_user_id": claimant_user_id,
        "content_url": content_url,
        "content_type": content_type,
        "original_work_description": inp["original_work_description"],
        "sworn_statement": inp.get("sworn_statement", True),
        "good_faith_belief": inp.get("good_faith_belief", True),
        "signature": inp.get("signature", ""),
        "created_at": ts,
        "updated_at": ts,
    }
    if target_user_id:
        item["target_user_id"] = target_user_id
    if content_id:
        item["content_id"] = content_id
    T.dmca_claims.put_item(Item=item)

    # Hide content immediately
    snapshot: Dict[str, Any] = {}
    content_removed = False
    if content_id:
        snapshot = hide_content_for_dmca(
            claim_id=claim_id,
            content_type=content_type,
            content_id=content_id,
        )
        content_removed = True

    # Transition to content_removed
    content_removed_at = now_ts()
    strike_number = count_strikes(target_user_id) + 1 if target_user_id else 1

    update_expr = (
        "SET #status = :s, updated_at = :ts, content_removed_at = :cra, "
        "strike_number = :sn, content_snapshot = :snap"
    )
    expr_values: Dict[str, Any] = {
        ":s": "content_removed",
        ":ts": content_removed_at,
        ":cra": content_removed_at,
        ":sn": strike_number,
        ":snap": snapshot,
    }
    T.dmca_claims.update_item(
        Key={"claim_id": claim_id},
        UpdateExpression=update_expr,
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues=expr_values,
    )

    # Audit
    write_moderation_audit_event(
        action="dmca_claim_filed",
        actor_user_id=claimant_user_id,
        ticket_id=claim_id,
        content_type=content_type,
        content_id=content_id,
        target_user_id=target_user_id,
        metadata={"strike_number": strike_number, "content_removed": content_removed},
    )

    # Notify creator
    if target_user_id:
        write_alert(
            target_user_id,
            event="dmca_claim_filed",
            outcome="warning",
            title="DMCA takedown notice received",
            details={
                "claim_id": claim_id,
                "content_type": content_type,
                "content_id": content_id,
                "claimant_name": inp["claimant_name"],
                "original_work_description": (inp.get("original_work_description", ""))[:200],
            },
        )

    # Repeat infringer check
    if target_user_id and strike_number >= DMCA_STRIKE_THRESHOLD:
        try:
            apply_ban(
                offender_user_id=target_user_id,
                ticket_id=claim_id,
                admin_user_id="system",
                note="DMCA repeat infringer — automatic ban",
                duration_days=None,
                policy_category="dmca_repeat_infringer",
            )
            write_moderation_audit_event(
                action="dmca_repeat_infringer_ban",
                actor_user_id="system",
                ticket_id=claim_id,
                target_user_id=target_user_id,
                metadata={"strike_number": strike_number, "threshold": DMCA_STRIKE_THRESHOLD},
            )
            write_alert(
                target_user_id,
                event="dmca_repeat_infringer_ban",
                outcome="warning",
                title="Account terminated — repeat copyright infringement",
                details={
                    "claim_id": claim_id,
                    "strike_number": strike_number,
                    "threshold": DMCA_STRIKE_THRESHOLD,
                },
            )
        except Exception:
            logger.exception("Failed to apply repeat-infringer ban for user %s", target_user_id)

    return {
        "ok": True,
        "claim_id": claim_id,
        "status": "content_removed",
        "content_removed": content_removed,
        "strike_number": strike_number,
        "created_at": ts,
    }


def file_counter_notice(claim_id: str, inp: Dict[str, Any], user_id: str) -> Dict[str, Any]:
    """File a counter-notice on behalf of the content creator.

    Transitions claim: content_removed -> counter_notice_filed -> waiting_period.
    Sets waiting_period_expires_at = now + 14 days.
    """
    item = T.dmca_claims.get_item(Key={"claim_id": claim_id}).get("Item")
    if not item:
        raise ValueError("claim_not_found")

    # Only the target user can file a counter-notice
    if item.get("target_user_id") != user_id:
        raise PermissionError("not_target_user")

    current_status = item.get("status", "")
    if current_status != "content_removed":
        raise ValueError(f"invalid_status_transition:counter_notice requires content_removed, got {current_status}")

    ts = now_ts()
    waiting_period_expires_at = ts + DMCA_WAITING_PERIOD_DAYS * 86400

    T.dmca_claims.update_item(
        Key={"claim_id": claim_id},
        UpdateExpression=(
            "SET #status = :s, updated_at = :ts, "
            "counter_notice_text = :cnt, counter_notice_signature = :cns, "
            "counter_notice_filed_at = :cnf, "
            "waiting_period_expires_at = :wpe"
        ),
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":s": "waiting_period",
            ":ts": ts,
            ":cnt": inp["counter_notice_text"],
            ":cns": inp["counter_notice_signature"],
            ":cnf": ts,
            ":wpe": waiting_period_expires_at,
        },
    )

    # Audit
    write_moderation_audit_event(
        action="dmca_counter_notice_filed",
        actor_user_id=user_id,
        ticket_id=claim_id,
        target_user_id=item.get("target_user_id", ""),
    )

    # Notify claimant
    claimant_user_id = item.get("claimant_user_id", "")
    if claimant_user_id:
        write_alert(
            claimant_user_id,
            event="dmca_counter_notice_received",
            outcome="info",
            title="Counter-notice received for your DMCA claim",
            details={
                "claim_id": claim_id,
                "waiting_period_expires_at": waiting_period_expires_at,
            },
        )

    return {
        "ok": True,
        "claim_id": claim_id,
        "status": "waiting_period",
        "waiting_period_expires_at": waiting_period_expires_at,
        "counter_notice_filed_at": ts,
    }


def resolve_dmca_claim(
    claim_id: str,
    resolution: str,
    resolution_notes: str,
    admin_user_id: str,
) -> Dict[str, Any]:
    """Resolve a DMCA claim (admin action).

    If resolution is "restored", content is restored.
    """
    item = T.dmca_claims.get_item(Key={"claim_id": claim_id}).get("Item")
    if not item:
        raise ValueError("claim_not_found")

    current_status = item.get("status", "")
    if "resolved" not in _DMCA_STATUS_TRANSITIONS.get(current_status, set()):
        raise ValueError(f"invalid_status_transition:cannot resolve from {current_status}")

    ts = now_ts()
    T.dmca_claims.update_item(
        Key={"claim_id": claim_id},
        UpdateExpression=(
            "SET #status = :s, updated_at = :ts, resolved_at = :ra, "
            "resolution = :res, resolution_notes = :rn, "
            "resolved_by_admin_user_id = :admin"
        ),
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":s": "resolved",
            ":ts": ts,
            ":ra": ts,
            ":res": resolution,
            ":rn": resolution_notes,
            ":admin": admin_user_id,
        },
    )

    # Restore content if resolution is "restored"
    if resolution == "restored":
        restore_content_after_dmca(claim=item)
        target_user_id = item.get("target_user_id", "")
        if target_user_id:
            write_alert(
                target_user_id,
                event="dmca_content_restored",
                outcome="info",
                title="Your content has been restored",
                details={
                    "claim_id": claim_id,
                    "resolution": resolution,
                },
            )

    # Audit
    write_moderation_audit_event(
        action="dmca_resolved",
        actor_user_id=admin_user_id,
        ticket_id=claim_id,
        target_user_id=item.get("target_user_id", ""),
        metadata={"resolution": resolution, "notes": resolution_notes[:500]},
    )

    return {
        "ok": True,
        "claim_id": claim_id,
        "status": "resolved",
        "resolution": resolution,
        "resolved_at": ts,
    }


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------

def get_claim(claim_id: str) -> Optional[Dict[str, Any]]:
    """Return a single claim by ID, or None."""
    item = T.dmca_claims.get_item(Key={"claim_id": claim_id}).get("Item")
    if not item:
        return None
    return item


def list_claims_by_status(
    status: str,
    limit: int = 20,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List claims filtered by status, ordered by created_at descending."""
    kwargs: Dict[str, Any] = {
        "IndexName": "ByStatusCreatedAt",
        "KeyConditionExpression": Key("status").eq(status),
        "ScanIndexForward": False,
        "Limit": min(limit, 100),
    }
    start_key = decode_cursor(cursor)
    if start_key:
        kwargs["ExclusiveStartKey"] = start_key

    resp = T.dmca_claims.query(**kwargs)
    items = [_claim_out(i) for i in resp.get("Items", [])]
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))
    return {"items": items, "next_cursor": next_cursor}


def list_claims_by_user(
    target_user_id: str,
    limit: int = 20,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List claims against a specific user, ordered by created_at descending."""
    kwargs: Dict[str, Any] = {
        "IndexName": "ByTargetUserCreatedAt",
        "KeyConditionExpression": Key("target_user_id").eq(target_user_id),
        "ScanIndexForward": False,
        "Limit": min(limit, 100),
    }
    start_key = decode_cursor(cursor)
    if start_key:
        kwargs["ExclusiveStartKey"] = start_key

    resp = T.dmca_claims.query(**kwargs)
    items = [_claim_out(i) for i in resp.get("Items", [])]
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))
    return {"items": items, "next_cursor": next_cursor}


def list_claims_by_claimant(
    claimant_email: str,
    limit: int = 20,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List claims filed by a specific claimant email."""
    kwargs: Dict[str, Any] = {
        "IndexName": "ByClaimantCreatedAt",
        "KeyConditionExpression": Key("claimant_email").eq(claimant_email),
        "ScanIndexForward": False,
        "Limit": min(limit, 100),
    }
    start_key = decode_cursor(cursor)
    if start_key:
        kwargs["ExclusiveStartKey"] = start_key

    resp = T.dmca_claims.query(**kwargs)
    items = [_claim_out(i) for i in resp.get("Items", [])]
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))
    return {"items": items, "next_cursor": next_cursor}


# ---------------------------------------------------------------------------
# Strike counting
# ---------------------------------------------------------------------------

def count_strikes(target_user_id: str) -> int:
    """Count upheld DMCA claims against a user within the lookback window."""
    if not target_user_id:
        return 0

    cutoff = now_ts() - DMCA_STRIKE_LOOKBACK_DAYS * 86400
    count = 0
    exclusive_start_key = None

    while True:
        kwargs: Dict[str, Any] = {
            "IndexName": "ByTargetUserCreatedAt",
            "KeyConditionExpression": (
                Key("target_user_id").eq(target_user_id) & Key("created_at").gte(cutoff)
            ),
            "Limit": 100,
        }
        if exclusive_start_key:
            kwargs["ExclusiveStartKey"] = exclusive_start_key

        resp = T.dmca_claims.query(**kwargs)
        for item in resp.get("Items", []):
            status = item.get("status", "")
            resolution = item.get("resolution", "")
            # Count claims that are content_removed, escalated, or resolved-upheld
            if status in ("content_removed", "escalated"):
                count += 1
            elif status == "resolved" and resolution != "restored":
                count += 1

        exclusive_start_key = resp.get("LastEvaluatedKey")
        if not exclusive_start_key:
            break

    return count


def get_repeat_infringer_status(target_user_id: str) -> Dict[str, Any]:
    """Return the repeat infringer status for a user."""
    if not target_user_id:
        return {
            "user_id": target_user_id,
            "total_claims": 0,
            "upheld_claims": 0,
            "strike_count": 0,
            "threshold": DMCA_STRIKE_THRESHOLD,
            "status": "clear",
            "claim_history": [],
        }

    cutoff = now_ts() - DMCA_STRIKE_LOOKBACK_DAYS * 86400
    all_items: List[Dict[str, Any]] = []
    exclusive_start_key = None

    while True:
        kwargs: Dict[str, Any] = {
            "IndexName": "ByTargetUserCreatedAt",
            "KeyConditionExpression": (
                Key("target_user_id").eq(target_user_id) & Key("created_at").gte(cutoff)
            ),
            "Limit": 100,
        }
        if exclusive_start_key:
            kwargs["ExclusiveStartKey"] = exclusive_start_key

        resp = T.dmca_claims.query(**kwargs)
        all_items.extend(resp.get("Items", []))
        exclusive_start_key = resp.get("LastEvaluatedKey")
        if not exclusive_start_key:
            break

    upheld = 0
    claim_history = []
    for item in all_items:
        status = item.get("status", "")
        resolution = item.get("resolution", "")
        is_upheld = (
            status in ("content_removed", "escalated")
            or (status == "resolved" and resolution != "restored")
        )
        if is_upheld:
            upheld += 1
        claim_history.append({
            "claim_id": item.get("claim_id", ""),
            "status": status,
            "resolution": resolution,
            "created_at": _coerce_int(item.get("created_at")),
            "content_type": item.get("content_type", ""),
            "is_upheld": is_upheld,
        })

    if upheld >= DMCA_STRIKE_THRESHOLD:
        infringer_status = "banned"
    elif upheld >= DMCA_STRIKE_THRESHOLD - 1:
        infringer_status = "warning"
    else:
        infringer_status = "clear"

    return {
        "user_id": target_user_id,
        "total_claims": len(all_items),
        "upheld_claims": upheld,
        "strike_count": upheld,
        "threshold": DMCA_STRIKE_THRESHOLD,
        "status": infringer_status,
        "claim_history": claim_history,
    }


# ---------------------------------------------------------------------------
# DMCA Agent Config (stored in alert_prefs table)
# ---------------------------------------------------------------------------

_AGENT_CONFIG_PK = "SYSTEM_CONFIG#DMCA_AGENT"


def get_dmca_agent_config() -> Dict[str, Any]:
    """Read the DMCA designated agent config."""
    try:
        item = T.alert_prefs.get_item(Key={"user_sub": _AGENT_CONFIG_PK}).get("Item")
    except Exception:
        item = None
    if not item:
        return {}
    return {
        "agent_name": item.get("agent_name", ""),
        "agent_email": item.get("agent_email", ""),
        "agent_address": item.get("agent_address", ""),
        "agent_phone": item.get("agent_phone", ""),
    }


def set_dmca_agent_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Write / update the DMCA designated agent config."""
    ts = now_ts()
    T.alert_prefs.put_item(Item={
        "user_sub": _AGENT_CONFIG_PK,
        "agent_name": config["agent_name"],
        "agent_email": config["agent_email"],
        "agent_address": config.get("agent_address", ""),
        "agent_phone": config.get("agent_phone", ""),
        "updated_at": ts,
    })
    return {
        "agent_name": config["agent_name"],
        "agent_email": config["agent_email"],
        "agent_address": config.get("agent_address", ""),
        "agent_phone": config.get("agent_phone", ""),
    }


# ---------------------------------------------------------------------------
# Background: process expired waiting periods
# ---------------------------------------------------------------------------

def process_expired_dmca_waiting_periods() -> int:
    """Scan for claims in waiting_period whose waiting_period_expires_at <= now.

    Auto-resolves them with resolution="restored" and restores content.
    Returns the number of claims processed.
    """
    ts = now_ts()
    processed = 0
    exclusive_start_key = None

    while True:
        kwargs: Dict[str, Any] = {
            "IndexName": "ByWaitingPeriodExpiry",
            "KeyConditionExpression": (
                Key("status").eq("waiting_period")
                & Key("waiting_period_expires_at").lte(ts)
            ),
            "Limit": 25,
        }
        if exclusive_start_key:
            kwargs["ExclusiveStartKey"] = exclusive_start_key

        resp = T.dmca_claims.query(**kwargs)
        items = resp.get("Items", [])
        for item in items:
            claim_id = item.get("claim_id", "")
            try:
                resolve_dmca_claim(
                    claim_id=claim_id,
                    resolution="restored",
                    resolution_notes="Waiting period expired — content automatically restored",
                    admin_user_id="system",
                )
                processed += 1
            except Exception:
                logger.exception("Failed to auto-resolve expired DMCA claim %s", claim_id)

        exclusive_start_key = resp.get("LastEvaluatedKey")
        if not exclusive_start_key:
            break

    return processed


async def _dmca_timer_loop() -> None:
    """Periodically auto-resolve expired DMCA waiting periods (17 U.S.C. 512(g)).

    Disabled by default in dev/test (``S.dmca_timer_enabled``) to keep test runs
    deterministic. Never raises out of the loop.
    """
    import asyncio

    if not S.dmca_timer_enabled:
        logger.info("DMCA waiting-period timer disabled")
        return
    interval = max(60, int(S.dmca_timer_interval_seconds))
    logger.info("DMCA waiting-period timer started (interval=%ds)", interval)
    while True:
        try:
            processed = process_expired_dmca_waiting_periods()
            if processed:
                logger.info(
                    "dmca_timer: auto-resolved %d expired waiting period(s)",
                    processed,
                )
        except Exception:  # noqa: BLE001
            logger.exception("dmca_timer: unhandled error during sweep")
        await asyncio.sleep(interval)


def start_dmca_timer_task() -> None:
    """FastAPI startup hook: launch the DMCA waiting-period timer if enabled."""
    import asyncio

    if not S.dmca_timer_enabled:
        logger.info("DMCA waiting-period timer not started (disabled)")
        return
    try:
        asyncio.get_event_loop().create_task(_dmca_timer_loop())
    except RuntimeError:
        # No running loop yet -- schedule on the current loop policy.
        asyncio.ensure_future(_dmca_timer_loop())
