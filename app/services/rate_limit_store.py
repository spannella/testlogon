"""
Rate limit counter store (PLATFORM-001).

DDB-backed fixed-window counters with atomic conditional updates.
Designed for clean abstraction -- swap to Redis later if needed.
"""
from __future__ import annotations

import ipaddress
import logging
from typing import List, Optional, Tuple

from botocore.exceptions import ClientError

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Core rate-limit check (fixed-window counter)
# ---------------------------------------------------------------------------

def check_rate_limit(
    pk: str,
    window_seconds: int,
    max_requests: int,
) -> Tuple[bool, int, int]:
    """
    Atomically check and increment a rate limit counter.

    Returns ``(allowed, remaining, reset_timestamp)``.
    Uses a fixed-window approach aligned to ``window_seconds`` boundaries.
    """
    now = now_ts()
    window_start = now - (now % window_seconds)
    reset = window_start + window_seconds

    try:
        result = T.rate_limits.update_item(
            Key={"pk": pk, "sk": "GLOBAL"},
            UpdateExpression=(
                "SET #cnt = if_not_exists(#cnt, :zero) + :one, "
                "window_start = :ws, ttl_epoch = :ttl"
            ),
            ConditionExpression=(
                "attribute_not_exists(window_start) OR window_start = :ws"
            ),
            ExpressionAttributeNames={"#cnt": "count"},
            ExpressionAttributeValues={
                ":zero": 0,
                ":one": 1,
                ":ws": window_start,
                ":ttl": reset + 3600,
            },
            ReturnValues="ALL_NEW",
        )
        count = int(result["Attributes"]["count"])
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            # Window rolled over -- reset counter to 1
            T.rate_limits.put_item(
                Item={
                    "pk": pk,
                    "sk": "GLOBAL",
                    "count": 1,
                    "window_start": window_start,
                    "ttl_epoch": reset + 3600,
                },
            )
            count = 1
        else:
            raise

    allowed = count <= max_requests
    remaining = max(0, max_requests - count)
    return allowed, remaining, reset


# ---------------------------------------------------------------------------
# Blocklist / Allowlist helpers
# ---------------------------------------------------------------------------

def is_blocked(ip: str) -> bool:
    """Return True if *ip* is in the blocklist (exact match)."""
    try:
        resp = T.rate_limits.get_item(
            Key={"pk": "BLOCKLIST#IP", "sk": ip},
            ProjectionExpression="pk",
        )
        return "Item" in resp
    except Exception:
        logger.warning("rate_limit_store: blocklist check failed for %s", ip, exc_info=True)
        return False


def is_allowlisted(ip: str) -> bool:
    """Return True if *ip* matches an allowlist CIDR entry."""
    try:
        resp = T.rate_limits.query(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": "ALLOWLIST#IP"},
            ProjectionExpression="sk",
        )
        items = resp.get("Items", [])
        if not items:
            return False
        ip_obj = ipaddress.ip_address(ip)
        for item in items:
            cidr = item.get("sk", "")
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if ip_obj in net:
                    return True
            except ValueError:
                continue
        return False
    except Exception:
        logger.warning("rate_limit_store: allowlist check failed for %s", ip, exc_info=True)
        return False


# ---------------------------------------------------------------------------
# Blocklist / Allowlist management
# ---------------------------------------------------------------------------

def add_to_blocklist(
    ip: str,
    *,
    reason: str = "",
    added_by: str = "",
    expires_in_hours: Optional[int] = None,
) -> dict:
    now = now_ts()
    item: dict = {
        "pk": "BLOCKLIST#IP",
        "sk": ip,
        "added_by": added_by,
        "added_at": now,
        "reason": reason,
    }
    if expires_in_hours and expires_in_hours > 0:
        item["ttl_epoch"] = now + expires_in_hours * 3600
    T.rate_limits.put_item(Item=item)
    return item


def remove_from_blocklist(ip: str) -> None:
    T.rate_limits.delete_item(Key={"pk": "BLOCKLIST#IP", "sk": ip})


def add_to_allowlist(
    cidr: str,
    *,
    reason: str = "",
    added_by: str = "",
) -> dict:
    now = now_ts()
    item: dict = {
        "pk": "ALLOWLIST#IP",
        "sk": cidr,
        "added_by": added_by,
        "added_at": now,
        "reason": reason,
    }
    T.rate_limits.put_item(Item=item)
    return item


def remove_from_allowlist(cidr: str) -> None:
    T.rate_limits.delete_item(Key={"pk": "ALLOWLIST#IP", "sk": cidr})


def list_blocklist() -> List[dict]:
    try:
        resp = T.rate_limits.query(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": "BLOCKLIST#IP"},
        )
        return resp.get("Items", [])
    except Exception:
        logger.warning("rate_limit_store: list_blocklist failed", exc_info=True)
        return []


def list_allowlist() -> List[dict]:
    try:
        resp = T.rate_limits.query(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": "ALLOWLIST#IP"},
        )
        return resp.get("Items", [])
    except Exception:
        logger.warning("rate_limit_store: list_allowlist failed", exc_info=True)
        return []
