from __future__ import annotations

"""MODX-6: ban-evasion fingerprinting (device / email / IP signal seam).

Bans key on ``user_sub`` only, so a banned user recycles a fresh account and is
back in minutes. This module adds the *seam* the plan calls for: capture
device / email / IP fingerprints, LINK them to the offender on ban, and expose a
registration-screen check that flags a new signup whose fingerprint matches an
active ban.

Storage is infra-free: fingerprint links live in the existing app single-table
under ``pk = BANFP#{kind}#{hash}``, ``sk = USER#{user_sub}`` so a registration
can Query by fingerprint hash and find every banned account that shares it — no
new DynamoDB table, no GSI, no signup rewrite required. The signup path only has
to call :func:`screen_registration` with whatever signals it has.

Fail-open on the *capture* side (never break a ban), fail-safe (flag, don't hard
-block by default) on the *screen* side so a false positive can't lock out a
legitimate new user unless the caller opts into blocking.
"""

import hashlib
import logging
import os
import time
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from app.core.aws import ddb
from app.services.moderation_policy_engine import is_user_currently_banned

logger = logging.getLogger(__name__)

APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")

# Which signals we fingerprint. Extendable without a schema change.
FINGERPRINT_KINDS = ("device", "email", "ip")


def _norm(kind: str, value: Optional[str]) -> str:
    v = str(value or "").strip().lower()
    if kind == "email":
        # canonicalise gmail-style dots/plus so trivial aliasing is caught
        if "@" in v:
            local, _, domain = v.partition("@")
            local = local.split("+", 1)[0]
            if domain in ("gmail.com", "googlemail.com"):
                local = local.replace(".", "")
            v = f"{local}@{domain}"
    return v


def _hash(kind: str, value: str) -> str:
    return hashlib.sha256(f"{kind}:{value}".encode("utf-8")).hexdigest()[:32]


def _fp_pk(kind: str, h: str) -> str:
    return f"BANFP#{kind}#{h}"


# callers pass device_id / email / ip; the fingerprint KIND for device is "device".
_KIND_KWARG = {"device": "device_id", "email": "email", "ip": "ip"}


def _signals(**raw: Optional[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for kind in FINGERPRINT_KINDS:
        v = _norm(kind, raw.get(_KIND_KWARG[kind]) or raw.get(kind))
        if v:
            out[kind] = v
    return out


def record_ban_fingerprints(
    *,
    user_sub: str,
    device_id: Optional[str] = None,
    email: Optional[str] = None,
    ip: Optional[str] = None,
    source_ticket_id: str = "",
    now_ts: Optional[int] = None,
) -> Dict[str, Any]:
    """Link the offender's fingerprints so future signups can be screened.

    Signals may come straight from the ban call OR, when absent, from what the
    account captured at signup (``account_state`` / user row). Best-effort:
    never raises so it can never break :func:`apply_ban`.
    """
    ts = int(now_ts or time.time())
    if not user_sub:
        return {"recorded": 0}

    sig = _signals(device_id=device_id, email=email, ip=ip)
    # Backfill from anything the account persisted at signup. Prefer the durable
    # users row (account_state is overwritten by the ban itself), then account_state.
    if len(sig) < len(FINGERPRINT_KINDS):
        try:
            from app.core.tables import T
            usr = {}
            try:
                usr = T.users.get_item(Key={"user_sub": user_sub}).get("Item") or {}
            except Exception:
                usr = {}
            st = T.account_state.get_item(Key={"user_sub": user_sub}).get("Item") or {}
            def _pick(*keys):
                for src in (usr, st):
                    for k in keys:
                        if src.get(k):
                            return src.get(k)
                return None
            sig.setdefault("device", _norm("device", _pick("signup_device_id", "device_id")))
            sig.setdefault("email", _norm("email", _pick("signup_email", "email")))
            sig.setdefault("ip", _norm("ip", _pick("signup_ip", "last_ip")))
            sig = {k: v for k, v in sig.items() if v}
        except Exception:
            logger.exception("ban_fingerprint: signup-signal backfill failed for %s", user_sub)

    recorded = 0
    table = ddb.Table(APP_TABLE)
    for kind, value in sig.items():
        h = _hash(kind, value)
        try:
            table.put_item(
                Item={
                    "pk": _fp_pk(kind, h),
                    "sk": f"USER#{user_sub}",
                    "entity_type": "ban_fingerprint",
                    "fingerprint_kind": kind,
                    "fingerprint_hash": h,
                    "user_sub": user_sub,
                    "source_ticket_id": str(source_ticket_id or ""),
                    "created_at": ts,
                }
            )
            recorded += 1
        except Exception:
            logger.exception("ban_fingerprint: link write failed (%s) for %s", kind, user_sub)
    return {"recorded": recorded, "kinds": sorted(sig.keys())}


def _matches_for(kind: str, value: str) -> List[Dict[str, Any]]:
    from boto3.dynamodb.conditions import Key

    h = _hash(kind, value)
    try:
        resp = ddb.Table(APP_TABLE).query(
            KeyConditionExpression=Key("pk").eq(_fp_pk(kind, h)),
            Limit=25,
        )
    except ClientError:
        logger.exception("ban_fingerprint: query failed for %s", kind)
        return []
    return list(resp.get("Items", []) or [])


def screen_registration(
    *,
    device_id: Optional[str] = None,
    email: Optional[str] = None,
    ip: Optional[str] = None,
) -> Dict[str, Any]:
    """Registration-time seam: does this signup fingerprint match an ACTIVE ban?

    Returns ``{"evasion": bool, "matched_users": [...], "matched_kinds": [...]}``.
    Only counts links whose owner is *currently* banned (expired bans clear),
    so a rehabilitated / time-served account never poisons the fingerprint.
    """
    sig = _signals(device_id=device_id, email=email, ip=ip)
    matched_users: set = set()
    matched_kinds: set = set()
    for kind, value in sig.items():
        for item in _matches_for(kind, value):
            uid = str(item.get("user_sub") or "")
            if not uid:
                continue
            try:
                if is_user_currently_banned(uid):
                    matched_users.add(uid)
                    matched_kinds.add(kind)
            except Exception:
                # fail-safe: a read error must not falsely flag a legit signup
                logger.exception("ban_fingerprint: ban-check failed for %s", uid)
    return {
        "evasion": bool(matched_users),
        "matched_users": sorted(matched_users),
        "matched_kinds": sorted(matched_kinds),
    }
