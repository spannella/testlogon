"""Fraud detection service (FIN-015).

Consolidated payment-fraud detection: velocity checks, per-user risk
scoring (0-100), manual review queue (flags), fraud-case lifecycle,
user financial freeze/unfreeze, chargeback tracking with auto-flag, and
a fraud-case audit trail.

This is UNRELATED to ``app/services/ad_fraud_prevention.py`` (ADS-014 ad
impression fraud). All state lives in the ``fraud_detection`` DDB table
(handle ``T.fraud_cases``).

Note on naming: the FIN-015 ticket prose splits this into
``fraud_rules.py`` + ``fraud_management.py``; per the implementation
instructions this is a single DISTINCT-named module ``fraud_detection``.
"""

from __future__ import annotations

import logging
import uuid
from decimal import Decimal
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts
from app.core.cursor import encode_cursor, decode_cursor
from app.core.settings import S

logger = logging.getLogger("fraud_detection")

# --- Default thresholds (overridable via DDB config) -----------------------
VELOCITY_MAX_TX_PER_HOUR = 20
VELOCITY_MAX_AMOUNT_PER_HOUR = 50000  # $500
LARGE_TX_THRESHOLD = 25000  # $250
NEW_ACCOUNT_AGE_DAYS = 7
NEW_ACCOUNT_HIGH_VALUE = 10000  # $100
CHARGEBACK_THRESHOLD = 3
FLAG_SCORE_THRESHOLD = 70

_CONFIG_KEYS = (
    "velocity_max_tx_per_hour",
    "velocity_max_amount_per_hour",
    "large_tx_threshold",
    "new_account_age_days",
    "new_account_high_value",
    "chargeback_threshold",
    "flag_score_threshold",
)


# ===========================================================================
# Config
# ===========================================================================

def get_fraud_config() -> Dict[str, Any]:
    """Get current fraud thresholds from DDB, falling back to code defaults."""
    resp = T.fraud_cases.get_item(Key={"pk": "CONFIG", "sk": "FRAUD_RULES"})
    item = resp.get("Item")
    defaults = {
        "velocity_max_tx_per_hour": VELOCITY_MAX_TX_PER_HOUR,
        "velocity_max_amount_per_hour": VELOCITY_MAX_AMOUNT_PER_HOUR,
        "large_tx_threshold": LARGE_TX_THRESHOLD,
        "new_account_age_days": NEW_ACCOUNT_AGE_DAYS,
        "new_account_high_value": NEW_ACCOUNT_HIGH_VALUE,
        "chargeback_threshold": CHARGEBACK_THRESHOLD,
        "flag_score_threshold": S.fraud_score_threshold or FLAG_SCORE_THRESHOLD,
    }
    if not item:
        return defaults
    out: Dict[str, Any] = dict(defaults)
    for k, v in item.items():
        if k in ("pk", "sk"):
            continue
        out[k] = int(v) if isinstance(v, Decimal) else v
    return out


def update_fraud_config(*, admin_sub: str, **thresholds: Any) -> Dict[str, Any]:
    """Update fraud thresholds (root-only at the router layer)."""
    now = now_ts()
    existing = get_fraud_config()
    for k, v in thresholds.items():
        if v is not None:
            existing[k] = v
    existing["updated_at"] = now
    existing["updated_by"] = admin_sub

    item: Dict[str, Any] = {"pk": "CONFIG", "sk": "FRAUD_RULES"}
    for k, v in existing.items():
        item[k] = Decimal(str(v)) if isinstance(v, (int, float)) and not isinstance(v, bool) else v
    T.fraud_cases.put_item(Item=item)
    return existing


# ===========================================================================
# Rule checks + risk scoring
# ===========================================================================

def velocity_check(user_id: str, *, config: Optional[dict] = None) -> Optional[Dict[str, Any]]:
    """Return a violation dict if the user exceeded transaction velocity.

    Reads the real billing ledger (``T.billing``) for entries in the last
    hour. Ledger SKs are ``LEDGER#{ts}#{entry_id}`` so a ``between`` range
    bounds the time window.
    """
    if config is None:
        config = get_fraud_config()
    max_tx = config.get("velocity_max_tx_per_hour", VELOCITY_MAX_TX_PER_HOUR)
    max_amount = config.get("velocity_max_amount_per_hour", VELOCITY_MAX_AMOUNT_PER_HOUR)

    now = now_ts()
    one_hour_ago = now - 3600

    items: List[dict] = []
    try:
        last_key = None
        while True:
            kwargs = {
                "KeyConditionExpression": Key("pk").eq(f"USER#{user_id}")
                & Key("sk").between(f"LEDGER#{one_hour_ago}", f"LEDGER#{now}~"),
            }
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            resp = T.billing.query(**kwargs)
            items.extend(resp.get("Items", []))
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
    except Exception:
        # Billing ledger unavailable (e.g. table not configured in this env).
        # Fall back to the persisted 24h counter on the risk row so velocity
        # signals still work from precomputed/seeded data.
        logger.exception("velocity_check_ledger_unavailable")
        score_resp = T.fraud_cases.get_item(Key={"pk": f"RISK#USER#{user_id}", "sk": "SCORE"})
        score_item = score_resp.get("Item") or {}
        tx_count = int(score_item.get("tx_count_24h", 0))
        tx_total = int(score_item.get("tx_total_24h", 0))
        # The persisted counter is a 24h figure; scale to an hourly estimate.
        hourly_count = tx_count // 24 if tx_count else 0
        if tx_count > max_tx:
            return {"rule": "velocity_count", "detail": f"{tx_count} tx in 24h (max/hr {max_tx})"}
        if hourly_count > max_tx:
            return {"rule": "velocity_count", "detail": f"~{hourly_count} tx/hr (max {max_tx})"}
        return None

    tx_count = len(items)
    tx_total = sum(int(it.get("amount_cents", 0)) for it in items)

    if tx_count > max_tx:
        return {"rule": "velocity_count", "detail": f"{tx_count} tx in last hour (max {max_tx})"}
    if tx_total > max_amount:
        return {"rule": "velocity_amount", "detail": f"{tx_total}c in last hour (max {max_amount}c)"}
    return None


def large_amount_check(amount_cents: int, *, config: Optional[dict] = None) -> Optional[Dict[str, Any]]:
    if config is None:
        config = get_fraud_config()
    threshold = config.get("large_tx_threshold", LARGE_TX_THRESHOLD)
    if amount_cents > threshold:
        return {"rule": "large_amount", "detail": f"{amount_cents}c exceeds threshold {threshold}c"}
    return None


def new_account_check(
    account_age_days: int, amount_cents: int, *, config: Optional[dict] = None
) -> Optional[Dict[str, Any]]:
    if config is None:
        config = get_fraud_config()
    age_threshold = config.get("new_account_age_days", NEW_ACCOUNT_AGE_DAYS)
    value_threshold = config.get("new_account_high_value", NEW_ACCOUNT_HIGH_VALUE)
    if account_age_days < age_threshold and amount_cents > value_threshold:
        return {
            "rule": "new_account",
            "detail": f"Account {account_age_days}d old, tx {amount_cents}c",
        }
    return None


def chargeback_check(user_id: str, *, config: Optional[dict] = None) -> Optional[Dict[str, Any]]:
    if config is None:
        config = get_fraud_config()
    threshold = config.get("chargeback_threshold", CHARGEBACK_THRESHOLD)
    resp = T.fraud_cases.get_item(Key={"pk": f"RISK#USER#{user_id}", "sk": "SCORE"})
    item = resp.get("Item")
    if not item:
        return None
    cb_count = int(item.get("chargeback_count", 0))
    if cb_count >= threshold:
        return {"rule": "chargeback_rate", "detail": f"{cb_count} chargebacks (threshold {threshold})"}
    return None


def compute_risk_score(user_id: str, *, account_age_days: Optional[int] = None) -> Dict[str, Any]:
    """Recompute and persist the full 0-100 risk score for a user.

    Components: velocity (0-25), amount (0-15), account_age (0-20),
    chargeback (0-30), geo (0-10). Persists the SCORE row plus a
    HISTORY#{ts} audit point.
    """
    resp = T.fraud_cases.get_item(Key={"pk": f"RISK#USER#{user_id}", "sk": "SCORE"})
    item = resp.get("Item", {}) or {}
    config = get_fraud_config()

    tx_24h = int(item.get("tx_count_24h", 0))
    max_tx = config.get("velocity_max_tx_per_hour", VELOCITY_MAX_TX_PER_HOUR) * 24
    velocity_score = min(25, int(25 * tx_24h / max(max_tx, 1)))

    tx_total = int(item.get("tx_total_24h", 0))
    max_amount = config.get("velocity_max_amount_per_hour", VELOCITY_MAX_AMOUNT_PER_HOUR) * 24
    amount_score = min(15, int(15 * tx_total / max(max_amount, 1)))

    # Account age component: newer accounts score higher, decaying over 90d.
    if account_age_days is None:
        age_score = int(item.get("components", {}).get("account_age", 0) or 0)
    else:
        age_score = max(0, min(20, int(20 * (1 - min(account_age_days, 90) / 90))))

    cb_count = int(item.get("chargeback_count", 0))
    cb_threshold = config.get("chargeback_threshold", CHARGEBACK_THRESHOLD)
    chargeback_score = min(30, int(30 * cb_count / max(cb_threshold, 1)))

    geo_score = int(item.get("components", {}).get("geo", 0) or 0)

    components = {
        "velocity": velocity_score,
        "amount": amount_score,
        "account_age": age_score,
        "chargeback": chargeback_score,
        "geo": geo_score,
    }
    total_score = min(100, sum(components.values()))
    flagged = total_score >= config.get("flag_score_threshold", FLAG_SCORE_THRESHOLD)

    now = now_ts()
    T.fraud_cases.put_item(Item={
        "pk": f"RISK#USER#{user_id}",
        "sk": "SCORE",
        "score": Decimal(str(total_score)),
        "components": {k: Decimal(str(v)) for k, v in components.items()},
        "flagged": flagged,
        "frozen": item.get("frozen", False),
        "frozen_at": item.get("frozen_at"),
        "frozen_by": item.get("frozen_by"),
        "tx_count_24h": Decimal(str(tx_24h)),
        "tx_total_24h": Decimal(str(tx_total)),
        "chargeback_count": Decimal(str(cb_count)),
        "last_scored_at": Decimal(str(now)),
    })
    T.fraud_cases.put_item(Item={
        "pk": f"RISK#USER#{user_id}",
        "sk": f"HISTORY#{now}",
        "score": Decimal(str(total_score)),
        "components": {k: Decimal(str(v)) for k, v in components.items()},
        "created_at": Decimal(str(now)),
    })
    return {"score": total_score, "components": components, "flagged": flagged}


def evaluate_transaction(
    *, user_id: str, amount_cents: int, entry_type: str,
    tx_id: str = "", ip_address: Optional[str] = None, account_age_days: int = 0,
) -> Dict[str, Any]:
    """Run all fraud rules against a transaction; flag/block as needed.

    Returns ``{triggered_rules, risk_score, flagged, action}``. When
    ``FRAUD_DETECTION_ENABLED`` is false, short-circuits to ``allow``.
    """
    if not S.fraud_detection_enabled:
        return {"triggered_rules": [], "risk_score": 0, "flagged": False, "action": "allow"}

    config = get_fraud_config()
    triggered: List[Dict[str, Any]] = []
    for check in (
        velocity_check(user_id, config=config),
        large_amount_check(amount_cents, config=config),
        new_account_check(account_age_days, amount_cents, config=config),
        chargeback_check(user_id, config=config),
    ):
        if check:
            triggered.append(check)

    score_data = compute_risk_score(user_id, account_age_days=account_age_days)
    score = score_data["score"]
    threshold = config.get("flag_score_threshold", FLAG_SCORE_THRESHOLD)
    flagged = score >= threshold or len(triggered) > 0

    if score >= 90 or len(triggered) >= 3:
        action = "block"
    elif flagged:
        action = "flag"
    else:
        action = "allow"

    if action == "block" and not S.fraud_block_enabled:
        # Flag-only mode: downgrade block to flag.
        action = "flag"

    if flagged and triggered:
        # Persist a flag for the strongest triggered rule (audit trail).
        create_flag(
            user_id=user_id, tx_id=tx_id or "",
            rule_triggered=triggered[0]["rule"], risk_score=score,
            amount_cents=amount_cents,
        )

    logger.info(
        "fraud_evaluation",
        extra={
            "user_id": user_id, "amount_cents": amount_cents,
            "entry_type": entry_type, "score": score,
            "triggered_rules": [r["rule"] for r in triggered], "action": action,
        },
    )
    return {
        "triggered_rules": triggered,
        "risk_score": score,
        "flagged": flagged,
        "action": action,
    }


# ===========================================================================
# Flags (review queue)
# ===========================================================================

def create_flag(
    *, user_id: str, tx_id: str, rule_triggered: str,
    risk_score: int, amount_cents: int,
) -> Dict[str, Any]:
    flag_id = f"flg_{uuid.uuid4().hex[:8]}"
    now = now_ts()
    T.fraud_cases.put_item(Item={
        "pk": f"FLAG#{flag_id}",
        "sk": "META",
        "GSI1PK": "FLAGS#PENDING",
        "GSI1SK": Decimal(str(now)),
        "GSI2PK": f"FLAGS#USER#{user_id}",
        "GSI2SK": Decimal(str(now)),
        "flag_id": flag_id,
        "user_id": user_id,
        "tx_id": tx_id,
        "rule_triggered": rule_triggered,
        "risk_score": Decimal(str(risk_score)),
        "amount_cents": Decimal(str(amount_cents)),
        "status": "pending",
        "notes": "",
        "created_at": Decimal(str(now)),
    })
    logger.info("flag_created", extra={"flag_id": flag_id, "user_id": user_id, "rule": rule_triggered})
    return {"flag_id": flag_id, "status": "pending", "created_at": now}


def list_review_queue(
    *, status: str = "pending", limit: int = 50, cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """List flagged transactions for the admin review queue (GSI1 by status)."""
    gsi_pk = f"FLAGS#{status.upper()}"
    kwargs: Dict[str, Any] = {
        "IndexName": "GSI1",
        "KeyConditionExpression": Key("GSI1PK").eq(gsi_pk),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if cursor:
        decoded = decode_cursor(cursor)
        if decoded:
            kwargs["ExclusiveStartKey"] = decoded
    resp = T.fraud_cases.query(**kwargs)
    items = resp.get("Items", [])
    next_cursor = encode_cursor(resp["LastEvaluatedKey"]) if "LastEvaluatedKey" in resp else None
    return {
        "flags": [_flag_to_dict(it) for it in items],
        "count": len(items),
        "cursor": next_cursor,
    }


def get_flag(flag_id: str) -> Optional[Dict[str, Any]]:
    resp = T.fraud_cases.get_item(Key={"pk": f"FLAG#{flag_id}", "sk": "META"})
    item = resp.get("Item")
    return _flag_to_dict(item) if item else None


def review_decision(
    *, flag_id: str, action: str, admin_sub: str, notes: str = "",
) -> Optional[Dict[str, Any]]:
    """Admin review decision on a flag: approve / block / investigate."""
    now = now_ts()
    resp = T.fraud_cases.get_item(Key={"pk": f"FLAG#{flag_id}", "sk": "META"})
    if not resp.get("Item"):
        return None

    resolution_map = {"approve": "false_positive", "block": "confirmed_fraud", "investigate": None}
    resolution = resolution_map.get(action)
    new_status = (
        "investigating" if action == "investigate"
        else ("approved" if action == "approve" else "blocked")
    )
    new_gsi1pk = "FLAGS#PENDING" if action == "investigate" else "FLAGS#RESOLVED"

    T.fraud_cases.update_item(
        Key={"pk": f"FLAG#{flag_id}", "sk": "META"},
        UpdateExpression=(
            "SET #s = :s, reviewed_by = :rb, reviewed_at = :ra, "
            "resolution = :res, notes = :n, GSI1PK = :g1pk"
        ),
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": new_status,
            ":rb": admin_sub,
            ":ra": Decimal(str(now)),
            ":res": resolution,
            ":n": notes,
            ":g1pk": new_gsi1pk,
        },
    )
    logger.info("flag_reviewed", extra={"flag_id": flag_id, "action": action, "admin": admin_sub})
    return {"flag_id": flag_id, "status": new_status, "resolution": resolution}


# ===========================================================================
# User freeze / risk profile
# ===========================================================================

def is_frozen(user_id: str) -> bool:
    """Hook other financial flows can call to block ops for a frozen user."""
    resp = T.fraud_cases.get_item(Key={"pk": f"RISK#USER#{user_id}", "sk": "SCORE"})
    item = resp.get("Item")
    return bool(item.get("frozen")) if item else False


def freeze_user(*, user_id: str, admin_sub: str, reason: str) -> Dict[str, Any]:
    now = now_ts()
    # Ensure the SCORE row exists (idempotent for users with no prior history).
    T.fraud_cases.update_item(
        Key={"pk": f"RISK#USER#{user_id}", "sk": "SCORE"},
        UpdateExpression="SET frozen = :t, frozen_at = :fa, frozen_by = :fb",
        ExpressionAttributeValues={":t": True, ":fa": Decimal(str(now)), ":fb": admin_sub},
    )
    try:
        from app.services.alerts import write_alert
        write_alert(
            user_id,
            event="account.financial_freeze",
            outcome="warning",
            title="Financial operations temporarily suspended",
            details={"reason": "Account review in progress"},
        )
    except Exception:  # pragma: no cover - alert is best-effort
        logger.exception("freeze_alert_failed")
    logger.warning("user_frozen", extra={"user_id": user_id, "admin": admin_sub, "reason": reason})
    return {"user_id": user_id, "frozen": True, "frozen_at": now}


def unfreeze_user(*, user_id: str, admin_sub: str) -> Dict[str, Any]:
    T.fraud_cases.update_item(
        Key={"pk": f"RISK#USER#{user_id}", "sk": "SCORE"},
        UpdateExpression="SET frozen = :f REMOVE frozen_at, frozen_by",
        ExpressionAttributeValues={":f": False},
    )
    try:
        from app.services.alerts import write_alert
        write_alert(
            user_id,
            event="account.financial_unfreeze",
            outcome="info",
            title="Financial operations restored",
            details={},
        )
    except Exception:  # pragma: no cover
        logger.exception("unfreeze_alert_failed")
    logger.info("user_unfrozen", extra={"user_id": user_id, "admin": admin_sub})
    return {"user_id": user_id, "frozen": False}


def get_user_risk_profile(user_id: str) -> Dict[str, Any]:
    """Full risk profile (score, components, freeze state, recent flags)."""
    resp = T.fraud_cases.get_item(Key={"pk": f"RISK#USER#{user_id}", "sk": "SCORE"})
    score_item = resp.get("Item", {}) or {}

    flags_resp = T.fraud_cases.query(
        IndexName="GSI2",
        KeyConditionExpression=Key("GSI2PK").eq(f"FLAGS#USER#{user_id}"),
        ScanIndexForward=False,
        Limit=20,
    )
    flags = [_flag_to_dict(it) for it in flags_resp.get("Items", [])]

    return {
        "user_id": user_id,
        "score": int(score_item.get("score", 0)),
        "components": {k: int(v) for k, v in (score_item.get("components", {}) or {}).items()},
        "flagged": bool(score_item.get("flagged", False)),
        "frozen": bool(score_item.get("frozen", False)),
        "frozen_at": int(score_item["frozen_at"]) if score_item.get("frozen_at") else None,
        "frozen_by": score_item.get("frozen_by"),
        "tx_count_24h": int(score_item.get("tx_count_24h", 0)),
        "tx_total_24h": int(score_item.get("tx_total_24h", 0)),
        "chargeback_count": int(score_item.get("chargeback_count", 0)),
        "last_scored_at": int(score_item.get("last_scored_at", 0)),
        "recent_flags": flags,
    }


# ===========================================================================
# Chargebacks
# ===========================================================================

def record_chargeback(*, user_id: str, amount_cents: int = 0, tx_id: str = "") -> Dict[str, Any]:
    """Increment a user's chargeback count and auto-flag over threshold.

    Returns ``{user_id, chargeback_count, auto_flagged, flag_id}``.
    """
    resp = T.fraud_cases.update_item(
        Key={"pk": f"RISK#USER#{user_id}", "sk": "SCORE"},
        UpdateExpression="SET chargeback_count = if_not_exists(chargeback_count, :z) + :one",
        ExpressionAttributeValues={":z": Decimal("0"), ":one": Decimal("1")},
        ReturnValues="ALL_NEW",
    )
    cb_count = int(resp.get("Attributes", {}).get("chargeback_count", 0))

    config = get_fraud_config()
    threshold = config.get("chargeback_threshold", CHARGEBACK_THRESHOLD)
    score_data = compute_risk_score(user_id)

    auto_flagged = False
    flag_id = None
    if cb_count >= threshold:
        flag = create_flag(
            user_id=user_id, tx_id=tx_id,
            rule_triggered="chargeback_rate",
            risk_score=score_data["score"], amount_cents=amount_cents,
        )
        auto_flagged = True
        flag_id = flag["flag_id"]

    logger.warning(
        "chargeback_recorded",
        extra={"user_id": user_id, "chargeback_count": cb_count, "auto_flagged": auto_flagged},
    )
    return {
        "user_id": user_id,
        "chargeback_count": cb_count,
        "auto_flagged": auto_flagged,
        "flag_id": flag_id,
    }


# ===========================================================================
# Fraud cases (audit trail)
# ===========================================================================

def flag_case(
    *, user_id: str, flag_ids: List[str], admin_sub: str, notes: str = "",
) -> Dict[str, Any]:
    """Open a new fraud investigation case linking one or more flags."""
    case_id = f"case_{uuid.uuid4().hex[:8]}"
    now = now_ts()
    T.fraud_cases.put_item(Item={
        "pk": f"CASE#{case_id}",
        "sk": "META",
        "GSI1PK": "CASES#OPEN",
        "GSI1SK": Decimal(str(now)),
        "case_id": case_id,
        "user_id": user_id,
        "status": "open",
        "assigned_to": admin_sub,
        "flags": list(flag_ids),
        "notes": notes,
        "created_at": Decimal(str(now)),
    })
    logger.info("case_created", extra={"case_id": case_id, "user_id": user_id, "admin": admin_sub})
    return _case_to_dict(T.fraud_cases.get_item(Key={"pk": f"CASE#{case_id}", "sk": "META"})["Item"])


def get_case(case_id: str) -> Optional[Dict[str, Any]]:
    resp = T.fraud_cases.get_item(Key={"pk": f"CASE#{case_id}", "sk": "META"})
    item = resp.get("Item")
    return _case_to_dict(item) if item else None


def resolve_case(
    *, case_id: str, resolution: str, admin_sub: str, notes: str = "",
) -> Optional[Dict[str, Any]]:
    """Resolve a fraud case. Returns None if not found, "conflict" if already resolved."""
    resp = T.fraud_cases.get_item(Key={"pk": f"CASE#{case_id}", "sk": "META"})
    item = resp.get("Item")
    if not item:
        return None
    if item.get("status") == "resolved":
        return {"conflict": True}

    now = now_ts()
    T.fraud_cases.update_item(
        Key={"pk": f"CASE#{case_id}", "sk": "META"},
        UpdateExpression=(
            "SET #s = :s, resolution = :r, notes = :n, resolved_at = :ra, GSI1PK = :g1pk"
        ),
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": "resolved",
            ":r": resolution,
            ":n": notes,
            ":ra": Decimal(str(now)),
            ":g1pk": "CASES#CLOSED",
        },
    )
    logger.info("case_resolved", extra={"case_id": case_id, "resolution": resolution, "admin": admin_sub})
    return {"case_id": case_id, "status": "resolved", "resolution": resolution, "resolved_at": now}


def list_cases(*, status: str = "open", limit: int = 50) -> List[Dict[str, Any]]:
    """List fraud cases by status via GSI1 (CASES#OPEN / CASES#CLOSED)."""
    gsi_pk = "CASES#CLOSED" if status in ("resolved", "closed") else "CASES#OPEN"
    resp = T.fraud_cases.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq(gsi_pk),
        ScanIndexForward=False,
        Limit=limit,
    )
    items = [_case_to_dict(it) for it in resp.get("Items", [])]
    # "open" GSI partition holds both open + investigating; filter if needed.
    if status == "investigating":
        items = [c for c in items if c["status"] == "investigating"]
    elif status == "open":
        items = [c for c in items if c["status"] in ("open", "investigating")]
    return items


# ===========================================================================
# Stats
# ===========================================================================

def get_fraud_stats() -> Dict[str, Any]:
    """Dashboard counters: pending flags, open cases, frozen users, resolved today."""
    pending = T.fraud_cases.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq("FLAGS#PENDING"),
        Select="COUNT",
    ).get("Count", 0)

    open_cases = T.fraud_cases.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq("CASES#OPEN"),
        Select="COUNT",
    ).get("Count", 0)

    today_start = now_ts() - (now_ts() % 86400)
    resolved_today = T.fraud_cases.query(
        IndexName="GSI1",
        KeyConditionExpression=Key("GSI1PK").eq("FLAGS#RESOLVED")
        & Key("GSI1SK").gte(Decimal(str(today_start))),
        Select="COUNT",
    ).get("Count", 0)

    # Frozen users: infrequent admin stat — scan with LastEvaluatedKey loop.
    frozen_users = 0
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "FilterExpression": Key("sk").eq("SCORE"),
            "ProjectionExpression": "frozen",
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        scan = T.fraud_cases.scan(**kwargs)
        frozen_users += sum(1 for it in scan.get("Items", []) if it.get("frozen"))
        last_key = scan.get("LastEvaluatedKey")
        if not last_key:
            break

    return {
        "pending_flags": int(pending),
        "open_cases": int(open_cases),
        "frozen_users": int(frozen_users),
        "flags_resolved_today": int(resolved_today),
        "avg_resolution_hours": 0.0,
    }


# ===========================================================================
# Serializers
# ===========================================================================

def _flag_to_dict(item: dict) -> dict:
    return {
        "flag_id": item.get("flag_id", ""),
        "user_id": item.get("user_id", ""),
        "tx_id": item.get("tx_id", ""),
        "rule_triggered": item.get("rule_triggered", ""),
        "risk_score": int(item.get("risk_score", 0)),
        "amount_cents": int(item.get("amount_cents", 0)),
        "status": item.get("status", "pending"),
        "reviewed_by": item.get("reviewed_by"),
        "reviewed_at": int(item["reviewed_at"]) if item.get("reviewed_at") else None,
        "resolution": item.get("resolution"),
        "notes": item.get("notes", ""),
        "created_at": int(item.get("created_at", 0)),
    }


def _case_to_dict(item: dict) -> dict:
    return {
        "case_id": item.get("case_id", ""),
        "user_id": item.get("user_id", ""),
        "status": item.get("status", "open"),
        "assigned_to": item.get("assigned_to"),
        "flags": list(item.get("flags", []) or []),
        "resolution": item.get("resolution"),
        "notes": item.get("notes", ""),
        "created_at": int(item.get("created_at", 0)),
        "resolved_at": int(item["resolved_at"]) if item.get("resolved_at") else None,
    }
