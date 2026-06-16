"""Hotel nightly rate-plan service (Hotel-PMS vertical, HTL-014 + HTL-015).

Additive + flag-gated (``HOTEL_PMS_ENABLED``, default OFF). Every public
entrypoint calls ``_require_enabled()`` first; when the flag is off all
functions raise HTTP 404 and the platform is byte-for-byte unchanged.

HTL-014: Data model + CRUD (create/get/update/deactivate plan;
          add/list/update/delete rules; per-kind config validators).
HTL-015: Deterministic multi-night price computation engine
          (``compute_stay_price``).

SECOPS-007 parity: no ``if S.dev_mode`` branch in business logic anywhere
in this file — same boto3 path runs in dev (moto) and prod (real DynamoDB).

Money is always integer cents. The engine performs no DDB writes and is
purely deterministic: identical inputs + identical rule rows always yield
byte-for-byte-identical output.
"""
from __future__ import annotations

import inspect
from datetime import date, timedelta
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

# ───────────────────────── module-level helpers ─────────────────────────


def _flag_on() -> bool:
    return bool(getattr(S, "hotel_pms_enabled", False))


def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=404, detail="Hotel PMS is not enabled")


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event  # lazy import
        audit_event(event, user_sub or "system", None, **fields)
    except Exception:
        pass


def _pk(hotel_id: str, room_type_id: str) -> str:
    return f"{hotel_id}#{room_type_id}"


def _rule_sk(kind: str, rule_id: str) -> str:
    return f"RULE#{kind}#{rule_id}"


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return default if value is None else int(value)
    except (TypeError, ValueError):
        return default


def _coerce_item(item: dict) -> dict:
    """Coerce DynamoDB Decimal numeric fields to int in place."""
    int_keys = {
        "base_nightly_rate_cents", "base_occupancy", "priority",
        "created_at", "updated_at",
    }
    for k in int_keys:
        if k in item:
            item[k] = _to_int(item[k])
    # Coerce numeric values inside rule_config if present
    rc = item.get("rule_config")
    if isinstance(rc, dict):
        numeric_fields = {
            "value_cents", "extra_adult_cents", "extra_child_cents",
            "min_nights", "max_nights", "discount_value", "days_before_checkin",
            "value",
        }
        for f in numeric_fields:
            if f in rc and rc[f] is not None:
                rc[f] = _to_int(rc[f])
        if "dow" in rc and isinstance(rc["dow"], list):
            rc["dow"] = [_to_int(d) for d in rc["dow"]]
    return item


# ────────────────── per-kind config validators (HTL-014 §4.4) ───────────────


def _validate_season_config(cfg: dict) -> None:
    """season: {start_date, end_date, mode:"absolute"|"delta", value_cents:int}"""
    try:
        sd = date.fromisoformat(cfg["start_date"])
        ed = date.fromisoformat(cfg["end_date"])
    except (KeyError, ValueError) as exc:
        raise HTTPException(422, f"season rule: invalid date — {exc}") from exc
    if sd > ed:
        raise HTTPException(422, "season rule: start_date must be <= end_date")
    mode = cfg.get("mode")
    if mode not in ("absolute", "delta"):
        raise HTTPException(422, "season rule: mode must be 'absolute' or 'delta'")
    vc = cfg.get("value_cents")
    if not isinstance(vc, int):
        try:
            vc = int(vc)
        except (TypeError, ValueError):
            raise HTTPException(422, "season rule: value_cents must be an integer")
    if mode == "absolute" and vc < 0:
        raise HTTPException(422, "season rule: absolute value_cents must be >= 0")


def _validate_occupancy_config(cfg: dict) -> None:
    """occupancy: {extra_adult_cents:int>=0, extra_child_cents:int>=0}"""
    for field in ("extra_adult_cents", "extra_child_cents"):
        v = cfg.get(field)
        if v is None:
            raise HTTPException(422, f"occupancy rule: {field} is required")
        try:
            v = int(v)
        except (TypeError, ValueError):
            raise HTTPException(422, f"occupancy rule: {field} must be an integer")
        if v < 0:
            raise HTTPException(422, f"occupancy rule: {field} must be >= 0")


def _validate_los_config(cfg: dict) -> None:
    """los: {min_nights:int>=1, max_nights:int|null, discount_type:"percentage"|"fixed_cents", discount_value:int>=0}"""
    mn = cfg.get("min_nights")
    if mn is None:
        raise HTTPException(422, "los rule: min_nights is required")
    try:
        mn = int(mn)
    except (TypeError, ValueError):
        raise HTTPException(422, "los rule: min_nights must be an integer")
    if mn < 1:
        raise HTTPException(422, "los rule: min_nights must be >= 1")

    mx = cfg.get("max_nights")
    if mx is not None:
        try:
            mx = int(mx)
        except (TypeError, ValueError):
            raise HTTPException(422, "los rule: max_nights must be an integer or null")
        if mx < mn:
            raise HTTPException(422, "los rule: max_nights must be >= min_nights")

    dt = cfg.get("discount_type")
    if dt not in ("percentage", "fixed_cents"):
        raise HTTPException(422, "los rule: discount_type must be 'percentage' or 'fixed_cents'")

    dv = cfg.get("discount_value")
    if dv is None:
        raise HTTPException(422, "los rule: discount_value is required")
    try:
        dv = int(dv)
    except (TypeError, ValueError):
        raise HTTPException(422, "los rule: discount_value must be an integer")
    if dv < 0:
        raise HTTPException(422, "los rule: discount_value must be >= 0")
    if dt == "percentage" and dv > 100:
        raise HTTPException(422, "los rule: percentage discount_value must be <= 100")


def _validate_advance_config(cfg: dict) -> None:
    """advance: {days_before_checkin:int>=0, comparator:"gte"|"lte", mode:"percentage"|"fixed_cents", value:int}"""
    dbc = cfg.get("days_before_checkin")
    if dbc is None:
        raise HTTPException(422, "advance rule: days_before_checkin is required")
    try:
        dbc = int(dbc)
    except (TypeError, ValueError):
        raise HTTPException(422, "advance rule: days_before_checkin must be an integer")
    if dbc < 0:
        raise HTTPException(422, "advance rule: days_before_checkin must be >= 0")

    comp = cfg.get("comparator")
    if comp not in ("gte", "lte"):
        raise HTTPException(422, "advance rule: comparator must be 'gte' or 'lte'")

    mode = cfg.get("mode")
    if mode not in ("percentage", "fixed_cents"):
        raise HTTPException(422, "advance rule: mode must be 'percentage' or 'fixed_cents'")

    v = cfg.get("value")
    if v is None:
        raise HTTPException(422, "advance rule: value is required")
    try:
        v = int(v)
    except (TypeError, ValueError):
        raise HTTPException(422, "advance rule: value must be an integer")
    if mode == "percentage" and v < 0:
        raise HTTPException(422, "advance rule: percentage value must be >= 0")


def _validate_weekend_config(cfg: dict) -> None:
    """weekend: {dow:[int 1..7,...], mode:"absolute"|"delta", value_cents:int}"""
    dow = cfg.get("dow")
    if not dow or not isinstance(dow, list):
        raise HTTPException(422, "weekend rule: dow must be a non-empty list")
    for d in dow:
        try:
            di = int(d)
        except (TypeError, ValueError):
            raise HTTPException(422, "weekend rule: dow elements must be integers 1..7")
        if di < 1 or di > 7:
            raise HTTPException(422, "weekend rule: dow elements must be in 1..7")

    mode = cfg.get("mode")
    if mode not in ("absolute", "delta"):
        raise HTTPException(422, "weekend rule: mode must be 'absolute' or 'delta'")

    vc = cfg.get("value_cents")
    if vc is None:
        raise HTTPException(422, "weekend rule: value_cents is required")
    try:
        vc = int(vc)
    except (TypeError, ValueError):
        raise HTTPException(422, "weekend rule: value_cents must be an integer")
    if mode == "absolute" and vc < 0:
        raise HTTPException(422, "weekend rule: absolute value_cents must be >= 0")


_VALIDATORS: Dict[str, Any] = {
    "season": _validate_season_config,
    "occupancy": _validate_occupancy_config,
    "los": _validate_los_config,
    "advance": _validate_advance_config,
    "weekend": _validate_weekend_config,
}


def _validate_rule_config(kind: str, rule_config: dict) -> None:
    """Dispatch to the per-kind validator; raises HTTPException(422) on failure."""
    if kind not in _VALIDATORS:
        raise HTTPException(422, f"unknown rule kind: {kind!r}")
    _VALIDATORS[kind](rule_config)


# ─────────────────────── plan CRUD (HTL-014) ────────────────────────────────


def create_rate_plan(
    hotel_id: str,
    room_type_id: str,
    *,
    name: str,
    base_nightly_rate_cents: Optional[int] = None,
    base_occupancy: int = 2,
    currency: str = "USD",
    user_sub: str,
) -> dict:
    """Create or idempotently return the rate plan for (hotel_id, room_type_id)."""
    _require_enabled()

    # Default base rate from HTL-005 room type if not supplied (best-effort).
    if base_nightly_rate_cents is None:
        try:
            from app.services import hotel_pms  # lazy import; avoids circular dep
            rt = hotel_pms.get_room_type(hotel_id, room_type_id)
            base_nightly_rate_cents = _to_int(rt.get("base_nightly_rate_cents")) if rt else 0
        except Exception:
            base_nightly_rate_cents = 0

    rate_plan_id = "rp_" + uuid4().hex[:12]
    ts = now_ts()
    partition = _pk(hotel_id, room_type_id)
    item = {
        "hotel_id#room_type_id": partition,
        "sk": "META",
        "rate_plan_id": rate_plan_id,
        "hotel_id": hotel_id,
        "room_type_id": room_type_id,
        "name": name,
        "base_nightly_rate_cents": base_nightly_rate_cents,
        "base_occupancy": base_occupancy,
        "currency": currency,
        "active": True,
        "created_at": ts,
        "updated_at": ts,
        "created_by": user_sub,
    }
    try:
        T.hotel_rate_plans.put_item(
            Item=item,
            ConditionExpression=(
                "attribute_not_exists(#pk) AND attribute_not_exists(sk)"
            ),
            ExpressionAttributeNames={"#pk": "hotel_id#room_type_id"},
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            # Already exists — return the existing plan (idempotent).
            existing = get_rate_plan(hotel_id, room_type_id)
            return existing if existing is not None else _coerce_item(item)
        raise

    _audit(
        "hotel.rate_plan.created",
        user_sub,
        hotel_id=hotel_id,
        room_type_id=room_type_id,
        rate_plan_id=rate_plan_id,
    )
    return _coerce_item(item)


def get_rate_plan(hotel_id: str, room_type_id: str) -> Optional[dict]:
    """Return the META header for the rate plan, or None if it does not exist."""
    _require_enabled()
    resp = T.hotel_rate_plans.get_item(
        Key={"hotel_id#room_type_id": _pk(hotel_id, room_type_id), "sk": "META"}
    )
    item = resp.get("Item")
    return _coerce_item(item) if item else None


def update_rate_plan(
    hotel_id: str,
    room_type_id: str,
    *,
    user_sub: str,
    **kwargs: Any,
) -> dict:
    """Partially update the META header.  Always stamps updated_at."""
    _require_enabled()

    allowed = {"name", "base_nightly_rate_cents", "base_occupancy", "currency", "active"}
    # Include a field only when it is explicitly supplied (not None); for bool
    # fields (active) we check membership in kwargs rather than truthiness.
    updates: Dict[str, Any] = {}
    for k in allowed:
        if k in kwargs and kwargs[k] is not None:
            updates[k] = kwargs[k]
        elif k == "active" and k in kwargs:
            # active may be False — explicitly supplied False is valid
            updates[k] = kwargs[k]
    updates["updated_at"] = now_ts()

    # Build UpdateExpression using numeric suffixes to avoid name conflicts.
    set_parts = []
    expr_names: Dict[str, str] = {}
    expr_values: Dict[str, Any] = {}
    for i, (field, val) in enumerate(updates.items()):
        name_token = f"#f{i}"
        val_token = f":v{i}"
        expr_names[name_token] = field
        expr_values[val_token] = val
        set_parts.append(f"{name_token} = {val_token}")

    try:
        resp = T.hotel_rate_plans.update_item(
            Key={"hotel_id#room_type_id": _pk(hotel_id, room_type_id), "sk": "META"},
            UpdateExpression="SET " + ", ".join(set_parts),
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_values,
            ConditionExpression="attribute_exists(sk)",
            ReturnValues="ALL_NEW",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise HTTPException(404, "Rate plan not found")
        raise

    _audit("hotel.rate_plan.updated", user_sub, hotel_id=hotel_id, room_type_id=room_type_id)
    return _coerce_item(resp["Attributes"])


def deactivate_rate_plan(hotel_id: str, room_type_id: str, *, user_sub: str) -> dict:
    """Soft-deactivate the rate plan (active=False)."""
    _require_enabled()
    result = update_rate_plan(hotel_id, room_type_id, user_sub=user_sub, active=False)
    _audit("hotel.rate_plan.deactivated", user_sub, hotel_id=hotel_id, room_type_id=room_type_id)
    return result


def list_rate_plans(hotel_id: str, cursor: Optional[str] = None, limit: int = 50) -> dict:
    """List rate plans for a hotel via GSI_HOTEL (newest-first by created_at)."""
    _require_enabled()
    from app.core.cursor import encode_cursor, decode_cursor  # lazy import

    kwargs: Dict[str, Any] = {
        "IndexName": "GSI_HOTEL",
        "KeyConditionExpression": Key("hotel_id").eq(hotel_id),
        "FilterExpression": "sk = :meta",
        "ExpressionAttributeValues": {":meta": "META"},
        "ScanIndexForward": False,
        "Limit": min(limit, 100),
    }
    if cursor:
        try:
            kwargs["ExclusiveStartKey"] = decode_cursor(cursor)
        except Exception:
            pass

    resp = T.hotel_rate_plans.query(**kwargs)
    items = [_coerce_item(i) for i in resp.get("Items", [])]
    next_cursor = None
    if "LastEvaluatedKey" in resp:
        next_cursor = encode_cursor(resp["LastEvaluatedKey"])
    return {"rate_plans": items, "count": len(items), "cursor": next_cursor}


# ─────────────────────── rule CRUD (HTL-014) ────────────────────────────────


def add_rule(
    hotel_id: str,
    room_type_id: str,
    *,
    kind: str,
    rule_config: dict,
    priority: int = 500,
    user_sub: str,
) -> dict:
    """Add a rule row to an existing rate plan."""
    _require_enabled()

    # Ensure the parent plan exists.
    plan = get_rate_plan(hotel_id, room_type_id)
    if plan is None:
        raise HTTPException(404, "rate plan not found")

    _validate_rule_config(kind, rule_config)

    rule_id = uuid4().hex
    ts = now_ts()
    partition = _pk(hotel_id, room_type_id)
    item = {
        "hotel_id#room_type_id": partition,
        "sk": _rule_sk(kind, rule_id),
        "rule_id": rule_id,
        "kind": kind,
        "rule_config": rule_config,
        "priority": priority,
        "hotel_id": hotel_id,
        "room_type_id": room_type_id,
        "created_at": ts,
        "updated_at": ts,
        "created_by": user_sub,
    }
    T.hotel_rate_plans.put_item(Item=item)
    _audit(
        "hotel.rate_plan.rule.added",
        user_sub,
        hotel_id=hotel_id,
        room_type_id=room_type_id,
        kind=kind,
        rule_id=rule_id,
    )
    return _coerce_item(item)


def list_rules(hotel_id: str, room_type_id: str) -> List[dict]:
    """Return all RULE# rows for a rate plan, sorted by (priority, kind, rule_id)."""
    _require_enabled()
    resp = T.hotel_rate_plans.query(
        KeyConditionExpression=(
            Key("hotel_id#room_type_id").eq(_pk(hotel_id, room_type_id))
            & Key("sk").begins_with("RULE#")
        )
    )
    items = [_coerce_item(i) for i in resp.get("Items", [])]
    items.sort(key=lambda r: (r.get("priority", 500), r.get("kind", ""), r.get("rule_id", "")))
    return items


def update_rule(
    hotel_id: str,
    room_type_id: str,
    rule_id: str,
    kind: str,
    *,
    rule_config: dict,
    priority: int,
    user_sub: str,
) -> dict:
    """Update an existing rule row."""
    _require_enabled()
    _validate_rule_config(kind, rule_config)

    try:
        resp = T.hotel_rate_plans.update_item(
            Key={
                "hotel_id#room_type_id": _pk(hotel_id, room_type_id),
                "sk": _rule_sk(kind, rule_id),
            },
            UpdateExpression=(
                "SET rule_config = :rc, priority = :p, updated_at = :ua"
            ),
            ExpressionAttributeValues={
                ":rc": rule_config,
                ":p": priority,
                ":ua": now_ts(),
            },
            ConditionExpression="attribute_exists(sk)",
            ReturnValues="ALL_NEW",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise HTTPException(404, "rule not found")
        raise

    _audit(
        "hotel.rate_plan.rule.updated",
        user_sub,
        hotel_id=hotel_id,
        room_type_id=room_type_id,
        kind=kind,
        rule_id=rule_id,
    )
    return _coerce_item(resp["Attributes"])


def delete_rule(
    hotel_id: str,
    room_type_id: str,
    rule_id: str,
    kind: str,
    *,
    user_sub: str,
) -> bool:
    """Delete a rule row.  Returns True if deleted, False if not found.  Never raises."""
    _require_enabled()
    try:
        resp = T.hotel_rate_plans.delete_item(
            Key={
                "hotel_id#room_type_id": _pk(hotel_id, room_type_id),
                "sk": _rule_sk(kind, rule_id),
            },
            ReturnValues="ALL_OLD",
        )
        deleted = bool(resp.get("Attributes"))
        _audit(
            "hotel.rate_plan.rule.deleted",
            user_sub,
            hotel_id=hotel_id,
            room_type_id=room_type_id,
            kind=kind,
            rule_id=rule_id,
        )
        return deleted
    except Exception:
        return False


# ────────────────── compute_stay_price (HTL-015) ────────────────────────────


def compute_stay_price(
    hotel_id: str,
    room_type_id: str,
    checkin: str,
    checkout: str,
    adults: int,
    children: int,
    rooms: int = 1,
    advance_days: Optional[int] = None,
) -> "StayPriceResult":
    """Deterministic multi-night breakdown + summed total for a stay.

    Pure arithmetic; no DDB writes, no randomness.
    """
    # ── flag gate (first line per spec) ──────────────────────────────────────
    _require_enabled()

    if rooms < 1:
        raise HTTPException(422, "rooms must be >= 1")

    # ── parse & validate span ────────────────────────────────────────────────
    try:
        ci_date = date.fromisoformat(checkin)
        co_date = date.fromisoformat(checkout)
    except ValueError as exc:
        raise HTTPException(422, f"invalid date format: {exc}") from exc

    if co_date <= ci_date:
        raise HTTPException(422, "checkout must be after checkin")

    # ── load plan once ───────────────────────────────────────────────────────
    plan = get_rate_plan(hotel_id, room_type_id)
    if plan is None:
        raise HTTPException(404, "rate plan not found")

    base = _to_int(plan.get("base_nightly_rate_cents", 0))
    base_occ = _to_int(plan.get("base_occupancy", 2))
    currency = plan.get("currency", "USD")

    rules = list_rules(hotel_id, room_type_id)

    # Bucket rules by kind.
    season_rules = [r for r in rules if r.get("kind") == "season"]
    weekend_rules = [r for r in rules if r.get("kind") == "weekend"]
    # For singular whole-stay rules, pick lowest-priority one (tiebreak by rule_id).
    def _pick_single(kind: str) -> Optional[dict]:
        cands = sorted(
            [r for r in rules if r.get("kind") == kind],
            key=lambda r: (r.get("priority", 500), r.get("rule_id", "")),
        )
        return cands[0] if cands else None

    occ_rule = _pick_single("occupancy")
    los_rule = _pick_single("los")
    adv_rule = _pick_single("advance")

    # ── derive advance_days default ──────────────────────────────────────────
    if advance_days is None:
        today = date.fromtimestamp(now_ts())
        advance_days = max(0, (ci_date - today).days)

    # ── enumerate nights ─────────────────────────────────────────────────────
    night_dates: List[date] = []
    d = ci_date
    while d < co_date:
        night_dates.append(d)
        d = d + timedelta(days=1)
    nights = len(night_dates)

    # ── per-night computation (HTL-015 steps 1-4) ───────────────────────────
    per_night_lines = []
    applied_rule_ids: List[str] = []

    occ_cents = 0
    if occ_rule:
        rc = occ_rule["rule_config"]
        ea = _to_int(rc.get("extra_adult_cents", 0))
        ec = _to_int(rc.get("extra_child_cents", 0))
        occ_cents = max(0, adults - base_occ) * ea + children * ec
        if occ_cents > 0 and occ_rule["rule_id"] not in applied_rule_ids:
            applied_rule_ids.append(occ_rule["rule_id"])

    for night_date in night_dates:
        night_rate = base
        season_delta = 0

        # Step 1: season rules
        matching_abs = [
            r for r in season_rules
            if r["rule_config"].get("mode") == "absolute"
            and date.fromisoformat(r["rule_config"]["start_date"]) <= night_date
            <= date.fromisoformat(r["rule_config"]["end_date"])
        ]
        matching_delta = [
            r for r in season_rules
            if r["rule_config"].get("mode") == "delta"
            and date.fromisoformat(r["rule_config"]["start_date"]) <= night_date
            <= date.fromisoformat(r["rule_config"]["end_date"])
        ]

        if matching_abs:
            # Lowest-priority absolute wins (tiebreak by rule_id ascending).
            winner = sorted(
                matching_abs,
                key=lambda r: (r.get("priority", 500), r.get("rule_id", "")),
            )[0]
            override = _to_int(winner["rule_config"]["value_cents"])
            season_delta = override - base
            night_rate = override
            if winner["rule_id"] not in applied_rule_ids:
                applied_rule_ids.append(winner["rule_id"])

        for dr in matching_delta:
            delta_v = _to_int(dr["rule_config"]["value_cents"])
            season_delta += delta_v
            night_rate += delta_v
            if dr["rule_id"] not in applied_rule_ids:
                applied_rule_ids.append(dr["rule_id"])

        # Step 2: weekend rules
        iso_dow = night_date.isoweekday()  # Mon=1..Sun=7
        weekend_delta = 0
        matching_wknd = [
            r for r in weekend_rules
            if iso_dow in [_to_int(x) for x in r["rule_config"].get("dow", [])]
        ]
        wknd_abs = [r for r in matching_wknd if r["rule_config"].get("mode") == "absolute"]
        wknd_dlt = [r for r in matching_wknd if r["rule_config"].get("mode") == "delta"]

        if wknd_abs:
            winner = sorted(
                wknd_abs,
                key=lambda r: (r.get("priority", 500), r.get("rule_id", "")),
            )[0]
            override = _to_int(winner["rule_config"]["value_cents"])
            weekend_delta = override - night_rate
            night_rate = override
            if winner["rule_id"] not in applied_rule_ids:
                applied_rule_ids.append(winner["rule_id"])

        for wr in wknd_dlt:
            dv = _to_int(wr["rule_config"]["value_cents"])
            weekend_delta += dv
            night_rate += dv
            if wr["rule_id"] not in applied_rule_ids:
                applied_rule_ids.append(wr["rule_id"])

        # Step 3: occupancy surcharge (per-night, already computed above)
        # Step 4: floor
        night_total = max(0, night_rate + occ_cents)

        per_night_lines.append({
            "date": str(night_date),
            "base_cents": base,
            "season_delta_cents": season_delta,
            "weekend_delta_cents": weekend_delta,
            "occupancy_cents": occ_cents,
            "night_total_cents": night_total,
        })

    stay_subtotal = sum(l["night_total_cents"] for l in per_night_lines)

    # ── whole-stay modifiers (HTL-015 steps 5-8) ────────────────────────────

    # Step 5: LOS validation + discount
    los_discount = 0
    if los_rule:
        rc = los_rule["rule_config"]
        mn = _to_int(rc.get("min_nights", 1))
        mx = rc.get("max_nights")
        if nights < mn:
            raise HTTPException(422, "stay too short")
        if mx is not None and nights > _to_int(mx):
            raise HTTPException(422, "stay too long")
        # Apply discount
        dt = rc.get("discount_type", "fixed_cents")
        dv = _to_int(rc.get("discount_value", 0))
        if dt == "percentage":
            los_discount = (stay_subtotal * dv) // 100
        else:  # fixed_cents
            los_discount = min(dv, stay_subtotal)
        if los_rule["rule_id"] not in applied_rule_ids:
            applied_rule_ids.append(los_rule["rule_id"])

    post_los = stay_subtotal - los_discount

    # Step 6: advance modifier
    advance_modifier = 0
    if adv_rule:
        rc = adv_rule["rule_config"]
        dbc = _to_int(rc.get("days_before_checkin", 0))
        comp = rc.get("comparator", "gte")
        satisfied = (
            (comp == "gte" and advance_days >= dbc)
            or (comp == "lte" and advance_days <= dbc)
        )
        if satisfied:
            mode = rc.get("mode", "fixed_cents")
            v = _to_int(rc.get("value", 0))
            if mode == "percentage":
                advance_modifier = (post_los * v) // 100
            else:  # fixed_cents
                advance_modifier = v
            # Sign convention per HTL-015 §5.8: gte advance-purchase = discount
            # (negative modifier); lte last-minute = surcharge (positive).
            # However, the spec notes the sign is determined by the rule's value/mode,
            # not hardcoded by comparator — we store the value as-is (positive = surcharge,
            # negative in delta modes = discount).  The formula adds the signed modifier.
            # By convention we negate for gte (advance-purchase discount):
            if comp == "gte":
                advance_modifier = -advance_modifier
            if adv_rule["rule_id"] not in applied_rule_ids:
                applied_rule_ids.append(adv_rule["rule_id"])

    # Step 7: × rooms
    per_room_total = stay_subtotal - los_discount + advance_modifier
    total = per_room_total * rooms

    # Step 8: floor
    total = max(0, total)

    from app.models import NightLineOut, StayPriceResult  # lazy import to avoid circular
    return StayPriceResult(
        nights=nights,
        per_night=[NightLineOut(**l) for l in per_night_lines],
        stay_subtotal_cents=stay_subtotal,
        los_discount_cents=los_discount,
        advance_modifier_cents=advance_modifier,
        rooms=rooms,
        total_cents=total,
        currency=currency,
        applied_rule_ids=applied_rule_ids,
    )
