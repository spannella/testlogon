"""OFBiz pricing/promotions rules engine (OFB-019) + public façade (OFB-020).

Tiered / bulk / conditional discount strategies with scope filtering, priority,
and stacking (best_deal_wins vs. stackable). ``apply_pricing_rules`` is THE
single public entry point (DECISIONS D2) consumed by cart/checkout and ECM.

Additive, flag-gated behind ``S.pricing_rules_enabled`` (default OFF). With the
flag off, ``apply_pricing_rules`` returns a zero-discount breakdown and every
CRUD function raises HTTP 404. Discount is always capped at the cart subtotal
(never negative). SECOPS-007 parity: no ``dev_mode`` branch.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

VALID_RULE_TYPES = frozenset({"tiered", "bulk", "conditional"})
VALID_STACKING = frozenset({"best_deal_wins", "stackable"})


def _flag_on() -> bool:
    return bool(getattr(S, "pricing_rules_enabled", False))


def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=404, detail="Pricing rules not enabled")


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event

        audit_event(event, user_sub or "system", None, **fields)
    except Exception:
        pass


def _to_int(v: Any) -> int:
    try:
        return int(v)
    except Exception:
        return 0


# ── result dataclasses ──────────────────────────────────────────────────────
@dataclass
class PerItemDiscount:
    sku: str
    quantity: int
    original_line_cents: int
    discounted_line_cents: int
    discount_cents: int


@dataclass
class RuleDiscountResult:
    rule_id: str
    rule_type: str
    priority: int
    stacking_mode: str
    discount_cents: int
    per_item_discounts: List[PerItemDiscount]
    final_cart_cents: int
    applied: bool
    reason_skipped: Optional[str] = None


@dataclass
class StackedDiscountResult:
    total_discount_cents: int
    applied_rule_ids: List[str]
    per_rule_breakdown: List[RuleDiscountResult]
    final_cart_cents: int


@dataclass
class PricingBreakdownResult:
    subtotal_cents: int
    rule_discount_cents: int
    final_cents_before_promo: int
    applied_rules: List[Dict[str, Any]] = field(default_factory=list)


# ── config validation ───────────────────────────────────────────────────────
def _validate_tiered_config(cfg: Dict[str, Any]) -> Optional[str]:
    tiers = cfg.get("tiers")
    if not tiers or not isinstance(tiers, list):
        return "tiered rule requires non-empty tiers"
    prev_max = 0
    for i, t in enumerate(tiers):
        mn = _to_int(t.get("min_qty"))
        mx = t.get("max_qty")
        if mn < 1:
            return "tier min_qty must be >= 1"
        if i == 0 and mn != 1:
            return "first tier must start at min_qty=1"
        if mn != prev_max + 1:
            return "tiers must be contiguous and non-overlapping"
        if mx is None:
            if i != len(tiers) - 1:
                return "only the last tier may be unbounded"
            prev_max = 10 ** 12
        else:
            mx = _to_int(mx)
            if mx < mn:
                return "tier max_qty must be >= min_qty"
            prev_max = mx
    if tiers[-1].get("max_qty") is not None:
        return "last tier must be unbounded (max_qty=null)"
    return None


def _validate_bulk_config(cfg: Dict[str, Any]) -> Optional[str]:
    if _to_int(cfg.get("threshold_qty")) < 2:
        return "bulk rule requires threshold_qty >= 2"
    if cfg.get("discount_type") not in ("percentage", "fixed_per_unit"):
        return "bulk discount_type must be percentage|fixed_per_unit"
    if _to_int(cfg.get("discount_value")) < 1:
        return "bulk discount_value must be >= 1"
    return None


def _validate_conditional_config(cfg: Dict[str, Any]) -> Optional[str]:
    if _to_int(cfg.get("min_cart_total_cents")) < 1:
        return "conditional rule requires min_cart_total_cents >= 1"
    if cfg.get("discount_type") not in ("percentage", "fixed_amount"):
        return "conditional discount_type must be percentage|fixed_amount"
    if _to_int(cfg.get("discount_value")) < 1:
        return "conditional discount_value must be >= 1"
    return None


def _validate_config(rule_type: str, cfg: Dict[str, Any]) -> Optional[str]:
    if rule_type == "tiered":
        return _validate_tiered_config(cfg)
    if rule_type == "bulk":
        return _validate_bulk_config(cfg)
    if rule_type == "conditional":
        return _validate_conditional_config(cfg)
    return "unknown rule_type"


# ── CRUD ────────────────────────────────────────────────────────────────────
def _rule_pk(rule_id: str) -> str:
    return f"RULE#{rule_id}"


def _project(item: Dict[str, Any]) -> Dict[str, Any]:
    cfg = item.get("rule_config")
    if isinstance(cfg, str):
        try:
            cfg = json.loads(cfg)
        except Exception:
            cfg = {}
    return {
        "rule_id": item.get("rule_id", ""),
        "name": item.get("name", ""),
        "description": item.get("description"),
        "rule_type": item.get("rule_type", ""),
        "stacking_mode": item.get("stacking_mode", "best_deal_wins"),
        "priority": _to_int(item.get("priority")),
        "active": bool(item.get("active", True)),
        "created_at": _to_int(item.get("created_at")),
        "updated_at": _to_int(item.get("updated_at")),
        "created_by": item.get("created_by", ""),
        "expires_at": _to_int(item.get("expires_at")),
        "max_uses": _to_int(item.get("max_uses")),
        "current_uses": _to_int(item.get("current_uses")),
        "max_uses_per_user": _to_int(item.get("max_uses_per_user")),
        "applies_to_checkout_types": list(item.get("applies_to_checkout_types") or []),
        "scope_category_ids": list(item.get("scope_category_ids") or []),
        "scope_skus": list(item.get("scope_skus") or []),
        "scope_creator_user_id": item.get("scope_creator_user_id") or "",
        "required_subscription_plan_ids": list(item.get("required_subscription_plan_ids") or []),
        "rule_config": cfg or {},
        "linked_promo_code_id": item.get("linked_promo_code_id") or "",
    }


def create_rule(
    creator_id: str,
    name: str,
    rule_type: str,
    stacking_mode: str,
    rule_config: Dict[str, Any],
    *,
    priority: int = 500,
    description: str = "",
    applies_to_checkout_types: Optional[List[str]] = None,
    scope_category_ids: Optional[List[str]] = None,
    scope_skus: Optional[List[str]] = None,
    scope_creator_user_id: str = "",
    required_subscription_plan_ids: Optional[List[str]] = None,
    expires_at: int = 0,
    max_uses: int = 0,
    max_uses_per_user: int = 0,
    linked_promo_code_id: str = "",
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    _require_enabled()
    if rule_type not in VALID_RULE_TYPES:
        return None, "invalid rule_type"
    if stacking_mode not in VALID_STACKING:
        return None, "invalid stacking_mode"
    err = _validate_config(rule_type, rule_config or {})
    if err:
        return None, err
    priority = max(1, min(1000, int(priority)))

    rule_id = "pr_" + uuid.uuid4().hex[:12]
    ts = now_ts()
    item = {
        "pk": _rule_pk(rule_id),
        "sk": "META",
        "rule_id": rule_id,
        "name": name.strip(),
        "description": (description or "").strip() or None,
        "rule_type": rule_type,
        "stacking_mode": stacking_mode,
        "priority": priority,
        "active": True,
        "created_at": ts,
        "updated_at": ts,
        "created_by": creator_id,
        "expires_at": int(expires_at),
        "max_uses": int(max_uses),
        "current_uses": 0,
        "max_uses_per_user": int(max_uses_per_user),
        "applies_to_checkout_types": sorted(set(applies_to_checkout_types or ["shop"])),
        "scope_category_ids": sorted(set(scope_category_ids or [])),
        "scope_skus": sorted(set(scope_skus or [])),
        "scope_creator_user_id": scope_creator_user_id or "",
        "required_subscription_plan_ids": sorted(set(required_subscription_plan_ids or [])),
        "rule_config": json.dumps(rule_config or {}),
        "linked_promo_code_id": linked_promo_code_id or "",
        "active_pk": "ACTIVE",
        "GSI1PK": f"CREATOR#{creator_id}" if creator_id else "GLOBAL#RULES",
        "GSI1SK": ts,
    }
    T.pricing_rules.put_item(Item=item)
    _audit("pricing_rule_created", creator_id, rule_id=rule_id, rule_type=rule_type)
    return _project(item), None


def get_rule(rule_id: str) -> Optional[Dict[str, Any]]:
    _require_enabled()
    resp = T.pricing_rules.get_item(Key={"pk": _rule_pk(rule_id), "sk": "META"})
    item = resp.get("Item")
    return _project(item) if item else None


def list_rules(creator_id: str, *, limit: int = 100) -> Dict[str, Any]:
    _require_enabled()
    resp = T.pricing_rules.query(
        IndexName="ByCreatorCreatedAt",
        KeyConditionExpression=Key("GSI1PK").eq(f"CREATOR#{creator_id}"),
        ScanIndexForward=False,
        Limit=limit,
    )
    return {"rules": [_project(it) for it in resp.get("Items", [])], "cursor": None}


def update_rule(rule_id: str, creator_id: str, **updates: Any) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    _require_enabled()
    existing = get_rule(rule_id)
    if existing is None:
        return None, "rule not found"
    if existing["created_by"] != creator_id:
        return None, "not the rule owner"

    mutable = {
        "name", "description", "active", "priority", "expires_at", "max_uses",
        "rule_config", "stacking_mode", "scope_category_ids", "scope_skus",
        "required_subscription_plan_ids",
    }
    sets: List[str] = ["updated_at = :ts"]
    vals: Dict[str, Any] = {":ts": now_ts()}
    names: Dict[str, str] = {}
    for key, value in updates.items():
        if value is None or key not in mutable:
            continue
        if key == "rule_config":
            err = _validate_config(updates.get("rule_type", existing["rule_type"]), value)
            if err:
                return None, err
            vals[":rc"] = json.dumps(value)
            sets.append("rule_config = :rc")
        elif key == "stacking_mode":
            if value not in VALID_STACKING:
                return None, "invalid stacking_mode"
            vals[":sm"] = value
            sets.append("stacking_mode = :sm")
        elif key == "active":
            vals[":act"] = bool(value)
            sets.append("active = :act")
            vals[":apk"] = "ACTIVE" if value else "INACTIVE"
            sets.append("active_pk = :apk")
        elif key == "name":
            names["#nm"] = "name"
            vals[":nm"] = str(value).strip()
            sets.append("#nm = :nm")
        elif key == "priority":
            vals[":pr"] = max(1, min(1000, int(value)))
            sets.append("priority = :pr")
        elif key in ("expires_at", "max_uses"):
            vals[f":{key}"] = int(value)
            sets.append(f"{key} = :{key}")
        elif key in ("scope_category_ids", "scope_skus", "required_subscription_plan_ids"):
            vals[f":{key}"] = sorted(set(value))
            sets.append(f"{key} = :{key}")
        elif key == "description":
            vals[":desc"] = str(value).strip() or None
            sets.append("description = :desc")

    kwargs: Dict[str, Any] = {
        "Key": {"pk": _rule_pk(rule_id), "sk": "META"},
        "UpdateExpression": "SET " + ", ".join(sets),
        "ExpressionAttributeValues": vals,
    }
    if names:
        kwargs["ExpressionAttributeNames"] = names
    T.pricing_rules.update_item(**kwargs)
    _audit("pricing_rule_updated", creator_id, rule_id=rule_id)
    return get_rule(rule_id), None


def deactivate_rule(rule_id: str, creator_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    return update_rule(rule_id, creator_id, active=False)


# ── discount computation ────────────────────────────────────────────────────
def _scope_filter(rule: Dict[str, Any], cart_items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    cats = set(rule.get("scope_category_ids") or [])
    skus = set(rule.get("scope_skus") or [])
    if not cats and not skus:
        return list(cart_items)
    out = []
    for it in cart_items:
        if cats and it.get("category_id") in cats:
            out.append(it)
        elif skus and it.get("sku") in skus:
            out.append(it)
    return out


def _line_total(item: Dict[str, Any]) -> int:
    lt = item.get("line_total_cents")
    if lt is not None:
        return _to_int(lt)
    return _to_int(item.get("unit_price_cents")) * _to_int(item.get("quantity"))


def _tier_for_qty(tiers: List[Dict[str, Any]], qty: int) -> Optional[Dict[str, Any]]:
    for t in tiers:
        mn = _to_int(t.get("min_qty"))
        mx = t.get("max_qty")
        if qty >= mn and (mx is None or qty <= _to_int(mx)):
            return t
    return None


def compute_discount(
    rule: Dict[str, Any],
    cart_items: List[Dict[str, Any]],
    cart_total_cents: int,
    user_sub: str,
) -> RuleDiscountResult:
    """Compute a single rule's discount against the in-scope cart subset."""
    rid = rule["rule_id"]
    rtype = rule["rule_type"]
    cfg = rule.get("rule_config") or {}
    in_scope = _scope_filter(rule, cart_items)

    def _result(discount: int, per_item: List[PerItemDiscount], applied: bool, reason: Optional[str] = None):
        discount = max(0, min(discount, cart_total_cents))
        return RuleDiscountResult(
            rule_id=rid,
            rule_type=rtype,
            priority=_to_int(rule.get("priority")),
            stacking_mode=rule.get("stacking_mode", "best_deal_wins"),
            discount_cents=discount,
            per_item_discounts=per_item,
            final_cart_cents=max(0, cart_total_cents - discount),
            applied=applied,
            reason_skipped=reason,
        )

    if not in_scope:
        return _result(0, [], False, "scope_miss")

    per_item: List[PerItemDiscount] = []
    total = 0

    if rtype == "tiered":
        tiers = cfg.get("tiers") or []
        for it in in_scope:
            qty = _to_int(it.get("quantity"))
            unit = _to_int(it.get("unit_price_cents"))
            tier = _tier_for_qty(tiers, qty)
            line_disc = 0
            if tier is not None:
                line_disc = max(0, (unit - _to_int(tier.get("unit_price_cents"))) * qty)
            if line_disc:
                orig = unit * qty
                per_item.append(PerItemDiscount(it.get("sku", ""), qty, orig, orig - line_disc, line_disc))
                total += line_disc
        if total == 0:
            return _result(0, [], False, "no_tier_discount")
        return _result(total, per_item, True)

    if rtype == "bulk":
        threshold = _to_int(cfg.get("threshold_qty"))
        dtype = cfg.get("discount_type")
        dval = _to_int(cfg.get("discount_value"))
        any_met = False
        for it in in_scope:
            qty = _to_int(it.get("quantity"))
            unit = _to_int(it.get("unit_price_cents"))
            if qty < threshold:
                continue
            any_met = True
            line = unit * qty
            if dtype == "percentage":
                line_disc = (line * dval) // 100
            else:  # fixed_per_unit
                line_disc = min(dval * qty, line)
            if line_disc:
                per_item.append(PerItemDiscount(it.get("sku", ""), qty, line, line - line_disc, line_disc))
                total += line_disc
        if not any_met:
            return _result(0, [], False, "quantity_below_threshold")
        return _result(total, per_item, True)

    if rtype == "conditional":
        subtotal = sum(_line_total(it) for it in in_scope)
        min_total = _to_int(cfg.get("min_cart_total_cents"))
        if subtotal < min_total:
            return _result(0, [], False, "cart_total_below_threshold")
        dtype = cfg.get("discount_type")
        dval = _to_int(cfg.get("discount_value"))
        if dtype == "percentage":
            disc = (subtotal * dval) // 100
        else:  # fixed_amount
            disc = min(dval, subtotal)
        return _result(disc, [], disc > 0, None if disc > 0 else "no_discount")

    return _result(0, [], False, "unknown_rule_type")


def _is_eligible(rule: Dict[str, Any], checkout_type: str, now: int) -> bool:
    if not rule.get("active"):
        return False
    exp = _to_int(rule.get("expires_at"))
    if exp and exp < now:
        return False
    mu = _to_int(rule.get("max_uses"))
    if mu and _to_int(rule.get("current_uses")) >= mu:
        return False
    cts = rule.get("applies_to_checkout_types") or []
    if cts and checkout_type not in cts:
        return False
    return True


def resolve_applicable_rules(
    checkout_type: str,
    cart_items: List[Dict[str, Any]],
    cart_total_cents: int,
    user_sub: str,
    creator_id: str,
    explicit_rule_ids: Optional[List[str]] = None,
    exclude_rule_ids: Optional[Set[str]] = None,
) -> List[Dict[str, Any]]:
    """Return active, non-expired, in-scope rules ordered by priority ASC.

    ``explicit_rule_ids``: restrict to only those rule IDs. Otherwise scan the
    creator's rules + platform-wide (GLOBAL#RULES) rules.
    ``exclude_rule_ids``: rule IDs to skip (prevents double-count when a promo
    code already applied a rule — DECISIONS D2 / ESCALATIONS §A row 24).
    """
    _require_enabled()
    now = now_ts()
    exclude = exclude_rule_ids or set()
    candidates: List[Dict[str, Any]] = []

    if explicit_rule_ids:
        for rid in explicit_rule_ids:
            r = get_rule(rid)
            if r:
                candidates.append(r)
    else:
        seen: Set[str] = set()
        for pk in ([f"CREATOR#{creator_id}"] if creator_id else []) + ["GLOBAL#RULES"]:
            resp = T.pricing_rules.query(
                IndexName="ByCreatorCreatedAt",
                KeyConditionExpression=Key("GSI1PK").eq(pk),
            )
            for it in resp.get("Items", []):
                r = _project(it)
                if r["rule_id"] in seen:
                    continue
                seen.add(r["rule_id"])
                candidates.append(r)

    out = [
        r
        for r in candidates
        if r["rule_id"] not in exclude and _is_eligible(r, checkout_type, now)
    ]
    out.sort(key=lambda r: _to_int(r.get("priority")))
    return out


def apply_stacking(results: List[RuleDiscountResult], cart_total_cents: int) -> StackedDiscountResult:
    """Combine per-rule results: sum stackables + the single best best-deal-wins
    winner; cap at cart total."""
    applied = [r for r in results if r.applied and r.discount_cents > 0]
    stackable = [r for r in applied if r.stacking_mode == "stackable"]
    bdw = [r for r in applied if r.stacking_mode == "best_deal_wins"]

    winner: Optional[RuleDiscountResult] = None
    for r in bdw:
        if winner is None or r.discount_cents > winner.discount_cents or (
            r.discount_cents == winner.discount_cents and r.priority < winner.priority
        ):
            winner = r

    combined = sum(r.discount_cents for r in stackable)
    if winner is not None:
        combined += winner.discount_cents
    combined = max(0, min(combined, cart_total_cents))

    applied_ids = [r.rule_id for r in stackable]
    if winner is not None:
        applied_ids.append(winner.rule_id)
    return StackedDiscountResult(
        total_discount_cents=combined,
        applied_rule_ids=applied_ids,
        per_rule_breakdown=list(results),
        final_cart_cents=max(0, cart_total_cents - combined),
    )


def apply_pricing_rules(
    user_sub: str,
    items: List[Dict[str, Any]],
    *,
    checkout_type: str,
    creator_id: Optional[str] = None,
    exclude_rule_ids: Optional[Set[str]] = None,
) -> PricingBreakdownResult:
    """THE single public entry point for the pricing engine (DECISIONS D2).

    Returns a zero-discount breakdown when the flag is off (no raise) so callers
    can invoke it unconditionally. Internally resolves → computes → stacks."""
    subtotal = sum(_line_total(it) for it in items)
    if not _flag_on():
        return PricingBreakdownResult(
            subtotal_cents=subtotal,
            rule_discount_cents=0,
            final_cents_before_promo=subtotal,
            applied_rules=[],
        )
    rules = resolve_applicable_rules(
        checkout_type,
        items,
        subtotal,
        user_sub,
        creator_id or "",
        exclude_rule_ids=exclude_rule_ids,
    )
    results = [compute_discount(r, items, subtotal, user_sub) for r in rules]
    stacked = apply_stacking(results, subtotal)
    applied_lines = [
        {"rule_id": r.rule_id, "rule_type": r.rule_type, "discount_cents": r.discount_cents}
        for r in stacked.per_rule_breakdown
        if r.applied and r.rule_id in stacked.applied_rule_ids
    ]
    return PricingBreakdownResult(
        subtotal_cents=subtotal,
        rule_discount_cents=stacked.total_discount_cents,
        final_cents_before_promo=stacked.final_cart_cents,
        applied_rules=applied_lines,
    )


def redeem_rule(
    rule_id: str,
    user_sub: str,
    original_price_cents: int,
    final_price_cents: int,
    cart_id: str = "",
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Atomically record a rule redemption (OFB-020 calls this at purchase).

    Increments ``current_uses`` (conditional on the global cap) and writes a
    per-user REDEEM# audit row. Canonical export name per DECISIONS D2."""
    _require_enabled()
    rule = get_rule(rule_id)
    if rule is None:
        return None, "rule not found"
    max_uses = _to_int(rule.get("max_uses"))
    try:
        if max_uses > 0:
            T.pricing_rules.update_item(
                Key={"pk": _rule_pk(rule_id), "sk": "META"},
                UpdateExpression="ADD current_uses :one",
                ConditionExpression=Attr("current_uses").lt(max_uses),
                ExpressionAttributeValues={":one": 1},
            )
        else:
            T.pricing_rules.update_item(
                Key={"pk": _rule_pk(rule_id), "sk": "META"},
                UpdateExpression="ADD current_uses :one",
                ExpressionAttributeValues={":one": 1},
            )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return None, "rule max_uses exceeded"
        raise
    ts = now_ts()
    T.pricing_rules.put_item(
        Item={
            "pk": _rule_pk(rule_id),
            "sk": f"REDEEM#{user_sub}#{ts:010d}#{uuid.uuid4().hex[:8]}",
            "rule_id": rule_id,
            "user_sub": user_sub,
            "original_price_cents": int(original_price_cents),
            "final_price_cents": int(final_price_cents),
            "cart_id": cart_id or "",
            "ts": ts,
        }
    )
    return get_rule(rule_id), None
