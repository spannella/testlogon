"""hotel_cancellation.py — HTL-033 + HTL-034 cancellation/no-show policy engine.

HTL-033: pure compute (compute_cancellation_refund) + idempotent side-effect orchestration
         (apply_cancellation, apply_no_show).
HTL-034: policy persistence (upsert_cancellation_policy, get_cancellation_policy,
         resolve_policy_for_reservation).

No new DynamoDB table. No new feature flag (reuses HOTEL_PMS_ENABLED from HTL-001).
No if-S.dev_mode branch anywhere (SECOPS-007 parity).
Money: integer cents only, one refund mechanism (new_ledger_entry / apply_balance_delta /
settle_or_reverse_ledger from billing_shared), never forked.
"""
from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import (
    apply_balance_delta,
    ddb_put,
    new_ledger_entry,
    settle_or_reverse_ledger,
    user_pk,
)

# ---------------------------------------------------------------------------
# Flag / audit helpers (copied verbatim from inventory.py:50-56, 92-98)
# ---------------------------------------------------------------------------


def _flag_on() -> bool:
    return bool(getattr(S, "hotel_pms_enabled", False))


def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=404, detail="Hotel PMS is not enabled")


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event  # noqa: F401
        audit_event(event, user_sub or "system", None, **fields)
    except Exception:
        pass


def _clamp(v: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, int(v)))


# ---------------------------------------------------------------------------
# HTL-034 policy helpers
# ---------------------------------------------------------------------------

_ZERO_PENALTY_DEFAULT: dict = {
    "free_until_days_before": 0,
    "penalty_pct": 0,
    "penalty_fixed_cents": 0,
    "no_show_fee_cents": 0,
}


def _policy_sk(policy_id: str) -> str:
    """SK for a cancellation policy child row on the hotels partition."""
    return f"CANCELPOLICY#{policy_id}"


# ---------------------------------------------------------------------------
# HTL-033 §4.2 — pure math, no I/O, not flag-gated
# ---------------------------------------------------------------------------


def compute_cancellation_refund(
    reservation: dict,
    policy: dict,
    now: int | None = None,
) -> dict:
    """Pure, deterministic refund computation. No DDB, no side effects, not flag-gated.

    Returns dict with base_cents, penalty_cents, refundable_cents, days_to_checkin.
    """
    base = max(0, int(reservation.get("total_cents") or 0))
    check_in_ts = int(reservation["check_in_ts"])
    now = now if now is not None else now_ts()
    days_to_checkin = max(0, (check_in_ts - now) // 86400)

    free_until = int(policy.get("free_until_days_before", 0) or 0)
    if days_to_checkin >= free_until:
        penalty = 0
    elif int(policy.get("penalty_fixed_cents", 0) or 0) > 0:
        penalty = min(base, int(policy["penalty_fixed_cents"]))
    else:
        penalty = (base * _clamp(int(policy.get("penalty_pct", 0) or 0), 0, 100)) // 100

    penalty = _clamp(penalty, 0, base)
    refundable = max(0, base - penalty)
    return {
        "base_cents": base,
        "penalty_cents": penalty,
        "refundable_cents": refundable,
        "days_to_checkin": days_to_checkin,
    }


# ---------------------------------------------------------------------------
# HTL-033 §4.3 — idempotent cancellation side-effect driver
# ---------------------------------------------------------------------------


def apply_cancellation(
    reservation: dict,
    policy: dict,
    *,
    actor_sub: str,
    provider: str = "stripe",
    now: int | None = None,
    deposit_escrow_sk: str | None = None,
) -> dict:
    """Idempotent cancellation: release inventory, post exactly ONE refund ledger row.

    Does NOT mutate reservation status (HTL-019 owns the FSM transition).
    Returns the refund_ledger_sk so HTL-034 can back-write the idempotency token.
    """
    _require_enabled()
    rid = reservation["reservation_id"]

    # (1) Idempotency guard — stored single-write token.
    if reservation.get("cancellation_ledger_sk"):
        return {
            "reservation_id": rid,
            "penalty_cents": 0,
            "refundable_cents": 0,
            "refund_ledger_sk": reservation["cancellation_ledger_sk"],
            "released_nights": 0,
            "idempotent": True,
        }

    quote = compute_cancellation_refund(reservation, policy, now)
    pk = user_pk(reservation["user_sub"])
    currency = reservation.get("currency", "usd")

    # (2) Release per-date availability (HTL-011) — best-effort, must NOT block refund.
    released = 0
    hold_id = reservation.get("hold_id")
    if hold_id:
        try:
            from app.services.hotel_availability import release_hold  # lazy: HTL-011 forward dep
            release_hold(hold_id, reason="cancelled", user_sub=actor_sub,
                         terminal_status="released")
            released = 1
        except Exception:
            pass

    # (3) Reverse a held deposit escrow row, if any — best-effort (HTL-031 forward dep).
    if deposit_escrow_sk:
        try:
            settle_or_reverse_ledger(T.billing, "pk", pk, deposit_escrow_sk, "reversed")
        except Exception:
            pass

    # (4) Post EXACTLY ONE refund ledger row — the shared mechanism, never forked.
    refund_sk = None
    refundable = quote["refundable_cents"]
    if refundable > 0:
        refund_sk, led_item = new_ledger_entry(
            key_name="pk",
            key_value=pk,
            entry_type="adjustment",
            amount_cents=refundable,
            state="settled",
            reason="refund",
            meta={"reason": "hotel_cancellation", "reservation_id": rid},
            extra={
                "provider": provider,
                "reservation_id": rid,
                "hotel_id": reservation.get("hotel_id", ""),
            },
        )
        ddb_put(T.billing, led_item)
        apply_balance_delta(
            T.billing, pk,
            {"payments_settled_cents": -refundable},
            currency=currency,
        )
        if reservation.get("ledger_sk"):
            try:
                settle_or_reverse_ledger(
                    T.billing, "pk", pk, reservation["ledger_sk"], "reversed"
                )
            except Exception:
                pass

    _audit(
        "hotel.reservation.cancelled",
        actor_sub,
        reservation_id=rid,
        penalty_cents=quote["penalty_cents"],
        refundable_cents=refundable,
        provider=provider,
    )
    return {
        "reservation_id": rid,
        "penalty_cents": quote["penalty_cents"],
        "refundable_cents": refundable,
        "refund_ledger_sk": refund_sk,
        "released_nights": released,
        "idempotent": False,
    }


# ---------------------------------------------------------------------------
# HTL-033 §4.4 — idempotent no-show fee charge
# ---------------------------------------------------------------------------


def apply_no_show(
    reservation: dict,
    policy: dict,
    *,
    actor_sub: str,
    provider: str = "stripe",
    now: int | None = None,
) -> dict:
    """Idempotent no-show fee: post exactly ONE charge ledger row. No inventory release."""
    _require_enabled()
    rid = reservation["reservation_id"]

    if reservation.get("no_show_ledger_sk"):
        return {
            "reservation_id": rid,
            "no_show_fee_cents": 0,
            "no_show_ledger_sk": reservation["no_show_ledger_sk"],
            "idempotent": True,
        }

    fee = max(0, int(policy.get("no_show_fee_cents", 0) or 0))
    pk = user_pk(reservation["user_sub"])
    currency = reservation.get("currency", "usd")

    fee_sk = None
    if fee > 0:
        fee_sk, led_item = new_ledger_entry(
            key_name="pk",
            key_value=pk,
            entry_type="charge",
            amount_cents=fee,
            state="settled",
            reason="no_show_fee",
            meta={"reason": "hotel_no_show", "reservation_id": rid},
            extra={
                "provider": provider,
                "reservation_id": rid,
                "hotel_id": reservation.get("hotel_id", ""),
            },
        )
        ddb_put(T.billing, led_item)
        apply_balance_delta(
            T.billing, pk,
            {"payments_settled_cents": fee},
            currency=currency,
        )

    _audit(
        "hotel.reservation.no_show",
        actor_sub,
        reservation_id=rid,
        no_show_fee_cents=fee,
    )
    return {
        "reservation_id": rid,
        "no_show_fee_cents": fee,
        "no_show_ledger_sk": fee_sk,
        "idempotent": False,
    }


# ---------------------------------------------------------------------------
# HTL-034 §4.1 — policy CRUD on the hotels partition
# ---------------------------------------------------------------------------


def _get_hotel(hotel_id: str) -> dict | None:
    """Lazy accessor for hotel META row (HTL-001 forward dep)."""
    try:
        resp = T.hotels.get_item(Key={"hotel_id": hotel_id, "sk": "META"})
        return resp.get("Item")
    except Exception:
        return None


def upsert_cancellation_policy(
    hotel_id: str,
    *,
    scope: str = "default",
    free_until_days_before: int = 0,
    penalty_pct: int = 0,
    penalty_fixed_cents: int = 0,
    no_show_fee_cents: int = 0,
    user_sub: str,
) -> dict:
    """Create or overwrite the cancellation policy for (hotel, scope).

    One row per (hotel_id, scope); idempotent second call overwrites in place.
    Ownership: 404 on unknown hotel or non-owner sub.
    Validation: 422 on out-of-range values.
    """
    _require_enabled()

    # Parent + ownership check (HTL-001 forward dep).
    hotel = _get_hotel(hotel_id)
    if hotel is None or hotel.get("owner_sub") != user_sub:
        raise HTTPException(status_code=404, detail="Hotel not found")

    # Validate ranges.
    if not (0 <= penalty_pct <= 100):
        raise HTTPException(status_code=422, detail="penalty_pct out of range [0,100]")
    if free_until_days_before < 0:
        raise HTTPException(status_code=422, detail="negative cents")
    if penalty_fixed_cents < 0:
        raise HTTPException(status_code=422, detail="negative cents")
    if no_show_fee_cents < 0:
        raise HTTPException(status_code=422, detail="negative cents")

    policy_id = "default" if scope == "default" else scope
    sk = _policy_sk(policy_id)
    ts = now_ts()

    T.hotels.update_item(
        Key={"hotel_id": hotel_id, "sk": sk},
        UpdateExpression=(
            "SET policy_id=:pid, free_until_days_before=:f, penalty_pct=:p, "
            "penalty_fixed_cents=:pf, no_show_fee_cents=:n, updated_at=:u, "
            "created_at=if_not_exists(created_at, :u)"
        ),
        ExpressionAttributeValues={
            ":pid": policy_id,
            ":f": free_until_days_before,
            ":p": penalty_pct,
            ":pf": penalty_fixed_cents,
            ":n": no_show_fee_cents,
            ":u": ts,
        },
    )

    _audit(
        "hotel.cancel_policy.upsert",
        user_sub,
        hotel_id=hotel_id,
        policy_id=policy_id,
        penalty_pct=penalty_pct,
    )

    return {
        "hotel_id": hotel_id,
        "policy_id": policy_id,
        "scope": scope,
        "free_until_days_before": free_until_days_before,
        "penalty_pct": penalty_pct,
        "penalty_fixed_cents": penalty_fixed_cents,
        "no_show_fee_cents": no_show_fee_cents,
        "created_at": ts,
        "updated_at": ts,
    }


def get_cancellation_policy(hotel_id: str, scope: str = "default") -> dict | None:
    """Return the policy dict for (hotel_id, scope), or None if not set.

    Decimal values coerced to int at the boundary (§5.8).
    """
    _require_enabled()
    policy_id = "default" if scope == "default" else scope
    sk = _policy_sk(policy_id)
    resp = T.hotels.get_item(Key={"hotel_id": hotel_id, "sk": sk})
    item = resp.get("Item")
    if item is None:
        return None
    # Coerce Decimal -> int (moto returns Decimal for numeric attributes).
    return {
        "hotel_id": hotel_id,
        "policy_id": str(item.get("policy_id", policy_id)),
        "scope": scope,
        "free_until_days_before": int(item.get("free_until_days_before", 0)),
        "penalty_pct": int(item.get("penalty_pct", 0)),
        "penalty_fixed_cents": int(item.get("penalty_fixed_cents", 0)),
        "no_show_fee_cents": int(item.get("no_show_fee_cents", 0)),
        "created_at": int(item.get("created_at", 0)),
        "updated_at": int(item.get("updated_at", 0)),
    }


def resolve_policy_for_reservation(reservation: dict) -> dict:
    """Resolve the applicable cancellation policy for a reservation.

    Precedence: rate-plan-scoped → hotel default → implicit zero-penalty default.
    Never returns None; never raises (except on flag-off 404 via _require_enabled).
    """
    hotel_id = reservation.get("hotel_id", "")
    rate_plan_id = reservation.get("rate_plan_id")

    if rate_plan_id:
        scoped = get_cancellation_policy(hotel_id, scope=f"RATE#{rate_plan_id}")
        if scoped is not None:
            return scoped

    default = get_cancellation_policy(hotel_id, scope="default")
    if default is not None:
        return default

    return dict(_ZERO_PENALTY_DEFAULT)
