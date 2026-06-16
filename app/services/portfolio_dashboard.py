"""PMD-003 — Portfolio dashboard KPI service.

Read-only aggregation service for a landlord's property portfolio.
Mirrors the in-memory bucketing and ledger-scan strategy of
app/services/platform_financial_dashboard.py but scoped to the
rent-roll view rather than platform GMV/revenue.

Three public surfaces:
  compute_kpis(owner_sub)        → four headline KPIs
  monthly_rent_snapshot(...)     → monthly rent-ledger bucketing
  priority_items(owner_sub, ...) → upcoming expirations + open WOs

RULE-2: every sibling cluster call is guarded by its own feature flag.
  - PROP cluster  : if getattr(S, "property_mgmt_enabled", False)
  - LSE cluster   : if getattr(S, "leases_enabled", False)
  - RNT/billing   : try/except (billing table always present)
  - WOV cluster   : if getattr(S, "work_orders_enabled", False)
  - PMD-001 policy: if rent_policy._flag_on()

No DynamoDB writes. No new tables. No money moves.
"""
from __future__ import annotations

import calendar as _calendar
from decimal import Decimal
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional

from fastapi import HTTPException

from app.core.settings import S
from app.core.time import now_ts

_RNT_CHARGE_TYPE = "rent_charge"
_RNT_PAYMENT_TYPE = "rent_payment"
_OPEN_STATUSES = frozenset({"open", "in_progress", "waiting_on_user"})


# ---------------------------------------------------------------------------
# Flag guard (mirrors inventory.py:50-57)
# ---------------------------------------------------------------------------

def _flag_on() -> bool:
    return bool(getattr(S, "property_dashboard_enabled", False))


def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=404, detail="Property dashboard is not enabled")


def _to_int(v: Any) -> int:
    """Coerce DynamoDB Decimal / str / None to int."""
    if v is None:
        return 0
    if isinstance(v, Decimal):
        return int(v)
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event
        audit_event(event, user_sub or "system", None, **fields)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Private ledger iterator
# ---------------------------------------------------------------------------

def _iter_owner_rent_ledger(
    owner_sub: str,
    *,
    ledger_date_prefix: Optional[str] = None,
    max_pages: Optional[int] = None,
) -> Iterator[Dict[str, Any]]:
    """Paginated scan of owner's rent-type billing ledger rows.

    Yields only rent_charge / rent_payment rows that are not reversed.
    Caps at S.portfolio_kpi_max_ledger_scan_pages DDB pages.
    Mirrors platform_financial_dashboard._scan_ledger_entries pattern.
    """
    from boto3.dynamodb.conditions import Key, Attr
    from app.core.tables import T

    pk_val = f"USER#{owner_sub}"
    max_p = max_pages or _to_int(getattr(S, "portfolio_kpi_max_ledger_scan_pages", 50)) or 50
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("pk").eq(pk_val) & Key("sk").begins_with("LEDGER#"),
    }
    if ledger_date_prefix:
        kwargs["FilterExpression"] = Attr("ledger_date").begins_with(ledger_date_prefix)

    page = 0
    while True:
        resp = T.billing.query(**kwargs)
        for item in resp.get("Items", []):
            t = str(item.get("type", ""))
            s = str(item.get("state", ""))
            if t in (_RNT_CHARGE_TYPE, _RNT_PAYMENT_TYPE) and s != "reversed":
                yield item
        lek = resp.get("LastEvaluatedKey")
        page += 1
        if not lek or page >= max_p:
            break
        kwargs["ExclusiveStartKey"] = lek


# ---------------------------------------------------------------------------
# Public KPI computation
# ---------------------------------------------------------------------------

def compute_kpis(owner_sub: str) -> Dict[str, Any]:
    """Compute four headline KPIs for the landlord's portfolio.

    Each sub-computation is independently guarded; a missing cluster
    degrades to 0/0.0 rather than 500-ing.
    """
    _require_enabled()

    # 1. Occupancy (PROP cluster — guarded by property_mgmt_enabled)
    occupancy_rate = 0.0
    unit_count = 0
    occupied_units = 0
    try:
        if getattr(S, "property_mgmt_enabled", False):
            from app.services import property_mgmt as _pm
            rollup = _pm.portfolio_occupancy_rollup(owner_sub)
            if rollup:
                unit_count = _to_int(rollup.get("unit_count"))
                occupied_units = _to_int(rollup.get("occupied"))
                occupancy_rate = float(rollup.get("occupancy_rate", 0.0))
    except Exception:
        pass

    # 2. Active lease count (LSE cluster — guarded by leases_enabled)
    active_lease_count = 0
    try:
        if getattr(S, "leases_enabled", False):
            from app.services import leases as _lse
            cursor: Optional[str] = None
            while True:
                page = _lse.list_leases(owner_sub, status="active", limit=200, cursor=cursor)
                if not page:
                    break
                active_lease_count += len(page.get("leases", []))
                cursor = page.get("next_cursor")
                if not cursor:
                    break
    except Exception:
        pass

    # 3. Outstanding rent (BALANCE row fast path; fallback to ledger scan)
    outstanding_rent_cents = 0
    try:
        from app.core.tables import T
        from app.services.billing_shared import user_pk, compute_due
        balance_item = T.billing.get_item(
            Key={"pk": user_pk(owner_sub), "sk": "BALANCE"}
        ).get("Item")
        if balance_item:
            due = compute_due(balance_item)
            outstanding_rent_cents = max(0, _to_int(due.get("due_settled_cents")))
        else:
            for item in _iter_owner_rent_ledger(owner_sub):
                if str(item.get("type")) == _RNT_CHARGE_TYPE:
                    outstanding_rent_cents += _to_int(item.get("amount_cents"))
    except Exception:
        pass

    # 4. Open work-order count (WOV primary; ticket fallback)
    open_work_order_count = 0
    try:
        if getattr(S, "work_orders_enabled", False):
            from app.services import work_orders as _wov
            open_work_order_count = _wov.count_open_work_orders(owner_sub)
        else:
            raise ImportError("work_orders not enabled")
    except Exception:
        # Fallback: property-linked tickets in open-family statuses
        try:
            from app.services.tickets import TicketStore
            store = TicketStore()
            result = store.list_tickets(owner_sub=owner_sub, limit=500)
            tickets = result.get("tickets", []) if result else []
            for t in tickets:
                if str(t.get("status", "")) in _OPEN_STATUSES:
                    open_work_order_count += 1
        except Exception:
            open_work_order_count = 0

    return {
        "occupancy_rate":        occupancy_rate,
        "unit_count":            unit_count,
        "occupied_units":        occupied_units,
        "active_lease_count":    active_lease_count,
        "outstanding_rent_cents": outstanding_rent_cents,
        "open_work_order_count": open_work_order_count,
        "computed_at":           now_ts(),
    }


def monthly_rent_snapshot(owner_sub: str, *, year: int, month: int) -> Dict[str, Any]:
    """Scan the owner's rent ledger for a calendar month and bucket into
    collected / outstanding / overdue / charged totals.

    Uses PMD-001 rent_policy.get_policy to derive the overdue threshold.
    """
    _require_enabled()

    if not (1 <= month <= 12):
        raise HTTPException(status_code=422, detail="month must be 1-12")
    if year < 2000:
        raise HTTPException(status_code=422, detail="year must be >= 2000")

    prefix = f"{year:04d}-{month:02d}"

    # Fetch overdue threshold from PMD-001 policy (guarded by its own flag)
    rent_due_day = 1
    grace_period_days = 0
    try:
        from app.services import rent_policy as _rp
        if _rp._flag_on():
            policy = _rp.get_policy(owner_sub)
            rent_due_day = int(policy.get("rent_due_day", 1))
            grace_period_days = int(policy.get("grace_period_days", 0))
    except Exception:
        pass

    # Overdue threshold: past due+grace date for this month?
    last_day = _calendar.monthrange(year, month)[1]
    due_ts = (
        datetime(year, month, min(rent_due_day, last_day), tzinfo=timezone.utc).timestamp()
        + grace_period_days * 86400
    )
    now = now_ts()

    charged_cents = 0
    collected_cents = 0
    outstanding_cents = 0

    for item in _iter_owner_rent_ledger(owner_sub, ledger_date_prefix=prefix):
        amount = _to_int(item.get("amount_cents"))
        item_type = str(item.get("type", ""))

        if item_type == _RNT_CHARGE_TYPE:
            charged_cents += amount
            outstanding_cents += amount  # will be netted off by payments

        elif item_type == _RNT_PAYMENT_TYPE:
            collected_cents += amount
            outstanding_cents -= amount  # net off charges

    # Clamp outstanding (payments may exceed charges in pre-payment scenarios)
    outstanding_cents = max(0, outstanding_cents)

    # Overdue = unpaid past the grace window
    overdue_cents = 0
    if now > due_ts and outstanding_cents > 0:
        overdue_cents = outstanding_cents

    return {
        "year":               year,
        "month":              month,
        "charged_cents":      charged_cents,
        "collected_cents":    collected_cents,
        "outstanding_cents":  outstanding_cents,
        "overdue_cents":      overdue_cents,
        "rent_due_day":       rent_due_day,
        "grace_period_days":  grace_period_days,
        "computed_at":        now_ts(),
    }


def priority_items(owner_sub: str, *, limit: int = 20) -> Dict[str, Any]:
    """Return union of upcoming lease expirations and open WOs/tickets.

    Sorted: expirations ascending by end_date, WOs by updated_at desc.
    Both lists are guarded by their cluster's own flag.
    """
    _require_enabled()
    limit = max(1, min(int(limit), 100))

    # Upcoming lease expirations (LSE cluster — guarded by leases_enabled)
    upcoming_expirations: List[Dict[str, Any]] = []
    try:
        if getattr(S, "leases_enabled", False):
            from app.services import leases as _lse
            # list_upcoming_expirations returns list[dict] directly (LSE-003)
            result = _lse.list_upcoming_expirations(owner_sub, within_days=60)
            if result:
                for lse in result:
                    upcoming_expirations.append({
                        "kind":               "lease_expiring",
                        "lease_id":          lse.get("lease_id"),
                        "lease_number":      lse.get("lease_number"),
                        "unit_id":           lse.get("unit_id"),
                        "property_id":       lse.get("property_id"),
                        "tenant_id":         lse.get("tenant_id"),
                        "end_date":          _to_int(lse.get("end_date")),
                        "monthly_rent_cents": _to_int(lse.get("monthly_rent_cents")),
                    })
            upcoming_expirations.sort(key=lambda x: x["end_date"])
    except Exception:
        upcoming_expirations = []

    # Open work orders (WOV cluster — guarded by work_orders_enabled)
    open_work_orders: List[Dict[str, Any]] = []
    try:
        if getattr(S, "work_orders_enabled", False):
            from app.services import work_orders as _wov
            wos = _wov.list_open_work_orders(owner_sub, limit=limit)
            for wo in (wos or []):
                open_work_orders.append({
                    "kind":           "open_work_order",
                    "work_order_id": wo.get("work_order_id"),
                    "title":          wo.get("title"),
                    "status":         wo.get("status"),
                    "priority":       wo.get("priority"),
                    "property_id":    wo.get("property_id"),
                    "updated_at":     _to_int(wo.get("updated_at")),
                })
        else:
            raise ImportError("work_orders not enabled")
    except Exception:
        # WOV fallback: open-family tickets
        try:
            from app.services.tickets import TicketStore
            store = TicketStore()
            result = store.list_tickets(owner_sub=owner_sub, limit=limit)
            for t in (result.get("tickets", []) if result else []):
                if str(t.get("status", "")) in _OPEN_STATUSES:
                    open_work_orders.append({
                        "kind":       "open_ticket",
                        "ticket_id": t.get("ticket_id"),
                        "subject":    t.get("subject"),
                        "status":     t.get("status"),
                        "updated_at": _to_int(t.get("updated_at")),
                    })
        except Exception:
            open_work_orders = []

    combined = (upcoming_expirations + open_work_orders)[:limit]

    return {
        "upcoming_expirations": upcoming_expirations[:limit],
        "open_work_orders":     open_work_orders[:limit],
        "items":                combined,
        "count":                len(combined),
    }
