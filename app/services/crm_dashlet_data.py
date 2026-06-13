"""RPT-007 — Pre-built dashlet catalogue (data providers).

Provides ``get_dashlet_data(user_sub, dashlet_id)`` which reads the user's
dashboard from T.crm_dashboards, locates the dashlet by ID, and dispatches to
the appropriate data provider.

Also handles the RPT-008 ``saved_search`` dashlet type.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from typing import Any, Dict, List, Optional

from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import user_pk

logger = logging.getLogger(__name__)


def _coerce_int(val: Any) -> Optional[int]:
    if val is None:
        return None
    if isinstance(val, Decimal):
        return int(val)
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def get_dashlet_data(user_sub: str, dashlet_id: str) -> Dict[str, Any]:
    """Resolve dashlet config from dashboard and dispatch to provider."""
    # Read dashboard
    dashboard_id = f"DASH#{user_sub}#default"
    resp = T.crm_dashboards.get_item(Key={"dashboard_id": dashboard_id, "sk": "META"})
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Dashboard not found")

    dashlets_raw = item.get("dashlets", "[]")
    if isinstance(dashlets_raw, str):
        dashlets = json.loads(dashlets_raw)
    else:
        dashlets = list(dashlets_raw)

    dashlet = next((d for d in dashlets if d.get("dashlet_id") == dashlet_id), None)
    if not dashlet:
        raise ValueError("dashlet_not_found")

    dashlet_type = dashlet.get("dashlet_type")
    config = dashlet.get("config", {})
    fetched_at = now_ts()

    if dashlet_type == "recent_tickets":
        data = _provider_recent_tickets(user_sub, config)
    elif dashlet_type == "calendar_today":
        data = _provider_calendar_today(user_sub, config)
    elif dashlet_type == "my_contacts":
        data = _provider_my_contacts(user_sub, config)
    elif dashlet_type == "billing_summary":
        data = _provider_billing_summary(user_sub, config)
    elif dashlet_type == "report":
        data = _provider_report(user_sub, config)
    elif dashlet_type == "saved_search":
        saved_search_id = config.get("saved_search_id")
        if not saved_search_id:
            raise HTTPException(status_code=422, detail="saved_search dashlet requires config.saved_search_id")
        from app.services.crm_saved_searches import run_saved_search
        result = run_saved_search(saved_search_id, user_sub)
        data = result if isinstance(result, dict) else dict(result)
    else:
        raise ValueError(f"unknown_dashlet_type: {dashlet_type}")

    return {
        "dashlet_id": dashlet_id,
        "dashlet_type": dashlet_type,
        "fetched_at": fetched_at,
        "data": data,
    }


# ---------------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------------

def _provider_recent_tickets(user_sub: str, config: Dict[str, Any]) -> Dict[str, Any]:
    from app.core.settings import S
    from boto3.dynamodb.conditions import Key

    row_limit = min(int(config.get("row_limit", 10)), 50)
    status_filter = config.get("status_filter")

    index_name = S.tickets_owner_index_name
    gsi1pk = f"OWNER#{user_sub}"

    resp = T.tickets.query(
        IndexName=index_name,
        KeyConditionExpression=Key("gsi1pk").eq(gsi1pk),
        ScanIndexForward=False,
        Limit=100,
    )
    items = resp.get("Items", [])
    if status_filter:
        items = [i for i in items if i.get("status") == status_filter]

    tickets = []
    for item in items[:row_limit]:
        tickets.append({
            "ticket_id": item.get("ticket_id"),
            "subject": item.get("subject"),
            "status": item.get("status"),
            "created_at": _coerce_int(item.get("created_at")),
            "updated_at": _coerce_int(item.get("updated_at")),
        })
    return {"tickets": tickets, "count": len(tickets)}


def _provider_calendar_today(user_sub: str, config: Dict[str, Any]) -> Dict[str, Any]:
    from boto3.dynamodb.conditions import Key

    now = datetime.now(timezone.utc)
    date_utc = now.strftime("%Y-%m-%d")
    start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
    end_of_day = start_of_day + timedelta(days=1)

    # Try to find a calendar for the user
    calendar_id = config.get("calendar_id")
    if not calendar_id:
        # Attempt to resolve via calendar access index
        try:
            resp = T.calendar.query(
                KeyConditionExpression=Key("calendar_id").eq(f"CAL#{user_sub}"),
            )
            items = resp.get("Items", [])
            if items:
                calendar_id = items[0].get("calendar_id")
        except Exception:
            pass

    events: List[Dict[str, Any]] = []
    if calendar_id:
        try:
            resp = T.calendar.query(
                KeyConditionExpression=Key("calendar_id").eq(calendar_id) & Key("sk").begins_with("event#"),
                Limit=50,
            )
            for item in resp.get("Items", []):
                start_utc = item.get("start_utc", "")
                events.append({
                    "event_id": item.get("event_id"),
                    "title": item.get("title"),
                    "start_utc": start_utc,
                    "end_utc": item.get("end_utc"),
                    "all_day": bool(item.get("all_day", False)),
                })
        except Exception as exc:
            logger.warning("calendar_today_provider_error user=%s err=%s", user_sub, exc)

    return {"events": events, "date_utc": date_utc}


def _provider_my_contacts(user_sub: str, config: Dict[str, Any]) -> Dict[str, Any]:
    from boto3.dynamodb.conditions import Key

    row_limit = min(int(config.get("row_limit", 10)), 100)
    sort_by = config.get("sort_by", "last_contacted_at")

    resp = T.contacts.query(
        KeyConditionExpression=Key("owner_id").eq(user_sub),
        Limit=row_limit,
    )
    items = resp.get("Items", [])

    contacts = []
    for item in items:
        contacts.append({
            "contact_id": item.get("contact_id"),
            "name": item.get("name") or item.get("display_name"),
            "email": item.get("email"),
            "phone": item.get("phone"),
            "last_contacted_at": _coerce_int(item.get("last_contacted_at")),
        })
    return {"contacts": contacts, "count": len(contacts)}


def _provider_billing_summary(user_sub: str, config: Dict[str, Any]) -> Dict[str, Any]:
    from boto3.dynamodb.conditions import Key

    period_days = min(int(config.get("period_days", 30)), 365)
    cutoff = now_ts() - (period_days * 86400)

    pk_val = user_pk(user_sub)
    total_cents = 0
    tx_count = 0

    try:
        lek = None
        while True:
            kwargs: Dict[str, Any] = {
                "KeyConditionExpression": Key("pk").eq(pk_val) & Key("sk").begins_with("LEDGER#"),
                "Limit": 500,
            }
            if lek:
                kwargs["ExclusiveStartKey"] = lek
            resp = T.billing.query(**kwargs)
            for item in resp.get("Items", []):
                ts = _coerce_int(item.get("ts")) or 0
                if ts >= cutoff:
                    amt = item.get("amount_cents", 0)
                    total_cents += int(amt) if amt else 0
                    tx_count += 1
            lek = resp.get("LastEvaluatedKey")
            if not lek:
                break
    except Exception as exc:
        logger.warning("billing_summary_provider_error user=%s err=%s", user_sub, exc)

    return {
        "total_cents": total_cents,
        "tx_count": tx_count,
        "period_days": period_days,
        "currency": "usd",
    }


def _provider_report(user_sub: str, config: Dict[str, Any]) -> Dict[str, Any]:
    from boto3.dynamodb.conditions import Key

    report_id = config.get("report_id")
    if not report_id:
        raise HTTPException(status_code=422, detail="report dashlet requires config.report_id")

    use_cached = bool(config.get("use_cached", True))

    if use_cached:
        # Try to return the most recent RUN row
        try:
            resp = T.crm_reports.query(
                KeyConditionExpression=Key("report_id").eq(report_id) & Key("sk").begins_with("RUN#"),
                ScanIndexForward=False,
                Limit=1,
            )
            items = resp.get("Items", [])
            if items:
                run = items[0]
                columns = json.loads(run.get("columns", "[]"))
                rows = json.loads(run.get("rows", "[]"))
                return {
                    "columns": columns,
                    "rows": rows,
                    "row_count": int(run.get("row_count", 0)),
                    "run_at": _coerce_int(run.get("run_at")) or 0,
                    "source": "cached",
                }
        except Exception as exc:
            logger.warning("report_dashlet_cache_error report_id=%s err=%s", report_id, exc)

    # Fresh run
    from app.services.crm_reports import run_report
    result = run_report(report_id, user_sub)
    return {
        "columns": result.get("columns", []),
        "rows": result.get("rows", []),
        "row_count": result.get("row_count", 0),
        "run_at": result.get("run_at", 0),
        "source": "fresh",
    }
