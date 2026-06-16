from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, TypedDict

from boto3.dynamodb.conditions import Attr, Key  # PLT-002 adds Attr for FilterExpression scans
from botocore.exceptions import ClientError
from fastapi import HTTPException, Request

from app.core.aws import ddb
from app.core.settings import S
from app.services.api_metering_contract import route_id_from_request
from app.services.api_keys import parse_api_key, get_api_key_item
from app.services.api_metering_policy import classify_api_call, raise_limit_denied
from app.services.api_pricing_catalog import load_api_pricing_catalog, resolve_route_pricing
from app.services.usage_metering import period_id_for_datetime
from app.metrics import (
    record_api_usage_ingest_event,
    record_api_usage_ingest_lag,
    record_api_usage_limit_deny,
    record_api_usage_snapshot_finalize,
    record_api_usage_reconciliation_drift,
)


class ApiUsageEvent(TypedDict):
    event_id: str
    user_sub: str
    api_key_id: str
    route_id: str
    product: str
    status_code: int
    request_id: str
    request_attempt: int
    period_id: str
    billable: bool
    request_units: int
    unit_price_micros: int
    cost_micros: int
    pricing_catalog_version: str
    timestamp: str
    idempotency_key: str


class ApiUsagePeriodTotals(TypedDict):
    user_sub: str
    period_id: str
    calls_total: int
    billable_calls_total: int
    request_units_total: int
    cost_subtotal_micros: int


class ApiUsageKeyPeriodTotals(ApiUsagePeriodTotals):
    api_key_id: str


class ApiUsageRoutePeriodTotals(ApiUsagePeriodTotals):
    route_id: str
    unit_price_micros: int


class ApiChargeLineItem(TypedDict):
    route_id: str
    pricing_catalog_version: str
    quantity: int
    subtotal_micros: int
    unit_prices_micros: list[int]


class ApiPeriodChargeResult(TypedDict):
    user_sub: str
    period_id: str
    total_charge_micros: int
    line_items: list[ApiChargeLineItem]
    event_count: int


class ApiBillingUsageSnapshot(TypedDict):
    user_sub: str
    period_id: str
    version: int
    status: str
    finalized_at: str | None
    totals: ApiUsagePeriodTotals
    by_key: list[ApiUsageKeyPeriodTotals]
    by_route: list[ApiUsageRoutePeriodTotals]
    source_event_count: int


def _extract_request_id(request: Request) -> str:
    return (request.headers.get("x-request-id") or request.headers.get("x-correlation-id") or "").strip()


def _extract_request_attempt(request: Request) -> int:
    raw = (request.headers.get("x-request-attempt") or request.headers.get("x-retry-attempt") or "1").strip()
    try:
        val = int(raw)
    except ValueError:
        return 1
    return max(1, val)


def _extract_user_sub(request: Request) -> str:
    explicit = (request.headers.get("x-user-sub") or "").strip()
    if explicit:
        return explicit
    auth = (request.headers.get("authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip()
        if token and token.count(".") != 2:
            return token
    return ""


def _extract_api_key_id(request: Request) -> str:
    candidates = [request.headers.get("x-api-key"), request.headers.get("x-api_key")]
    auth = (request.headers.get("authorization") or "").strip()
    if auth.lower().startswith("apikey "):
        candidates.append(auth.split(" ", 1)[1].strip())
    for value in candidates:
        raw = (value or "").strip()
        if not raw:
            continue
        try:
            parsed = parse_api_key(raw)
            return str(parsed.get("key_id") or "")
        except Exception:
            continue
    return ""


def build_api_idempotency_key(*, request_id: str, route_id: str, request_attempt: int, status_code: int) -> str:
    rid = (request_id or "").strip() or "<missing_request_id>"
    return f"api_usage|{rid}|{route_id}|attempt={max(1, int(request_attempt))}|status={int(status_code)}"


def api_usage_event_id_from_idempotency_key(idempotency_key: str) -> str:
    digest = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()[:32]
    return f"auev_{digest}"


def _ttl_epoch_for_days(days: int, *, base: Optional[datetime] = None) -> int:
    safe_days = max(1, int(days))
    dt = (base or datetime.now(timezone.utc)) + timedelta(days=safe_days)
    return int(dt.timestamp())


def build_api_usage_event(request: Request, status_code: int) -> Optional[ApiUsageEvent]:
    route_id = route_id_from_request(request)
    if not route_id:
        return None

    product = _product_from_route_id(route_id)
    now = datetime.now(timezone.utc)
    request_id = _extract_request_id(request)
    request_attempt = _extract_request_attempt(request)
    decision = classify_api_call(
        int(status_code),
        is_rate_limited=int(status_code) == 429,
        is_auth_failed=int(status_code) in (401, 403),
    )
    rated = resolve_route_pricing(route_id=route_id, event_ts=int(now.timestamp()))
    idempotency_key = build_api_idempotency_key(
        request_id=request_id,
        route_id=route_id,
        request_attempt=request_attempt,
        status_code=int(status_code),
    )
    request_units = 1 if decision.counts_toward_quota else 0
    cost_micros = int(rated.unit_price_micros) * int(request_units) if decision.billable else 0
    return {
        "event_id": api_usage_event_id_from_idempotency_key(idempotency_key),
        "user_sub": _extract_user_sub(request),
        "api_key_id": _extract_api_key_id(request),
        "route_id": route_id,
        "product": product,
        "status_code": int(status_code),
        "request_id": request_id,
        "request_attempt": request_attempt,
        "period_id": period_id_for_datetime(now),
        "billable": bool(decision.billable),
        "request_units": request_units,
        "unit_price_micros": int(rated.unit_price_micros),
        "cost_micros": int(cost_micros),
        "pricing_catalog_version": str(rated.pricing_catalog_version),
        "timestamp": now.isoformat(),
        "idempotency_key": idempotency_key,
    }


def _product_from_route_id(route_id: str) -> str:
    rid = (route_id or "").strip().lower()
    if ":" not in rid:
        return "other"
    _method, path = rid.split(":", 1)
    if path.startswith("/v1/files") or path.startswith("/ui/files") or "/filemanager" in path:
        return "filemanager"
    if path.startswith("/v1/newsfeed") or "/newsfeed" in path:
        return "newsfeed"
    if path.startswith("/v1/tickets") or "/ticket" in path or "/helpdesk" in path:
        return "tickets"
    if "/cart" in path or "/checkout" in path or "/catalog" in path or "/orders" in path or "/commerce" in path:
        return "shopping"
    if (
        "/messaging/conversations/" in path
        and (
            "/messages/image" in path
            or "/messages/file" in path
            or "/messages/gallery" in path
            or "/attachment" in path
            or "/gallery" in path
        )
    ):
        return "messager_media"
    if path.startswith("/v1/messages") or "/messaging" in path or "/conversations" in path:
        return "messager"
    return "other"


def _is_conditional_check_failed(exc: Exception) -> bool:
    if not isinstance(exc, ClientError):
        return False
    return exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException"


def _aggregate_values(event: ApiUsageEvent) -> dict[str, int]:
    return {
        "calls": 1,
        "billable": 1 if event["billable"] else 0,
        "units": int(event["request_units"]),
        "cost": int(event["cost_micros"]),
    }


def _apply_generic_counter_row(table: Any, *, key: dict[str, str], attrs: dict[str, Any], vals: dict[str, int], updated_at: str) -> None:
    expr_vals = {
        ":updated_at": updated_at,
        ":calls_inc": vals["calls"],
        ":billable_inc": vals["billable"],
        ":units_inc": vals["units"],
        ":cost_inc": vals["cost"],
    }
    set_parts = ["updated_at = :updated_at"]
    for attr, value in attrs.items():
        token = f":{attr}"
        expr_vals[token] = value
        set_parts.append(f"{attr} = if_not_exists({attr}, {token})")
    table.update_item(
        Key=key,
        UpdateExpression=(
            "SET " + ", ".join(set_parts) +
            " ADD calls_total :calls_inc, billable_calls_total :billable_inc, "
            "request_units_total :units_inc, cost_subtotal_micros :cost_inc"
        ),
        ExpressionAttributeValues=expr_vals,
    )


def _apply_period_aggregate(table: Any, event: ApiUsageEvent) -> None:
    _apply_generic_counter_row(
        table,
        key={"PK": f"USER#{event['user_sub']}", "SK": f"API_USAGE#PERIOD#{event['period_id']}"},
        attrs={"entity_type": "api_usage_period_totals", "user_sub": event["user_sub"], "period_id": event["period_id"]},
        vals=_aggregate_values(event),
        updated_at=event["timestamp"],
    )


def _apply_key_aggregate(table: Any, event: ApiUsageEvent) -> None:
    api_key_id = event["api_key_id"] or "NONE"
    _apply_generic_counter_row(
        table,
        key={"PK": f"USER#{event['user_sub']}", "SK": f"API_USAGE#KEY#{api_key_id}#PERIOD#{event['period_id']}"},
        attrs={
            "entity_type": "api_key_usage_period_totals",
            "user_sub": event["user_sub"],
            "api_key_id": api_key_id,
            "period_id": event["period_id"],
        },
        vals=_aggregate_values(event),
        updated_at=event["timestamp"],
    )


def _apply_route_aggregate(table: Any, event: ApiUsageEvent) -> None:
    _apply_generic_counter_row(
        table,
        key={"PK": f"USER#{event['user_sub']}", "SK": f"API_USAGE#ROUTE#{event['route_id']}#PERIOD#{event['period_id']}"},
        attrs={
            "entity_type": "api_route_usage_period_totals",
            "user_sub": event["user_sub"],
            "route_id": event["route_id"],
            "period_id": event["period_id"],
            "unit_price_micros": int(event["unit_price_micros"]),
        },
        vals=_aggregate_values(event),
        updated_at=event["timestamp"],
    )

def _apply_product_aggregate(table: Any, event: ApiUsageEvent) -> None:
    _apply_generic_counter_row(
        table,
        key={"PK": f"USER#{event['user_sub']}", "SK": f"API_USAGE#PRODUCT#{event['product']}#PERIOD#{event['period_id']}"},
        attrs={
            "entity_type": "api_product_usage_period_totals",
            "user_sub": event["user_sub"],
            "product": event["product"],
            "period_id": event["period_id"],
        },
        vals=_aggregate_values(event),
        updated_at=event["timestamp"],
    )


def _apply_daily_aggregate(table: Any, event: ApiUsageEvent) -> None:
    day_utc = str(event["timestamp"])[:10]
    _apply_generic_counter_row(
        table,
        key={"PK": f"USER#{event['user_sub']}", "SK": f"API_USAGE#DAY#{day_utc}"},
        attrs={
            "entity_type": "api_usage_daily",
            "user_sub": event["user_sub"],
            "day_utc": day_utc,
            "period_id": day_utc[:7],
        },
        vals=_aggregate_values(event),
        updated_at=event["timestamp"],
    )


def _apply_api_usage_aggregates(table: Any, event: ApiUsageEvent) -> None:
    _apply_period_aggregate(table, event)
    _apply_key_aggregate(table, event)
    _apply_route_aggregate(table, event)
    _apply_product_aggregate(table, event)
    _apply_daily_aggregate(table, event)


def record_api_usage_event_and_aggregates(table: Any, event: ApiUsageEvent) -> bool:
    key = {"PK": f"USER#{event['user_sub']}", "SK": f"API_USAGE#EVENT#{event['event_id']}"}
    try:
        table.put_item(
            Item={
                **key,
                "entity_type": "api_usage_event",
                **event,
                "GSI_PERIOD_PK": f"PERIOD#{event['period_id']}",
                "GSI_PERIOD_SK": f"USER#{event['user_sub']}#TS#{event['timestamp']}#EVT#{event['event_id']}",
                "GSI_API_KEY_PK": f"APIKEY#{event['api_key_id'] or 'NONE'}",
                "GSI_API_KEY_SK": f"PERIOD#{event['period_id']}#TS#{event['timestamp']}#EVT#{event['event_id']}",
                "GSI_ROUTE_PK": f"ROUTE#{event['route_id']}",
                "GSI_ROUTE_SK": f"PERIOD#{event['period_id']}#TS#{event['timestamp']}#EVT#{event['event_id']}",
                "GSI_PRODUCT_PK": f"PRODUCT#{event['product']}",
                "GSI_PRODUCT_SK": f"PERIOD#{event['period_id']}#TS#{event['timestamp']}#EVT#{event['event_id']}",
                "aggregates_applied": False,
                "ttl_epoch": _ttl_epoch_for_days(getattr(S, "api_usage_event_retention_days", 365)),
            },
            ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
        )
    except Exception as exc:
        if not _is_conditional_check_failed(exc):
            record_api_usage_ingest_event("error")
            raise
        record_api_usage_ingest_event("duplicate")

    item = table.get_item(Key=key).get("Item") or {}
    if bool(item.get("aggregates_applied")):
        record_api_usage_ingest_event("duplicate")
        return False

    _apply_api_usage_aggregates(table, event)
    table.update_item(Key=key, UpdateExpression="SET aggregates_applied = :t", ExpressionAttributeValues={":t": True})
    try:
        ts = datetime.fromisoformat(str(event.get("timestamp") or ""))
        record_api_usage_ingest_lag((datetime.now(timezone.utc) - ts).total_seconds())
    except Exception:
        pass
    record_api_usage_ingest_event("success")
    return True


def query_api_usage_events_by_user_period(table: Any, *, user_sub: str, period_id: str, limit: int = 200) -> list[dict[str, Any]]:
    resp = table.query(
        KeyConditionExpression=Key("PK").eq(f"USER#{user_sub}") & Key("SK").begins_with("API_USAGE#EVENT#auev_"),
        Limit=max(1, min(int(limit), 1000)),
    )
    items = [it for it in resp.get("Items", []) if str(it.get("period_id")) == str(period_id)]
    items.sort(key=lambda x: str(x.get("timestamp") or ""))
    return items


def query_api_usage_events_by_period(table: Any, *, period_id: str, limit: int = 200) -> list[dict[str, Any]]:
    resp = table.query(
        IndexName="GSI_PERIOD",
        KeyConditionExpression=Key("GSI_PERIOD_PK").eq(f"PERIOD#{period_id}"),
        Limit=max(1, min(int(limit), 1000)),
    )
    return sorted(resp.get("Items", []), key=lambda x: str(x.get("GSI_PERIOD_SK") or ""))


def query_api_usage_events_by_api_key(table: Any, *, api_key_id: str, period_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
    resp = table.query(
        IndexName="GSI_API_KEY",
        KeyConditionExpression=Key("GSI_API_KEY_PK").eq(f"APIKEY#{api_key_id or 'NONE'}"),
        Limit=max(1, min(int(limit), 1000)),
    )
    items = resp.get("Items", [])
    if period_id:
        items = [it for it in items if str(it.get("period_id")) == str(period_id)]
    return sorted(items, key=lambda x: str(x.get("GSI_API_KEY_SK") or ""))


def query_api_usage_events_by_route(table: Any, *, route_id: str, period_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
    resp = table.query(
        IndexName="GSI_ROUTE",
        KeyConditionExpression=Key("GSI_ROUTE_PK").eq(f"ROUTE#{route_id}"),
        Limit=max(1, min(int(limit), 1000)),
    )
    items = resp.get("Items", [])
    if period_id:
        items = [it for it in items if str(it.get("period_id")) == str(period_id)]
    return sorted(items, key=lambda x: str(x.get("GSI_ROUTE_SK") or ""))


def query_api_key_period_totals(table: Any, *, user_sub: str, period_id: str) -> list[ApiUsageKeyPeriodTotals]:
    resp = table.query(
        KeyConditionExpression=Key("PK").eq(f"USER#{user_sub}") & Key("SK").begins_with("API_USAGE#KEY#"),
        Limit=2000,
    )
    items = [it for it in resp.get("Items", []) if str(it.get("period_id")) == str(period_id)]
    return [
        {
            "user_sub": user_sub,
            "api_key_id": str(it.get("api_key_id") or "NONE"),
            "period_id": period_id,
            "calls_total": int(it.get("calls_total") or 0),
            "billable_calls_total": int(it.get("billable_calls_total") or 0),
            "request_units_total": int(it.get("request_units_total") or 0),
            "cost_subtotal_micros": int(it.get("cost_subtotal_micros") or 0),
        }
        for it in items
    ]




def get_api_key_usage_period_totals(table: Any, *, user_sub: str, key_id: str, period_id: str) -> ApiUsageKeyPeriodTotals:
    item = table.get_item(Key={"PK": f"USER#{user_sub}", "SK": f"API_USAGE#KEY#{key_id}#PERIOD#{period_id}"}).get("Item") or {}
    return {
        "user_sub": user_sub,
        "api_key_id": key_id,
        "period_id": period_id,
        "calls_total": int(item.get("calls_total") or 0),
        "billable_calls_total": int(item.get("billable_calls_total") or 0),
        "request_units_total": int(item.get("request_units_total") or 0),
        "cost_subtotal_micros": int(item.get("cost_subtotal_micros") or 0),
    }

def query_api_route_period_totals(table: Any, *, user_sub: str, period_id: str) -> list[ApiUsageRoutePeriodTotals]:
    resp = table.query(
        KeyConditionExpression=Key("PK").eq(f"USER#{user_sub}") & Key("SK").begins_with("API_USAGE#ROUTE#"),
        Limit=5000,
    )
    items = [it for it in resp.get("Items", []) if str(it.get("period_id")) == str(period_id)]
    return [
        {
            "user_sub": user_sub,
            "route_id": str(it.get("route_id") or ""),
            "unit_price_micros": int(it.get("unit_price_micros") or 0),
            "period_id": period_id,
            "calls_total": int(it.get("calls_total") or 0),
            "billable_calls_total": int(it.get("billable_calls_total") or 0),
            "request_units_total": int(it.get("request_units_total") or 0),
            "cost_subtotal_micros": int(it.get("cost_subtotal_micros") or 0),
        }
        for it in items
    ]




def _encode_page_cursor(offset: int) -> str:
    payload = json.dumps({"offset": max(0, int(offset))}, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii")


def _decode_page_cursor(cursor: str | None) -> int:
    if not cursor:
        return 0
    try:
        data = base64.urlsafe_b64decode(str(cursor).encode("ascii")).decode("utf-8")
        parsed = json.loads(data)
        return max(0, int(parsed.get("offset", 0)))
    except Exception:
        raise HTTPException(400, "invalid cursor")


def _apply_breakdown_query(
    rows: list[dict[str, Any]],
    *,
    search: str | None,
    sort_by: str,
    order: str,
    limit: int,
    cursor: str | None,
) -> dict[str, Any]:
    needle = (search or "").strip().lower()
    if needle:
        rows = [r for r in rows if needle in str(r.get("route_id") or r.get("api_key_id") or "").lower()]

    reverse = (order or "desc").lower() != "asc"
    key_fn = {
        "calls_total": lambda r: int(r.get("calls_total") or 0),
        "cost_subtotal_micros": lambda r: int(r.get("cost_subtotal_micros") or 0),
        "request_units_total": lambda r: int(r.get("request_units_total") or 0),
    }.get(sort_by, lambda r: int(r.get("cost_subtotal_micros") or 0))
    rows = sorted(rows, key=key_fn, reverse=reverse)

    page_size = max(1, min(int(limit or 100), 500))
    offset = _decode_page_cursor(cursor)
    page = rows[offset: offset + page_size]
    next_offset = offset + page_size
    return {
        "items": page,
        "next_cursor": _encode_page_cursor(next_offset) if next_offset < len(rows) else None,
        "count": len(page),
        "total": len(rows),
    }


def aggregate_leaderboard(
    table: Any,
    *,
    period_id: str,
    dimension: str,
    metric: str,
    top_n: int,
    user_sub: str | None = None,
) -> dict[str, Any]:
    """PLT-002: Platform-wide or per-user leaderboard of top API consumers/endpoints.

    Args:
        table: DynamoDB Table handle for api_usage_events.
        period_id: YYYY-MM string for the billing period.
        dimension: "consumers" (per api_key_id) or "endpoints" (per route_id).
        metric: sort metric — "calls_total", "cost_subtotal_micros", or "request_units_total".
        top_n: max items to return (already clamped by caller).
        user_sub: if set, scope to this user only; if None, platform-wide scan.
    """
    if table is None:
        return {"items": [], "next_cursor": None, "count": 0, "total": 0, "total_rows_scanned": 0}

    if user_sub is not None:
        # Per-user query — use existing helpers, fast path
        if dimension == "consumers":
            rows = query_api_key_period_totals(table, user_sub=user_sub, period_id=period_id)
        else:
            rows = query_api_route_period_totals(table, user_sub=user_sub, period_id=period_id)
        result = _apply_breakdown_query(rows, search=None, sort_by=metric, order="desc", limit=top_n, cursor=None)
        result["total_rows_scanned"] = len(rows)
        return result

    # Platform-wide scan — merge across all user partitions
    if dimension == "consumers":
        target_entity_type = "api_key_usage_period_totals"
        group_key = "api_key_id"
    else:
        target_entity_type = "api_route_usage_period_totals"
        group_key = "route_id"

    merged: dict[str, dict[str, Any]] = {}
    rows_scanned = 0
    scan_kwargs: dict[str, Any] = {
        "FilterExpression": Attr("entity_type").eq(target_entity_type),
    }
    while True:
        resp = table.scan(**scan_kwargs)
        for item in resp.get("Items", []):
            rows_scanned += 1
            if str(item.get("period_id")) != str(period_id):
                continue
            key_val = str(item.get(group_key) or "")
            if key_val not in merged:
                merged[key_val] = {
                    group_key: key_val,
                    "user_sub": "",  # cross-user sum
                    "calls_total": 0,
                    "billable_calls_total": 0,
                    "request_units_total": 0,
                    "cost_subtotal_micros": 0,
                    "unit_price_micros": 0,
                }
            merged[key_val]["calls_total"] += int(item.get("calls_total") or 0)
            merged[key_val]["billable_calls_total"] += int(item.get("billable_calls_total") or 0)
            merged[key_val]["request_units_total"] += int(item.get("request_units_total") or 0)
            merged[key_val]["cost_subtotal_micros"] += int(item.get("cost_subtotal_micros") or 0)
            if dimension == "endpoints":
                # unit_price_micros is route-level; take last-seen value
                merged[key_val]["unit_price_micros"] = int(item.get("unit_price_micros") or 0)
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        scan_kwargs["ExclusiveStartKey"] = lek

    flat_rows = list(merged.values())
    result = _apply_breakdown_query(flat_rows, search=None, sort_by=metric, order="desc", limit=top_n, cursor=None)
    result["total_rows_scanned"] = rows_scanned
    return result


def list_api_usage_key_breakdown(
    table: Any,
    *,
    user_sub: str,
    period_id: str,
    search: str | None = None,
    sort_by: str = "cost_subtotal_micros",
    order: str = "desc",
    limit: int = 100,
    cursor: str | None = None,
) -> dict[str, Any]:
    return _apply_breakdown_query(
        query_api_key_period_totals(table, user_sub=user_sub, period_id=period_id),
        search=search,
        sort_by=sort_by,
        order=order,
        limit=limit,
        cursor=cursor,
    )


def list_api_usage_route_breakdown(
    table: Any,
    *,
    user_sub: str,
    period_id: str,
    search: str | None = None,
    sort_by: str = "cost_subtotal_micros",
    order: str = "desc",
    limit: int = 100,
    cursor: str | None = None,
) -> dict[str, Any]:
    return _apply_breakdown_query(
        query_api_route_period_totals(table, user_sub=user_sub, period_id=period_id),
        search=search,
        sort_by=sort_by,
        order=order,
        limit=limit,
        cursor=cursor,
    )

def query_api_usage_daily(table: Any, *, user_sub: str, from_day: str, to_day: str) -> dict[str, Any]:
    if from_day > to_day:
        raise HTTPException(400, "invalid daily usage range")
    resp = table.query(
        KeyConditionExpression=Key("PK").eq(f"USER#{user_sub}") & Key("SK").begins_with("API_USAGE#DAY#"),
        Limit=5000,
    )
    items = []
    for it in resp.get("Items", []):
        day = str(it.get("day_utc") or "")
        if not day or day < from_day or day > to_day:
            continue
        items.append(
            {
                "day_utc": day,
                "period_id": str(it.get("period_id") or day[:7]),
                "calls_total": int(it.get("calls_total") or 0),
                "billable_calls_total": int(it.get("billable_calls_total") or 0),
                "request_units_total": int(it.get("request_units_total") or 0),
                "cost_subtotal_micros": int(it.get("cost_subtotal_micros") or 0),
            }
        )
    items.sort(key=lambda x: x["day_utc"])
    return {"items": items}


def get_api_usage_period_totals(table: Any, *, user_sub: str, period_id: str) -> ApiUsagePeriodTotals:
    item = table.get_item(Key={"PK": f"USER#{user_sub}", "SK": f"API_USAGE#PERIOD#{period_id}"}).get("Item") or {}
    return {
        "user_sub": user_sub,
        "period_id": period_id,
        "calls_total": int(item.get("calls_total") or 0),
        "billable_calls_total": int(item.get("billable_calls_total") or 0),
        "request_units_total": int(item.get("request_units_total") or 0),
        "cost_subtotal_micros": int(item.get("cost_subtotal_micros") or 0),
    }




def get_api_usage_summary_for_period(table: Any, *, user_sub: str, period_id: str) -> dict[str, Any]:
    if table is None:
        totals: ApiUsagePeriodTotals = {
            "user_sub": user_sub,
            "period_id": period_id,
            "calls_total": 0,
            "billable_calls_total": 0,
            "request_units_total": 0,
            "cost_subtotal_micros": 0,
        }
    else:
        totals = get_api_usage_period_totals(table, user_sub=user_sub, period_id=period_id)

    calls_limit = _quota_limit_int(getattr(S, "api_usage_account_monthly_calls_limit", 0))
    spend_limit = _quota_limit_int(getattr(S, "api_usage_account_monthly_spend_micros_limit", 0))

    calls_used = int(totals["calls_total"])
    spend_used = int(totals["cost_subtotal_micros"])

    return {
        "period": period_id,
        "totals": {
            "calls_total": calls_used,
            "billable_calls_total": int(totals["billable_calls_total"]),
            "request_units_total": int(totals["request_units_total"]),
            "cost_subtotal_micros": spend_used,
            "estimated_cost_micros": spend_used,
        },
        "limits": {
            "monthly_calls_limit": calls_limit,
            "monthly_spend_micros_limit": spend_limit,
        },
        "remaining": {
            "monthly_calls_remaining": max(0, calls_limit - calls_used) if calls_limit > 0 else None,
            "monthly_spend_micros_remaining": max(0, spend_limit - spend_used) if spend_limit > 0 else None,
        },
    }

def recompute_period_totals_from_events(events: list[dict[str, Any]]) -> ApiUsagePeriodTotals:
    out: ApiUsagePeriodTotals = {
        "user_sub": str(events[0].get("user_sub") or "") if events else "",
        "period_id": str(events[0].get("period_id") or "") if events else "",
        "calls_total": 0,
        "billable_calls_total": 0,
        "request_units_total": 0,
        "cost_subtotal_micros": 0,
    }
    for event in events:
        out["calls_total"] += 1
        out["billable_calls_total"] += 1 if bool(event.get("billable")) else 0
        out["request_units_total"] += int(event.get("request_units") or 0)
        out["cost_subtotal_micros"] += int(event.get("cost_micros") or 0)
    return out




def build_api_billing_usage_snapshot_item(
    *,
    user_sub: str,
    period_id: str,
    version: int,
    status: str,
    totals: ApiUsagePeriodTotals,
    by_key: list[ApiUsageKeyPeriodTotals],
    by_route: list[ApiUsageRoutePeriodTotals],
    source_event_count: int,
    now_iso: str | None = None,
) -> dict[str, Any]:
    if version < 1:
        raise HTTPException(400, "snapshot version must be >= 1")
    if status not in {"draft", "finalized", "invoiced"}:
        raise HTTPException(400, "invalid snapshot status")
    ts = now_iso or datetime.now(timezone.utc).isoformat()
    return {
        "PK": f"USER#{user_sub}",
        "SK": f"API_USAGE#SNAPSHOT#{period_id}#V{version:04d}",
        "entity_type": "api_billing_usage_snapshot",
        "user_sub": user_sub,
        "period_id": period_id,
        "version": int(version),
        "status": status,
        "created_at": ts,
        "finalized_at": ts if status == "finalized" else None,
        "totals": totals,
        "by_key": by_key,
        "by_route": by_route,
        "source_event_count": int(source_event_count),
    }


def _latest_api_snapshot_version(table: Any, *, user_sub: str, period_id: str) -> int:
    resp = table.query(
        KeyConditionExpression=Key("PK").eq(f"USER#{user_sub}") & Key("SK").begins_with(f"API_USAGE#SNAPSHOT#{period_id}#V"),
        Limit=200,
    )
    max_ver = 0
    for it in resp.get("Items", []):
        max_ver = max(max_ver, int(it.get("version") or 0))
    return max_ver


def create_api_billing_usage_snapshot(
    table: Any,
    *,
    user_sub: str,
    period_id: str,
    status: str = "draft",
    version: int | None = None,
) -> ApiBillingUsageSnapshot:
    events = _scan_api_usage_events(table, user_sub=user_sub, period_id=period_id)
    totals = recompute_period_totals_from_events(events)
    _, by_key_map, by_route_map, _ = _accumulate_expected(events)

    by_key: list[ApiUsageKeyPeriodTotals] = []
    for (uid, key_id, pid), vals in sorted(by_key_map.items()):
        if uid != user_sub or pid != period_id:
            continue
        by_key.append({"user_sub": uid, "api_key_id": key_id, "period_id": pid, **vals})

    by_route: list[ApiUsageRoutePeriodTotals] = []
    for (uid, route_id, pid), vals in sorted(by_route_map.items()):
        if uid != user_sub or pid != period_id:
            continue
        by_route.append({"user_sub": uid, "route_id": route_id, "period_id": pid, **vals})

    ver = int(version or (_latest_api_snapshot_version(table, user_sub=user_sub, period_id=period_id) + 1))
    key = {"PK": f"USER#{user_sub}", "SK": f"API_USAGE#SNAPSHOT#{period_id}#V{ver:04d}"}
    existing = table.get_item(Key=key).get("Item") or {}
    if existing and str(existing.get("status") or "") in {"finalized", "invoiced"}:
        raise HTTPException(409, "finalized snapshot is immutable")

    item = build_api_billing_usage_snapshot_item(
        user_sub=user_sub,
        period_id=period_id,
        version=ver,
        status=status,
        totals=totals,
        by_key=by_key,
        by_route=by_route,
        source_event_count=len(events),
    )
    if existing:
        item["created_at"] = existing.get("created_at") or item["created_at"]
    table.put_item(Item=item)
    return {
        "user_sub": user_sub,
        "period_id": period_id,
        "version": ver,
        "status": status,
        "finalized_at": item.get("finalized_at"),
        "totals": totals,
        "by_key": by_key,
        "by_route": by_route,
        "source_event_count": len(events),
    }


def finalize_api_billing_usage_snapshot(table: Any, *, user_sub: str, period_id: str, version: int | None = None) -> ApiBillingUsageSnapshot:
    if version is None:
        version = _latest_api_snapshot_version(table, user_sub=user_sub, period_id=period_id)
        if version < 1:
            version = 1
    key = {"PK": f"USER#{user_sub}", "SK": f"API_USAGE#SNAPSHOT#{period_id}#V{int(version):04d}"}
    existing = table.get_item(Key=key).get("Item") or {}
    if existing and str(existing.get("status") or "") in {"finalized", "invoiced"}:
        record_api_usage_snapshot_finalize("already_finalized")
        return {
            "user_sub": user_sub,
            "period_id": period_id,
            "version": int(existing.get("version") or version),
            "status": str(existing.get("status") or "finalized"),
            "finalized_at": existing.get("finalized_at"),
            "totals": existing.get("totals") or {},
            "by_key": existing.get("by_key") or [],
            "by_route": existing.get("by_route") or [],
            "source_event_count": int(existing.get("source_event_count") or 0),
        }
    try:
        out = create_api_billing_usage_snapshot(table, user_sub=user_sub, period_id=period_id, version=int(version), status="finalized")
        record_api_usage_snapshot_finalize("success")
        return out
    except Exception:
        record_api_usage_snapshot_finalize("error")
        raise



def _sorted_billable_events_for_period(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    filtered = [ev for ev in events if bool(ev.get("billable")) and int(ev.get("request_units") or 0) > 0]
    return sorted(filtered, key=lambda ev: (str(ev.get("timestamp") or ""), str(ev.get("event_id") or "")))


def calculate_period_charges_from_events(*, period_id: str, events: list[dict[str, Any]]) -> ApiPeriodChargeResult:
    ordered = _sorted_billable_events_for_period(events)
    counters: dict[tuple[str, str], int] = {}
    line_map: dict[tuple[str, str], ApiChargeLineItem] = {}
    catalog = load_api_pricing_catalog()

    user_sub = str(ordered[0].get("user_sub") or "") if ordered else ""

    for ev in ordered:
        route_id = str(ev.get("route_id") or "")
        pricing_version = str(ev.get("pricing_catalog_version") or "")
        key = (route_id, pricing_version)
        counters[key] = counters.get(key, 0) + 1
        call_no = counters[key]

        ts = datetime.fromisoformat(str(ev.get("timestamp") or datetime.now(timezone.utc).isoformat()))
        priced = resolve_route_pricing(
            route_id=route_id,
            event_ts=int(ts.timestamp()),
            call_number_in_period=call_no,
            pricing_catalog_version=pricing_version or None,
            catalog=catalog,
        )
        unit = int(priced.unit_price_micros)

        if key not in line_map:
            line_map[key] = {
                "route_id": route_id,
                "pricing_catalog_version": priced.pricing_catalog_version,
                "quantity": 0,
                "subtotal_micros": 0,
                "unit_prices_micros": [],
            }
        line = line_map[key]
        line["quantity"] += 1
        line["subtotal_micros"] += unit
        line["unit_prices_micros"].append(unit)

    line_items = sorted(line_map.values(), key=lambda x: (x["route_id"], x["pricing_catalog_version"]))
    total = sum(int(it["subtotal_micros"]) for it in line_items)
    return {
        "user_sub": user_sub,
        "period_id": period_id,
        "total_charge_micros": int(total),
        "line_items": line_items,
        "event_count": len(ordered),
    }


def calculate_period_charges(table: Any, *, user_sub: str, period_id: str) -> ApiPeriodChargeResult:
    events = _scan_api_usage_events(table, user_sub=user_sub, period_id=period_id)
    out = calculate_period_charges_from_events(period_id=period_id, events=events)
    out["user_sub"] = user_sub
    return out

def _scan_api_usage_events(table: Any, *, user_sub: str | None = None, period_id: str | None = None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if user_sub:
        resp = table.query(
            KeyConditionExpression=Key("PK").eq(f"USER#{user_sub}") & Key("SK").begins_with("API_USAGE#EVENT#auev_"),
            Limit=5000,
        )
        for it in resp.get("Items", []):
            if period_id and str(it.get("period_id")) != period_id:
                continue
            out.append(it)
        return out

    resp = table.scan(Limit=5000)
    for it in resp.get("Items", []):
        if it.get("entity_type") != "api_usage_event":
            continue
        if period_id and str(it.get("period_id")) != period_id:
            continue
        out.append(it)
    return out


def _accumulate_expected(events: list[dict[str, Any]]) -> tuple[dict, dict, dict, dict]:
    period: dict[tuple[str, str], dict[str, int]] = {}
    by_key: dict[tuple[str, str, str], dict[str, int]] = {}
    by_route: dict[tuple[str, str, str], dict[str, int]] = {}
    daily: dict[tuple[str, str], dict[str, int]] = {}

    for ev in events:
        user_sub = str(ev.get("user_sub") or "")
        period_id = str(ev.get("period_id") or "")
        route_id = str(ev.get("route_id") or "")
        api_key_id = str(ev.get("api_key_id") or "NONE")
        day = str(ev.get("timestamp") or "")[:10]
        if not user_sub or not period_id or not route_id:
            continue

        inc_calls = 1
        inc_bill = 1 if bool(ev.get("billable")) else 0
        inc_units = int(ev.get("request_units") or 0)
        inc_cost = int(ev.get("cost_micros") or 0)

        pkey = (user_sub, period_id)
        period.setdefault(pkey, {"calls_total": 0, "billable_calls_total": 0, "request_units_total": 0, "cost_subtotal_micros": 0})
        period[pkey]["calls_total"] += inc_calls
        period[pkey]["billable_calls_total"] += inc_bill
        period[pkey]["request_units_total"] += inc_units
        period[pkey]["cost_subtotal_micros"] += inc_cost

        kkey = (user_sub, api_key_id, period_id)
        by_key.setdefault(kkey, {"calls_total": 0, "billable_calls_total": 0, "request_units_total": 0, "cost_subtotal_micros": 0})
        by_key[kkey]["calls_total"] += inc_calls
        by_key[kkey]["billable_calls_total"] += inc_bill
        by_key[kkey]["request_units_total"] += inc_units
        by_key[kkey]["cost_subtotal_micros"] += inc_cost

        rkey = (user_sub, route_id, period_id)
        by_route.setdefault(rkey, {"calls_total": 0, "billable_calls_total": 0, "request_units_total": 0, "cost_subtotal_micros": 0, "unit_price_micros": int(ev.get("unit_price_micros") or 0)})
        by_route[rkey]["calls_total"] += inc_calls
        by_route[rkey]["billable_calls_total"] += inc_bill
        by_route[rkey]["request_units_total"] += inc_units
        by_route[rkey]["cost_subtotal_micros"] += inc_cost
        by_route[rkey]["unit_price_micros"] = int(ev.get("unit_price_micros") or by_route[rkey]["unit_price_micros"])

        if day:
            dkey = (user_sub, day)
            daily.setdefault(dkey, {"calls_total": 0, "billable_calls_total": 0, "request_units_total": 0, "cost_subtotal_micros": 0})
            daily[dkey]["calls_total"] += inc_calls
            daily[dkey]["billable_calls_total"] += inc_bill
            daily[dkey]["request_units_total"] += inc_units
            daily[dkey]["cost_subtotal_micros"] += inc_cost

    return period, by_key, by_route, daily


def recompute_api_usage_aggregates(*, table: Any, scope: str, user_sub: str | None = None, period_id: str | None = None, apply: bool = True) -> dict[str, Any]:
    if scope not in {"user", "all"}:
        raise HTTPException(400, "invalid recompute scope")
    if scope == "user" and not user_sub:
        raise HTTPException(400, "user_sub required for user scope")

    events = _scan_api_usage_events(table, user_sub=user_sub if scope == "user" else None, period_id=period_id)
    period, by_key, by_route, daily = _accumulate_expected(events)
    drift_report = {"period": 0, "key": 0, "route": 0, "daily": 0}

    for (uid, p), vals in period.items():
        stored = table.get_item(Key={"PK": f"USER#{uid}", "SK": f"API_USAGE#PERIOD#{p}"}).get("Item") or {}
        if any(int(stored.get(k) or 0) != int(vals[k]) for k in ("calls_total", "billable_calls_total", "request_units_total", "cost_subtotal_micros")):
            drift_report["period"] += 1
        if apply:
            table.put_item(Item={"PK": f"USER#{uid}", "SK": f"API_USAGE#PERIOD#{p}", "entity_type": "api_usage_period_totals", "user_sub": uid, "period_id": p, **vals, "updated_at": datetime.now(timezone.utc).isoformat()})

    for (uid, key_id, p), vals in by_key.items():
        stored = table.get_item(Key={"PK": f"USER#{uid}", "SK": f"API_USAGE#KEY#{key_id}#PERIOD#{p}"}).get("Item") or {}
        if any(int(stored.get(k) or 0) != int(vals[k]) for k in ("calls_total", "billable_calls_total", "request_units_total", "cost_subtotal_micros")):
            drift_report["key"] += 1
        if apply:
            table.put_item(Item={"PK": f"USER#{uid}", "SK": f"API_USAGE#KEY#{key_id}#PERIOD#{p}", "entity_type": "api_key_usage_period_totals", "user_sub": uid, "api_key_id": key_id, "period_id": p, **vals, "updated_at": datetime.now(timezone.utc).isoformat()})

    for (uid, route_id, p), vals in by_route.items():
        stored = table.get_item(Key={"PK": f"USER#{uid}", "SK": f"API_USAGE#ROUTE#{route_id}#PERIOD#{p}"}).get("Item") or {}
        if any(int(stored.get(k) or 0) != int(vals[k]) for k in ("calls_total", "billable_calls_total", "request_units_total", "cost_subtotal_micros", "unit_price_micros")):
            drift_report["route"] += 1
        if apply:
            table.put_item(Item={"PK": f"USER#{uid}", "SK": f"API_USAGE#ROUTE#{route_id}#PERIOD#{p}", "entity_type": "api_route_usage_period_totals", "user_sub": uid, "route_id": route_id, "period_id": p, **vals, "updated_at": datetime.now(timezone.utc).isoformat()})

    for (uid, day), vals in daily.items():
        stored = table.get_item(Key={"PK": f"USER#{uid}", "SK": f"API_USAGE#DAY#{day}"}).get("Item") or {}
        if any(int(stored.get(k) or 0) != int(vals[k]) for k in ("calls_total", "billable_calls_total", "request_units_total", "cost_subtotal_micros")):
            drift_report["daily"] += 1
        if apply:
            table.put_item(Item={"PK": f"USER#{uid}", "SK": f"API_USAGE#DAY#{day}", "entity_type": "api_usage_daily", "user_sub": uid, "day_utc": day, "period_id": day[:7], **vals, "updated_at": datetime.now(timezone.utc).isoformat()})

    for area, rows in drift_report.items():
        record_api_usage_reconciliation_drift(area=area, rows=int(rows))

    return {
        "scope": scope,
        "user_sub": user_sub,
        "period_id": period_id,
        "events_scanned": len(events),
        "period_rows": len(period),
        "key_rows": len(by_key),
        "route_rows": len(by_route),
        "daily_rows": len(daily),
        "drift_report": drift_report,
        "applied": apply,
    }






def generate_api_invoice_line_items_for_snapshot(
    table: Any,
    *,
    user_sub: str,
    period_id: str,
    snapshot_version: int,
    include_key_sublines: bool = False,
) -> dict[str, Any]:
    if snapshot_version < 1:
        raise HTTPException(400, "snapshot_version must be >= 1")
    snapshot_sk = f"API_USAGE#SNAPSHOT#{period_id}#V{snapshot_version:04d}"
    snap = table.get_item(Key={"PK": f"USER#{user_sub}", "SK": snapshot_sk}).get("Item") or {}
    if not snap:
        raise HTTPException(404, "snapshot not found")
    if str(snap.get("status") or "") not in {"finalized", "invoiced"}:
        raise HTTPException(409, "snapshot must be finalized before invoicing")

    route_items = []
    total_micros = 0
    for row in (snap.get("by_route") or []):
        subtotal = int(row.get("cost_subtotal_micros") or 0)
        total_micros += subtotal
        route_items.append(
            {
                "line_type": "route_total",
                "route_id": str(row.get("route_id") or ""),
                "quantity": int(row.get("request_units_total") or row.get("calls_total") or 0),
                "subtotal_micros": subtotal,
                "snapshot_sk": snapshot_sk,
            }
        )

    key_items = []
    if include_key_sublines:
        for row in (snap.get("by_key") or []):
            key_items.append(
                {
                    "line_type": "api_key_subline",
                    "api_key_id": str(row.get("api_key_id") or "NONE"),
                    "quantity": int(row.get("request_units_total") or row.get("calls_total") or 0),
                    "subtotal_micros": int(row.get("cost_subtotal_micros") or 0),
                    "snapshot_sk": snapshot_sk,
                }
            )

    invoice_sk = f"API_USAGE#INVOICE#{period_id}#V{snapshot_version:04d}"
    record = {
        "PK": f"USER#{user_sub}",
        "SK": invoice_sk,
        "entity_type": "api_usage_invoice_lines",
        "user_sub": user_sub,
        "period_id": period_id,
        "snapshot_version": int(snapshot_version),
        "snapshot_sk": snapshot_sk,
        "line_items": route_items,
        "key_sublines": key_items,
        "total_amount_micros": int(total_micros),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    table.put_item(Item=record)
    return {
        "user_sub": user_sub,
        "period_id": period_id,
        "snapshot_version": int(snapshot_version),
        "snapshot_sk": snapshot_sk,
        "invoice_sk": invoice_sk,
        "line_items": route_items,
        "key_sublines": key_items,
        "total_amount_micros": int(total_micros),
    }


def create_api_billing_adjustment(
    table: Any,
    *,
    user_sub: str,
    period_id: str,
    snapshot_version: int,
    adjustment_type: str,
    amount_micros: int,
    reason: str,
    reference_id: str | None = None,
) -> dict[str, Any]:
    if snapshot_version < 1:
        raise HTTPException(400, "snapshot_version must be >= 1")
    if adjustment_type not in {"credit", "debit"}:
        raise HTTPException(400, "adjustment_type must be credit or debit")
    amt = max(0, int(amount_micros or 0))
    if amt <= 0:
        raise HTTPException(400, "amount_micros must be > 0")

    snapshot_sk = f"API_USAGE#SNAPSHOT#{period_id}#V{snapshot_version:04d}"
    snap = table.get_item(Key={"PK": f"USER#{user_sub}", "SK": snapshot_sk}).get("Item") or {}
    if not snap:
        raise HTTPException(404, "snapshot not found")

    seed = "|".join([str(user_sub), str(period_id), str(snapshot_version), str(adjustment_type), str(amt), str(reason), str(reference_id or ""), datetime.now(timezone.utc).isoformat()])
    adj_id = f"adj_{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:12]}"
    adj_sk = f"API_USAGE#ADJUSTMENT#{period_id}#V{snapshot_version:04d}#{adj_id}"
    sign = -1 if adjustment_type == "credit" else 1
    rec = {
        "PK": f"USER#{user_sub}",
        "SK": adj_sk,
        "entity_type": "api_usage_billing_adjustment",
        "user_sub": user_sub,
        "period_id": period_id,
        "snapshot_version": int(snapshot_version),
        "snapshot_sk": snapshot_sk,
        "adjustment_id": adj_id,
        "adjustment_type": adjustment_type,
        "amount_micros": amt,
        "signed_amount_micros": sign * amt,
        "reason": str(reason or "")[:512],
        "reference_id": reference_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    table.put_item(Item=rec)
    return {
        "ok": True,
        "adjustment_id": adj_id,
        "snapshot_version": int(snapshot_version),
        "snapshot_sk": snapshot_sk,
        "signed_amount_micros": sign * amt,
        "reason": rec["reason"],
        "reference_id": reference_id,
    }


def export_api_billing_reconciliation_report(
    table: Any,
    *,
    user_sub: str,
    period_id: str,
    snapshot_version: int,
) -> dict[str, Any]:
    snapshot_sk = f"API_USAGE#SNAPSHOT#{period_id}#V{snapshot_version:04d}"
    invoice_sk = f"API_USAGE#INVOICE#{period_id}#V{snapshot_version:04d}"
    snap = table.get_item(Key={"PK": f"USER#{user_sub}", "SK": snapshot_sk}).get("Item") or {}
    if not snap:
        raise HTTPException(404, "snapshot not found")
    invoice = table.get_item(Key={"PK": f"USER#{user_sub}", "SK": invoice_sk}).get("Item") or {}

    q = table.query(
        KeyConditionExpression=Key("PK").eq(f"USER#{user_sub}") & Key("SK").begins_with(f"API_USAGE#ADJUSTMENT#{period_id}#V{snapshot_version:04d}#"),
        Limit=2000,
    )
    adjustments = q.get("Items", [])
    adjustments_total = sum(int(it.get("signed_amount_micros") or 0) for it in adjustments)

    snapshot_total = int((snap.get("totals") or {}).get("cost_subtotal_micros") or 0)
    invoice_total = int(invoice.get("total_amount_micros") or 0)
    reconciled_total = invoice_total + adjustments_total

    return {
        "user_sub": user_sub,
        "period_id": period_id,
        "snapshot_version": int(snapshot_version),
        "snapshot_sk": snapshot_sk,
        "invoice_sk": invoice_sk,
        "snapshot_total_micros": snapshot_total,
        "invoice_total_micros": invoice_total,
        "adjustments_total_micros": adjustments_total,
        "reconciled_total_micros": reconciled_total,
        "variance_vs_snapshot_micros": reconciled_total - snapshot_total,
        "adjustments": [
            {
                "adjustment_id": it.get("adjustment_id"),
                "adjustment_type": it.get("adjustment_type"),
                "signed_amount_micros": int(it.get("signed_amount_micros") or 0),
                "snapshot_sk": it.get("snapshot_sk"),
                "reason": it.get("reason"),
                "reference_id": it.get("reference_id"),
            }
            for it in adjustments
        ],
    }


def run_api_billing_shadow_validation(
    table: Any,
    *,
    user_sub: str,
    period_id: str,
    snapshot_version: int,
    expected_total_micros: int | None = None,
    variance_threshold_micros: int = 0,
    sample_expected_by_route: dict[str, int] | None = None,
    cycle_id: str | None = None,
) -> dict[str, Any]:
    if snapshot_version < 1:
        raise HTTPException(400, "snapshot_version must be >= 1")
    snapshot_sk = f"API_USAGE#SNAPSHOT#{period_id}#V{snapshot_version:04d}"
    snap = table.get_item(Key={"PK": f"USER#{user_sub}", "SK": snapshot_sk}).get("Item") or {}
    if not snap:
        raise HTTPException(404, "snapshot not found")

    charges = calculate_period_charges(table, user_sub=user_sub, period_id=period_id)
    charge_total = int(charges.get("total_charge_micros") or 0)
    snapshot_total = int((snap.get("totals") or {}).get("cost_subtotal_micros") or 0)

    manual_total = int(expected_total_micros) if expected_total_micros is not None else charge_total
    threshold = max(0, int(variance_threshold_micros or 0))
    variance_vs_manual = charge_total - manual_total
    variance_vs_snapshot = charge_total - snapshot_total

    expected_route = sample_expected_by_route or {}
    sampled = []
    for route_id, expected in expected_route.items():
        matched = [it for it in charges.get("line_items", []) if str(it.get("route_id") or "") == str(route_id)]
        actual = sum(int(it.get("subtotal_micros") or 0) for it in matched)
        sampled.append(
            {
                "route_id": str(route_id),
                "expected_subtotal_micros": int(expected),
                "actual_subtotal_micros": int(actual),
                "variance_micros": int(actual - int(expected)),
                "within_threshold": abs(int(actual - int(expected))) <= threshold,
            }
        )

    samples_ok = all(bool(row.get("within_threshold")) for row in sampled)
    total_ok = abs(int(variance_vs_manual)) <= threshold
    snapshot_ok = abs(int(variance_vs_snapshot)) <= threshold
    within_threshold = bool(total_ok and snapshot_ok and samples_ok)

    normalized_cycle = str(cycle_id or period_id).strip() or period_id
    report_sk = f"API_USAGE#SHADOW_BILLING#{period_id}#V{snapshot_version:04d}#{normalized_cycle}"
    report = {
        "PK": f"USER#{user_sub}",
        "SK": report_sk,
        "entity_type": "api_usage_shadow_billing_report",
        "user_sub": user_sub,
        "period_id": period_id,
        "snapshot_version": int(snapshot_version),
        "snapshot_sk": snapshot_sk,
        "cycle_id": normalized_cycle,
        "expected_total_micros": manual_total,
        "calculated_total_micros": charge_total,
        "snapshot_total_micros": snapshot_total,
        "variance_vs_expected_micros": variance_vs_manual,
        "variance_vs_snapshot_micros": variance_vs_snapshot,
        "variance_threshold_micros": threshold,
        "within_threshold": within_threshold,
        "sample_route_checks": sampled,
        "line_items": charges.get("line_items", []),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    table.put_item(Item=report)
    return {
        "user_sub": user_sub,
        "period_id": period_id,
        "snapshot_version": int(snapshot_version),
        "snapshot_sk": snapshot_sk,
        "shadow_report_sk": report_sk,
        "cycle_id": normalized_cycle,
        "variance_threshold_micros": threshold,
        "within_threshold": within_threshold,
        "variance_vs_expected_micros": variance_vs_manual,
        "variance_vs_snapshot_micros": variance_vs_snapshot,
        "sample_route_checks": sampled,
        "calculated_total_micros": charge_total,
        "expected_total_micros": manual_total,
        "snapshot_total_micros": snapshot_total,
    }


def record_api_billing_cutover_signoff(
    table: Any,
    *,
    user_sub: str,
    period_id: str,
    snapshot_version: int,
    shadow_report_sk: str,
    product_approved_by: str,
    finance_approved_by: str,
    engineering_approved_by: str,
    cutover_criteria: str,
    rollback_criteria: str,
) -> dict[str, Any]:
    if snapshot_version < 1:
        raise HTTPException(400, "snapshot_version must be >= 1")
    if not str(shadow_report_sk or "").strip():
        raise HTTPException(400, "shadow_report_sk is required")
    for label, val in {
        "product_approved_by": product_approved_by,
        "finance_approved_by": finance_approved_by,
        "engineering_approved_by": engineering_approved_by,
    }.items():
        if not str(val or "").strip():
            raise HTTPException(400, f"{label} is required")

    shadow = table.get_item(Key={"PK": f"USER#{user_sub}", "SK": shadow_report_sk}).get("Item") or {}
    if not shadow:
        raise HTTPException(404, "shadow report not found")
    if not bool(shadow.get("within_threshold")):
        raise HTTPException(409, "shadow validation not within threshold")

    signoff_sk = f"API_USAGE#CUTOVER_SIGNOFF#{period_id}#V{snapshot_version:04d}"
    rec = {
        "PK": f"USER#{user_sub}",
        "SK": signoff_sk,
        "entity_type": "api_usage_cutover_signoff",
        "user_sub": user_sub,
        "period_id": period_id,
        "snapshot_version": int(snapshot_version),
        "shadow_report_sk": shadow_report_sk,
        "approvals": {
            "product": str(product_approved_by).strip(),
            "finance": str(finance_approved_by).strip(),
            "engineering": str(engineering_approved_by).strip(),
        },
        "cutover_criteria": str(cutover_criteria or "")[:2000],
        "rollback_criteria": str(rollback_criteria or "")[:2000],
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    table.put_item(Item=rec)
    return {
        "ok": True,
        "user_sub": user_sub,
        "period_id": period_id,
        "snapshot_version": int(snapshot_version),
        "signoff_sk": signoff_sk,
        "shadow_report_sk": shadow_report_sk,
        "approvals": rec["approvals"],
    }

def _now_epoch() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _quota_limit_int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except Exception:
        return 0


def _quota_table() -> Any:
    return _api_usage_table()


def _quota_key(user_sub: str, bucket: str) -> dict[str, str]:
    return {"PK": f"USER#{user_sub}", "SK": f"API_QUOTA#{bucket}"}


def _quota_update_with_limit(
    table: Any,
    *,
    user_sub: str,
    bucket: str,
    field_name: str,
    increment: int,
    limit: int,
    reset_at: int,
    limit_type: str,
    route_id: str,
    api_key_id: str | None = None,
    capture_current: bool = False,
) -> int | None:
    if limit <= 0 or increment <= 0:
        return None
    key = _quota_key(user_sub, bucket)
    names = {"#f": field_name}
    expr_vals = {
        ":inc": int(increment),
        ":limit": int(limit),
        ":updated_at": datetime.now(timezone.utc).isoformat(),
        ":ttl": int(reset_at + 86400),
        ":entity_type": "api_quota_counter",
        ":user_sub": user_sub,
        ":bucket": bucket,
    }
    try:
        table.update_item(
            Key=key,
            UpdateExpression=(
                "SET entity_type = if_not_exists(entity_type, :entity_type), "
                "user_sub = if_not_exists(user_sub, :user_sub), "
                "bucket = if_not_exists(bucket, :bucket), "
                "updated_at = :updated_at, ttl_epoch = :ttl "
                "ADD #f :inc"
            ),
            ConditionExpression="attribute_not_exists(#f) OR #f < :limit",
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=expr_vals,
        )
    except Exception as exc:
        if not _is_conditional_check_failed(exc):
            raise
        current = int(table.get_item(Key=key).get("Item", {}).get(field_name, limit) or limit)
        record_api_usage_limit_deny("api_key" if api_key_id else "account", limit_type)
        raise_limit_denied(
            limit_type=limit_type,
            scope="api_key" if api_key_id else "account",
            current=current,
            limit=limit,
            reset_at=reset_at,
            route_id=route_id,
            api_key_id=api_key_id,
        )

    if not capture_current:
        return None
    return int(table.get_item(Key=key).get("Item", {}).get(field_name, 0) or 0)




def _api_key_self_limits_for_request(*, request: Request, user_sub: str, route_id: str) -> dict[str, Any]:
    api_key_id = _extract_api_key_id(request)
    if not api_key_id:
        return {}
    item = get_api_key_item(api_key_id)
    if not item or str(item.get("user_sub") or "") != str(user_sub):
        return {}

    route_caps = item.get("route_caps") if isinstance(item.get("route_caps"), dict) else {}
    route_cap = route_caps.get(route_id) if isinstance(route_caps.get(route_id), dict) else {}
    return {
        "api_key_id": api_key_id,
        "monthly_calls_cap": _quota_limit_int(item.get("monthly_calls_cap")),
        "monthly_spend_cap_micros": _quota_limit_int(item.get("monthly_spend_cap_micros")),
        "route_monthly_calls_cap": _quota_limit_int(route_cap.get("monthly_calls_cap")),
        "route_monthly_spend_cap_micros": _quota_limit_int(route_cap.get("monthly_spend_cap_micros")),
    }

def _crossed_warning_threshold(*, current: int, increment: int, limit: int, threshold: int) -> bool:
    if limit <= 0:
        return False
    previous = max(0, int(current) - max(0, int(increment)))
    return (previous * 100 < int(limit) * int(threshold)) and (int(current) * 100 >= int(limit) * int(threshold))


def _warning_threshold_crossed(*, current: int, increment: int, limit: int) -> int:
    for threshold in (95, 85, 70):
        if _crossed_warning_threshold(current=current, increment=increment, limit=limit, threshold=threshold):
            return threshold
    return 0


def enforce_account_quota_pre_request(request: Request) -> dict[str, str]:
    route_id = route_id_from_request(request)
    if not route_id:
        return {}
    user_sub = _extract_user_sub(request)
    if not user_sub:
        return {}

    table = _quota_table()
    if table is None:
        return {}

    now = datetime.now(timezone.utc)
    now_epoch = int(now.timestamp())
    second_bucket = now.strftime("%Y%m%d%H%M%S")
    minute_bucket = now.strftime("%Y%m%d%H%M")
    day_bucket = now.strftime("%Y%m%d")
    month_bucket = now.strftime("%Y%m")

    rps_limit = _quota_limit_int(getattr(S, "api_usage_account_rps_limit", 0))
    rpm_limit = _quota_limit_int(getattr(S, "api_usage_account_rpm_limit", 0))
    daily_limit = _quota_limit_int(getattr(S, "api_usage_account_daily_calls_limit", 0))
    monthly_limit = _quota_limit_int(getattr(S, "api_usage_account_monthly_calls_limit", 0))
    monthly_spend_limit = _quota_limit_int(getattr(S, "api_usage_account_monthly_spend_micros_limit", 0))

    _quota_update_with_limit(
        table,
        user_sub=user_sub,
        bucket=f"RPS#{second_bucket}",
        field_name="calls_total",
        increment=1,
        limit=rps_limit,
        reset_at=now_epoch + 1,
        limit_type="rps",
        route_id=route_id,
    )
    _quota_update_with_limit(
        table,
        user_sub=user_sub,
        bucket=f"RPM#{minute_bucket}",
        field_name="calls_total",
        increment=1,
        limit=rpm_limit,
        reset_at=now_epoch + 60,
        limit_type="rpm",
        route_id=route_id,
    )
    _quota_update_with_limit(
        table,
        user_sub=user_sub,
        bucket=f"DAY#{day_bucket}",
        field_name="calls_total",
        increment=1,
        limit=daily_limit,
        reset_at=now_epoch + 86400,
        limit_type="daily_calls",
        route_id=route_id,
    )
    _quota_update_with_limit(
        table,
        user_sub=user_sub,
        bucket=f"MONTH#{month_bucket}",
        field_name="calls_total",
        increment=1,
        limit=monthly_limit,
        reset_at=now_epoch + 2678400,
        limit_type="monthly_calls",
        route_id=route_id,
    )

    if monthly_spend_limit > 0:
        priced = resolve_route_pricing(route_id=route_id, event_ts=now_epoch)
        _quota_update_with_limit(
            table,
            user_sub=user_sub,
            bucket=f"MONTH_SPEND#{month_bucket}",
            field_name="cost_subtotal_micros",
            increment=max(0, int(priced.unit_price_micros)),
            limit=monthly_spend_limit,
            reset_at=now_epoch + 2678400,
            limit_type="monthly_spend",
            route_id=route_id,
        )

    key_limits = _api_key_self_limits_for_request(request=request, user_sub=user_sub, route_id=route_id)
    api_key_id = str(key_limits.get("api_key_id") or "")
    warning_signals: list[str] = []
    warning_max = 0
    if api_key_id:
        key_monthly_calls_cap = _quota_limit_int(key_limits.get("monthly_calls_cap"))
        key_monthly_spend_cap = _quota_limit_int(key_limits.get("monthly_spend_cap_micros"))
        route_monthly_calls_cap = _quota_limit_int(key_limits.get("route_monthly_calls_cap"))
        route_monthly_spend_cap = _quota_limit_int(key_limits.get("route_monthly_spend_cap_micros"))

        key_calls_current = _quota_update_with_limit(
            table,
            user_sub=user_sub,
            bucket=f"KEY#{api_key_id}#MONTH#{month_bucket}",
            field_name="calls_total",
            increment=1,
            limit=key_monthly_calls_cap,
            reset_at=now_epoch + 2678400,
            limit_type="api_key_monthly_calls",
            route_id=route_id,
            api_key_id=api_key_id,
            capture_current=True,
        )
        threshold = _warning_threshold_crossed(current=int(key_calls_current or 0), increment=1, limit=key_monthly_calls_cap)
        if threshold:
            warning_signals.append(f"api_key_monthly_calls:{threshold}")
            warning_max = max(warning_max, threshold)

        route_calls_current = _quota_update_with_limit(
            table,
            user_sub=user_sub,
            bucket=f"KEY#{api_key_id}#ROUTE#{route_id}#MONTH#{month_bucket}",
            field_name="calls_total",
            increment=1,
            limit=route_monthly_calls_cap,
            reset_at=now_epoch + 2678400,
            limit_type="api_key_route_monthly_calls",
            route_id=route_id,
            api_key_id=api_key_id,
            capture_current=True,
        )
        threshold = _warning_threshold_crossed(current=int(route_calls_current or 0), increment=1, limit=route_monthly_calls_cap)
        if threshold:
            warning_signals.append(f"api_key_route_monthly_calls:{threshold}")
            warning_max = max(warning_max, threshold)

        if key_monthly_spend_cap > 0 or route_monthly_spend_cap > 0:
            priced = resolve_route_pricing(route_id=route_id, event_ts=now_epoch)
            price_increment = max(0, int(priced.unit_price_micros))
            key_spend_current = _quota_update_with_limit(
                table,
                user_sub=user_sub,
                bucket=f"KEY#{api_key_id}#MONTH_SPEND#{month_bucket}",
                field_name="cost_subtotal_micros",
                increment=price_increment,
                limit=key_monthly_spend_cap,
                reset_at=now_epoch + 2678400,
                limit_type="api_key_monthly_spend",
                route_id=route_id,
                api_key_id=api_key_id,
                capture_current=True,
            )
            threshold = _warning_threshold_crossed(current=int(key_spend_current or 0), increment=price_increment, limit=key_monthly_spend_cap)
            if threshold:
                warning_signals.append(f"api_key_monthly_spend:{threshold}")
                warning_max = max(warning_max, threshold)

            route_spend_current = _quota_update_with_limit(
                table,
                user_sub=user_sub,
                bucket=f"KEY#{api_key_id}#ROUTE#{route_id}#MONTH_SPEND#{month_bucket}",
                field_name="cost_subtotal_micros",
                increment=price_increment,
                limit=route_monthly_spend_cap,
                reset_at=now_epoch + 2678400,
                limit_type="api_key_route_monthly_spend",
                route_id=route_id,
                api_key_id=api_key_id,
                capture_current=True,
            )
            threshold = _warning_threshold_crossed(current=int(route_spend_current or 0), increment=price_increment, limit=route_monthly_spend_cap)
            if threshold:
                warning_signals.append(f"api_key_route_monthly_spend:{threshold}")
                warning_max = max(warning_max, threshold)

    headers = {
        "x-api-quota-route": route_id,
        "x-api-quota-user": user_sub,
    }
    if warning_signals:
        headers["x-api-limit-warning"] = ",".join(warning_signals)
        headers["x-api-limit-warning-max"] = str(warning_max)
    return headers



def _api_usage_table() -> Any:
    name = str(getattr(S, "api_usage_table_name", "") or "").strip()
    if not name:
        return None
    return ddb.Table(name)


def emit_api_usage_event(event: ApiUsageEvent) -> bool:
    table = _api_usage_table()
    if table is None:
        return False
    return record_api_usage_event_and_aggregates(table, event)


def record_api_usage_from_response(request: Request, status_code: int) -> Optional[Dict[str, Any]]:
    event = build_api_usage_event(request, status_code)
    if event is None:
        return None
    event["persisted"] = emit_api_usage_event(event)
    return event
