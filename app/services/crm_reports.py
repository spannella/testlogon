"""CRM Custom Report Builder (RPT-002, RPT-003, RPT-005).

Provides CRUD for report definitions and an on-demand execution engine
(``run_report``) that queries live DynamoDB data for six supported modules,
applies client-side condition filtering, optional GROUP BY aggregation
(RPT-003), and returns up to MAX_REPORT_ROWS rows.

All business logic is synchronous; the router calls ``run_report`` via
``asyncio.to_thread`` to avoid blocking the event loop.
"""

from __future__ import annotations

import collections
import json
import logging
from decimal import Decimal
from typing import Any, Dict, Iterator, List, Optional, Tuple
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.core.cursor import encode_cursor, decode_cursor
from app.services.billing_shared import user_pk
from app.services.alerts import audit_event

logger = logging.getLogger(__name__)

MAX_REPORT_ROWS = 2000  # overridden by S.crm_reports_max_rows at runtime


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _json_safe(val: Any) -> Any:
    """Recursively coerce DynamoDB Decimal → float/int and set → list."""
    if isinstance(val, Decimal):
        i = int(val)
        return i if val == i else float(val)
    if isinstance(val, set):
        return [_json_safe(v) for v in val]
    if isinstance(val, dict):
        return {k: _json_safe(v) for k, v in val.items()}
    if isinstance(val, list):
        return [_json_safe(v) for v in val]
    return val


def _coerce_numeric(value: Any) -> float:
    """Safely coerce a DynamoDB numeric (Decimal/int/float/str) to float."""
    if value is None:
        return 0.0
    if isinstance(value, Decimal):
        return float(value)
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


# ---------------------------------------------------------------------------
# Module data iterators
# ---------------------------------------------------------------------------

def _iter_tickets(owner_sub: str) -> Iterator[Dict[str, Any]]:
    """Iterate ticket META items for a user via the owner GSI."""
    index_name = S.tickets_owner_index_name
    gsi1pk = f"OWNER#{owner_sub}"
    lek: Optional[Dict] = None
    while True:
        kwargs: Dict[str, Any] = {
            "IndexName": index_name,
            "KeyConditionExpression": Key("gsi1pk").eq(gsi1pk),
            "ScanIndexForward": False,
            "Limit": 500,
        }
        if lek:
            kwargs["ExclusiveStartKey"] = lek
        resp = T.tickets.query(**kwargs)
        for item in resp.get("Items", []):
            yield item
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break


def _iter_orders(owner_sub: str) -> Iterator[Dict[str, Any]]:
    """Iterate order items for a user via the GSI_USER index."""
    lek: Optional[Dict] = None
    while True:
        kwargs: Dict[str, Any] = {
            "IndexName": "GSI_USER",
            "KeyConditionExpression": Key("user_id").eq(owner_sub),
            "Limit": 500,
        }
        if lek:
            kwargs["ExclusiveStartKey"] = lek
        resp = T.orders.query(**kwargs)
        for item in resp.get("Items", []):
            yield item
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break


def _iter_subscriptions(owner_sub: str) -> Iterator[Dict[str, Any]]:
    """Iterate subscription items for a user (SUBSCRIBER# partition)."""
    from boto3.dynamodb.conditions import Key as K
    pk_val = f"SUBSCRIBER#{owner_sub}"
    lek: Optional[Dict] = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": K("pk").eq(pk_val) & K("sk").begins_with("SUB#"),
            "Limit": 500,
        }
        if lek:
            kwargs["ExclusiveStartKey"] = lek
        resp = T.subscriptions.query(**kwargs)
        for item in resp.get("Items", []):
            yield item
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break


# ---------------------------------------------------------------------------
# Condition evaluation
# ---------------------------------------------------------------------------

def _eval_condition(item: Dict[str, Any], cond: Any) -> bool:
    """Evaluate a single ReportCondition against an item dict.

    Returns True if the item satisfies the condition.
    Unknown operator or coercion errors return False (logged at DEBUG).
    """
    from app.models import ReportCondition
    if not isinstance(cond, ReportCondition):
        # Accept plain dicts too (e.g. from JSON-decoded storage)
        try:
            cond = ReportCondition(**cond)
        except Exception:
            return True  # skip invalid conditions
    field_val = item.get(cond.field)
    op = cond.operator
    value = cond.value

    try:
        if op == "is_empty":
            return field_val is None or str(field_val).strip() == ""
        if op == "not_empty":
            return field_val is not None and str(field_val).strip() != ""
        if op == "eq":
            return str(field_val) == str(value) if value is not None else field_val is None
        if op == "neq":
            return str(field_val) != str(value) if value is not None else field_val is not None
        if op == "contains":
            return value is not None and str(value).lower() in str(field_val).lower()
        if op in ("gt", "lt", "gte", "lte"):
            fv = _coerce_numeric(field_val)
            cv = _coerce_numeric(value)
            if op == "gt":
                return fv > cv
            if op == "lt":
                return fv < cv
            if op == "gte":
                return fv >= cv
            return fv <= cv
    except Exception as exc:
        logger.debug("eval_condition_error field=%s op=%s err=%s", cond.field, op, exc)
    return False


# ---------------------------------------------------------------------------
# Core fetch-and-filter engine (shared with RPT-008 saved searches)
# ---------------------------------------------------------------------------

def _fetch_and_filter(
    module: str,
    conditions: List[Any],
    owner_sub: str,
    max_rows: int = MAX_REPORT_ROWS,
) -> List[Dict[str, Any]]:
    """Iterate all items for *module* accessible by *owner_sub*, apply
    client-side condition filtering, and return up to *max_rows* dicts.

    For the ``questionnaire_responses`` module a condition with
    ``field="questionnaire_id"`` and ``operator="eq"`` must be present.
    """
    cap = S.crm_reports_max_rows if max_rows == MAX_REPORT_ROWS else max_rows

    if module == "tickets":
        iterator: Iterator[Dict[str, Any]] = _iter_tickets(owner_sub)
    elif module == "contacts":
        from app.services.csv_export import _iter_contacts
        iterator = _iter_contacts(owner_sub)
    elif module == "billing_ledger":
        from app.services.csv_export import _iter_billing_entries
        iterator = _iter_billing_entries(owner_sub)
    elif module == "orders":
        iterator = _iter_orders(owner_sub)
    elif module == "subscriptions":
        iterator = _iter_subscriptions(owner_sub)
    elif module == "questionnaire_responses":
        qid = None
        for c in conditions:
            field = getattr(c, "field", None) or (c.get("field") if isinstance(c, dict) else None)
            op = getattr(c, "operator", None) or (c.get("operator") if isinstance(c, dict) else None)
            if field == "questionnaire_id" and op == "eq":
                qid = getattr(c, "value", None) or (c.get("value") if isinstance(c, dict) else None)
                break
        if not qid:
            raise HTTPException(status_code=422, detail="questionnaire_responses module requires a questionnaire_id eq condition")
        from app.services.csv_export import _iter_questionnaire_responses
        iterator = _iter_questionnaire_responses(qid)
    else:
        raise HTTPException(status_code=422, detail=f"Unknown module: {module}")

    results: List[Dict[str, Any]] = []
    for item in iterator:
        if all(_eval_condition(item, c) for c in conditions):
            results.append(item)
            if len(results) >= cap:
                break
    return results


# ---------------------------------------------------------------------------
# RPT-003: GROUP BY / aggregate engine
# ---------------------------------------------------------------------------

def _apply_group_by(
    rows: List[Dict[str, Any]],
    group_by_field: str,
    aggregates: List[Any],
) -> List[Dict[str, Any]]:
    """Group *rows* by *group_by_field* and compute aggregate functions per group.

    Operates on raw DynamoDB item dicts (Decimal numeric values).
    Returns a list of group-summary dicts.
    """
    groups: Dict[str, List[Dict[str, Any]]] = collections.defaultdict(list)
    for row in rows:
        key = str(row.get(group_by_field, "") or "")
        groups[key].append(row)

    result = []
    for group_key, group_rows in groups.items():
        summary: Dict[str, Any] = {group_by_field: group_key}
        for agg in aggregates:
            agg_field = getattr(agg, "field", agg.get("field") if isinstance(agg, dict) else "*")
            agg_func = getattr(agg, "function", agg.get("function") if isinstance(agg, dict) else "COUNT")
            col_name = f"{agg_field}_{agg_func}"
            if agg_func == "COUNT":
                if agg_field == "*":
                    summary[col_name] = len(group_rows)
                else:
                    summary[col_name] = sum(1 for r in group_rows if r.get(agg_field) is not None)
            else:
                numeric_vals = [
                    _coerce_numeric(r.get(agg_field))
                    for r in group_rows
                    if r.get(agg_field) is not None
                ]
                if not numeric_vals:
                    summary[col_name] = None
                elif agg_func == "SUM":
                    summary[col_name] = sum(numeric_vals)
                elif agg_func == "AVG":
                    summary[col_name] = sum(numeric_vals) / len(numeric_vals)
                elif agg_func == "MIN":
                    summary[col_name] = min(numeric_vals)
                elif agg_func == "MAX":
                    summary[col_name] = max(numeric_vals)
        result.append(summary)
    return result


# ---------------------------------------------------------------------------
# RPT-005: chart validation
# ---------------------------------------------------------------------------

def _validate_chart(chart: Any, fields: List[str], aggregates: List[Any]) -> None:
    """Raise ValueError if chart config references non-existent fields."""
    if chart is None:
        return
    agg_columns = set()
    for a in (aggregates or []):
        if isinstance(a, dict):
            f = a.get("field", "")
            fn = a.get("function", "")
        else:
            f = getattr(a, "field", "")
            fn = getattr(a, "function", "")
        agg_columns.add(f"{f}_{fn}")
    valid = set(fields) | agg_columns
    x_field = getattr(chart, "x_field", None) or (chart.get("x_field") if isinstance(chart, dict) else None)
    y_field = getattr(chart, "y_field", None) or (chart.get("y_field") if isinstance(chart, dict) else None)
    if x_field and x_field not in valid:
        raise ValueError(f"x_field '{x_field}' is not a declared field or aggregate column")
    if y_field and y_field not in valid:
        raise ValueError(f"y_field '{y_field}' is not a declared field or aggregate column")


# ---------------------------------------------------------------------------
# Project row to list
# ---------------------------------------------------------------------------

def _project_row(item: Dict[str, Any], columns: List[str]) -> List[Any]:
    """Extract *columns* from a raw DDB item, returning None for missing fields."""
    return [_json_safe(item.get(col)) for col in columns]


# ---------------------------------------------------------------------------
# Item ↔ Pydantic conversions
# ---------------------------------------------------------------------------

def _item_to_report_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Return a plain dict representation of a report META item (not a Pydantic model)."""
    fields = json.loads(item.get("fields", "[]"))
    conditions = json.loads(item.get("conditions", "[]"))
    aggregates_raw = json.loads(item.get("aggregates", "[]"))
    chart = None
    if item.get("chart"):
        chart_data = item["chart"]
        if isinstance(chart_data, str):
            chart_data = json.loads(chart_data)
        chart = chart_data
    return {
        "report_id": item["report_id"],
        "name": item["name"],
        "description": item.get("description"),
        "module": item["module"],
        "fields": fields,
        "conditions": conditions,
        "group_by": item.get("group_by"),
        "aggregates": aggregates_raw,
        "chart": chart,
        "owner_sub": item["owner_sub"],
        "created_at": int(item["created_at"]),
        "updated_at": int(item["updated_at"]),
    }


# ---------------------------------------------------------------------------
# Public service functions
# ---------------------------------------------------------------------------

def create_report(owner_sub: str, payload: Any) -> Any:
    """Create a new report definition."""
    # Validate chart if provided
    if payload.chart is not None:
        try:
            _validate_chart(payload.chart, payload.fields, payload.aggregates)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))

    report_id = f"RPT#{uuid4().hex[:12]}"
    now = now_ts()

    # Serialize chart config
    chart_val = None
    if payload.chart is not None:
        chart_val = payload.chart.model_dump()

    item: Dict[str, Any] = {
        "report_id": report_id,
        "sk": "META",
        "GSI1PK": f"OWNER#{owner_sub}",
        "GSI1SK": now,
        "owner_sub": owner_sub,
        "name": payload.name,
        "module": payload.module,
        "fields": json.dumps(payload.fields),
        "conditions": json.dumps([c.model_dump() for c in payload.conditions]),
        "aggregates": json.dumps([a.model_dump() for a in payload.aggregates]),
        "created_at": now,
        "updated_at": now,
    }
    if payload.description is not None:
        item["description"] = payload.description
    if payload.group_by is not None:
        item["group_by"] = payload.group_by
    if chart_val is not None:
        item["chart"] = chart_val

    T.crm_reports.put_item(Item=item)
    try:
        audit_event("report.created", owner_sub, None, report_id=report_id, module=payload.module)
    except Exception:
        pass
    return _item_to_report_out(item)


def get_report(report_id: str, owner_sub: str) -> Any:
    """Get a report by ID, enforcing ownership."""
    resp = T.crm_reports.get_item(Key={"report_id": report_id, "sk": "META"})
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Report not found")
    if item.get("owner_sub") != owner_sub:
        raise HTTPException(status_code=403, detail="Forbidden")
    return _item_to_report_out(item)


def list_reports(owner_sub: str, cursor: Optional[str] = None, limit: int = 20) -> Dict[str, Any]:
    """List reports for an owner, newest first, paginated."""
    gsi_pk = f"OWNER#{owner_sub}"
    kwargs: Dict[str, Any] = {
        "IndexName": "owner-reports-index",
        "KeyConditionExpression": Key("GSI1PK").eq(gsi_pk),
        "ScanIndexForward": False,
        "Limit": min(limit, 50),
    }
    lek = decode_cursor(cursor)
    if lek:
        kwargs["ExclusiveStartKey"] = lek
    resp = T.crm_reports.query(**kwargs)
    items = resp.get("Items", [])
    next_cursor = encode_cursor(resp.get("LastEvaluatedKey"))
    return {
        "reports": [_item_to_report_out(i) for i in items],
        "next_cursor": next_cursor,
    }


def update_report(report_id: str, owner_sub: str, patch: Any) -> Any:
    """Partial update on a report definition."""

    existing = get_report(report_id, owner_sub)  # ownership check

    update_expr_parts = ["#upd = :upd"]
    expr_names = {"#upd": "updated_at"}
    expr_vals: Dict[str, Any] = {":upd": now_ts(), ":sub": owner_sub}

    if patch.name is not None:
        update_expr_parts.append("#nm = :nm")
        expr_names["#nm"] = "name"
        expr_vals[":nm"] = patch.name
    if patch.description is not None:
        update_expr_parts.append("description = :desc")
        expr_vals[":desc"] = patch.description
    if patch.fields is not None:
        update_expr_parts.append("fields = :fields")
        expr_vals[":fields"] = json.dumps(patch.fields)
    if patch.conditions is not None:
        update_expr_parts.append("conditions = :conds")
        expr_vals[":conds"] = json.dumps([c.model_dump() for c in patch.conditions])

    # RPT-003: group_by / aggregates
    if hasattr(patch, "group_by") and patch.group_by is not None:
        update_expr_parts.append("group_by = :gb")
        expr_vals[":gb"] = patch.group_by
    if hasattr(patch, "aggregates") and patch.aggregates is not None:
        update_expr_parts.append("aggregates = :aggs")
        expr_vals[":aggs"] = json.dumps([a.model_dump() for a in patch.aggregates])

    # RPT-005: chart
    if hasattr(patch, "chart"):
        if patch.chart is None:
            # Explicit removal
            update_expr_parts.append("chart = :chart")
            expr_vals[":chart"] = None
        elif patch.chart is not None:
            # Validate chart
            eff_fields = patch.fields if patch.fields is not None else json.loads(
                T.crm_reports.get_item(Key={"report_id": report_id, "sk": "META"}).get("Item", {}).get("fields", "[]")
            )
            eff_aggs = patch.aggregates if (hasattr(patch, "aggregates") and patch.aggregates is not None) else []
            try:
                _validate_chart(patch.chart, eff_fields, eff_aggs)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc))
            update_expr_parts.append("chart = :chart")
            expr_vals[":chart"] = patch.chart.model_dump()
            try:
                audit_event("report.chart_config_updated", owner_sub, None, report_id=report_id)
            except Exception:
                pass

    T.crm_reports.update_item(
        Key={"report_id": report_id, "sk": "META"},
        UpdateExpression="SET " + ", ".join(update_expr_parts),
        ExpressionAttributeNames=expr_names if expr_names else None,
        ExpressionAttributeValues=expr_vals,
        ConditionExpression="owner_sub = :sub",
    )
    try:
        audit_event("report.updated", owner_sub, None, report_id=report_id)
    except Exception:
        pass
    return get_report(report_id, owner_sub)


def delete_report(report_id: str, owner_sub: str) -> None:
    """Delete a report and all its RUN + SCHEDULE rows."""

    get_report(report_id, owner_sub)  # ownership check

    # Gather all child rows (RUN# and SCHEDULE#)
    run_resp = T.crm_reports.query(
        KeyConditionExpression=Key("report_id").eq(report_id) & Key("sk").begins_with("RUN#"),
    )
    sched_resp = T.crm_reports.query(
        KeyConditionExpression=Key("report_id").eq(report_id) & Key("sk").begins_with("SCHEDULE#"),
    )

    with T.crm_reports.batch_writer() as bw:
        bw.delete_item(Key={"report_id": report_id, "sk": "META"})
        for item in run_resp.get("Items", []):
            bw.delete_item(Key={"report_id": report_id, "sk": item["sk"]})
        for item in sched_resp.get("Items", []):
            bw.delete_item(Key={"report_id": report_id, "sk": item["sk"]})

    try:
        audit_event("report.deleted", owner_sub, None, report_id=report_id)
    except Exception:
        pass


def run_report(report_id: str, owner_sub: str) -> Dict[str, Any]:
    """Execute a report definition and write a RUN row.

    This function is synchronous and is called via asyncio.to_thread in the router.
    """

    # Read definition (ownership check included)
    resp = T.crm_reports.get_item(Key={"report_id": report_id, "sk": "META"})
    meta = resp.get("Item")
    if not meta:
        raise HTTPException(status_code=404, detail="Report not found")
    if meta.get("owner_sub") != owner_sub:
        raise HTTPException(status_code=403, detail="Forbidden")

    run_id = uuid4().hex[:4]
    run_at = now_ts()
    status = "ok"
    error_msg = None
    columns: List[str] = []
    output_rows: List[Any] = []
    row_count = 0

    try:
        module = meta["module"]
        fields = json.loads(meta.get("fields", "[]"))
        conditions_raw = json.loads(meta.get("conditions", "[]"))
        group_by = meta.get("group_by")
        aggregates_raw = json.loads(meta.get("aggregates", "[]"))

        from app.models import ReportCondition, AggregateSpec
        conditions = [ReportCondition(**c) for c in conditions_raw]
        aggregates = [AggregateSpec(**a) for a in aggregates_raw]

        raw_rows = _fetch_and_filter(module, conditions, owner_sub, max_rows=S.crm_reports_max_rows)

        if group_by:
            grouped = _apply_group_by(raw_rows, group_by, aggregates)
            columns = [group_by] + [f"{a.field}_{a.function}" for a in aggregates]
            output_rows = [[_json_safe(g.get(c)) for c in columns] for g in grouped[:S.crm_reports_max_rows]]
            row_count = len(output_rows)
        else:
            columns = fields
            output_rows = [_project_row(r, columns) for r in raw_rows[:S.crm_reports_max_rows]]
            row_count = len(output_rows)

    except HTTPException:
        raise
    except Exception as exc:
        status = "error"
        error_msg = str(exc)[:500]
        row_count = 0
        columns = []
        output_rows = []

    sk_run = f"RUN#{run_at:010d}#{run_id}"
    run_item: Dict[str, Any] = {
        "report_id": report_id,
        "sk": sk_run,
        "run_id": run_id,
        "run_at": run_at,
        "status": status,
        "row_count": row_count,
        "columns": json.dumps(columns),
        "rows": json.dumps(output_rows),
    }
    if error_msg:
        run_item["error_msg"] = error_msg
    T.crm_reports.put_item(Item=run_item)

    try:
        audit_event("report.run", owner_sub, None, report_id=report_id, row_count=row_count, status=status)
    except Exception:
        pass

    if status == "error":
        raise HTTPException(status_code=500, detail="Report execution failed")

    # RPT-005: echo chart config from META row
    chart = None
    if meta.get("chart"):
        try:
            from app.models import ChartConfig
            chart_data = meta["chart"]
            if isinstance(chart_data, str):
                chart_data = json.loads(chart_data)
            chart = ChartConfig(**chart_data)
        except Exception:
            pass

    return {
        "report_id": report_id,
        "run_id": run_id,
        "run_at": run_at,
        "status": status,
        "row_count": row_count,
        "columns": columns,
        "rows": output_rows,
        "error_msg": error_msg,
        "chart": chart,
    }
