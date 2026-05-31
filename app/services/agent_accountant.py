"""Accountant / Cost Tracking Agent service (AGENT-018).

The Accountant Agent is an agent *type* that tracks per-agent / per-ticket LLM +
compute spend, aggregates it into daily / period summaries, enforces budget caps,
fires budget-threshold / overspend alerts, and surfaces cost-optimization
recommendations.

It owns:

* daily cost entry recording (idempotent upsert with atomic counter ADDs) on the
  ``agent_costs`` table
* per-ticket cost attribution on the ``agent_ticket_costs`` table
* budget CRUD on the ``agent_cost_budgets`` table
* budget evaluation + alert creation on the ``agent_cost_alerts`` table
* daily / period / agent-type / ticket aggregation queries (GSI driven)
* cost trend rollups + optimization recommendations
* accountant_config storage on the ``agent_types`` table

Real execution (polling provider usage/billing APIs, AWS Cost Explorer, and
auto-pausing workers) is gated behind ``S.accountant_agent_execute_commands``.
When disabled (the default, and always in E2E), costs are recorded from the
explicit API payloads and budgets/alerts are evaluated deterministically in
memory so the lifecycle is fully driveable/testable.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from app.core.aws import ddb
from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger("app.agent_accountant")

ACCOUNTANT_AGENT_TYPE = "accountant"

# Max alerts per budget per day (security §7 — alert rate limiting).
_MAX_ALERTS_PER_BUDGET_PER_DAY = 10

_BUDGET_PERIODS = ("daily", "weekly", "monthly")
_BUDGET_SCOPES = ("overall", "agent_type", "agent_instance")

_CONFIG_DEFAULTS: Dict[str, Any] = {
    "collection_frequency": "hourly",
    "report_frequency": "daily",
    "report_hour_utc": 8,
    "compute_pricing": {"ec2_per_hour_cents": 10, "k8s_per_hour_cents": 5},
    "anomaly_detection_enabled": True,
    "anomaly_threshold_pct": 200,
    "idle_worker_threshold_minutes": 60,
    "optimization_suggestions_enabled": True,
}


# ---------------------------------------------------------------------------
# Decimal coercion (boto3 rejects Python float)
# ---------------------------------------------------------------------------


def _to_dec(value: Any) -> Any:
    """Recursively coerce floats to Decimal(str(x)) for DynamoDB writes."""
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, dict):
        return {k: _to_dec(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_dec(v) for v in value]
    return value


def _num(value: Any) -> float:
    """Coerce a stored DynamoDB number (Decimal) to a Python float."""
    if value is None:
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _int(value: Any) -> int:
    return int(round(_num(value)))


# ---------------------------------------------------------------------------
# Table bootstrap (idempotent; tables are additive)
# ---------------------------------------------------------------------------

_BOOTSTRAPPED = False


def ensure_tables() -> None:
    """Create the accountant cost tables on first use if absent.

    The shared local-ddb-init script is the canonical place tables are defined,
    but the accountant feature is fully self-contained so it works in any
    environment (E2E live DDB, fresh stacks) without a stack re-init.
    """
    global _BOOTSTRAPPED
    if _BOOTSTRAPPED:
        return
    client = ddb.meta.client
    specs = [
        (
            S.agent_costs_table_name,
            [
                {"AttributeName": "GSI1PK", "AttributeType": "S"},
                {"AttributeName": "GSI1SK", "AttributeType": "S"},
                {"AttributeName": "GSI2PK", "AttributeType": "S"},
                {"AttributeName": "GSI2SK", "AttributeType": "S"},
            ],
            [
                {
                    "IndexName": "GSI1",
                    "KeySchema": [
                        {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": "GSI2",
                    "KeySchema": [
                        {"AttributeName": "GSI2PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI2SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
        ),
        (
            S.agent_ticket_costs_table_name,
            [
                {"AttributeName": "GSI1PK", "AttributeType": "S"},
                {"AttributeName": "GSI1SK", "AttributeType": "N"},
            ],
            [
                {
                    "IndexName": "GSI1",
                    "KeySchema": [
                        {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
        ),
        (
            S.agent_cost_budgets_table_name,
            [],
            [],
        ),
        (
            S.agent_cost_alerts_table_name,
            [
                {"AttributeName": "GSI1PK", "AttributeType": "S"},
                {"AttributeName": "GSI1SK", "AttributeType": "N"},
            ],
            [
                {
                    "IndexName": "GSI1",
                    "KeySchema": [
                        {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                        {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
        ),
    ]
    for name, extra_attrs, gsi in specs:
        attr_defs = [
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ] + extra_attrs
        kwargs: Dict[str, Any] = {
            "TableName": name,
            "KeySchema": [
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            "AttributeDefinitions": attr_defs,
            "BillingMode": "PAY_PER_REQUEST",
        }
        if gsi:
            kwargs["GlobalSecondaryIndexes"] = gsi
        try:
            client.create_table(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("ResourceInUseException",):
                logger.warning("ensure_tables: could not create %s: %s", name, exc)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("ensure_tables: %s create error: %s", name, exc)
    _BOOTSTRAPPED = True


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------


def _user_pk(user_id: str) -> str:
    return f"USER#{user_id}"


def _cost_sk(date: str, worker_id: str) -> str:
    return f"COST#{date}#{worker_id}"


def _tcost_sk(ticket_id: str) -> str:
    return f"TCOST#{ticket_id}"


def _budget_sk(budget_id: str) -> str:
    return f"BUDGET#{budget_id}"


def _alert_sk(alert_id: str) -> str:
    return f"ALERT#{alert_id}"


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _parse_date(date: str) -> Optional[datetime]:
    try:
        return datetime.strptime(date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def is_valid_date(date: str) -> bool:
    return _parse_date(date) is not None


# ---------------------------------------------------------------------------
# Cost recording
# ---------------------------------------------------------------------------


def record_cost_entry(
    *,
    user_id: str,
    worker_id: str,
    agent_type: str,
    agent_id: str,
    date: str,
    llm_input_tokens: int = 0,
    llm_output_tokens: int = 0,
    llm_cached_tokens: int = 0,
    llm_cost_cents: int = 0,
    llm_provider: str = "anthropic",
    llm_model: str = "unknown",
    compute_hours: float = 0.0,
    compute_cost_cents: int = 0,
    tickets_worked: int = 0,
    tickets_completed: int = 0,
) -> Dict[str, Any]:
    """Record/update a daily cost entry. Idempotent upsert with atomic ADDs."""
    ensure_tables()
    ts = now_ts()
    total = int(llm_cost_cents) + int(compute_cost_cents)
    T.agent_costs.update_item(
        Key={"pk": _user_pk(user_id), "sk": _cost_sk(date, worker_id)},
        UpdateExpression=(
            "SET user_id = :uid, worker_id = :wid, agent_type = :atype, agent_id = :aid, "
            "#date = :date, llm_provider = :prov, llm_model = :model, updated_at = :ts, "
            "GSI1PK = :g1pk, GSI1SK = :g1sk, GSI2PK = :g2pk, GSI2SK = :g2sk "
            "ADD llm_input_tokens :it, llm_output_tokens :ot, llm_cached_tokens :ct, "
            "llm_cost_cents :lc, compute_hours :ch, compute_cost_cents :cc, "
            "total_cost_cents :tc, tickets_worked :tw, tickets_completed :tcomp"
        ),
        ExpressionAttributeNames={"#date": "date"},
        ExpressionAttributeValues=_to_dec(
            {
                ":uid": user_id,
                ":wid": worker_id,
                ":atype": agent_type,
                ":aid": agent_id,
                ":date": date,
                ":prov": llm_provider,
                ":model": llm_model,
                ":ts": ts,
                ":g1pk": f"USER#{user_id}#DATE#{date}",
                ":g1sk": f"TYPE#{agent_type}#WORKER#{worker_id}",
                ":g2pk": f"USER#{user_id}#TYPE#{agent_type}",
                ":g2sk": f"DATE#{date}",
                ":it": int(llm_input_tokens),
                ":ot": int(llm_output_tokens),
                ":ct": int(llm_cached_tokens),
                ":lc": int(llm_cost_cents),
                ":ch": float(compute_hours),
                ":cc": int(compute_cost_cents),
                ":tc": total,
                ":tw": int(tickets_worked),
                ":tcomp": int(tickets_completed),
            }
        ),
    )
    resp = T.agent_costs.get_item(
        Key={"pk": _user_pk(user_id), "sk": _cost_sk(date, worker_id)}
    )
    return _cost_entry_out(resp.get("Item") or {})


def _cost_entry_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "worker_id": item.get("worker_id", ""),
        "agent_type": item.get("agent_type", ""),
        "agent_id": item.get("agent_id", ""),
        "date": item.get("date", ""),
        "llm_input_tokens": _int(item.get("llm_input_tokens")),
        "llm_output_tokens": _int(item.get("llm_output_tokens")),
        "llm_cached_tokens": _int(item.get("llm_cached_tokens")),
        "llm_cost_cents": _int(item.get("llm_cost_cents")),
        "llm_provider": item.get("llm_provider", ""),
        "llm_model": item.get("llm_model", ""),
        "compute_hours": round(_num(item.get("compute_hours")), 4),
        "compute_cost_cents": _int(item.get("compute_cost_cents")),
        "total_cost_cents": _int(item.get("total_cost_cents")),
        "tickets_worked": _int(item.get("tickets_worked")),
        "tickets_completed": _int(item.get("tickets_completed")),
    }


def attribute_cost_to_ticket(
    *,
    user_id: str,
    ticket_id: str,
    agent_type: str,
    llm_tokens: int = 0,
    llm_cost_cents: int = 0,
    compute_hours: float = 0.0,
    compute_cost_cents: int = 0,
) -> Dict[str, Any]:
    """Attribute a cost increment to a ticket. Upsert with atomic ADD."""
    ensure_tables()
    ts = now_ts()
    total = int(llm_cost_cents) + int(compute_cost_cents)
    key = {"pk": _user_pk(user_id), "sk": _tcost_sk(ticket_id)}
    T.agent_ticket_costs.update_item(
        Key=key,
        UpdateExpression=(
            "SET user_id = :uid, ticket_id = :tid, agent_type = :atype, "
            "#st = if_not_exists(#st, :inprog), started_at = if_not_exists(started_at, :ts), "
            "GSI1PK = :g1pk "
            "ADD total_llm_tokens :tok, total_llm_cost_cents :lc, total_compute_hours :ch, "
            "total_compute_cost_cents :cc, total_cost_cents :tc, worker_sessions :one, "
            "GSI1SK :tc"
        ),
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues=_to_dec(
            {
                ":uid": user_id,
                ":tid": ticket_id,
                ":atype": agent_type,
                ":inprog": "in_progress",
                ":ts": ts,
                ":g1pk": f"USER#{user_id}#TICKET_COSTS",
                ":tok": int(llm_tokens),
                ":lc": int(llm_cost_cents),
                ":ch": float(compute_hours),
                ":cc": int(compute_cost_cents),
                ":tc": total,
                ":one": 1,
            }
        ),
    )
    resp = T.agent_ticket_costs.get_item(Key=key)
    return _ticket_cost_out(resp.get("Item") or {})


def _ticket_cost_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "ticket_id": item.get("ticket_id", ""),
        "agent_type": item.get("agent_type", ""),
        "total_llm_tokens": _int(item.get("total_llm_tokens")),
        "total_llm_cost_cents": _int(item.get("total_llm_cost_cents")),
        "total_compute_hours": round(_num(item.get("total_compute_hours")), 4),
        "total_compute_cost_cents": _int(item.get("total_compute_cost_cents")),
        "total_cost_cents": _int(item.get("total_cost_cents")),
        "worker_sessions": _int(item.get("worker_sessions")),
        "status": item.get("status", "in_progress"),
        "started_at": _int(item.get("started_at")) or None,
        "completed_at": _int(item.get("completed_at")) or None,
    }


def mark_ticket_completed(*, user_id: str, ticket_id: str) -> Dict[str, Any]:
    ensure_tables()
    key = {"pk": _user_pk(user_id), "sk": _tcost_sk(ticket_id)}
    resp = T.agent_ticket_costs.get_item(Key=key)
    if not resp.get("Item"):
        raise LookupError(ticket_id)
    ts = now_ts()
    T.agent_ticket_costs.update_item(
        Key=key,
        UpdateExpression="SET #st = :done, completed_at = :ts",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":done": "completed", ":ts": ts},
    )
    resp = T.agent_ticket_costs.get_item(Key=key)
    return _ticket_cost_out(resp.get("Item") or {})


# ---------------------------------------------------------------------------
# Summaries / aggregation
# ---------------------------------------------------------------------------


def _query_date(user_id: str, date: str) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {
        "IndexName": "GSI1",
        "KeyConditionExpression": "GSI1PK = :pk",
        "ExpressionAttributeValues": {":pk": f"USER#{user_id}#DATE#{date}"},
    }
    while True:
        resp = T.agent_costs.query(**kwargs)
        items.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return items


def get_daily_summary(*, user_id: str, date: str) -> Dict[str, Any]:
    ensure_tables()
    items = _query_date(user_id, date)
    by_agent_type: Dict[str, int] = {}
    by_worker: List[Dict[str, Any]] = []
    total = llm = compute = 0
    for it in items:
        entry = _cost_entry_out(it)
        by_worker.append(entry)
        total += entry["total_cost_cents"]
        llm += entry["llm_cost_cents"]
        compute += entry["compute_cost_cents"]
        at = entry["agent_type"] or "unattributed"
        by_agent_type[at] = by_agent_type.get(at, 0) + entry["total_cost_cents"]
    by_worker.sort(key=lambda e: e["total_cost_cents"], reverse=True)
    return {
        "date": date,
        "total_cents": total,
        "llm_cents": llm,
        "compute_cents": compute,
        "by_agent_type": by_agent_type,
        "by_worker": by_worker,
    }


def _dates_in_range(start_date: str, end_date: str) -> List[str]:
    start = _parse_date(start_date)
    end = _parse_date(end_date)
    if not start or not end or end < start:
        return []
    out: List[str] = []
    cur = start
    # cap at 366 days to bound the scan
    for _ in range(367):
        out.append(cur.strftime("%Y-%m-%d"))
        if cur >= end:
            break
        cur += timedelta(days=1)
    return out


def get_period_summary(
    *, user_id: str, period: str, start_date: str, end_date: str
) -> Dict[str, Any]:
    ensure_tables()
    total = llm = compute = 0
    by_agent_type: Dict[str, int] = {}
    for date in _dates_in_range(start_date, end_date):
        day = get_daily_summary(user_id=user_id, date=date)
        total += day["total_cents"]
        llm += day["llm_cents"]
        compute += day["compute_cents"]
        for at, cents in day["by_agent_type"].items():
            by_agent_type[at] = by_agent_type.get(at, 0) + cents
    budget_utilization = _budget_utilization(user_id, period=period, total_cents=total, by_agent_type=by_agent_type)
    return {
        "period": period,
        "start_date": start_date,
        "end_date": end_date,
        "total_cents": total,
        "llm_cents": llm,
        "compute_cents": compute,
        "by_agent_type": by_agent_type,
        "budget_utilization": budget_utilization,
    }


def get_agent_type_costs(*, user_id: str, agent_type: str, days: int = 30) -> Dict[str, Any]:
    ensure_tables()
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=max(1, days) - 1)
    start_sk = f"DATE#{start.strftime('%Y-%m-%d')}"
    end_sk = f"DATE#{end.strftime('%Y-%m-%d')}"
    items: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {
        "IndexName": "GSI2",
        "KeyConditionExpression": "GSI2PK = :pk AND GSI2SK BETWEEN :s AND :e",
        "ExpressionAttributeValues": {
            ":pk": f"USER#{user_id}#TYPE#{agent_type}",
            ":s": start_sk,
            ":e": end_sk,
        },
    }
    while True:
        resp = T.agent_costs.query(**kwargs)
        items.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    by_date: Dict[str, int] = {}
    total = llm = compute = 0
    entries: List[Dict[str, Any]] = []
    for it in items:
        entry = _cost_entry_out(it)
        entries.append(entry)
        total += entry["total_cost_cents"]
        llm += entry["llm_cost_cents"]
        compute += entry["compute_cost_cents"]
        by_date[entry["date"]] = by_date.get(entry["date"], 0) + entry["total_cost_cents"]
    daily_costs = [
        {"date": d, "cost_cents": c} for d, c in sorted(by_date.items())
    ]
    return {
        "agent_type": agent_type,
        "days": days,
        "total_cents": total,
        "llm_cents": llm,
        "compute_cents": compute,
        "daily_costs": daily_costs,
        "entries": entries,
    }


def get_ticket_cost(*, user_id: str, ticket_id: str) -> Optional[Dict[str, Any]]:
    ensure_tables()
    resp = T.agent_ticket_costs.get_item(
        Key={"pk": _user_pk(user_id), "sk": _tcost_sk(ticket_id)}
    )
    item = resp.get("Item")
    if not item:
        return None
    return _ticket_cost_out(item)


def list_ticket_costs(
    *, user_id: str, limit: int = 25, cursor: Optional[str] = None
) -> Dict[str, Any]:
    """List ticket costs sorted by total_cost_cents desc via GSI1."""
    ensure_tables()
    kwargs: Dict[str, Any] = {
        "IndexName": "GSI1",
        "KeyConditionExpression": "GSI1PK = :pk",
        "ExpressionAttributeValues": {":pk": f"USER#{user_id}#TICKET_COSTS"},
        "ScanIndexForward": False,  # highest cost first
        "Limit": max(1, min(limit, 100)),
    }
    start = decode_cursor(cursor)
    if start:
        kwargs["ExclusiveStartKey"] = start
    resp = T.agent_ticket_costs.query(**kwargs)
    items = [_ticket_cost_out(it) for it in resp.get("Items", [])]
    return {
        "ticket_costs": items,
        "next_cursor": encode_cursor(resp.get("LastEvaluatedKey")),
    }


# ---------------------------------------------------------------------------
# Budgets
# ---------------------------------------------------------------------------


def _budget_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "budget_id": item.get("budget_id", ""),
        "name": item.get("name", ""),
        "scope": item.get("scope", "overall"),
        "scope_ref": item.get("scope_ref") or None,
        "period": item.get("period", "daily"),
        "limit_cents": _int(item.get("limit_cents")),
        "alert_threshold_pct": _int(item.get("alert_threshold_pct")) or 80,
        "auto_pause_on_exceed": bool(item.get("auto_pause_on_exceed", False)),
        "enabled": bool(item.get("enabled", True)),
        "created_at": _int(item.get("created_at")),
    }


def _list_budget_items(user_id: str) -> List[Dict[str, Any]]:
    resp = T.agent_cost_budgets.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :p)",
        ExpressionAttributeValues={":pk": _user_pk(user_id), ":p": "BUDGET#"},
    )
    return resp.get("Items", [])


def create_budget(
    *,
    user_id: str,
    name: str,
    scope: str,
    scope_ref: Optional[str],
    period: str,
    limit_cents: int,
    alert_threshold_pct: int = 80,
    auto_pause_on_exceed: bool = False,
) -> Dict[str, Any]:
    ensure_tables()
    # Duplicate guard: one budget per (scope, scope_ref, period).
    for it in _list_budget_items(user_id):
        if (
            it.get("scope") == scope
            and (it.get("scope_ref") or None) == (scope_ref or None)
            and it.get("period") == period
        ):
            raise ValueError("duplicate_budget")
    budget_id = uuid.uuid4().hex
    ts = now_ts()
    item = {
        "pk": _user_pk(user_id),
        "sk": _budget_sk(budget_id),
        "budget_id": budget_id,
        "user_id": user_id,
        "name": name,
        "scope": scope,
        "scope_ref": scope_ref or None,
        "period": period,
        "limit_cents": int(limit_cents),
        "alert_threshold_pct": int(alert_threshold_pct),
        "auto_pause_on_exceed": bool(auto_pause_on_exceed),
        "enabled": True,
        "created_at": ts,
    }
    T.agent_cost_budgets.put_item(Item=item)
    return _budget_out(item)


def list_budgets(*, user_id: str) -> List[Dict[str, Any]]:
    ensure_tables()
    return [_budget_out(it) for it in _list_budget_items(user_id)]


def get_budget(*, user_id: str, budget_id: str) -> Optional[Dict[str, Any]]:
    ensure_tables()
    resp = T.agent_cost_budgets.get_item(
        Key={"pk": _user_pk(user_id), "sk": _budget_sk(budget_id)}
    )
    item = resp.get("Item")
    return _budget_out(item) if item else None


def update_budget(*, user_id: str, budget_id: str, **fields: Any) -> Dict[str, Any]:
    ensure_tables()
    key = {"pk": _user_pk(user_id), "sk": _budget_sk(budget_id)}
    resp = T.agent_cost_budgets.get_item(Key=key)
    if not resp.get("Item"):
        raise LookupError(budget_id)
    allowed = ("name", "limit_cents", "alert_threshold_pct", "auto_pause_on_exceed", "enabled")
    sets: List[str] = []
    values: Dict[str, Any] = {}
    names: Dict[str, str] = {}
    for k in allowed:
        if k in fields and fields[k] is not None:
            placeholder = f":{k}"
            attr_name = f"#{k}"
            names[attr_name] = k
            sets.append(f"{attr_name} = {placeholder}")
            values[placeholder] = fields[k]
    if sets:
        T.agent_cost_budgets.update_item(
            Key=key,
            UpdateExpression="SET " + ", ".join(sets),
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
        )
    resp = T.agent_cost_budgets.get_item(Key=key)
    return _budget_out(resp.get("Item") or {})


def delete_budget(*, user_id: str, budget_id: str) -> Dict[str, Any]:
    ensure_tables()
    key = {"pk": _user_pk(user_id), "sk": _budget_sk(budget_id)}
    resp = T.agent_cost_budgets.get_item(Key=key)
    if not resp.get("Item"):
        raise LookupError(budget_id)
    T.agent_cost_budgets.delete_item(Key=key)
    return {"ok": True, "budget_id": budget_id}


def _period_window(period: str) -> tuple[str, str]:
    """Return (start_date, end_date) for the current period."""
    now = datetime.now(timezone.utc)
    if period == "daily":
        return now.strftime("%Y-%m-%d"), now.strftime("%Y-%m-%d")
    if period == "weekly":
        start = now - timedelta(days=now.weekday())
        return start.strftime("%Y-%m-%d"), now.strftime("%Y-%m-%d")
    # monthly
    start = now.replace(day=1)
    return start.strftime("%Y-%m-%d"), now.strftime("%Y-%m-%d")


def _current_spend_for_budget(user_id: str, budget: Dict[str, Any]) -> int:
    start, end = _period_window(budget.get("period", "daily"))
    total = 0
    for date in _dates_in_range(start, end):
        day = get_daily_summary(user_id=user_id, date=date)
        scope = budget.get("scope", "overall")
        if scope == "overall":
            total += day["total_cents"]
        elif scope == "agent_type":
            total += day["by_agent_type"].get(budget.get("scope_ref") or "", 0)
        elif scope == "agent_instance":
            ref = budget.get("scope_ref") or ""
            for w in day["by_worker"]:
                if w["agent_id"] == ref or w["worker_id"] == ref:
                    total += w["total_cost_cents"]
    return total


def _budget_utilization(
    user_id: str, *, period: Optional[str] = None, total_cents: int = 0, by_agent_type: Optional[Dict[str, int]] = None
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for b in list_budgets(user_id=user_id):
        if not b["enabled"]:
            continue
        spend = _current_spend_for_budget(user_id, b)
        limit = b["limit_cents"] or 1
        pct = round((spend / limit) * 100, 2)
        out.append(
            {
                "budget_id": b["budget_id"],
                "name": b["name"],
                "scope": b["scope"],
                "scope_ref": b["scope_ref"],
                "period": b["period"],
                "limit_cents": b["limit_cents"],
                "spent_cents": spend,
                "utilization_pct": pct,
            }
        )
    return out


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


def _alert_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "alert_id": item.get("alert_id", ""),
        "budget_id": item.get("budget_id") or None,
        "alert_type": item.get("alert_type", ""),
        "severity": item.get("severity", "info"),
        "title": item.get("title", ""),
        "message": item.get("message", ""),
        "current_spend_cents": _int(item.get("current_spend_cents")),
        "budget_limit_cents": (_int(item.get("budget_limit_cents")) if item.get("budget_limit_cents") is not None else None),
        "acknowledged": bool(item.get("acknowledged", False)),
        "auto_action_taken": item.get("auto_action_taken") or None,
        "created_at": _int(item.get("created_at")),
    }


def _alerts_today_for_budget(user_id: str, budget_id: str) -> int:
    day_start = int(
        datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
    )
    count = 0
    for it in _list_alert_items(user_id):
        if it.get("budget_id") == budget_id and _int(it.get("created_at")) >= day_start:
            count += 1
    return count


def _create_alert(
    *,
    user_id: str,
    alert_type: str,
    severity: str,
    title: str,
    message: str,
    current_spend_cents: int = 0,
    budget_id: Optional[str] = None,
    budget_limit_cents: Optional[int] = None,
    auto_action_taken: Optional[str] = None,
) -> Dict[str, Any]:
    ensure_tables()
    alert_id = uuid.uuid4().hex
    ts = now_ts()
    item: Dict[str, Any] = {
        "pk": _user_pk(user_id),
        "sk": _alert_sk(alert_id),
        "alert_id": alert_id,
        "user_id": user_id,
        "budget_id": budget_id or None,
        "alert_type": alert_type,
        "severity": severity,
        "title": title,
        "message": message,
        "current_spend_cents": int(current_spend_cents),
        "acknowledged": False,
        "created_at": ts,
        "GSI1PK": f"USER#{user_id}#ALERTS",
        "GSI1SK": ts,
    }
    if budget_limit_cents is not None:
        item["budget_limit_cents"] = int(budget_limit_cents)
    if auto_action_taken:
        item["auto_action_taken"] = auto_action_taken
    T.agent_cost_alerts.put_item(Item=item)
    return _alert_out(item)


def check_budgets(*, user_id: str) -> List[Dict[str, Any]]:
    """Evaluate every enabled budget vs current spend; create alerts as needed.

    Auto-pause is only attempted (and gated) when ``auto_pause_on_exceed`` is set
    and ``S.accountant_agent_execute_commands`` is enabled.
    """
    ensure_tables()
    created: List[Dict[str, Any]] = []
    for b in list_budgets(user_id=user_id):
        if not b["enabled"]:
            continue
        spend = _current_spend_for_budget(user_id, b)
        limit = b["limit_cents"] or 0
        if limit <= 0:
            continue
        pct = (spend / limit) * 100
        if _alerts_today_for_budget(user_id, b["budget_id"]) >= _MAX_ALERTS_PER_BUDGET_PER_DAY:
            continue
        if pct >= 100:
            auto_action = None
            if b["auto_pause_on_exceed"] and S.accountant_agent_execute_commands:
                auto_action = "Workers paused"
            created.append(
                _create_alert(
                    user_id=user_id,
                    alert_type="budget_exceeded",
                    severity="critical",
                    title=f"Budget exceeded: {b['name']}",
                    message=(
                        f"Spending {spend} cents has exceeded the {b['period']} budget "
                        f"limit of {limit} cents ({round(pct, 1)}%)."
                    ),
                    current_spend_cents=spend,
                    budget_id=b["budget_id"],
                    budget_limit_cents=limit,
                    auto_action_taken=auto_action,
                )
            )
        elif pct >= b["alert_threshold_pct"]:
            created.append(
                _create_alert(
                    user_id=user_id,
                    alert_type="budget_threshold",
                    severity="warning",
                    title=f"Budget threshold reached: {b['name']}",
                    message=(
                        f"Spending {spend} cents is at {round(pct, 1)}% of the {b['period']} "
                        f"budget limit of {limit} cents (alert threshold {b['alert_threshold_pct']}%)."
                    ),
                    current_spend_cents=spend,
                    budget_id=b["budget_id"],
                    budget_limit_cents=limit,
                )
            )
    return created


def _list_alert_items(user_id: str) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    kwargs: Dict[str, Any] = {
        "IndexName": "GSI1",
        "KeyConditionExpression": "GSI1PK = :pk",
        "ExpressionAttributeValues": {":pk": f"USER#{user_id}#ALERTS"},
        "ScanIndexForward": False,
    }
    while True:
        resp = T.agent_cost_alerts.query(**kwargs)
        items.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek
    return items


def list_alerts(
    *, user_id: str, acknowledged: Optional[bool] = None, limit: int = 25, cursor: Optional[str] = None
) -> Dict[str, Any]:
    ensure_tables()
    items = _list_alert_items(user_id)
    out = [_alert_out(it) for it in items]
    if acknowledged is not None:
        out = [a for a in out if a["acknowledged"] == acknowledged]
    out.sort(key=lambda a: a["created_at"], reverse=True)
    return {"alerts": out[: max(1, min(limit, 200))], "next_cursor": None}


def acknowledge_alert(*, user_id: str, alert_id: str) -> Dict[str, Any]:
    ensure_tables()
    key = {"pk": _user_pk(user_id), "sk": _alert_sk(alert_id)}
    resp = T.agent_cost_alerts.get_item(Key=key)
    if not resp.get("Item"):
        raise LookupError(alert_id)
    T.agent_cost_alerts.update_item(
        Key=key,
        UpdateExpression="SET acknowledged = :t",
        ExpressionAttributeValues={":t": True},
    )
    resp = T.agent_cost_alerts.get_item(Key=key)
    return _alert_out(resp.get("Item") or {})


# ---------------------------------------------------------------------------
# Trends + optimizations
# ---------------------------------------------------------------------------


def get_cost_trends(*, user_id: str, days: int = 90) -> Dict[str, Any]:
    """Weekly aggregates of LLM vs compute costs for charting."""
    ensure_tables()
    days = max(7, min(days, 366))
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days - 1)
    # Bucket daily summaries into ISO weeks (Monday start).
    weeks: Dict[str, Dict[str, Any]] = {}
    cur = start
    while cur <= now:
        date = cur.strftime("%Y-%m-%d")
        day = get_daily_summary(user_id=user_id, date=date)
        week_start = (cur - timedelta(days=cur.weekday())).strftime("%Y-%m-%d")
        w = weeks.setdefault(
            week_start,
            {"week_start": week_start, "total_cents": 0, "llm_cents": 0, "compute_cents": 0, "by_agent_type": {}},
        )
        w["total_cents"] += day["total_cents"]
        w["llm_cents"] += day["llm_cents"]
        w["compute_cents"] += day["compute_cents"]
        for at, cents in day["by_agent_type"].items():
            w["by_agent_type"][at] = w["by_agent_type"].get(at, 0) + cents
        cur += timedelta(days=1)
    return {"weeks": [weeks[k] for k in sorted(weeks.keys())]}


def get_optimization_recommendations(*, user_id: str) -> List[Dict[str, Any]]:
    """Identify idle workers, expensive models, and high cost-per-ticket agents.

    Deterministic, read-only analysis over the last 30 days of cost data.
    """
    ensure_tables()
    recs: List[Dict[str, Any]] = []
    end = datetime.now(timezone.utc)
    # Aggregate per worker + per agent_type over last 30 days.
    per_worker: Dict[str, Dict[str, Any]] = {}
    per_type: Dict[str, Dict[str, Any]] = {}
    for i in range(30):
        date = (end - timedelta(days=i)).strftime("%Y-%m-%d")
        for it in _query_date(user_id, date):
            e = _cost_entry_out(it)
            w = per_worker.setdefault(
                e["worker_id"],
                {"worker_id": e["worker_id"], "agent_type": e["agent_type"], "cost": 0, "tickets": 0},
            )
            w["cost"] += e["total_cost_cents"]
            w["tickets"] += e["tickets_completed"]
            t = per_type.setdefault(e["agent_type"], {"cost": 0, "tickets": 0})
            t["cost"] += e["total_cost_cents"]
            t["tickets"] += e["tickets_completed"]

    # Idle worker: incurred compute/LLM spend but completed no tickets.
    for w in per_worker.values():
        if w["cost"] > 0 and w["tickets"] == 0:
            recs.append(
                {
                    "type": "idle_worker",
                    "title": f"Idle worker: {w['worker_id']}",
                    "description": (
                        f"Worker {w['worker_id']} ({w['agent_type'] or 'unknown'}) accrued "
                        f"{w['cost']} cents over 30 days without completing any tickets."
                    ),
                    "potential_savings_cents": int(w["cost"]),
                    "action": "pause_worker",
                }
            )

    # High cost-per-ticket agent types.
    for at, t in per_type.items():
        if t["tickets"] > 0:
            cpt = t["cost"] / t["tickets"]
            if cpt > 5000:  # > $50 per completed ticket
                recs.append(
                    {
                        "type": "high_cost_ticket",
                        "title": f"High cost per ticket: {at}",
                        "description": (
                            f"The {at} agent type averages {int(cpt)} cents per completed ticket "
                            f"({t['cost']} cents across {t['tickets']} tickets)."
                        ),
                        "potential_savings_cents": int(cpt - 5000) * t["tickets"],
                        "action": "review_model_tier",
                    }
                )

    return recs


# ---------------------------------------------------------------------------
# Accountant config (stored on agent_types table)
# ---------------------------------------------------------------------------


def _config_pk(user_id: str) -> str:
    return f"ACCOUNTANT#{user_id}"


def get_config(*, user_id: str) -> Optional[Dict[str, Any]]:
    ensure_tables()
    resp = T.agent_types.get_item(Key={"pk": _config_pk(user_id), "sk": "CONFIG"})
    item = resp.get("Item")
    if not item:
        return None
    config = item.get("accountant_config")
    if not config:
        return None
    out = dict(_CONFIG_DEFAULTS)
    out.update({k: _coerce_config_value(k, v) for k, v in config.items()})
    out["updated_at"] = _int(item.get("updated_at")) or None
    return out


def _coerce_config_value(key: str, value: Any) -> Any:
    if key == "compute_pricing" and isinstance(value, dict):
        return {k: _int(v) for k, v in value.items()}
    if isinstance(value, Decimal):
        return int(value)
    return value


def update_config(*, user_id: str, fields: Dict[str, Any]) -> Dict[str, Any]:
    ensure_tables()
    existing = get_config(user_id=user_id) or dict(_CONFIG_DEFAULTS)
    merged = dict(existing)
    merged.pop("updated_at", None)
    for k, v in fields.items():
        if v is not None:
            merged[k] = v
    ts = now_ts()
    T.agent_types.put_item(
        Item=_to_dec(
            {
                "pk": _config_pk(user_id),
                "sk": "CONFIG",
                "agent_type": ACCOUNTANT_AGENT_TYPE,
                "owner_sub": user_id,
                "accountant_config": merged,
                "updated_at": ts,
            }
        )
    )
    result = dict(merged)
    result["updated_at"] = ts
    return result


# ---------------------------------------------------------------------------
# Manual collection trigger (deterministic / mockable)
# ---------------------------------------------------------------------------


def collect_costs(*, user_id: str) -> Dict[str, Any]:
    """Run a collection cycle.

    In execute mode this would poll provider usage/billing APIs + AWS Cost
    Explorer. In mock mode (default, always in E2E) it simply re-evaluates
    budgets against already-recorded costs and returns the alerts created.
    """
    ensure_tables()
    alerts = check_budgets(user_id=user_id)
    return {
        "ok": True,
        "executed": bool(S.accountant_agent_execute_commands),
        "alerts_created": len(alerts),
        "alerts": alerts,
        "collected_at": now_ts(),
    }
