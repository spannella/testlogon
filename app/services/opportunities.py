"""Sales pipeline — Opportunities service (OPP-002..OPP-006)."""
from __future__ import annotations

import calendar
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from boto3.dynamodb.conditions import Attr, Key
from fastapi import HTTPException

from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.models import (
    LEAD_SOURCE_CHOICES,
    OPPORTUNITY_STAGES,
    ForecastWorksheetIn,
    ForecastWorksheetOut,
    OppContactRoleIn,
    OppContactRoleOut,
    OpportunityCreateIn,
    OpportunityOut,
    OpportunityUpdateIn,
    PipelineReportOut,
    PipelineStageMetric,
    SalesQuotaIn,
    SalesQuotaListOut,
    SalesQuotaOut,
    StageConfigIn,
    StageConfigItemOut,
    StageConfigOut,
)
from app.services.alerts import audit_event

# ── Contact role constants ────────────────────────────────────────────────────

CONTACT_ROLES = (
    "decision_maker",
    "evaluator",
    "influencer",
    "champion",
    "end_user",
    "executive_sponsor",
    "technical_buyer",
    "other",
)

# ── Feature flag guard ────────────────────────────────────────────────────────


def _require_flag() -> None:
    """Raise HTTP 503 when the sales pipeline feature is disabled."""
    if not S.sales_pipeline_enabled:
        raise HTTPException(503, detail={"code": "sales_pipeline_disabled"})


# ── OPP-002: Opportunity CRUD helpers ─────────────────────────────────────────


def _item_to_out(item: dict) -> OpportunityOut:
    """Convert a raw DDB item to OpportunityOut; raises 404 for soft-deleted."""
    if item.get("deleted_at"):
        raise HTTPException(404, detail={"code": "opportunity_not_found"})
    return OpportunityOut(
        opp_id=item["opp_id"],
        owner_sub=item["owner_sub"],
        name=item["name"],
        stage=item["stage"],
        amount_cents=int(item["amount_cents"]),
        weighted_amount_cents=int(item["weighted_amount_cents"]),
        close_date=int(item["close_date"]),
        probability=int(item["probability"]),
        lead_source=item.get("lead_source"),
        description=item.get("description"),
        account_party_id=item.get("account_party_id"),
        contact_party_id=item.get("contact_party_id"),
        created_at=int(item["created_at"]),
        updated_at=int(item["updated_at"]),
    )


def create_opportunity(
    owner_sub: str,
    data: OpportunityCreateIn,
    request=None,
) -> OpportunityOut:
    _require_flag()
    if data.stage not in OPPORTUNITY_STAGES:
        raise HTTPException(400, detail={"code": "invalid_stage", "stage": data.stage})
    if data.lead_source is not None and data.lead_source not in LEAD_SOURCE_CHOICES:
        raise HTTPException(400, detail={"code": "invalid_lead_source"})

    opp_id = "opp_" + uuid4().hex
    ts = now_ts()
    weighted = data.amount_cents * data.probability // 100
    item: Dict[str, Any] = {
        "pk": f"USER#{owner_sub}",
        "sk": f"OPP#{opp_id}",
        "opp_id": opp_id,
        "owner_sub": owner_sub,
        "name": data.name,
        "stage": data.stage,
        "amount_cents": data.amount_cents,
        "weighted_amount_cents": weighted,
        "close_date": data.close_date,
        "probability": data.probability,
        "lead_source": data.lead_source,
        "description": data.description,
        "account_party_id": data.account_party_id,
        "contact_party_id": data.contact_party_id,
        "created_at": ts,
        "updated_at": ts,
    }
    # Strip None values — DynamoDB cannot store NULL as a GSI key attribute.
    item = {k: v for k, v in item.items() if v is not None}
    T.sales_opportunities.put_item(Item=item)
    audit_event("opportunity.created", owner_sub, request, opp_id=opp_id, stage=data.stage)
    return _item_to_out(item)


def get_opportunity(owner_sub: str, opp_id: str) -> OpportunityOut:
    _require_flag()
    resp = T.sales_opportunities.get_item(
        Key={"pk": f"USER#{owner_sub}", "sk": f"OPP#{opp_id}"}
    )
    item = resp.get("Item")
    if not item:
        raise HTTPException(404, detail={"code": "opportunity_not_found"})
    return _item_to_out(item)


def update_opportunity(
    owner_sub: str,
    opp_id: str,
    data: OpportunityUpdateIn,
    request=None,
) -> OpportunityOut:
    _require_flag()
    current = get_opportunity(owner_sub, opp_id)

    if data.stage is not None and data.stage not in OPPORTUNITY_STAGES:
        raise HTTPException(400, detail={"code": "invalid_stage"})
    if data.lead_source is not None and data.lead_source not in LEAD_SOURCE_CHOICES:
        raise HTTPException(400, detail={"code": "invalid_lead_source"})

    # OPP-003: validate stage transition when changing stage
    if data.stage is not None and data.stage != current.stage:
        config = get_stage_config()
        # Check if new stage is in the config
        valid_stage_keys = {s.stage_key for s in config.stages}
        if valid_stage_keys and data.stage not in valid_stage_keys:
            raise HTTPException(400, detail={"code": "invalid_stage", "stage": data.stage})

        won_key = next((s.stage_key for s in config.stages if s.is_won), "closed_won")
        lost_key = next((s.stage_key for s in config.stages if s.is_lost), "closed_lost")
        terminal_keys = {won_key, lost_key}

        if current.stage in terminal_keys:
            if not S.sales_pipeline_allow_reopen:
                raise HTTPException(400, detail={
                    "code": "stage_transition_blocked",
                    "reason": "opportunity_is_closed",
                    "current_stage": current.stage,
                })
            negotiation_key = _reopen_target_stage(config)
            if data.stage != negotiation_key:
                raise HTTPException(400, detail={
                    "code": "stage_transition_blocked",
                    "reason": "closed_opportunity_may_only_reopen_to_negotiation",
                    "allowed_target": negotiation_key,
                })

        audit_event(
            "opportunity.stage_changed",
            owner_sub,
            None,
            opp_id=opp_id,
            from_stage=current.stage,
            to_stage=data.stage,
        )

    ts = now_ts()
    new_amount = data.amount_cents if data.amount_cents is not None else current.amount_cents
    new_prob = data.probability if data.probability is not None else current.probability
    new_weighted = new_amount * new_prob // 100

    set_parts = ["#updated_at = :updated_at", "weighted_amount_cents = :weighted"]
    expr_names: Dict[str, str] = {"#updated_at": "updated_at"}
    expr_values: Dict[str, Any] = {
        ":updated_at": ts,
        ":weighted": new_weighted,
        ":cond_updated_at": current.updated_at,
    }
    field_map = {
        "name": data.name,
        "stage": data.stage,
        "amount_cents": data.amount_cents,
        "close_date": data.close_date,
        "probability": data.probability,
        "lead_source": data.lead_source,
        "description": data.description,
        "account_party_id": data.account_party_id,
        "contact_party_id": data.contact_party_id,
    }
    for attr, val in field_map.items():
        if val is not None:
            safe_name = f"#{attr}"
            set_parts.append(f"{safe_name} = :{attr}")
            expr_names[safe_name] = attr
            expr_values[f":{attr}"] = val

    T.sales_opportunities.update_item(
        Key={"pk": f"USER#{owner_sub}", "sk": f"OPP#{opp_id}"},
        UpdateExpression="SET " + ", ".join(set_parts),
        ConditionExpression="#updated_at = :cond_updated_at",
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_values,
    )
    audit_event("opportunity.updated", owner_sub, request, opp_id=opp_id)
    return get_opportunity(owner_sub, opp_id)


def delete_opportunity(owner_sub: str, opp_id: str, request=None) -> None:
    _require_flag()
    get_opportunity(owner_sub, opp_id)  # 404 if missing or wrong owner
    ts = now_ts()
    T.sales_opportunities.update_item(
        Key={"pk": f"USER#{owner_sub}", "sk": f"OPP#{opp_id}"},
        UpdateExpression="SET deleted_at = :ts",
        ExpressionAttributeValues={":ts": ts},
    )
    audit_event("opportunity.deleted", owner_sub, request, opp_id=opp_id)


def list_opportunities(
    owner_sub: str,
    stage: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> Tuple[List[OpportunityOut], Optional[str]]:
    _require_flag()
    limit = max(1, min(limit, 200))
    exclusive_start = decode_cursor(cursor)

    items: List[dict] = []
    last_key = exclusive_start
    while True:
        filter_expr = Attr("deleted_at").not_exists()
        if stage:
            filter_expr = filter_expr & Attr("stage").eq(stage)
        kwargs: Dict[str, Any] = {
            "IndexName": "GSI_BY_USER_CLOSE",
            "KeyConditionExpression": Key("owner_sub").eq(owner_sub),
            "FilterExpression": filter_expr,
            "Limit": limit * 4,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key

        resp = T.sales_opportunities.query(**kwargs)
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")

        if len(items) >= limit or not last_key:
            break

    result_items = items[:limit]
    next_cursor: Optional[str] = None
    if len(items) > limit or last_key:
        last_item = result_items[-1] if result_items else None
        if last_item:
            lek = {
                "pk": last_item["pk"],
                "sk": last_item["sk"],
                "owner_sub": last_item["owner_sub"],
                "close_date": last_item["close_date"],
            }
            next_cursor = encode_cursor(lek)

    return [_item_to_out(i) for i in result_items], next_cursor


# ── OPP-003: Stage pipeline config ───────────────────────────────────────────


def _default_stage_config() -> StageConfigOut:
    """Build a default stage config from OPPORTUNITY_STAGES tuple."""
    stages = []
    for i, stage_key in enumerate(OPPORTUNITY_STAGES):
        stages.append(StageConfigItemOut(
            stage_key=stage_key,
            label=stage_key.replace("_", " ").title(),
            probability_default=0,
            order=i,
            is_won=(stage_key == "closed_won"),
            is_lost=(stage_key == "closed_lost"),
            color=None,
        ))
    return StageConfigOut(stages=stages, updated_at=None, updated_by_sub=None)


def _reopen_target_stage(config: StageConfigOut) -> str:
    """Return the highest-ordered non-terminal stage key for reopen transitions."""
    active = [s for s in config.stages if not s.is_won and not s.is_lost]
    if not active:
        return config.stages[0].stage_key if config.stages else "negotiation_review"
    return max(active, key=lambda s: s.order).stage_key


def _validate_stage_config(data: StageConfigIn) -> None:
    """Raise HTTP 400 if the stage config violates constraints."""
    won_count = sum(1 for s in data.stages if s.is_won)
    lost_count = sum(1 for s in data.stages if s.is_lost)
    if won_count != 1:
        raise HTTPException(400, detail={"code": "invalid_stage_config", "reason": "exactly_one_is_won_required"})
    if lost_count != 1:
        raise HTTPException(400, detail={"code": "invalid_stage_config", "reason": "exactly_one_is_lost_required"})
    keys = [s.stage_key for s in data.stages]
    if len(keys) != len(set(keys)):
        raise HTTPException(400, detail={"code": "invalid_stage_config", "reason": "duplicate_stage_key"})
    if len(data.stages) < 1:
        raise HTTPException(400, detail={"code": "invalid_stage_config", "reason": "stages_empty"})


def get_stage_config() -> StageConfigOut:
    _require_flag()
    item = T.sales_opportunities.get_item(
        Key={"pk": "STAGE_CONFIG", "sk": "META"}
    ).get("Item")
    if not item:
        return _default_stage_config()
    raw = item.get("stages")
    if isinstance(raw, str):
        stages_list = json.loads(raw)
    else:
        stages_list = raw or []
    return StageConfigOut(
        stages=[StageConfigItemOut(**s) for s in stages_list],
        updated_at=int(item.get("updated_at", 0)) or None,
        updated_by_sub=item.get("updated_by_sub"),
    )


def set_stage_config(admin_sub: str, data: StageConfigIn) -> StageConfigOut:
    _require_flag()
    _validate_stage_config(data)
    now = now_ts()
    payload = {
        "pk": "STAGE_CONFIG",
        "sk": "META",
        "stages": json.dumps([s.model_dump() for s in data.stages]),
        "updated_at": now,
        "updated_by_sub": admin_sub,
    }
    T.sales_opportunities.put_item(Item=payload)
    audit_event(
        "sales_stage_config.updated",
        admin_sub,
        None,
        stage_count=len(data.stages),
        won_key=next(s.stage_key for s in data.stages if s.is_won),
        lost_key=next(s.stage_key for s in data.stages if s.is_lost),
    )
    return get_stage_config()


# ── OPP-004: Contact-role junction ───────────────────────────────────────────


def _contact_item_to_out(item: dict) -> OppContactRoleOut:
    return OppContactRoleOut(
        opp_id=item["opp_id"],
        contact_ref=item["contact_ref"],
        contact_role=item["contact_role"],
        owner_sub=item["owner_sub"],
        created_at=int(item["created_at"]),
    )


def add_contact_role(
    owner_sub: str,
    opp_id: str,
    data: OppContactRoleIn,
) -> OppContactRoleOut:
    _require_flag()
    get_opportunity(owner_sub, opp_id)  # ownership gate
    if data.contact_role not in CONTACT_ROLES:
        raise HTTPException(400, detail={"code": "invalid_contact_role"})

    ts = now_ts()
    sk = f"OPP#{opp_id}#CONTACT#{data.contact_ref}"
    item = {
        "pk": f"USER#{owner_sub}",
        "sk": sk,
        "opp_id": opp_id,
        "contact_ref": data.contact_ref,
        "contact_role": data.contact_role,
        "owner_sub": owner_sub,
        "created_at": ts,
    }
    try:
        T.sales_opportunities.put_item(
            Item=item,
            ConditionExpression=Attr("sk").not_exists(),
        )
    except Exception as exc:
        if "ConditionalCheckFailed" in str(type(exc).__name__):
            raise HTTPException(409, detail={"code": "contact_role_exists"})
        raise
    audit_event(
        "opportunity.contact_role_added",
        owner_sub,
        None,
        opp_id=opp_id,
        contact_ref=data.contact_ref,
        contact_role=data.contact_role,
    )
    return _contact_item_to_out(item)


def list_contact_roles(owner_sub: str, opp_id: str) -> List[OppContactRoleOut]:
    _require_flag()
    get_opportunity(owner_sub, opp_id)  # ownership gate

    items: List[dict] = []
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": (
                Key("pk").eq(f"USER#{owner_sub}") &
                Key("sk").begins_with(f"OPP#{opp_id}#CONTACT#")
            ),
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.sales_opportunities.query(**kwargs)
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    results = [_contact_item_to_out(i) for i in items]
    results.sort(key=lambda r: r.created_at)
    return results


def remove_contact_role(owner_sub: str, opp_id: str, contact_ref: str) -> None:
    _require_flag()
    get_opportunity(owner_sub, opp_id)  # ownership gate

    sk = f"OPP#{opp_id}#CONTACT#{contact_ref}"
    resp = T.sales_opportunities.get_item(Key={"pk": f"USER#{owner_sub}", "sk": sk})
    if not resp.get("Item"):
        raise HTTPException(404, detail={"code": "contact_role_not_found"})

    T.sales_opportunities.delete_item(Key={"pk": f"USER#{owner_sub}", "sk": sk})
    audit_event(
        "opportunity.contact_role_removed",
        owner_sub,
        None,
        opp_id=opp_id,
        contact_ref=contact_ref,
    )


# ── OPP-005: Period parsing ───────────────────────────────────────────────────

_RE_MONTHLY = re.compile(r"^\d{4}-(0[1-9]|1[0-2])$")
_RE_QUARTERLY = re.compile(r"^\d{4}-Q[1-4]$")
_RE_ANNUAL = re.compile(r"^\d{4}$")


def _parse_period_key(period_key: str) -> Tuple[int, int]:
    """Return (ts_from, ts_to) Unix-second inclusive boundaries for the period."""
    if _RE_MONTHLY.match(period_key):
        year, month = int(period_key[:4]), int(period_key[5:])
        _, last_day = calendar.monthrange(year, month)
        ts_from = int(datetime(year, month, 1, 0, 0, 0, tzinfo=timezone.utc).timestamp())
        ts_to = int(datetime(year, month, last_day, 23, 59, 59, tzinfo=timezone.utc).timestamp())
        return ts_from, ts_to
    if _RE_QUARTERLY.match(period_key):
        year = int(period_key[:4])
        q = int(period_key[6])
        start_month = (q - 1) * 3 + 1
        end_month = start_month + 2
        _, last_day = calendar.monthrange(year, end_month)
        ts_from = int(datetime(year, start_month, 1, 0, 0, 0, tzinfo=timezone.utc).timestamp())
        ts_to = int(datetime(year, end_month, last_day, 23, 59, 59, tzinfo=timezone.utc).timestamp())
        return ts_from, ts_to
    if _RE_ANNUAL.match(period_key):
        year = int(period_key)
        ts_from = int(datetime(year, 1, 1, 0, 0, 0, tzinfo=timezone.utc).timestamp())
        ts_to = int(datetime(year, 12, 31, 23, 59, 59, tzinfo=timezone.utc).timestamp())
        return ts_from, ts_to
    raise HTTPException(400, detail={"code": "invalid_period_key"})


# ── OPP-005: Quota functions ──────────────────────────────────────────────────


def _quota_item_to_out(item: dict) -> SalesQuotaOut:
    return SalesQuotaOut(
        user_sub=item["user_sub"],
        period_type=item["period_type"],
        period_key=item["period_key"],
        target_amount_cents=int(item["target_amount_cents"]),
        created_at=int(item["created_at"]),
        updated_at=int(item["updated_at"]),
        set_by_sub=item["set_by_sub"],
    )


def set_quota(admin_sub: str, data: SalesQuotaIn) -> SalesQuotaOut:
    _require_flag()
    _parse_period_key(data.period_key)  # validate format
    ts = now_ts()
    item = {
        "pk": f"USER#{data.user_sub}",
        "sk": f"QUOTA#{data.period_key}",
        "user_sub": data.user_sub,
        "period_type": data.period_type,
        "period_key": data.period_key,
        "target_amount_cents": data.target_amount_cents,
        "created_at": ts,
        "updated_at": ts,
        "set_by_sub": admin_sub,
    }
    T.sales_quotas.put_item(Item=item)
    audit_event(
        "quota.set",
        admin_sub,
        None,
        user_sub=data.user_sub,
        period_key=data.period_key,
        target_amount_cents=data.target_amount_cents,
    )
    return _quota_item_to_out(item)


def get_quota(user_sub: str, period_key: str) -> Optional[SalesQuotaOut]:
    _require_flag()
    resp = T.sales_quotas.get_item(
        Key={"pk": f"USER#{user_sub}", "sk": f"QUOTA#{period_key}"}
    )
    item = resp.get("Item")
    if not item:
        return None
    return _quota_item_to_out(item)


def list_quotas_for_user(
    user_sub: str,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> Tuple[List[SalesQuotaOut], Optional[str]]:
    _require_flag()
    limit = max(1, min(limit, 200))
    exclusive_start = decode_cursor(cursor)

    items: List[dict] = []
    last_key = exclusive_start
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": (
                Key("pk").eq(f"USER#{user_sub}") &
                Key("sk").begins_with("QUOTA#")
            ),
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = T.sales_quotas.query(**kwargs)
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if len(items) >= limit or not last_key:
            break

    result_items = items[:limit]
    next_cursor: Optional[str] = None
    if len(items) > limit or last_key:
        last_item = result_items[-1] if result_items else None
        if last_item:
            lek = {"pk": last_item["pk"], "sk": last_item["sk"]}
            next_cursor = encode_cursor(lek)

    return [_quota_item_to_out(i) for i in result_items], next_cursor


# ── OPP-005: Forecast worksheet ──────────────────────────────────────────────


def _compute_closed_cents(user_sub: str, ts_from: int, ts_to: int) -> int:
    """Aggregate amount_cents of closed_won opportunities via GSI_BY_USER_CLOSE."""
    closed_cents = 0
    lek = None
    while True:
        kwargs: Dict[str, Any] = {
            "IndexName": "GSI_BY_USER_CLOSE",
            "KeyConditionExpression": (
                Key("owner_sub").eq(user_sub) &
                Key("close_date").between(ts_from, ts_to)
            ),
            "FilterExpression": (
                Attr("stage").eq("closed_won") & Attr("sk").begins_with("OPP#")
            ),
        }
        if lek:
            kwargs["ExclusiveStartKey"] = lek
        resp = T.sales_opportunities.query(**kwargs)
        for item in resp.get("Items", []):
            closed_cents += int(item.get("amount_cents", 0))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
    return closed_cents


def upsert_forecast(user_sub: str, period_key: str, data: ForecastWorksheetIn) -> ForecastWorksheetOut:
    _require_flag()
    ts_from, ts_to = _parse_period_key(period_key)
    closed_cents = _compute_closed_cents(user_sub, ts_from, ts_to)
    quota = get_quota(user_sub, period_key)
    quota_cents = quota.target_amount_cents if quota else 0
    attainment_pct = (closed_cents * 100 // quota_cents) if quota_cents > 0 else 0

    ts = now_ts()
    # Preserve created_at if row already exists
    existing = T.sales_opportunities.get_item(
        Key={"pk": f"USER#{user_sub}", "sk": f"FORECAST#{period_key}"}
    ).get("Item")
    created_at = int(existing["created_at"]) if existing else ts

    item = {
        "pk": f"USER#{user_sub}",
        "sk": f"FORECAST#{period_key}",
        "user_sub": user_sub,
        "period_key": period_key,
        "committed_cents": data.committed_cents,
        "best_case_cents": data.best_case_cents,
        "pipeline_cents": data.pipeline_cents,
        "notes": data.notes,
        "created_at": created_at,
        "updated_at": ts,
    }
    item = {k: v for k, v in item.items() if v is not None}
    T.sales_opportunities.put_item(Item=item)
    audit_event("forecast.upserted", user_sub, None, period_key=period_key)

    return ForecastWorksheetOut(
        user_sub=user_sub,
        period_key=period_key,
        committed_cents=data.committed_cents,
        best_case_cents=data.best_case_cents,
        pipeline_cents=data.pipeline_cents,
        closed_cents=closed_cents,
        quota_cents=quota_cents,
        attainment_pct=attainment_pct,
        notes=data.notes,
        created_at=created_at,
        updated_at=ts,
    )


def get_forecast(user_sub: str, period_key: str) -> ForecastWorksheetOut:
    _require_flag()
    ts_from, ts_to = _parse_period_key(period_key)
    item = T.sales_opportunities.get_item(
        Key={"pk": f"USER#{user_sub}", "sk": f"FORECAST#{period_key}"}
    ).get("Item")
    if not item:
        raise HTTPException(404, detail={"code": "forecast_not_found"})

    closed_cents = _compute_closed_cents(user_sub, ts_from, ts_to)
    quota = get_quota(user_sub, period_key)
    quota_cents = quota.target_amount_cents if quota else 0
    attainment_pct = (closed_cents * 100 // quota_cents) if quota_cents > 0 else 0

    return ForecastWorksheetOut(
        user_sub=user_sub,
        period_key=period_key,
        committed_cents=int(item.get("committed_cents", 0)),
        best_case_cents=int(item.get("best_case_cents", 0)),
        pipeline_cents=int(item.get("pipeline_cents", 0)),
        closed_cents=closed_cents,
        quota_cents=quota_cents,
        attainment_pct=attainment_pct,
        notes=item.get("notes"),
        created_at=int(item["created_at"]),
        updated_at=int(item["updated_at"]),
    )


# ── OPP-006: Pipeline funnel report ──────────────────────────────────────────


def _load_stage_config_raw() -> List[Dict[str, Any]]:
    """Return ordered stage config list; falls back to OPPORTUNITY_STAGES tuple."""
    row = T.sales_opportunities.get_item(
        Key={"pk": "STAGE_CONFIG", "sk": "META"}
    ).get("Item")
    if row:
        raw = row.get("stages")
        if isinstance(raw, str):
            stages_list = json.loads(raw)
        else:
            stages_list = raw or []
        if stages_list:
            return sorted(stages_list, key=lambda s: s.get("order", 0))
    return [
        {
            "stage_key": s,
            "label": s.replace("_", " ").title(),
            "order": i,
            "is_won": s == "closed_won",
            "is_lost": s == "closed_lost",
        }
        for i, s in enumerate(OPPORTUNITY_STAGES)
    ]


def pipeline_report(
    owner_sub: str,
    close_date_from: Optional[int] = None,
    close_date_to: Optional[int] = None,
) -> PipelineReportOut:
    """Per-rep funnel report."""
    _require_flag()
    stage_config = _load_stage_config_raw()

    # Build key condition
    kce = Key("owner_sub").eq(owner_sub)
    if close_date_from is not None and close_date_to is not None:
        kce = kce & Key("close_date").between(close_date_from, close_date_to)
    elif close_date_from is not None:
        kce = kce & Key("close_date").gte(close_date_from)
    elif close_date_to is not None:
        kce = kce & Key("close_date").lte(close_date_to)

    all_items: List[dict] = []
    lek = None
    while True:
        kwargs: Dict[str, Any] = {
            "IndexName": "GSI_BY_USER_CLOSE",
            "KeyConditionExpression": kce,
        }
        if lek:
            kwargs["ExclusiveStartKey"] = lek
        resp = T.sales_opportunities.query(**kwargs)
        all_items.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break

    # Filter in Python: only OPP# rows, not soft-deleted
    opp_items = [
        i for i in all_items
        if i.get("sk", "").startswith("OPP#") and not i.get("deleted_at")
    ]

    return _build_report(opp_items, stage_config)


def pipeline_report_all(
    admin_sub: str,
    close_date_from: Optional[int] = None,
    close_date_to: Optional[int] = None,
) -> PipelineReportOut:
    """Admin cross-user funnel report via GSI_BY_STAGE."""
    _require_flag()
    stage_config = _load_stage_config_raw()
    all_items: List[dict] = []

    for stage_cfg in stage_config:
        stage_key = stage_cfg["stage_key"]
        kce = Key("stage").eq(stage_key)
        if close_date_from is not None and close_date_to is not None:
            kce = kce & Key("close_date").between(close_date_from, close_date_to)
        elif close_date_from is not None:
            kce = kce & Key("close_date").gte(close_date_from)
        elif close_date_to is not None:
            kce = kce & Key("close_date").lte(close_date_to)

        lek = None
        while True:
            kwargs: Dict[str, Any] = {
                "IndexName": "GSI_BY_STAGE",
                "KeyConditionExpression": kce,
            }
            if lek:
                kwargs["ExclusiveStartKey"] = lek
            resp = T.sales_opportunities.query(**kwargs)
            # Filter: only OPP# rows, not soft-deleted
            for item in resp.get("Items", []):
                if item.get("sk", "").startswith("OPP#") and not item.get("deleted_at"):
                    all_items.append(item)
            lek = resp.get("LastEvaluatedKey")
            if not lek:
                break

    audit_event(
        "sales_pipeline_report.admin_accessed",
        admin_sub,
        None,
        close_date_from=close_date_from,
        close_date_to=close_date_to,
    )
    return _build_report(all_items, stage_config)


def _build_report(opp_items: List[dict], stage_config: List[Dict[str, Any]]) -> PipelineReportOut:
    """Build PipelineReportOut from items and stage config."""
    # Initialize buckets
    buckets: Dict[str, Dict[str, Any]] = {}
    for cfg in stage_config:
        sk = cfg["stage_key"]
        buckets[sk] = {
            "stage": sk,
            "label": cfg.get("label", sk),
            "count": 0,
            "total_amount_cents": 0,
            "weighted_amount_cents": 0,
            "sum_close_date": 0,
            "is_won": cfg.get("is_won", False),
            "is_lost": cfg.get("is_lost", False),
        }

    for item in opp_items:
        s = item.get("stage", "")
        if s not in buckets:
            continue  # unknown stage — skip
        b = buckets[s]
        b["count"] += 1
        b["total_amount_cents"] += int(item.get("amount_cents", 0))
        b["weighted_amount_cents"] += int(item.get("weighted_amount_cents", 0))
        b["sum_close_date"] += int(item.get("close_date", 0))

    stages_out = []
    total_amount = 0
    total_weighted = 0
    for cfg in stage_config:
        sk = cfg["stage_key"]
        b = buckets[sk]
        avg_close = b["sum_close_date"] // b["count"] if b["count"] > 0 else None
        stages_out.append(PipelineStageMetric(
            stage=sk,
            label=b["label"],
            count=b["count"],
            total_amount_cents=b["total_amount_cents"],
            weighted_amount_cents=b["weighted_amount_cents"],
            avg_close_date=avg_close,
        ))
        if not b["is_won"] and not b["is_lost"]:
            total_amount += b["total_amount_cents"]
            total_weighted += b["weighted_amount_cents"]

    return PipelineReportOut(
        stages=stages_out,
        total_amount_cents=total_amount,
        total_weighted_cents=total_weighted,
        generated_at=now_ts(),
    )
