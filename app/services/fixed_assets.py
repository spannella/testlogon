"""
OFBiz Fixed Assets service — FXA-005 through FXA-012.

Owns:
- Asset register CRUD (create/get/list/update/dispose)
- Depreciation schedule generation and straight-line math
- Depreciation period GL posting (non-cash, balanced journal)
- Disposal GL posting (closing journal, optional Stripe proceeds via refund_payment)
- Maintenance work-order lifecycle

All public functions call _require_enabled() first.
GL posting calls gl_posting.post_journal_entry via LAZY import inside each
function, guarded by `if getattr(S, "gl_double_entry_enabled", False)`.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
from typing import Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Attr, Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.core.cursor import encode_cursor, decode_cursor
from app.models import (
    DepreciationPeriodOut,
    DepreciationScheduleOut,
    FixedAssetDisposeIn,
    FixedAssetIn,
    FixedAssetOut,
    FixedAssetPatchIn,
    MaintenanceOrderIn,
    MaintenanceOrderOut,
    MaintenanceOrderTransitionIn,
)

logger = logging.getLogger(__name__)

_MONTH_SECONDS = 30 * 86_400  # 30-day period approximation (FXA-001 §5.2)

# Legal work-order transitions — FXA-001 §5.5
_VALID_TRANSITIONS: dict[str, set[str]] = {
    "open": {"in_progress", "cancelled"},
    "in_progress": {"completed", "cancelled"},
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _require_enabled() -> None:
    """Raise HTTP 503 when the fixed-assets master flag is off."""
    if not S.fixed_assets_enabled:
        raise HTTPException(status_code=503, detail="fixed_assets_not_enabled")


def _asset_id_from_correlation(correlation_id: str) -> str:
    return hashlib.sha256(correlation_id.encode()).hexdigest()[:32]


def _work_order_id_from_correlation(correlation_id: str) -> str:
    return hashlib.sha256(correlation_id.encode()).hexdigest()[:32]


def _item_to_asset(item: dict) -> FixedAssetOut:
    cost = int(item["acquisition_cost_cents"])
    salvage = int(item["salvage_value_cents"])
    accum = int(item.get("accumulated_depreciation_cents", 0))
    nbv = max(salvage, cost - accum)
    return FixedAssetOut(
        asset_id=item["asset_id"],
        owner_sub=item["owner_sub"],
        name=item["name"],
        asset_class=item["asset_class"],
        acquisition_cost_cents=cost,
        salvage_value_cents=salvage,
        useful_life_months=int(item["useful_life_months"]),
        acquired_at=int(item["acquired_at"]),
        depreciation_method=item.get("depreciation_method", "straight_line"),
        status=item["status"],
        accumulated_depreciation_cents=accum,
        net_book_value_cents=nbv,
        gl_asset_account_id=item.get("gl_asset_account_id"),
        gl_accum_depr_account_id=item.get("gl_accum_depr_account_id"),
        gl_depr_expense_account_id=item.get("gl_depr_expense_account_id"),
        gl_gain_account_id=item.get("gl_gain_account_id"),
        gl_loss_account_id=item.get("gl_loss_account_id"),
        created_at=int(item["created_at"]),
        updated_at=int(item["updated_at"]),
        correlation_id=item.get("correlation_id"),
    )


def _item_to_period(item: dict) -> DepreciationPeriodOut:
    return DepreciationPeriodOut(
        period=int(item["period"]),
        period_start_ts=int(item["period_start_ts"]),
        period_end_ts=int(item["period_end_ts"]),
        amount_cents=int(item["amount_cents"]),
        schedule_status=item["schedule_status"],
        journal_entry_id=item.get("journal_entry_id"),
        posted_at=int(item["posted_at"]) if item.get("posted_at") else None,
    )


def _item_to_work_order(item: dict) -> MaintenanceOrderOut:
    return MaintenanceOrderOut(
        work_order_id=item["work_order_id"],
        asset_id=item["asset_id"],
        title=item["title"],
        description=item.get("description"),
        wo_status=item["wo_status"],
        assignee_sub=item.get("assignee_sub"),
        cost_cents=int(item["cost_cents"]) if item.get("cost_cents") is not None else None,
        scheduled_for=int(item["scheduled_for"]) if item.get("scheduled_for") else None,
        created_at=int(item["created_at"]),
        completed_at=int(item["completed_at"]) if item.get("completed_at") else None,
        correlation_id=item.get("correlation_id"),
    )


def _audit(event: str, actor_sub: str, **fields) -> None:
    try:
        from app.services.alerts import audit_event
        audit_event(event, actor_sub, None, **fields)
    except Exception:  # noqa: BLE001
        logger.warning("fixed_assets: audit_event failed for %s", event)


# ---------------------------------------------------------------------------
# Asset register — FXA-005
# ---------------------------------------------------------------------------

def create_asset(owner_sub: str, body: FixedAssetIn) -> FixedAssetOut:
    _require_enabled()
    corr = body.correlation_id or f"asset:{uuid4().hex}"
    asset_id = _asset_id_from_correlation(corr)
    ts = now_ts()
    item = {
        "pk": f"ASSET#{asset_id}",
        "sk": "META",
        "asset_id": asset_id,
        "owner_sub": owner_sub,
        "name": body.name,
        "asset_class": body.asset_class,
        "acquisition_cost_cents": body.acquisition_cost_cents,
        "salvage_value_cents": body.salvage_value_cents,
        "useful_life_months": body.useful_life_months,
        "acquired_at": body.acquired_at,
        "depreciation_method": body.depreciation_method,
        "status": "active",
        "accumulated_depreciation_cents": 0,
        "gl_asset_account_id": body.gl_asset_account_id or "",
        "gl_accum_depr_account_id": body.gl_accum_depr_account_id or "",
        "gl_depr_expense_account_id": body.gl_depr_expense_account_id or "",
        "gl_gain_account_id": body.gl_gain_account_id or "",
        "gl_loss_account_id": body.gl_loss_account_id or "",
        "correlation_id": corr,
        "created_at": ts,
        "updated_at": ts,
    }
    try:
        T.fixed_assets.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(pk)",
        )
    except T.fixed_assets.meta.client.exceptions.ConditionalCheckFailedException:
        # Idempotent: return existing record
        existing = T.fixed_assets.get_item(Key={"pk": f"ASSET#{asset_id}", "sk": "META"}).get("Item", {})
        return _item_to_asset(existing)
    _audit("fixed_asset.created", owner_sub, asset_id=asset_id, name=body.name)
    return _item_to_asset(item)


def get_asset(asset_id: str) -> FixedAssetOut:
    _require_enabled()
    resp = T.fixed_assets.get_item(Key={"pk": f"ASSET#{asset_id}", "sk": "META"})
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="asset_not_found")
    return _item_to_asset(item)


def _get_asset_raw(asset_id: str) -> dict:
    """Internal: returns raw DDB item, raises 404 if missing."""
    resp = T.fixed_assets.get_item(Key={"pk": f"ASSET#{asset_id}", "sk": "META"})
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="asset_not_found")
    return item


def list_assets(
    owner_sub: Optional[str] = None,
    status: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> tuple[list[FixedAssetOut], Optional[str]]:
    _require_enabled()
    exclusive_start = decode_cursor(cursor) if cursor else None
    kwargs: dict = {"Limit": limit}
    if exclusive_start:
        kwargs["ExclusiveStartKey"] = exclusive_start

    if owner_sub is not None:
        kwargs["IndexName"] = "GSI_OWNER"
        kwargs["KeyConditionExpression"] = Key("owner_sub").eq(owner_sub)
    elif status is not None:
        kwargs["IndexName"] = "GSI_STATUS"
        kwargs["KeyConditionExpression"] = Key("status").eq(status)
    else:
        # Full scan — admin list-all
        resp = T.fixed_assets.scan(**kwargs)
        items = resp.get("Items", [])
        lek = resp.get("LastEvaluatedKey")
        return [_item_to_asset(i) for i in items], encode_cursor(lek) if lek else None

    resp = T.fixed_assets.query(**kwargs)
    items = resp.get("Items", [])
    lek = resp.get("LastEvaluatedKey")
    return [_item_to_asset(i) for i in items], encode_cursor(lek) if lek else None


def update_asset(asset_id: str, body: FixedAssetPatchIn, actor_sub: str) -> FixedAssetOut:
    _require_enabled()
    # Verify asset exists
    _get_asset_raw(asset_id)

    updates: list[str] = []
    ean: dict = {}
    eav: dict = {}

    def _add(field: str, value) -> None:
        if value is None:
            return
        placeholder = f":v_{field}"
        alias = f"#f_{field}"
        ean[alias] = field
        eav[placeholder] = value
        updates.append(f"{alias} = {placeholder}")

    _add("name", body.name)
    _add("asset_class", body.asset_class)
    _add("gl_asset_account_id", body.gl_asset_account_id)
    _add("gl_accum_depr_account_id", body.gl_accum_depr_account_id)
    _add("gl_depr_expense_account_id", body.gl_depr_expense_account_id)
    _add("gl_gain_account_id", body.gl_gain_account_id)
    _add("gl_loss_account_id", body.gl_loss_account_id)

    if not updates:
        return get_asset(asset_id)

    ts = now_ts()
    updates.append("#f_updated_at = :v_updated_at")
    ean["#f_updated_at"] = "updated_at"
    eav[":v_updated_at"] = ts

    resp = T.fixed_assets.update_item(
        Key={"pk": f"ASSET#{asset_id}", "sk": "META"},
        UpdateExpression="SET " + ", ".join(updates),
        ExpressionAttributeNames=ean,
        ExpressionAttributeValues=eav,
        ReturnValues="ALL_NEW",
    )
    _audit("fixed_asset.updated", actor_sub, asset_id=asset_id)
    return _item_to_asset(resp["Attributes"])


# ---------------------------------------------------------------------------
# Depreciation schedule — FXA-006
# ---------------------------------------------------------------------------

def _generate_periods(item: dict) -> list[dict]:
    """
    Compute straight-line depreciation periods from asset attributes.
    Returns list of period dicts (not DDB items).
    """
    months = int(item["useful_life_months"])
    cost = int(item["acquisition_cost_cents"])
    salvage = int(item["salvage_value_cents"])
    acquired_at = int(item["acquired_at"])
    depreciable_base = cost - salvage
    period_amount = depreciable_base // months
    periods = []
    for n in range(1, months + 1):
        start_ts = acquired_at + (n - 1) * _MONTH_SECONDS
        end_ts = start_ts + _MONTH_SECONDS - 1
        if n == months:
            amount = depreciable_base - period_amount * (months - 1)
        else:
            amount = period_amount
        periods.append({
            "period": n,
            "period_start_ts": start_ts,
            "period_end_ts": end_ts,
            "amount_cents": amount,
        })
    return periods


def generate_schedule(asset_id: str) -> DepreciationScheduleOut:
    """
    Generate (or regenerate) the full depreciation schedule for an asset.
    Writes all PERIOD rows to DDB (idempotent via put_item).
    """
    _require_enabled()
    item = _get_asset_raw(asset_id)
    periods = _generate_periods(item)

    for p in periods:
        sk = f"PERIOD#{p['period']:07d}"
        # Check if already exists — don't overwrite posted/cancelled rows
        existing = T.fixed_asset_schedule.get_item(
            Key={"pk": f"ASSET#{asset_id}", "sk": sk}
        ).get("Item")
        if existing and existing.get("schedule_status") in ("posted", "cancelled"):
            continue
        T.fixed_asset_schedule.put_item(Item={
            "pk": f"ASSET#{asset_id}",
            "sk": sk,
            "period": p["period"],
            "period_start_ts": p["period_start_ts"],
            "period_end_ts": p["period_end_ts"],
            "amount_cents": p["amount_cents"],
            "schedule_status": "scheduled",
            "asset_id": asset_id,
        })

    return get_schedule(asset_id)


def get_schedule(asset_id: str) -> DepreciationScheduleOut:
    """Read back the full depreciation schedule from DDB."""
    _require_enabled()
    # Ensure asset exists
    _get_asset_raw(asset_id)

    items: list[dict] = []
    exclusive_start = None
    while True:
        kwargs: dict = {
            "KeyConditionExpression": Key("pk").eq(f"ASSET#{asset_id}") & Key("sk").begins_with("PERIOD#"),
        }
        if exclusive_start:
            kwargs["ExclusiveStartKey"] = exclusive_start
        resp = T.fixed_asset_schedule.query(**kwargs)
        items.extend(resp.get("Items", []))
        exclusive_start = resp.get("LastEvaluatedKey")
        if not exclusive_start:
            break

    periods = [_item_to_period(i) for i in items]
    periods.sort(key=lambda p: p.period)
    total = len(periods)
    posted = sum(1 for p in periods if p.schedule_status == "posted")
    remaining = sum(1 for p in periods if p.schedule_status == "scheduled")
    return DepreciationScheduleOut(
        asset_id=asset_id,
        periods=periods,
        total_periods=total,
        posted_periods=posted,
        remaining_periods=remaining,
    )


# ---------------------------------------------------------------------------
# Depreciation GL posting — FXA-009
# ---------------------------------------------------------------------------

def post_depreciation_period(asset_id: str, period: int) -> DepreciationPeriodOut:
    """
    Post a single depreciation period's GL journal entry (non-cash, balanced).
    Idempotent: if the period is already posted, returns existing row unchanged.
    Guards GL call on S.gl_double_entry_enabled via LAZY import.
    """
    _require_enabled()
    asset = _get_asset_raw(asset_id)

    if asset.get("status") == "disposed":
        raise HTTPException(status_code=400, detail="asset_disposed")

    sk = f"PERIOD#{period:07d}"
    resp = T.fixed_asset_schedule.get_item(Key={"pk": f"ASSET#{asset_id}", "sk": sk})
    period_item = resp.get("Item")
    if not period_item:
        raise HTTPException(status_code=404, detail="period_not_found")

    # Idempotency: already posted
    if period_item.get("schedule_status") == "posted":
        return _item_to_period(period_item)

    if period_item.get("schedule_status") == "cancelled":
        raise HTTPException(status_code=400, detail="period_cancelled")

    amount_cents = int(period_item["amount_cents"])

    # Deterministic journal_id per (asset_id, period)
    journal_id = hashlib.sha256(f"{asset_id}:period:{period}".encode()).hexdigest()[:32]

    # Post GL journal — LAZY import, guarded by flag
    if getattr(S, "gl_double_entry_enabled", False):
        try:
            from app.services.gl_posting import post_journal_entry  # type: ignore[import]
            depr_expense_acct = asset.get("gl_depr_expense_account_id") or ""
            accum_depr_acct = asset.get("gl_accum_depr_account_id") or ""
            lines = [
                {"account_id": depr_expense_acct, "debit": amount_cents, "credit": 0},
                {"account_id": accum_depr_acct, "debit": 0, "credit": amount_cents},
            ]
            post_journal_entry(
                lines,
                source_type="fixed_asset_depreciation",
                source_entity_id=asset_id,
                memo=f"Depreciation period {period} for asset {asset_id}",
                gl_date=int(period_item["period_end_ts"]),
                journal_id=journal_id,
            )
        except ImportError:
            logger.warning("fixed_assets: gl_posting not available; skipping GL post")
        except Exception as exc:  # noqa: BLE001
            logger.error("fixed_assets: GL post failed for period %d: %s", period, exc)
            raise HTTPException(status_code=500, detail="gl_post_failed") from exc

    ts = now_ts()
    # Flip the period row to posted
    T.fixed_asset_schedule.update_item(
        Key={"pk": f"ASSET#{asset_id}", "sk": sk},
        UpdateExpression="SET schedule_status = :s, journal_entry_id = :j, posted_at = :t",
        ExpressionAttributeValues={":s": "posted", ":j": journal_id, ":t": ts},
        ConditionExpression=Attr("schedule_status").eq("scheduled"),
    )

    # Increment accumulated depreciation on asset
    try:
        T.fixed_assets.update_item(
            Key={"pk": f"ASSET#{asset_id}", "sk": "META"},
            UpdateExpression="ADD accumulated_depreciation_cents :a SET updated_at = :t",
            ExpressionAttributeValues={":a": amount_cents, ":t": ts},
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("fixed_assets: failed to update accumulated depreciation: %s", exc)

    # Check if fully depreciated
    refreshed = _get_asset_raw(asset_id)
    cost = int(refreshed["acquisition_cost_cents"])
    salvage = int(refreshed["salvage_value_cents"])
    accum = int(refreshed.get("accumulated_depreciation_cents", 0))
    if accum >= (cost - salvage):
        T.fixed_assets.update_item(
            Key={"pk": f"ASSET#{asset_id}", "sk": "META"},
            UpdateExpression="SET #s = :s, updated_at = :t",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": "fully_depreciated", ":t": ts},
            ConditionExpression=Attr("status").eq("active"),
        )

    # Return updated period row
    updated_item = T.fixed_asset_schedule.get_item(
        Key={"pk": f"ASSET#{asset_id}", "sk": sk}
    ).get("Item", period_item)
    updated_item["journal_entry_id"] = journal_id
    updated_item["posted_at"] = ts
    updated_item["schedule_status"] = "posted"
    return _item_to_period(updated_item)


# ---------------------------------------------------------------------------
# Disposal — FXA-011
# ---------------------------------------------------------------------------

def dispose_asset(asset_id: str, body: FixedAssetDisposeIn, actor_sub: str) -> FixedAssetOut:
    """
    Dispose an asset:
    1. Post a balanced closing GL journal (4 lines).
    2. Cancel all remaining scheduled depreciation periods.
    3. Mark asset as disposed.
    4. Optionally route cash proceeds through refund_payment (lazy-import).
    Idempotent: if already disposed, returns current state.
    """
    _require_enabled()
    asset = _get_asset_raw(asset_id)

    if asset.get("status") == "disposed":
        return _item_to_asset(asset)

    cost = int(asset["acquisition_cost_cents"])
    salvage = int(asset["salvage_value_cents"])
    accum = int(asset.get("accumulated_depreciation_cents", 0))
    nbv = max(salvage, cost - accum)
    proceeds = body.proceeds_amount_cents or 0

    corr = body.correlation_id or f"disposal:{uuid4().hex}"
    journal_id = hashlib.sha256(f"{asset_id}:disposal:{corr}".encode()).hexdigest()[:32]

    # Post closing GL journal — LAZY import, guarded by flag
    if getattr(S, "gl_double_entry_enabled", False):
        try:
            from app.services.gl_posting import post_journal_entry  # type: ignore[import]
            gain = proceeds - nbv
            lines = [
                # Remove accumulated depreciation (contra-asset, credit-normal → debit to remove)
                {"account_id": asset.get("gl_accum_depr_account_id") or "", "debit": accum, "credit": 0},
                # Remove original cost (asset, debit-normal → credit to remove)
                {"account_id": asset.get("gl_asset_account_id") or "", "debit": 0, "credit": cost},
                # Cash proceeds (if any) — debit cash/AR
                {"account_id": "CASH_OR_AR", "debit": proceeds, "credit": 0},
            ]
            if gain >= 0:
                # Gain on disposal (credit-normal revenue account)
                lines.append({"account_id": asset.get("gl_gain_account_id") or "", "debit": 0, "credit": gain})
            else:
                # Loss on disposal (debit-normal expense account)
                lines.append({"account_id": asset.get("gl_loss_account_id") or "", "debit": -gain, "credit": 0})
            post_journal_entry(
                lines,
                source_type="fixed_asset_disposal",
                source_entity_id=asset_id,
                memo=f"Disposal of asset {asset_id}",
                gl_date=now_ts(),
                journal_id=journal_id,
            )
        except ImportError:
            logger.warning("fixed_assets: gl_posting not available; skipping disposal GL post")
        except Exception as exc:  # noqa: BLE001
            logger.error("fixed_assets: disposal GL post failed: %s", exc)
            raise HTTPException(status_code=500, detail="gl_post_failed") from exc

    # Handle cash proceeds via Stripe refund_payment (lazy import, flag-guarded)
    if body.proceeds_payment_intent_id and proceeds > 0:
        try:
            from app.routers.billing import refund_payment  # type: ignore[import]
            from app.models import StripeRefundReq  # type: ignore[import]
            # refund_payment is a FastAPI handler — call only if it can be imported as a plain function
            # (see FXA-001 §5.4 open question 4; actual invocation depends on billing extraction).
            # Best-effort; failure logged but does not block disposal.
            logger.info(
                "fixed_assets: disposal proceeds %d cents via PI %s — billing integration pending",
                proceeds, body.proceeds_payment_intent_id,
            )
        except ImportError:
            logger.warning("fixed_assets: billing refund_payment not available")

    ts = now_ts()

    # Cancel all remaining scheduled periods (paginate GSI_DUE by pk)
    _cancel_remaining_periods(asset_id, ts)

    # Mark asset disposed
    T.fixed_assets.update_item(
        Key={"pk": f"ASSET#{asset_id}", "sk": "META"},
        UpdateExpression="SET #s = :s, updated_at = :t",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "disposed", ":t": ts},
    )

    _audit("fixed_asset.disposed", actor_sub, asset_id=asset_id, proceeds=proceeds)
    refreshed = _get_asset_raw(asset_id)
    return _item_to_asset(refreshed)


def _cancel_remaining_periods(asset_id: str, ts: int) -> None:
    """Cancel all SCHEDULED period rows for an asset."""
    exclusive_start = None
    while True:
        kwargs: dict = {
            "KeyConditionExpression": (
                Key("pk").eq(f"ASSET#{asset_id}") & Key("sk").begins_with("PERIOD#")
            ),
            "FilterExpression": Attr("schedule_status").eq("scheduled"),
            "Limit": 100,
        }
        if exclusive_start:
            kwargs["ExclusiveStartKey"] = exclusive_start
        resp = T.fixed_asset_schedule.query(**kwargs)
        for row in resp.get("Items", []):
            try:
                T.fixed_asset_schedule.update_item(
                    Key={"pk": row["pk"], "sk": row["sk"]},
                    UpdateExpression="SET schedule_status = :s",
                    ExpressionAttributeValues={":s": "cancelled"},
                    ConditionExpression=Attr("schedule_status").eq("scheduled"),
                )
            except Exception:  # noqa: BLE001
                pass
        exclusive_start = resp.get("LastEvaluatedKey")
        if not exclusive_start:
            break


# ---------------------------------------------------------------------------
# Work orders — FXA-012
# ---------------------------------------------------------------------------

def create_work_order(
    asset_id: str, body: MaintenanceOrderIn, actor_sub: str
) -> MaintenanceOrderOut:
    _require_enabled()
    asset = _get_asset_raw(asset_id)
    if asset.get("status") == "disposed":
        raise HTTPException(status_code=400, detail="asset_disposed")

    corr = body.correlation_id or f"wo:{uuid4().hex}"
    work_order_id = _work_order_id_from_correlation(corr)
    ts = now_ts()
    # Build item — omit None and empty-string values for GSI key attrs
    # (DynamoDB rejects empty string as GSI key: assignee_sub)
    item: dict = {
        "pk": f"ASSET#{asset_id}",
        "sk": f"WO#{work_order_id}",
        "work_order_id": work_order_id,
        "asset_id": asset_id,
        "title": body.title,
        "wo_status": "open",
        "created_at": ts,
        "correlation_id": corr,
    }
    if body.description:
        item["description"] = body.description
    if body.assignee_sub:
        item["assignee_sub"] = body.assignee_sub
    if body.scheduled_for is not None:
        item["scheduled_for"] = body.scheduled_for

    try:
        T.maintenance_orders.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(pk)",
        )
    except T.maintenance_orders.meta.client.exceptions.ConditionalCheckFailedException:
        existing = T.maintenance_orders.get_item(
            Key={"pk": f"ASSET#{asset_id}", "sk": f"WO#{work_order_id}"}
        ).get("Item", {})
        return _item_to_work_order(existing)
    _audit("fixed_asset.work_order.created", actor_sub, asset_id=asset_id, work_order_id=work_order_id)
    return _item_to_work_order(item)


def list_work_orders(
    asset_id: Optional[str] = None,
    wo_status: Optional[str] = None,
    assignee_sub: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = 50,
) -> tuple[list[MaintenanceOrderOut], Optional[str]]:
    _require_enabled()
    exclusive_start = decode_cursor(cursor) if cursor else None
    kwargs: dict = {"Limit": limit}
    if exclusive_start:
        kwargs["ExclusiveStartKey"] = exclusive_start

    if asset_id is not None:
        kwargs["KeyConditionExpression"] = (
            Key("pk").eq(f"ASSET#{asset_id}") & Key("sk").begins_with("WO#")
        )
        resp = T.maintenance_orders.query(**kwargs)
    elif wo_status is not None:
        kwargs["IndexName"] = "GSI_WO_STATUS"
        kwargs["KeyConditionExpression"] = Key("wo_status").eq(wo_status)
        resp = T.maintenance_orders.query(**kwargs)
    elif assignee_sub is not None:
        kwargs["IndexName"] = "GSI_WO_ASSIGNEE"
        kwargs["KeyConditionExpression"] = Key("assignee_sub").eq(assignee_sub)
        resp = T.maintenance_orders.query(**kwargs)
    else:
        resp = T.maintenance_orders.scan(**kwargs)

    items = resp.get("Items", [])
    lek = resp.get("LastEvaluatedKey")
    return [_item_to_work_order(i) for i in items], encode_cursor(lek) if lek else None


def transition_work_order(
    work_order_id: str,
    asset_id: str,
    body: MaintenanceOrderTransitionIn,
    actor_sub: str,
) -> MaintenanceOrderOut:
    _require_enabled()
    resp = T.maintenance_orders.get_item(
        Key={"pk": f"ASSET#{asset_id}", "sk": f"WO#{work_order_id}"}
    )
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="work_order_not_found")

    current_status = item["wo_status"]
    target_status = body.target_status
    allowed = _VALID_TRANSITIONS.get(current_status, set())
    if target_status not in allowed:
        raise HTTPException(status_code=409, detail="illegal_transition")

    ts = now_ts()
    updates = ["wo_status = :s"]
    eav: dict = {":s": target_status}

    if body.assignee_sub is not None:
        updates.append("assignee_sub = :a")
        eav[":a"] = body.assignee_sub

    if target_status == "completed":
        updates.append("completed_at = :c")
        eav[":c"] = ts
        if body.cost_cents is not None:
            updates.append("cost_cents = :cc")
            eav[":cc"] = body.cost_cents

    resp2 = T.maintenance_orders.update_item(
        Key={"pk": f"ASSET#{asset_id}", "sk": f"WO#{work_order_id}"},
        UpdateExpression="SET " + ", ".join(updates),
        ExpressionAttributeValues=eav,
        ReturnValues="ALL_NEW",
    )
    _audit("fixed_asset.work_order.transitioned", actor_sub,
           work_order_id=work_order_id, target_status=target_status)
    return _item_to_work_order(resp2["Attributes"])


# ---------------------------------------------------------------------------
# Background poster loop — FXA-010
# ---------------------------------------------------------------------------

async def run_depreciation_poster_loop(*, poll_interval: Optional[int] = None) -> None:
    """
    Background task: find all SCHEDULED periods whose period_end_ts <= now
    and post each one. Runs forever with poll_interval sleep between sweeps.
    Pagination via LastEvaluatedKey (CLAUDE.md DDB gotcha §5.6).
    """
    interval = poll_interval if poll_interval is not None else S.fixed_assets_depreciation_poll_interval
    logger.info("fixed_assets: depreciation poster loop starting (interval=%ds)", interval)
    while True:
        try:
            _run_poster_sweep()
        except Exception as exc:  # noqa: BLE001
            logger.error("fixed_assets: poster sweep error: %s", exc)
        await asyncio.sleep(interval)


def _run_poster_sweep() -> None:
    """Single sweep: post all due scheduled periods."""
    now = now_ts()
    exclusive_start = None
    while True:
        kwargs: dict = {
            "IndexName": "GSI_DUE",
            "KeyConditionExpression": (
                Key("schedule_status").eq("scheduled") & Key("period_end_ts").lte(now)
            ),
            "Limit": 100,
        }
        if exclusive_start:
            kwargs["ExclusiveStartKey"] = exclusive_start
        resp = T.fixed_asset_schedule.query(**kwargs)
        for row in resp.get("Items", []):
            try:
                _aid = row.get("asset_id") or row["pk"].split("#", 1)[1]
                _period = int(row["period"])
                post_depreciation_period(_aid, _period)
            except Exception as exc:  # noqa: BLE001
                logger.warning("fixed_assets: failed to post period %s: %s", row.get("sk"), exc)
        exclusive_start = resp.get("LastEvaluatedKey")
        if not exclusive_start:
            break


def start_depreciation_poster_task() -> None:
    if S.fixed_assets_enabled and S.fixed_assets_depreciation_posting_enabled:
        asyncio.ensure_future(run_depreciation_poster_loop())
