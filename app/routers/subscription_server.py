from __future__ import annotations

import os
import uuid
from typing import Any, Dict, List, Literal, Optional

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from fastapi import APIRouter, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field, conint, conlist

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.routers.newsfeed import put_notification
from app.services.billing_shared import ddb_put as billing_put
from app.services.billing_shared import user_pk
from app.services.filemanager import get_node, norm_path
from app.services.alerts import audit_event
from app.services.profile import get_profile_identity
from app.services.purchase_history import record_billing_transaction
from app.services.subscription_access import get_subscription_settings, set_subscription_settings

router = APIRouter(tags=["subscriptions"])
FEE_BPS = int(os.environ.get("SUBSCRIPTION_FEE_BPS", "1000"))


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def require_user(x_user_id: Optional[str], expected_user_id: Optional[str] = None) -> str:
    if not x_user_id:
        raise HTTPException(status_code=401, detail="Missing user identity (X-User-Id header)")
    if expected_user_id and x_user_id != expected_user_id:
        raise HTTPException(status_code=403, detail="User does not match requested identity")
    return x_user_id


def interval_seconds(interval: str) -> int:
    if interval == "year":
        return 365 * 24 * 3600
    return 30 * 24 * 3600


def ddb_put_item(item: Dict[str, Any]) -> None:
    try:
        T.subscriptions.put_item(Item=item)
    except ClientError as exc:
        raise HTTPException(status_code=500, detail=f"DynamoDB error: {exc.response['Error'].get('Message','unknown')}") from exc


def ddb_get_item(pk: str, sk: str) -> Optional[Dict[str, Any]]:
    try:
        resp = T.subscriptions.get_item(Key={"pk": pk, "sk": sk})
        return resp.get("Item")
    except ClientError as exc:
        raise HTTPException(status_code=500, detail=f"DynamoDB error: {exc.response['Error'].get('Message','unknown')}") from exc


def ddb_query(pk: str) -> List[Dict[str, Any]]:
    try:
        resp = T.subscriptions.query(KeyConditionExpression=Key("pk").eq(pk))
        return resp.get("Items", [])
    except ClientError as exc:
        raise HTTPException(status_code=500, detail=f"DynamoDB error: {exc.response['Error'].get('Message','unknown')}") from exc


def pk_plan(plan_id: str) -> str:
    return f"PLAN#{plan_id}"


def pk_creator(creator_id: str) -> str:
    return f"CREATOR#{creator_id}"


def pk_subscriber(subscriber_id: str) -> str:
    return f"SUBSCRIBER#{subscriber_id}"


def pk_subscription(subscription_id: str) -> str:
    return f"SUB#{subscription_id}"


def normalize_asset_paths(paths: Optional[List[str]]) -> List[str]:
    if not paths:
        return []
    if not S.filemgr_table_name:
        raise HTTPException(status_code=500, detail="file manager not configured")
    normalized: List[str] = []
    for path in paths:
        normalized.append(norm_path(path, is_folder=None))
    return normalized


def resolve_plan_assets(owner_id: str, paths: List[str]) -> List[Dict[str, Any]]:
    assets: List[Dict[str, Any]] = []
    for path in paths:
        node = get_node(owner_id, path)
        assets.append({
            "path": node.get("path"),
            "name": node.get("name"),
            "type": node.get("type"),
            "size": node.get("size"),
            "content_type": node.get("content_type"),
        })
    return assets


def attach_creator_profile(plan: Dict[str, Any]) -> Dict[str, Any]:
    enriched = plan.copy()
    enriched["creator_profile"] = get_profile_identity(plan["creator_id"])
    return enriched


def attach_subscription_profiles(sub: Dict[str, Any]) -> Dict[str, Any]:
    enriched = sub.copy()
    enriched["creator_profile"] = get_profile_identity(sub["creator_id"])
    enriched["subscriber_profile"] = get_profile_identity(sub["subscriber_id"])
    return enriched


def normalize_subscription(sub: Dict[str, Any]) -> Dict[str, Any]:
    if "auto_renew" in sub:
        return sub
    normalized = sub.copy()
    normalized["auto_renew"] = not bool(sub.get("cancel_at_period_end", False))
    return normalized


def _select_plan_price(plan: Dict[str, Any], interval: str) -> int:
    if interval == "year" and plan.get("annual_price_cents"):
        return int(plan["annual_price_cents"])
    return int(plan["price_cents"])


def _plan_interval(plan: Dict[str, Any], requested: Optional[str]) -> str:
    if requested in ("month", "year"):
        return requested
    return plan.get("interval", "month")


def _discount_sk(code: str) -> str:
    return f"DISCOUNT#{code.upper()}"


def _get_discount(creator_id: str, code: str) -> Optional[Dict[str, Any]]:
    return ddb_get_item(pk_creator(creator_id), _discount_sk(code))


def _apply_discount(amount_cents: int, discount: Dict[str, Any]) -> int:
    percent = int(discount.get("percent_off", 0))
    if percent <= 0:
        return amount_cents
    discounted = int(amount_cents * (100 - percent) / 100)
    return max(0, discounted)


def record_billing_subscription(sub: Dict[str, Any]) -> None:
    item = {
        "pk": user_pk(sub["subscriber_id"]),
        "sk": f"SUB#{sub['subscription_id']}",
        "subscription_id": sub["subscription_id"],
        "plan_id": sub["plan_id"],
        "creator_id": sub["creator_id"],
        "status": sub["status"],
        "price_cents": sub["price_cents"],
        "currency": sub["currency"],
        "created_at": sub["created_at"],
        "updated_at": sub["updated_at"],
        "provider": sub["provider"],
        "provider_subscription_id": sub["provider_subscription_id"],
    }
    billing_put(T.billing, item)


def record_billing_payment(invoice: Dict[str, Any], subscription_id: str) -> None:
    item = {
        "pk": user_pk(invoice["subscriber_id"]),
        "sk": f"PAY#{invoice['invoice_id']}",
        "external_id": invoice["invoice_id"],
        "kind": "subscription_charge",
        "status": invoice["status"],
        "amount_cents": invoice["amount_cents"],
        "currency": invoice["currency"],
        "subscription_id": subscription_id,
        "created_at": invoice["created_at"],
        "updated_at": invoice["created_at"],
    }
    billing_put(T.billing, item)


def mark_invoice_refunded(subscription_id: str, reason: str) -> Optional[Dict[str, Any]]:
    items = ddb_query(pk_subscription(subscription_id))
    invoices = [it for it in items if it.get("sk", "").startswith("INV#")]
    invoices.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    for invoice in invoices:
        status = (invoice.get("status") or "").lower()
        if status == "paid":
            invoice["status"] = "refunded"
            invoice["refund_reason"] = reason
            invoice["refunded_at"] = now_ts()
            ddb_put_item(invoice)
            return invoice
    return None


def _billing_query_by_pk(user_id: str) -> List[Dict[str, Any]]:
    try:
        resp = T.billing.query(
            KeyConditionExpression=Key("pk").eq(user_pk(user_id)) & Key("sk").begins_with("SUB#"),
        )
        return resp.get("Items", [])
    except ClientError:
        return []


def _billing_query_by_user_sub(user_id: str) -> List[Dict[str, Any]]:
    try:
        resp = T.billing.query(
            KeyConditionExpression=Key("user_sub").eq(user_id) & Key("sk").begins_with("SUB#"),
        )
        return resp.get("Items", [])
    except ClientError:
        return []


def _normalize_external_subscription(item: Dict[str, Any], provider: str) -> Dict[str, Any]:
    return {
        "provider": provider,
        "subscription_id": item.get("subscription_id"),
        "plan_id": item.get("plan_id"),
        "status": item.get("status"),
        "payment_token_id": item.get("payment_token_id"),
        "next_renewal_date": item.get("next_renewal_date") or item.get("next_renewal_time"),
        "last_transaction_id": item.get("last_transaction_id") or item.get("last_external_id"),
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
        "raw": item.get("raw"),
    }


class PlanCreateIn(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    description: Optional[str] = Field(default=None, max_length=1000)
    price_cents: conint(gt=0)
    currency: str = Field(default="usd", min_length=3, max_length=10)
    interval: Literal["month", "year"] = "month"
    annual_price_cents: Optional[conint(gt=0)] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    asset_paths: List[str] = Field(default_factory=list)


class PlanUpdateIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=128)
    description: Optional[str] = Field(default=None, max_length=1000)
    price_cents: Optional[conint(gt=0)] = None
    currency: Optional[str] = Field(default=None, min_length=3, max_length=10)
    interval: Optional[Literal["month", "year"]] = None
    annual_price_cents: Optional[conint(gt=0)] = None
    status: Optional[Literal["active", "archived"]] = None
    metadata: Optional[Dict[str, Any]] = None
    asset_paths: Optional[conlist(str, max_length=50)] = None


class PlanOut(BaseModel):
    plan_id: str
    creator_id: str
    name: str
    description: Optional[str]
    price_cents: int
    currency: str
    interval: str
    annual_price_cents: Optional[int] = None
    status: str
    metadata: Dict[str, Any]
    assets: List[Dict[str, Any]]
    created_at: int
    updated_at: int
    creator_profile: Optional[Dict[str, Optional[str]]] = None


class SubscribeIn(BaseModel):
    subscriber_id: Optional[str] = None
    interval: Optional[Literal["month", "year"]] = None
    discount_code: Optional[str] = None


class SubscriptionOut(BaseModel):
    subscription_id: str
    plan_id: str
    creator_id: str
    subscriber_id: str
    interval: str
    provider: str
    provider_subscription_id: str
    status: str
    start_at: int
    current_period_end: int
    cancel_at_period_end: bool
    price_cents: int
    currency: str
    auto_renew: bool
    created_at: int
    updated_at: int
    creator_profile: Optional[Dict[str, Optional[str]]] = None
    subscriber_profile: Optional[Dict[str, Optional[str]]] = None
    summary: Optional["SubscriptionSummaryOut"] = None


class SubscriptionCancelIn(BaseModel):
    cancel_at_period_end: bool = True
    reason: Optional[str] = None


class SubscriptionResumeIn(BaseModel):
    reason: Optional[str] = None


class SubscriptionRenewalIn(BaseModel):
    auto_renew: bool = True
    effective: Literal["immediate", "period_end"] = "period_end"
    reason: Optional[str] = None


class InvoiceOut(BaseModel):
    invoice_id: str
    subscription_id: str
    provider_invoice_id: str
    amount_cents: int
    currency: str
    status: str
    period_start: int
    period_end: int
    created_at: int


class EarningsOut(BaseModel):
    creator_id: str
    period_start: Optional[int]
    period_end: Optional[int]
    currency: str
    gross_cents: int
    fee_cents: int
    net_cents: int


class WebhookIn(BaseModel):
    event_type: str
    subscription_id: Optional[str] = None
    invoice_id: Optional[str] = None
    status: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ExternalSubscriptionOut(BaseModel):
    provider: str
    subscription_id: Optional[str] = None
    plan_id: Optional[str] = None
    status: Optional[str] = None
    payment_token_id: Optional[str] = None
    next_renewal_date: Optional[str] = None
    last_transaction_id: Optional[str] = None
    created_at: Optional[int] = None
    updated_at: Optional[int] = None
    raw: Optional[Dict[str, Any]] = None


class SubscriptionSettingsIn(BaseModel):
    require_subscription: bool = False
    disable_auto_renew: bool = False


class SubscriptionSettingsOut(BaseModel):
    require_subscription: bool
    disable_auto_renew: bool
    updated_at: int


class SubscriptionSummaryOut(BaseModel):
    subscription_id: str
    status: str
    cancel_at_period_end: bool
    total_paid_cents: int
    currency: str
    next_amount_cents: int
    next_renewal_at: Optional[int] = None
    last_invoice_at: Optional[int] = None


class CreatorBulkPriceIn(BaseModel):
    price_cents: conint(gt=0)
    annual_price_cents: Optional[conint(gt=0)] = None


class CreatorSubscriberActionIn(BaseModel):
    reason: Optional[str] = None


class DiscountCodeCreateIn(BaseModel):
    code: str = Field(..., min_length=3, max_length=32)
    percent_off: conint(ge=1, le=100)
    duration: Literal["once", "repeating", "forever"] = "once"
    duration_months: Optional[conint(ge=1, le=36)] = None
    active: bool = True


class DiscountCodeOut(BaseModel):
    code: str
    percent_off: int
    duration: str
    duration_months: Optional[int] = None
    active: bool
    created_at: int
    updated_at: int


# -----------------------------
# Plan helpers
# -----------------------------

def build_plan_items(plan: Dict[str, Any]) -> List[Dict[str, Any]]:
    creator_index = plan.copy()
    creator_index.update({"pk": pk_creator(plan["creator_id"]), "sk": f"PLAN#{plan['plan_id']}", "entity": "plan_index"})
    base = plan.copy()
    base.update({"pk": pk_plan(plan["plan_id"]), "sk": "META", "entity": "plan"})
    return [base, creator_index]


def save_plan(plan: Dict[str, Any]) -> None:
    for item in build_plan_items(plan):
        ddb_put_item(item)


# -----------------------------
# Subscription helpers
# -----------------------------

def build_subscription_items(sub: Dict[str, Any]) -> List[Dict[str, Any]]:
    base = sub.copy()
    base.update({"pk": pk_subscription(sub["subscription_id"]), "sk": "META", "entity": "subscription"})
    creator_index = sub.copy()
    creator_index.update({"pk": pk_creator(sub["creator_id"]), "sk": f"SUB#{sub['subscription_id']}", "entity": "subscription_index"})
    subscriber_index = sub.copy()
    subscriber_index.update({"pk": pk_subscriber(sub["subscriber_id"]), "sk": f"SUB#{sub['subscription_id']}", "entity": "subscription_index"})
    return [base, creator_index, subscriber_index]


def save_subscription(sub: Dict[str, Any]) -> None:
    for item in build_subscription_items(sub):
        ddb_put_item(item)


def build_invoice_item(invoice: Dict[str, Any]) -> Dict[str, Any]:
    item = invoice.copy()
    item.update({"pk": pk_subscription(invoice["subscription_id"]), "sk": f"INV#{invoice['invoice_id']}", "entity": "invoice"})
    return item


def save_invoice(invoice: Dict[str, Any]) -> None:
    ddb_put_item(build_invoice_item(invoice))


def subscription_summary(sub: Dict[str, Any]) -> Dict[str, Any]:
    items = ddb_query(pk_subscription(sub["subscription_id"]))
    invoices = [it for it in items if it.get("sk", "").startswith("INV#")]
    invoices.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    total_paid = 0
    last_invoice_at = None
    for invoice in invoices:
        status = (invoice.get("status") or "").lower()
        if status == "paid":
            total_paid += int(invoice.get("amount_cents", 0))
        if last_invoice_at is None and invoice.get("created_at"):
            last_invoice_at = int(invoice.get("created_at"))

    status = (sub.get("status") or "").lower()
    cancel_at_period_end = bool(sub.get("cancel_at_period_end", False))
    next_amount = 0
    next_renewal_at = None
    if status in {"active", "past_due"} and not cancel_at_period_end:
        next_amount = int(sub.get("price_cents", 0))
        discount = sub.get("discount") or {}
        if discount and sub.get("discount_remaining_months", 0):
            next_amount = _apply_discount(next_amount, discount)
        next_renewal_at = int(sub.get("current_period_end") or 0) or None

    return {
        "subscription_id": sub["subscription_id"],
        "status": sub.get("status"),
        "cancel_at_period_end": cancel_at_period_end,
        "total_paid_cents": total_paid,
        "currency": sub.get("currency"),
        "next_amount_cents": next_amount,
        "next_renewal_at": next_renewal_at,
        "last_invoice_at": last_invoice_at,
    }


def _is_discount_active(discount: Dict[str, Any]) -> bool:
    return bool(discount.get("active", True))


def _discount_repeating_months(discount: Dict[str, Any]) -> int:
    if discount.get("duration") == "repeating":
        return int(discount.get("duration_months") or 0)
    return 0


def build_ledger_item(creator_id: str, entry: Dict[str, Any]) -> Dict[str, Any]:
    item = entry.copy()
    item.update({"pk": pk_creator(creator_id), "sk": f"LEDGER#{entry['created_at']}#{entry['entry_id']}", "entity": "ledger"})
    return item


def save_ledger_entry(creator_id: str, entry: Dict[str, Any]) -> None:
    ddb_put_item(build_ledger_item(creator_id, entry))


# -----------------------------
# API endpoints
# -----------------------------
@router.post("/api/creators/{creator_id}/plans", response_model=PlanOut)
async def create_plan(
    creator_id: str,
    body: PlanCreateIn,
    request: Request,
    x_user_id: Optional[str] = Header(default=None),
):
    require_user(x_user_id, creator_id)
    asset_paths = normalize_asset_paths(body.asset_paths)
    assets = resolve_plan_assets(creator_id, asset_paths) if asset_paths else []
    plan_id = new_id("plan")
    ts = now_ts()
    plan = {
        "plan_id": plan_id,
        "creator_id": creator_id,
        "name": body.name,
        "description": body.description,
        "price_cents": int(body.price_cents),
        "currency": body.currency.lower(),
        "interval": body.interval,
        "annual_price_cents": int(body.annual_price_cents) if body.annual_price_cents else None,
        "status": "active",
        "metadata": body.metadata,
        "assets": assets,
        "created_at": ts,
        "updated_at": ts,
    }
    save_plan(plan)
    audit_event(
        "subscription_plan_created",
        creator_id,
        request,
        outcome="success",
        plan_id=plan_id,
        price_cents=plan["price_cents"],
        interval=plan["interval"],
    )
    return attach_creator_profile(plan)


@router.get("/api/creators/{creator_id}/plans", response_model=List[PlanOut])
async def list_plans(creator_id: str, include_profile: bool = Query(default=False)):
    items = ddb_query(pk_creator(creator_id))
    plans = [it for it in items if it.get("sk", "").startswith("PLAN#")]
    plans.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    if include_profile:
        return [attach_creator_profile(p) for p in plans]
    return plans


@router.patch("/api/plans/{plan_id}", response_model=PlanOut)
async def update_plan(
    plan_id: str,
    body: PlanUpdateIn,
    request: Request,
    x_user_id: Optional[str] = Header(default=None),
):
    plan = ddb_get_item(pk_plan(plan_id), "META")
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    require_user(x_user_id, plan["creator_id"])
    updated = plan.copy()
    for field in ("name", "description", "price_cents", "currency", "interval", "status", "metadata"):
        value = getattr(body, field)
        if value is not None:
            if field == "currency":
                value = value.lower()
            updated[field] = value
    if body.annual_price_cents is not None:
        updated["annual_price_cents"] = int(body.annual_price_cents)
    if body.asset_paths is not None:
        asset_paths = normalize_asset_paths(list(body.asset_paths))
        updated["assets"] = resolve_plan_assets(plan["creator_id"], asset_paths) if asset_paths else []
    updated["updated_at"] = now_ts()
    save_plan(updated)
    audit_event(
        "subscription_plan_updated",
        plan["creator_id"],
        request,
        outcome="success",
        plan_id=plan_id,
        status=updated.get("status"),
    )
    return attach_creator_profile(updated)


@router.post("/api/plans/{plan_id}/archive", response_model=PlanOut)
async def archive_plan(
    plan_id: str,
    request: Request,
    x_user_id: Optional[str] = Header(default=None),
):
    plan = ddb_get_item(pk_plan(plan_id), "META")
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    require_user(x_user_id, plan["creator_id"])
    plan["status"] = "archived"
    plan["updated_at"] = now_ts()
    save_plan(plan)
    audit_event(
        "subscription_plan_archived",
        plan["creator_id"],
        request,
        outcome="success",
        plan_id=plan_id,
    )
    return attach_creator_profile(plan)


@router.post("/api/plans/{plan_id}/subscribe", response_model=SubscriptionOut)
async def subscribe(
    plan_id: str,
    body: SubscribeIn,
    request: Request,
    x_user_id: Optional[str] = Header(default=None),
):
    subscriber_id = require_user(x_user_id)
    if body.subscriber_id and body.subscriber_id != subscriber_id:
        raise HTTPException(status_code=403, detail="subscriber_id must match X-User-Id")
    plan = ddb_get_item(pk_plan(plan_id), "META")
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    if plan.get("status") != "active":
        raise HTTPException(status_code=400, detail="Plan is not active")
    if plan["creator_id"] == subscriber_id:
        raise HTTPException(status_code=400, detail="Creator cannot subscribe to their own plan")

    ts = now_ts()
    subscription_id = new_id("sub")
    provider_subscription_id = new_id("stub_sub")
    interval = _plan_interval(plan, body.interval)
    period_end = ts + interval_seconds(interval)
    base_price = _select_plan_price(plan, interval)
    applied_discount = None
    if body.discount_code:
        discount = _get_discount(plan["creator_id"], body.discount_code)
        if not discount or not _is_discount_active(discount):
            raise HTTPException(status_code=400, detail="Invalid or inactive discount code")
        applied_discount = {
            "code": discount["code"],
            "percent_off": discount["percent_off"],
            "duration": discount.get("duration"),
            "duration_months": discount.get("duration_months"),
        }
    price_cents = _apply_discount(base_price, discount) if applied_discount else base_price
    sub = {
        "subscription_id": subscription_id,
        "plan_id": plan_id,
        "creator_id": plan["creator_id"],
        "subscriber_id": subscriber_id,
        "interval": interval,
        "provider": "stub",
        "provider_subscription_id": provider_subscription_id,
        "status": "active",
        "start_at": ts,
        "current_period_end": period_end,
        "cancel_at_period_end": False,
        "price_cents": price_cents,
        "currency": plan["currency"],
        "auto_renew": True,
        "created_at": ts,
        "updated_at": ts,
    }
    if applied_discount:
        sub["discount"] = applied_discount
        if applied_discount.get("duration") == "repeating":
            sub["discount_remaining_months"] = int(applied_discount.get("duration_months") or 0)
        elif applied_discount.get("duration") == "once":
            sub["discount_remaining_months"] = 1
    creator_settings = get_subscription_settings(plan["creator_id"])
    if creator_settings.get("disable_auto_renew"):
        sub["auto_renew"] = False
        sub["cancel_at_period_end"] = True
    save_subscription(sub)
    record_billing_subscription(sub)

    invoice_id = new_id("inv")
    invoice = {
        "invoice_id": invoice_id,
        "subscription_id": subscription_id,
        "subscriber_id": subscriber_id,
        "provider_invoice_id": new_id("stub_inv"),
        "amount_cents": int(sub["price_cents"]),
        "currency": plan["currency"],
        "status": "paid",
        "period_start": ts,
        "period_end": period_end,
        "created_at": ts,
    }
    if applied_discount:
        invoice["discount"] = applied_discount
    save_invoice(invoice)
    record_billing_payment(invoice, subscription_id)
    record_billing_transaction(
        user_sub=subscriber_id,
        amount_cents=int(invoice["amount_cents"]),
        currency=invoice["currency"],
        description=f"Subscription {plan_id}",
        status="COMPLETED",
        external_ref=invoice_id,
        metadata={"subscription_id": subscription_id, "creator_id": plan["creator_id"]},
    )

    fee_cents = int(invoice["amount_cents"] * FEE_BPS / 10000)
    charge_entry = {
        "entry_id": new_id("led"),
        "subscription_id": subscription_id,
        "subscriber_id": subscriber_id,
        "entry_type": "charge",
        "amount_cents": invoice["amount_cents"],
        "currency": invoice["currency"],
        "created_at": ts,
        "metadata": {"invoice_id": invoice_id},
    }
    fee_entry = {
        "entry_id": new_id("led"),
        "subscription_id": subscription_id,
        "subscriber_id": subscriber_id,
        "entry_type": "fee",
        "amount_cents": fee_cents,
        "currency": invoice["currency"],
        "created_at": ts,
        "metadata": {"invoice_id": invoice_id},
    }
    save_ledger_entry(plan["creator_id"], charge_entry)
    save_ledger_entry(plan["creator_id"], fee_entry)

    put_notification(
        recipient_user_id=plan["creator_id"],
        notif_type="subscription_created",
        payload={"subscription_id": subscription_id, "plan_id": plan_id, "subscriber_id": subscriber_id},
    )
    put_notification(
        recipient_user_id=subscriber_id,
        notif_type="subscription_started",
        payload={"subscription_id": subscription_id, "plan_id": plan_id, "creator_id": plan["creator_id"]},
    )
    audit_event(
        "subscription_started",
        subscriber_id,
        request,
        outcome="success",
        subscription_id=subscription_id,
        plan_id=plan_id,
        creator_id=plan["creator_id"],
        price_cents=sub["price_cents"],
    )
    audit_event(
        "subscription_new_subscriber",
        plan["creator_id"],
        request,
        outcome="success",
        subscription_id=subscription_id,
        plan_id=plan_id,
        subscriber_id=subscriber_id,
    )

    return attach_subscription_profiles(sub)


@router.get("/api/subscriptions", response_model=List[SubscriptionOut])
async def list_subscriptions(
    subscriber_id: Optional[str] = None,
    include_profile: bool = Query(default=False),
    include_summary: bool = Query(default=False),
    x_user_id: Optional[str] = Header(default=None),
):
    user_id = require_user(x_user_id)
    if subscriber_id and subscriber_id != user_id:
        raise HTTPException(status_code=403, detail="subscriber_id must match X-User-Id")
    pk = pk_subscriber(user_id)
    items = ddb_query(pk)
    subs = [normalize_subscription(it) for it in items if it.get("sk", "").startswith("SUB#")]
    subs.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    if include_profile:
        subs = [attach_subscription_profiles(s) for s in subs]
    if include_summary:
        return [
            {**s, "summary": subscription_summary(s)}
            for s in subs
        ]
    return subs


@router.get("/api/creators/{creator_id}/subscriptions", response_model=List[SubscriptionOut])
async def list_creator_subscriptions(
    creator_id: str,
    include_profile: bool = Query(default=False),
    include_summary: bool = Query(default=False),
    x_user_id: Optional[str] = Header(default=None),
):
    require_user(x_user_id, creator_id)
    items = ddb_query(pk_creator(creator_id))
    subs = [normalize_subscription(it) for it in items if it.get("sk", "").startswith("SUB#")]
    subs.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    if include_profile:
        subs = [attach_subscription_profiles(s) for s in subs]
    if include_summary:
        return [
            {**s, "summary": subscription_summary(s)}
            for s in subs
        ]
    return subs


@router.get("/api/creators/{creator_id}/subscription-settings", response_model=SubscriptionSettingsOut)
async def get_creator_subscription_settings(creator_id: str, x_user_id: Optional[str] = Header(default=None)):
    require_user(x_user_id, creator_id)
    return get_subscription_settings(creator_id)


@router.post("/api/creators/{creator_id}/subscription-settings", response_model=SubscriptionSettingsOut)
async def update_creator_subscription_settings(
    creator_id: str,
    body: SubscriptionSettingsIn,
    request: Request,
    x_user_id: Optional[str] = Header(default=None),
):
    require_user(x_user_id, creator_id)
    updated = set_subscription_settings(
        creator_id,
        require_subscription=body.require_subscription,
        disable_auto_renew=body.disable_auto_renew,
    )
    audit_event(
        "subscription_settings_updated",
        creator_id,
        request,
        outcome="success",
        require_subscription=updated["require_subscription"],
        disable_auto_renew=updated["disable_auto_renew"],
    )
    return updated


@router.post("/api/creators/{creator_id}/plans/bulk-price", response_model=List[PlanOut])
async def bulk_update_plan_prices(
    creator_id: str,
    body: CreatorBulkPriceIn,
    request: Request,
    x_user_id: Optional[str] = Header(default=None),
):
    require_user(x_user_id, creator_id)
    items = ddb_query(pk_creator(creator_id))
    plans = [it for it in items if it.get("sk", "").startswith("PLAN#")]
    updated_plans = []
    for plan in plans:
        plan["price_cents"] = int(body.price_cents)
        if body.annual_price_cents is not None:
            plan["annual_price_cents"] = int(body.annual_price_cents)
        plan["updated_at"] = now_ts()
        save_plan(plan)
        updated_plans.append(plan)
    audit_event(
        "subscription_plan_bulk_price_update",
        creator_id,
        request,
        outcome="success",
        plan_count=len(updated_plans),
    )
    return [attach_creator_profile(p) for p in updated_plans]


@router.get("/api/subscriptions/external", response_model=List[ExternalSubscriptionOut])
async def list_external_subscriptions(
    provider: Optional[Literal["paypal", "ccbill"]] = None,
    x_user_id: Optional[str] = Header(default=None),
):
    user_id = require_user(x_user_id)
    external: List[Dict[str, Any]] = []
    if provider in (None, "paypal"):
        for item in _billing_query_by_pk(user_id):
            external.append(_normalize_external_subscription(item, "paypal"))
    if provider in (None, "ccbill"):
        for item in _billing_query_by_user_sub(user_id):
            external.append(_normalize_external_subscription(item, "ccbill"))
    external.sort(key=lambda x: x.get("created_at") or 0, reverse=True)
    return external


@router.post("/api/subscriptions/{subscription_id}/cancel", response_model=SubscriptionOut)
async def cancel_subscription(
    subscription_id: str,
    body: SubscriptionCancelIn,
    request: Request,
    x_user_id: Optional[str] = Header(default=None),
):
    sub = ddb_get_item(pk_subscription(subscription_id), "META")
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    sub = normalize_subscription(sub)
    user_id = require_user(x_user_id)
    if user_id not in (sub["subscriber_id"], sub["creator_id"]):
        raise HTTPException(status_code=403, detail="Not authorized to cancel this subscription")
    sub["cancel_at_period_end"] = body.cancel_at_period_end
    sub["auto_renew"] = False
    if body.cancel_at_period_end:
        sub["status"] = "canceling"
    else:
        sub["status"] = "canceled"
        sub["current_period_end"] = now_ts()
    sub["updated_at"] = now_ts()
    save_subscription(sub)
    record_billing_subscription(sub)
    put_notification(
        recipient_user_id=sub["creator_id"],
        notif_type="subscription_canceled",
        payload={"subscription_id": subscription_id, "subscriber_id": sub["subscriber_id"]},
    )
    put_notification(
        recipient_user_id=sub["subscriber_id"],
        notif_type="subscription_canceled",
        payload={"subscription_id": subscription_id, "creator_id": sub["creator_id"]},
    )
    audit_event(
        "subscription_canceled",
        sub["subscriber_id"],
        request,
        outcome="success",
        subscription_id=subscription_id,
        creator_id=sub["creator_id"],
        cancel_at_period_end=sub["cancel_at_period_end"],
    )
    audit_event(
        "subscription_canceled_by_subscriber",
        sub["creator_id"],
        request,
        outcome="success",
        subscription_id=subscription_id,
        subscriber_id=sub["subscriber_id"],
        cancel_at_period_end=sub["cancel_at_period_end"],
    )
    return attach_subscription_profiles(sub)


@router.post("/api/subscriptions/{subscription_id}/resume", response_model=SubscriptionOut)
async def resume_subscription(
    subscription_id: str,
    body: SubscriptionResumeIn,
    request: Request,
    x_user_id: Optional[str] = Header(default=None),
):
    sub = ddb_get_item(pk_subscription(subscription_id), "META")
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    sub = normalize_subscription(sub)
    user_id = require_user(x_user_id)
    if user_id not in (sub["subscriber_id"], sub["creator_id"]):
        raise HTTPException(status_code=403, detail="Not authorized to resume this subscription")
    sub["cancel_at_period_end"] = False
    sub["auto_renew"] = True
    sub["status"] = "active"
    sub["updated_at"] = now_ts()
    save_subscription(sub)
    record_billing_subscription(sub)
    put_notification(
        recipient_user_id=sub["creator_id"],
        notif_type="subscription_resumed",
        payload={"subscription_id": subscription_id, "subscriber_id": sub["subscriber_id"]},
    )
    put_notification(
        recipient_user_id=sub["subscriber_id"],
        notif_type="subscription_resumed",
        payload={"subscription_id": subscription_id, "creator_id": sub["creator_id"]},
    )
    audit_event(
        "subscription_resumed",
        sub["subscriber_id"],
        request,
        outcome="success",
        subscription_id=subscription_id,
        creator_id=sub["creator_id"],
    )
    audit_event(
        "subscription_resumed_by_subscriber",
        sub["creator_id"],
        request,
        outcome="success",
        subscription_id=subscription_id,
        subscriber_id=sub["subscriber_id"],
    )
    return attach_subscription_profiles(sub)


@router.post("/api/subscriptions/{subscription_id}/renewal", response_model=SubscriptionOut)
async def update_subscription_renewal(
    subscription_id: str,
    body: SubscriptionRenewalIn,
    request: Request,
    x_user_id: Optional[str] = Header(default=None),
):
    sub = ddb_get_item(pk_subscription(subscription_id), "META")
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    sub = normalize_subscription(sub)
    user_id = require_user(x_user_id)
    if user_id not in (sub["subscriber_id"], sub["creator_id"]):
        raise HTTPException(status_code=403, detail="Not authorized to update renewal settings")
    sub["auto_renew"] = body.auto_renew
    if not body.auto_renew:
        if body.effective == "immediate":
            sub["status"] = "canceled"
            sub["cancel_at_period_end"] = False
            sub["current_period_end"] = now_ts()
        else:
            sub["status"] = "canceling"
            sub["cancel_at_period_end"] = True
    else:
        sub["status"] = "active"
        sub["cancel_at_period_end"] = False
    sub["updated_at"] = now_ts()
    save_subscription(sub)
    record_billing_subscription(sub)
    audit_event(
        "subscription_renewal_updated",
        sub["subscriber_id"],
        request,
        outcome="success",
        subscription_id=subscription_id,
        auto_renew=body.auto_renew,
        effective=body.effective,
    )
    return attach_subscription_profiles(sub)


@router.post("/api/creators/{creator_id}/subscriptions/{subscription_id}/remove", response_model=SubscriptionOut)
async def remove_subscriber(
    creator_id: str,
    subscription_id: str,
    body: CreatorSubscriberActionIn,
    request: Request,
    x_user_id: Optional[str] = Header(default=None),
):
    require_user(x_user_id, creator_id)
    sub = ddb_get_item(pk_subscription(subscription_id), "META")
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    sub = normalize_subscription(sub)
    if sub["creator_id"] != creator_id:
        raise HTTPException(status_code=403, detail="Not authorized to manage this subscriber")
    sub["status"] = "canceled"
    sub["auto_renew"] = False
    sub["cancel_at_period_end"] = False
    sub["current_period_end"] = now_ts()
    sub["updated_at"] = now_ts()
    save_subscription(sub)
    record_billing_subscription(sub)

    refunded = mark_invoice_refunded(subscription_id, body.reason or "creator_removed")
    if refunded:
        record_billing_transaction(
            user_sub=sub["subscriber_id"],
            amount_cents=-int(refunded.get("amount_cents", 0)),
            currency=refunded.get("currency", sub.get("currency") or "usd"),
            description=f"Subscription refund {subscription_id}",
            status="REVERTED",
            external_ref=refunded.get("invoice_id") or subscription_id,
            metadata={"subscription_id": subscription_id, "reason": body.reason or "creator_removed"},
        )
        refund_entry = {
            "entry_id": new_id("led"),
            "subscription_id": subscription_id,
            "subscriber_id": sub["subscriber_id"],
            "entry_type": "refund",
            "amount_cents": int(refunded.get("amount_cents", 0)),
            "currency": refunded.get("currency", sub.get("currency")),
            "created_at": now_ts(),
            "metadata": {"invoice_id": refunded.get("invoice_id")},
        }
        save_ledger_entry(creator_id, refund_entry)

    audit_event(
        "subscription_removed_by_creator",
        creator_id,
        request,
        outcome="success",
        subscription_id=subscription_id,
        subscriber_id=sub["subscriber_id"],
        refunded=bool(refunded),
    )
    put_notification(
        recipient_user_id=sub["subscriber_id"],
        notif_type="subscription_removed",
        payload={"subscription_id": subscription_id, "creator_id": creator_id},
    )
    return attach_subscription_profiles(sub)


@router.post("/api/creators/{creator_id}/subscriptions/{subscription_id}/stop-renewal", response_model=SubscriptionOut)
async def stop_subscriber_renewal(
    creator_id: str,
    subscription_id: str,
    body: CreatorSubscriberActionIn,
    request: Request,
    x_user_id: Optional[str] = Header(default=None),
):
    require_user(x_user_id, creator_id)
    sub = ddb_get_item(pk_subscription(subscription_id), "META")
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    sub = normalize_subscription(sub)
    if sub["creator_id"] != creator_id:
        raise HTTPException(status_code=403, detail="Not authorized to manage this subscriber")
    sub["auto_renew"] = False
    sub["cancel_at_period_end"] = True
    sub["status"] = "canceling"
    sub["updated_at"] = now_ts()
    save_subscription(sub)
    record_billing_subscription(sub)
    audit_event(
        "subscription_auto_renew_disabled_by_creator",
        creator_id,
        request,
        outcome="success",
        subscription_id=subscription_id,
        subscriber_id=sub["subscriber_id"],
    )
    return attach_subscription_profiles(sub)


@router.post("/api/creators/{creator_id}/discounts", response_model=DiscountCodeOut)
async def create_discount_code(
    creator_id: str,
    body: DiscountCodeCreateIn,
    request: Request,
    x_user_id: Optional[str] = Header(default=None),
):
    require_user(x_user_id, creator_id)
    code = body.code.strip().upper()
    if body.duration == "repeating" and not body.duration_months:
        raise HTTPException(status_code=400, detail="duration_months required for repeating discounts")
    if body.duration != "repeating" and body.duration_months:
        raise HTTPException(status_code=400, detail="duration_months only valid for repeating discounts")
    ts = now_ts()
    item = {
        "pk": pk_creator(creator_id),
        "sk": _discount_sk(code),
        "entity": "discount",
        "code": code,
        "percent_off": int(body.percent_off),
        "duration": body.duration,
        "duration_months": body.duration_months,
        "active": bool(body.active),
        "created_at": ts,
        "updated_at": ts,
    }
    ddb_put_item(item)
    audit_event(
        "subscription_discount_created",
        creator_id,
        request,
        outcome="success",
        code=code,
        percent_off=item["percent_off"],
        duration=item["duration"],
    )
    return DiscountCodeOut(
        code=code,
        percent_off=item["percent_off"],
        duration=item["duration"],
        duration_months=item.get("duration_months"),
        active=item["active"],
        created_at=item["created_at"],
        updated_at=item["updated_at"],
    )


@router.get("/api/creators/{creator_id}/discounts", response_model=List[DiscountCodeOut])
async def list_discount_codes(creator_id: str, x_user_id: Optional[str] = Header(default=None)):
    require_user(x_user_id, creator_id)
    items = ddb_query(pk_creator(creator_id))
    discounts = [it for it in items if it.get("sk", "").startswith("DISCOUNT#")]
    discounts.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    return [
        DiscountCodeOut(
            code=it["code"],
            percent_off=int(it.get("percent_off", 0)),
            duration=it.get("duration", "once"),
            duration_months=it.get("duration_months"),
            active=bool(it.get("active", True)),
            created_at=int(it.get("created_at", 0)),
            updated_at=int(it.get("updated_at", 0)),
        )
        for it in discounts
    ]


@router.post("/api/creators/{creator_id}/discounts/{code}/disable", response_model=DiscountCodeOut)
async def disable_discount_code(
    creator_id: str,
    code: str,
    request: Request,
    x_user_id: Optional[str] = Header(default=None),
):
    require_user(x_user_id, creator_id)
    item = _get_discount(creator_id, code)
    if not item:
        raise HTTPException(status_code=404, detail="Discount code not found")
    item["active"] = False
    item["updated_at"] = now_ts()
    ddb_put_item(item)
    audit_event(
        "subscription_discount_disabled",
        creator_id,
        request,
        outcome="success",
        code=item["code"],
    )
    return DiscountCodeOut(
        code=item["code"],
        percent_off=int(item.get("percent_off", 0)),
        duration=item.get("duration", "once"),
        duration_months=item.get("duration_months"),
        active=False,
        created_at=int(item.get("created_at", 0)),
        updated_at=int(item.get("updated_at", 0)),
    )


@router.get("/api/subscriptions/{subscription_id}/invoices", response_model=List[InvoiceOut])
async def list_invoices(subscription_id: str, x_user_id: Optional[str] = Header(default=None)):
    sub = ddb_get_item(pk_subscription(subscription_id), "META")
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    sub = normalize_subscription(sub)
    user_id = require_user(x_user_id)
    if user_id not in (sub["subscriber_id"], sub["creator_id"]):
        raise HTTPException(status_code=403, detail="Not authorized to view invoices")
    items = ddb_query(pk_subscription(subscription_id))
    invoices = [it for it in items if it.get("sk", "").startswith("INV#")]
    invoices.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    return invoices


@router.get("/api/subscriptions/{subscription_id}/summary", response_model=SubscriptionSummaryOut)
async def get_subscription_summary(subscription_id: str, x_user_id: Optional[str] = Header(default=None)):
    sub = ddb_get_item(pk_subscription(subscription_id), "META")
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    sub = normalize_subscription(sub)
    user_id = require_user(x_user_id)
    if user_id not in (sub["subscriber_id"], sub["creator_id"]):
        raise HTTPException(status_code=403, detail="Not authorized to view summary")
    return subscription_summary(sub)


@router.get("/api/creators/{creator_id}/earnings", response_model=EarningsOut)
async def list_earnings(
    creator_id: str,
    period_start: Optional[int] = None,
    period_end: Optional[int] = None,
    x_user_id: Optional[str] = Header(default=None),
):
    require_user(x_user_id, creator_id)
    items = ddb_query(pk_creator(creator_id))
    ledger = [it for it in items if it.get("sk", "").startswith("LEDGER#")]
    gross = 0
    fee = 0
    currency = "usd"
    for entry in ledger:
        created_at = entry.get("created_at", 0)
        if period_start and created_at < period_start:
            continue
        if period_end and created_at > period_end:
            continue
        currency = entry.get("currency", currency)
        if entry.get("entry_type") == "charge":
            gross += int(entry.get("amount_cents", 0))
        if entry.get("entry_type") == "fee":
            fee += int(entry.get("amount_cents", 0))
    return {
        "creator_id": creator_id,
        "period_start": period_start,
        "period_end": period_end,
        "currency": currency,
        "gross_cents": gross,
        "fee_cents": fee,
        "net_cents": gross - fee,
    }


@router.post("/api/billing/webhooks/{provider}")
async def billing_webhook(provider: str, body: WebhookIn):
    if provider != "stub":
        raise HTTPException(status_code=400, detail="Unsupported provider")
    event_id = new_id("wh")
    ddb_put_item({
        "pk": f"WEBHOOK#{provider}",
        "sk": f"{now_ts()}#{event_id}",
        "event_type": body.event_type,
        "subscription_id": body.subscription_id,
        "invoice_id": body.invoice_id,
        "status": body.status,
        "metadata": body.metadata,
        "created_at": now_ts(),
        "entity": "webhook",
    })

    if not body.subscription_id:
        return {"ok": True, "event_id": event_id}

    sub = ddb_get_item(pk_subscription(body.subscription_id), "META")
    if not sub:
        return {"ok": True, "event_id": event_id}

    ts = now_ts()
    event_type = body.event_type.lower()
    if event_type == "invoice.paid":
        sub["status"] = "active"
        sub["current_period_end"] = ts + interval_seconds(sub.get("interval", "month"))
        sub["auto_renew"] = True
        if sub.get("discount_remaining_months"):
            sub["discount_remaining_months"] = max(0, int(sub["discount_remaining_months"]) - 1)
    elif event_type == "invoice.payment_failed":
        sub["status"] = "past_due"
    elif event_type == "subscription.canceled":
        sub["status"] = "canceled"
        sub["cancel_at_period_end"] = True
        sub["auto_renew"] = False

    sub["updated_at"] = ts
    save_subscription(sub)
    return {"ok": True, "event_id": event_id}
