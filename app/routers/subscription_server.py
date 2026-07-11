from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Tuple

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field, conint, conlist

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.routers.newsfeed import put_notification
from app.services.billing_shared import ddb_put as billing_put
from app.services.billing_shared import ddb_get as billing_get
from app.services.billing_shared import ddb_query_pk as billing_query_pk
from app.services.billing_shared import user_pk
from app.services.filemanager import get_node, norm_path
from app.services.alerts import audit_event
from app.services.profile import get_profile_identity
from app.services.purchase_history import record_billing_transaction
from app.services.subscription_access import get_subscription_settings, set_subscription_settings
from app.services.subscription_cycle_orders import emit_subscription_cycle_order
from app.auth.policy import require_admin_or_root

logger = logging.getLogger(__name__)

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


def _enforce_kyc_tier(user_sub: str, minimum_tier: int) -> None:
    """GAP-0268: Tier gate for the X-User-Id-authenticated subscription API.

    Inert pass-through unless both the enforcement flag and the gating flag are on
    (defaults OFF). Mirrors require_kyc_tier in app/auth/deps.py but works with this
    router's header-based auth instead of session auth.
    """
    if not (S.kyc_tier_enforcement_enabled and S.kyc_tier_gating_enabled):
        return
    from app.services.kyc_tiers import get_user_kyc_tier, KYC_TIER_NAMES
    tier = get_user_kyc_tier(user_sub)
    if tier < minimum_tier:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "kyc_tier_insufficient",
                "message": f"This action requires {KYC_TIER_NAMES.get(minimum_tier, f'Tier {minimum_tier}')} verification",
                "current_tier": tier,
                "required_tier": minimum_tier,
                "upgrade_url": "/kyc",
            },
        )


def interval_seconds(interval: str) -> int:
    if interval == "year":
        return 365 * 24 * 3600
    return 30 * 24 * 3600


def _iso_utc_from_ts(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _subscription_event_id(subscription_id: str, kind: str) -> str:
    return f"sub_{subscription_id}_{kind}"


def emit_subscription_cycle_order_and_reconcile(
    *,
    subscription: Dict[str, Any],
    plan: Dict[str, Any],
    invoice: Dict[str, Any],
) -> Dict[str, Any]:
    """Emit canonical recurring order and always invoke reconciliation using invoice-based identity."""
    normalized_invoice = dict(invoice)
    invoice_id = str(normalized_invoice.get("invoice_id") or normalized_invoice.get("provider_invoice_id") or "")
    if not invoice_id:
        raise ValueError("invoice_id or provider_invoice_id is required")
    normalized_invoice["invoice_id"] = invoice_id
    if not normalized_invoice.get("provider_invoice_id"):
        normalized_invoice["provider_invoice_id"] = invoice_id

    recurring = emit_subscription_cycle_order(
        subscription=subscription,
        plan=plan,
        invoice=normalized_invoice,
        enable_default_reconciliation=True,
    )
    reconciliation = dict(recurring.get("reconciliation") or {})
    if str(reconciliation.get("status") or "").lower() == "skipped":
        raise RuntimeError(f"subscription cycle reconciliation skipped for invoice {invoice_id}")
    return recurring


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
    if "renewal_policy" not in normalized:
        normalized["renewal_policy"] = "auto" if normalized["auto_renew"] else "manual"
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
        "interval": sub.get("interval"),
        "auto_renew": sub.get("auto_renew"),
        "cancel_at_period_end": sub.get("cancel_at_period_end"),
        "trial_start": sub.get("trial_start"),
        "trial_end": sub.get("trial_end"),
        "proration_policy": sub.get("proration_policy"),
        "renewal_policy": sub.get("renewal_policy"),
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


class PlanBenefit(BaseModel):
    """SUB-E0: a structured tier perk descriptor (label + optional detail).

    First-class, structured benefits beyond the free-form ``metadata`` blob so
    the app can render a real perk list. ``label`` is the short perk name,
    ``detail`` an optional longer description.
    """

    label: str = Field(..., min_length=1, max_length=200)
    detail: Optional[str] = Field(default=None, max_length=1000)


class PlanCreateIn(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    description: Optional[str] = Field(default=None, max_length=1000)
    price_cents: conint(gt=0)
    currency: str = Field(default="usd", min_length=3, max_length=10)
    interval: Literal["month", "year"] = "month"
    annual_price_cents: Optional[conint(gt=0)] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    asset_paths: List[str] = Field(default_factory=list)
    # SUB-E0: structured tier benefits/perks (list of {label, detail}).
    benefits: conlist(PlanBenefit, max_length=50) = Field(default_factory=list)


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
    # SUB-E0: replace the plan's structured benefits/perks (None = leave unchanged).
    benefits: Optional[conlist(PlanBenefit, max_length=50)] = None


class PlanOut(BaseModel):
    plan_id: str
    creator_id: str
    name: str
    description: Optional[str] = None
    price_cents: int
    currency: str = "USD"
    interval: str = "month"
    annual_price_cents: Optional[int] = None
    # Tolerant defaults: stored plans (esp. older/seeded ones) may omit these
    # optional-metadata fields; the list/get endpoints must not 500 on them.
    status: str = "active"
    metadata: Dict[str, Any] = Field(default_factory=dict)
    # SUB-E0: structured tier benefits; older/seeded plans default to [].
    benefits: List[Dict[str, Any]] = Field(default_factory=list)
    assets: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: int = 0
    updated_at: int = 0
    creator_profile: Optional[Dict[str, Optional[str]]] = None


class SubscribeIn(BaseModel):
    subscriber_id: Optional[str] = None
    # ADV-402: optional last-click CPA attribution handle carried from an ad CTA.
    ad_click_id: Optional[str] = None
    interval: Optional[Literal["month", "year"]] = None
    discount_code: Optional[str] = None
    # GAP-0342: promo_code is the platform-wide promo/coupon system
    # (app/services/promo_codes.py), distinct from the legacy per-creator
    # discount_code lookup. If both are supplied, promo_code takes precedence
    # and they do NOT stack.
    promo_code: Optional[str] = None
    trial_days: Optional[conint(ge=1, le=365)] = None
    # SUB-E0: the payment method to charge (explicit). When omitted the
    # subscriber's default_payment_method_id is used. A non-trial subscribe with
    # no resolvable PM is rejected with HTTP 402 (no phantom subscription).
    payment_method_id: Optional[str] = None
    # SUB-E0: client-supplied idempotency key. A retry with the same value returns
    # the already-created subscription and never double-charges/double-subscribes.
    client_request_id: Optional[str] = Field(default=None, max_length=128)


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
    # SUB-E0: authoritative next-charge timestamp (= current_period_end at create),
    # consumed by the E1 renewal engine instead of a derived value.
    next_billing_date: Optional[int] = None
    payment_method_id: Optional[str] = None
    payment_intent_id: Optional[str] = None
    trial_start: Optional[int] = None
    trial_end: Optional[int] = None
    proration_policy: Optional[str] = None
    renewal_policy: Optional[str] = None
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
    renewal_policy: Optional[Literal["auto", "manual", "cancel_at_period_end"]] = None
    reason: Optional[str] = None


class SubscriptionChangePlanIn(BaseModel):
    plan_id: str
    interval: Optional[Literal["month", "year"]] = None
    effective: Literal["immediate", "period_end"] = "immediate"
    proration_policy: Literal["none", "charge", "credit", "full"] = "full"
    proration_amount_cents: Optional[int] = None
    # SUB-E2: optional explicit PM to charge the upgrade delta against (falls back
    # to the subscription's stored payment_method_id).
    payment_method_id: Optional[str] = None
    provider_invoice_id: Optional[str] = None
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
    is_proration: Optional[bool] = None
    proration_amount_cents: Optional[int] = None
    proration_period_start: Optional[int] = None
    proration_period_end: Optional[int] = None


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


_ACTIVE_SUBSCRIBER_STATUSES = {"active", "trialing", "past_due"}


def count_active_subscribers(creator_id: str) -> int:
    """Count a creator's currently active (non-cancelled/expired) subscriptions.

    Reads the creator index (``CREATOR#{id}`` partition, ``SUB#`` items) which is
    written by ``save_subscription``. Used to drive milestone detection
    (GAP-0153) at signup time.
    """
    items = ddb_query(pk_creator(creator_id))
    count = 0
    for it in items:
        if not it.get("sk", "").startswith("SUB#"):
            continue
        status = (it.get("status") or "").lower()
        if status in _ACTIVE_SUBSCRIBER_STATUSES:
            count += 1
    return count


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
    if status in {"active", "past_due", "trialing"} and not cancel_at_period_end:
        next_amount = int(sub.get("price_cents", 0))
        discount = sub.get("discount") or {}
        if discount and sub.get("discount_remaining_months", 0):
            next_amount = _apply_discount(next_amount, discount)
        next_renewal_at = int(sub.get("current_period_end") or 0) or None
        if status == "trialing":
            next_amount = 0

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


def _mirror_creator_credit_to_billing(
    creator_id: str,
    amount_cents: int,
    *,
    currency: str,
    created_at: int,
    subscription_id: str,
    subscriber_id: str,
    invoice_id: Optional[str] = None,
) -> None:
    """Mirror a subscription creator NET credit into ``T.billing`` (GAP-0307).

    Subscription creator revenue is written to ``T.subscriptions`` under
    ``PK=CREATOR#{creator_id}`` with field ``entry_type``, but the creator
    earnings dashboard (``creator_earnings._query_credit_entries``) and the
    payout balance (``creator_payouts.get_available_balance``) query
    ``T.billing`` under ``PK=USER#{creator_id}`` with ``Attr("type").eq("credit")``.
    Without this mirror, subscription revenue is invisible to both.

    The mirrored item matches the EXACT shape those queries expect:
    ``pk=USER#{creator_id}``, ``sk=LEDGER#{ts}#{entry_id}``, ``type="credit"``,
    ``amount_cents`` (creator NET, after platform fee), ``currency``, ``ts``,
    ``reason`` containing ``"subscription"`` (so ``classify_entry`` buckets it
    under ``subscriptions``), and a ``created_at`` field.

    Best-effort: a billing-table write failure must NOT roll back the
    subscription charge, but it is logged. Same DDB path in dev and prod
    (no ``dev_mode`` branch) — ``T.billing`` is the same table in both.
    """
    try:
        if amount_cents <= 0:
            return
        entry_id = new_id("biled")
        item = {
            "pk": f"USER#{creator_id}",
            "sk": f"LEDGER#{created_at}#{entry_id}",
            "type": "credit",
            "amount_cents": int(amount_cents),
            "currency": currency,
            "reason": "subscription_charge",
            "ts": int(created_at),
            "created_at": int(created_at),
            "entry_id": entry_id,
            "subscription_id": subscription_id,
            "subscriber_id": subscriber_id,
            "meta": {"content_type": "subscription"},
        }
        if invoice_id:
            item["invoice_id"] = invoice_id
        T.billing.put_item(Item=item)
        logger.info(
            "creator_billing_credit_written creator_id=%s amount_cents=%s subscription_id=%s",
            creator_id,
            amount_cents,
            subscription_id,
        )
    except Exception:  # pragma: no cover - best-effort mirror, never block charge
        logger.exception(
            "creator_billing_credit_mirror_failed creator_id=%s subscription_id=%s",
            creator_id,
            subscription_id,
        )


# -----------------------------
# SUB-E0 — real subscribe charge (funds-guarded stripe-mock rail, tips pattern)
# -----------------------------

def resolve_subscription_payment_method(subscriber_id: str, explicit_pm: Optional[str]) -> str:
    """SUB-E0: resolve + validate the subscriber's PM for a subscribe charge.

    Fallback chain: explicit -> the subscriber's general
    ``default_payment_method_id`` (T.billing ``BILLING`` row). UNLIKE the tips
    resolver (which tolerates a blank PM in dev_mode), a subscription REQUIRES a
    real, owned PM: a missing/unowned PM raises HTTP 402 so a no-card subscribe is
    rejected and writes NOTHING (no phantom subscription/credit).
    """
    pm = explicit_pm
    if not pm:
        billing = billing_get(T.billing, user_pk(subscriber_id), "BILLING") or {}
        pm = billing.get("default_payment_method_id")
    if not pm:
        raise HTTPException(
            status_code=402,
            detail={"code": "no_payment_method", "message": "No payment method on file to subscribe."},
        )
    items = billing_query_pk(T.billing, user_pk(subscriber_id))
    pm_ids = {
        it["payment_method_id"]
        for it in items
        if it.get("sk", "").startswith("PM#") and "payment_method_id" in it
    }
    if pm not in pm_ids:
        raise HTTPException(
            status_code=402,
            detail={"code": "no_payment_method", "message": "Payment method not found."},
        )
    return pm


def _charge_subscription_payment_intent(
    *,
    subscriber_id: str,
    amount_cents: int,
    currency: str,
    payment_method_id: str,
    plan_id: str,
    subscription_id: str,
    idempotency_key: str,
) -> Optional[str]:
    """SUB-E0: real stripe-mock charge for a subscribe, mirroring
    tips._charge_tip_payment_intent (off_session=True, confirm=True, idempotency_key).

    Returns the PaymentIntent id on success, or None ONLY for the dev stub path
    (Stripe not configured). On a declined card / Stripe error / non-succeeded
    terminal status this raises HTTPException(402) so the CALLER writes NOTHING
    (no subscription, no invoice, no creator credit). The charge idempotency_key is
    threaded into the PaymentIntent so a retry never double-charges the processor.
    """
    if not getattr(S, "stripe_secret_key", "") or not payment_method_id:
        return None

    from app.routers.billing import ensure_stripe_configured, get_or_create_customer
    import stripe

    ensure_stripe_configured()
    customer_id = get_or_create_customer(subscriber_id)
    try:
        pi = stripe.PaymentIntent.create(
            amount=int(amount_cents),
            currency=(currency or "usd").lower(),
            customer=customer_id,
            payment_method=payment_method_id,
            off_session=True,
            confirm=True,
            description=f"Subscription {plan_id}",
            metadata={
                "app_user_id": subscriber_id,
                "purpose": "subscription",
                "plan_id": plan_id,
                "subscription_id": subscription_id,
            },
            idempotency_key=(idempotency_key or None),
        )
    except stripe.error.CardError as exc:
        logger.info("subscription charge declined for subscriber=%s: %s", subscriber_id, exc)
        raise HTTPException(402, {"code": "payment_failed", "message": str(exc)})
    except stripe.error.StripeError as exc:
        logger.warning("subscription charge stripe error for subscriber=%s: %s", subscriber_id, exc)
        raise HTTPException(402, {"code": "payment_failed", "message": "Subscription charge failed at the payment processor."})

    status = (pi.get("status") or "").lower()
    charged_ok = status == "succeeded" or (
        bool(getattr(S, "stripe_api_base", "")) and status not in ("canceled", "payment_failed")
    )
    if not charged_ok:
        raise HTTPException(
            402,
            {"code": "payment_failed", "message": f"Subscription charge did not succeed (status={status})."},
        )
    return pi.get("id")


def _sub_idem_sk(idempotency_key: str) -> str:
    return f"SUBIDEMP#{idempotency_key}"


def _load_subscribe_idem(subscriber_id: str, idempotency_key: str) -> Optional[str]:
    """Return the subscription_id previously created for this idempotency key."""
    if not idempotency_key:
        return None
    try:
        row = billing_get(T.billing, user_pk(subscriber_id), _sub_idem_sk(idempotency_key))
    except Exception:
        logger.warning("subscribe idempotency read failed", exc_info=True)
        return None
    if not row:
        return None
    return row.get("subscription_id")


def _store_subscribe_idem(subscriber_id: str, idempotency_key: str, subscription_id: str) -> None:
    """Persist the idempotency marker (best-effort, conditional attribute_not_exists)."""
    if not idempotency_key:
        return
    try:
        billing_put(
            T.billing,
            {
                "pk": user_pk(subscriber_id),
                "sk": _sub_idem_sk(idempotency_key),
                "subscription_id": subscription_id,
                "ts": now_ts(),
            },
            condition_expression="attribute_not_exists(sk)",
        )
    except Exception:
        logger.warning("subscribe idempotency store skipped", exc_info=True)


def _calendar_meta(calendar_id: str) -> Optional[Dict[str, Any]]:
    return T.calendar.get_item(Key={"calendar_id": calendar_id, "sk": "meta"}).get("Item")


def _calendar_event_item(
    *,
    calendar_id: str,
    event_id: str,
    name: str,
    description: str,
    start_ts: int,
    end_ts: int,
    timezone_name: str,
) -> Dict[str, Any]:
    return {
        "calendar_id": calendar_id,
        "sk": f"event#{event_id}",
        "event_id": event_id,
        "name": name,
        "description": description,
        "timezone": timezone_name,
        "start_utc": _iso_utc_from_ts(start_ts),
        "end_utc": _iso_utc_from_ts(end_ts),
        "all_day": False,
        "all_day_date": None,
        "created_at_utc": _iso_utc_from_ts(now_ts()),
    }


def _upsert_subscription_calendar_event(
    calendar_id: str,
    event_id: str,
    *,
    name: str,
    description: str,
    when_ts: Optional[int],
    timezone_name: str,
) -> None:
    if not when_ts:
        T.calendar.delete_item(Key={"calendar_id": calendar_id, "sk": f"event#{event_id}"})
        return
    start_ts = when_ts
    end_ts = when_ts + 3600
    item = _calendar_event_item(
        calendar_id=calendar_id,
        event_id=event_id,
        name=name,
        description=description,
        start_ts=start_ts,
        end_ts=end_ts,
        timezone_name=timezone_name,
    )
    T.calendar.put_item(Item=item)


def refresh_subscription_calendar_events(sub: Dict[str, Any], plan: Optional[Dict[str, Any]] = None) -> None:
    plan = plan or ddb_get_item(pk_plan(sub["plan_id"]), "META")
    if not plan:
        return
    calendar_id = (plan.get("metadata") or {}).get("calendar_id")
    if not calendar_id:
        return
    calendar_meta = _calendar_meta(calendar_id)
    if not calendar_meta:
        return
    timezone_name = calendar_meta.get("timezone", "UTC")
    sub_id = sub["subscription_id"]
    trial_end = sub.get("trial_end")
    renewal_at = sub.get("current_period_end") if not sub.get("cancel_at_period_end") else None
    cancel_at = sub.get("current_period_end") if sub.get("cancel_at_period_end") else None

    _upsert_subscription_calendar_event(
        calendar_id,
        _subscription_event_id(sub_id, "trial_end"),
        name="Subscription trial ends",
        description=f"Trial ends for subscription {sub_id}",
        when_ts=trial_end,
        timezone_name=timezone_name,
    )
    _upsert_subscription_calendar_event(
        calendar_id,
        _subscription_event_id(sub_id, "renewal"),
        name="Subscription renewal",
        description=f"Renewal for subscription {sub_id}",
        when_ts=renewal_at,
        timezone_name=timezone_name,
    )
    _upsert_subscription_calendar_event(
        calendar_id,
        _subscription_event_id(sub_id, "cancellation"),
        name="Subscription cancellation",
        description=f"Subscription {sub_id} ends",
        when_ts=cancel_at,
        timezone_name=timezone_name,
    )


def _proration_fraction(now: int, period_start: int, period_end: int) -> float:
    remaining = max(0, period_end - now)
    total = max(1, period_end - period_start)
    return min(1.0, max(0.0, remaining / total))


def calculate_proration(
    *,
    current_price: int,
    new_price: int,
    now: int,
    period_start: int,
    period_end: int,
) -> int:
    fraction = _proration_fraction(now, period_start, period_end)
    difference = new_price - current_price
    return int(round(difference * fraction))

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
        "benefits": [b.model_dump() for b in body.benefits],
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
    if body.benefits is not None:
        updated["benefits"] = [b.model_dump() for b in body.benefits]
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
    _enforce_kyc_tier(subscriber_id, 2)  # GAP-0268 (inert unless enforcement flag on)
    plan = ddb_get_item(pk_plan(plan_id), "META")
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    if plan.get("status") != "active":
        raise HTTPException(status_code=400, detail="Plan is not active")
    if plan["creator_id"] == subscriber_id:
        raise HTTPException(status_code=400, detail="Creator cannot subscribe to their own plan")

    # SUB-E0: idempotent replay — a retry with the same client_request_id returns
    # the already-created subscription (no second charge, no second record).
    idempotency_key = (body.client_request_id or "").strip()
    if idempotency_key:
        prior_sub_id = _load_subscribe_idem(subscriber_id, idempotency_key)
        if prior_sub_id:
            prior = ddb_get_item(pk_subscription(prior_sub_id), "META")
            if prior:
                return attach_subscription_profiles(normalize_subscription(prior))

    ts = now_ts()
    subscription_id = new_id("sub")
    provider_subscription_id = new_id("stub_sub")
    interval = _plan_interval(plan, body.interval)
    period_end = ts + interval_seconds(interval)
    base_price = _select_plan_price(plan, interval)
    applied_discount = None
    # GAP-0342: platform promo-code system (app/services/promo_codes.py).
    # When a promo_code is supplied it takes precedence over the legacy
    # creator discount_code (the two do NOT stack). We validate the code
    # *before* charging (TOCTOU guard) and atomically redeem it *after* the
    # charge succeeds — promo_codes.redeem_promo_code's conditional
    # current_uses increment is the real double-use guard.
    promo_validation = None
    promo_trial_days = 0
    if body.promo_code:
        from app.services import promo_codes as _promo_codes

        promo_validation = _promo_codes.validate_promo_code(
            code=body.promo_code,
            user_id=subscriber_id,
            checkout_type="subscription",
            item_price_cents=base_price,
            creator_user_id=plan["creator_id"],
        )
        if not promo_validation.get("valid"):
            raise HTTPException(
                status_code=400,
                detail=promo_validation.get("message") or "Invalid or expired promo code",
            )
        price_cents = int(promo_validation["final_price_cents"])
        promo_trial_days = int(promo_validation.get("free_trial_days") or 0)
    elif body.discount_code:
        discount = _get_discount(plan["creator_id"], body.discount_code)
        if not discount or not _is_discount_active(discount):
            raise HTTPException(status_code=400, detail="Invalid or inactive discount code")
        applied_discount = {
            "code": discount["code"],
            "percent_off": discount["percent_off"],
            "duration": discount.get("duration"),
            "duration_months": discount.get("duration_months"),
        }
        price_cents = _apply_discount(base_price, discount)
    else:
        price_cents = base_price
    trial_end = None
    trial_start = None
    status = "active"
    # GAP-0342: a free_trial promo grants trial days when the customer did
    # not request their own trial.
    if promo_trial_days and not body.trial_days:
        trial_start = ts
        trial_end = ts + promo_trial_days * 86400
        period_end = trial_end
        status = "trialing"
    if body.trial_days:
        trial_start = ts
        trial_end = ts + int(body.trial_days) * 86400
        period_end = trial_end
        status = "trialing"

    # SUB-E0: REAL, funds-guarded charge BEFORE writing any record. A charging
    # (non-trial, price > 0) subscribe resolves the subscriber's PM (explicit ->
    # default) and runs a stripe-mock PaymentIntent (the tips rail). A no-PM /
    # declined charge raises 402 HERE, so NOTHING is written — no subscription,
    # no invoice, no creator credit (no phantom revenue). Trials and fully
    # discounted ($0) subscribes collect no funds now and skip the charge.
    payment_method_id: Optional[str] = None
    payment_intent_id: Optional[str] = None
    charging = status != "trialing" and int(price_cents) > 0
    if charging:
        payment_method_id = resolve_subscription_payment_method(subscriber_id, body.payment_method_id)
        payment_intent_id = _charge_subscription_payment_intent(
            subscriber_id=subscriber_id,
            amount_cents=int(price_cents),
            currency=plan["currency"],
            payment_method_id=payment_method_id,
            plan_id=plan_id,
            subscription_id=subscription_id,
            idempotency_key=(idempotency_key or f"{subscription_id}:{ts}"),
        )
    elif status == "trialing":
        # SUB-E2: TRIAL requires a CARD UP FRONT. Capture + VALIDATE a real owned
        # PM at trial start (NO charge now); store it so the E1 sweeper can
        # AUTO-CONVERT (charge the stored PM) at trial_end. A trial with no
        # resolvable/owned PM is rejected 402 here -> no phantom trialing sub.
        payment_method_id = resolve_subscription_payment_method(subscriber_id, body.payment_method_id)

    sub = {
        "subscription_id": subscription_id,
        "plan_id": plan_id,
        "creator_id": plan["creator_id"],
        "subscriber_id": subscriber_id,
        "interval": interval,
        "provider": "stripe" if payment_intent_id else "stub",
        "provider_subscription_id": provider_subscription_id,
        "status": status,
        "start_at": ts,
        "current_period_end": period_end,
        # SUB-E0: authoritative next-charge timestamp for the E1 renewal engine.
        "next_billing_date": period_end,
        "payment_method_id": payment_method_id,
        "payment_intent_id": payment_intent_id,
        "cancel_at_period_end": False,
        "price_cents": price_cents,
        "currency": plan["currency"],
        "auto_renew": True,
        "trial_start": trial_start,
        "trial_end": trial_end,
        "proration_policy": "full",
        "renewal_policy": "auto",
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

    if status != "trialing":
        invoice_id = new_id("inv")
        invoice = {
            "invoice_id": invoice_id,
            "subscription_id": subscription_id,
            "subscriber_id": subscriber_id,
            # SUB-E0: real PaymentIntent id on a charged subscribe (not a stub id).
            "provider": "stripe" if payment_intent_id else "stub",
            "provider_invoice_id": payment_intent_id or new_id("stub_inv"),
            "payment_intent_id": payment_intent_id,
            "payment_method_id": payment_method_id,
            "amount_cents": int(sub["price_cents"]),
            "currency": plan["currency"],
            "status": "paid",
            "period_start": ts,
            "period_end": period_end,
            "created_at": ts,
        }
        if applied_discount:
            invoice["discount"] = applied_discount
        recurring = emit_subscription_cycle_order_and_reconcile(subscription=sub, plan=plan, invoice=invoice)
        invoice["recurring_order_id"] = recurring["order_id"]
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
        _mirror_creator_credit_to_billing(
            plan["creator_id"],
            int(invoice["amount_cents"]) - fee_cents,
            currency=invoice["currency"],
            created_at=ts,
            subscription_id=subscription_id,
            subscriber_id=subscriber_id,
            invoice_id=invoice_id,
        )

    # SUB-E0: persist the idempotency marker AFTER a successful charge + record
    # write, so a retry with the same client_request_id short-circuits to the
    # already-created subscription (no double charge / double subscribe).
    _store_subscribe_idem(subscriber_id, idempotency_key, subscription_id)

    # GAP-0342: record the promo redemption AFTER the subscription is
    # committed (and any charge has settled above). redeem_promo_code does an
    # atomic conditional current_uses increment — if the code was exhausted
    # between validate and now (TOCTOU), it fails and we reject the request.
    if promo_validation is not None:
        from app.services import promo_codes as _promo_codes

        _redeem_item, _redeem_err = _promo_codes.redeem_promo_code(
            code_id=promo_validation["code_id"],
            user_id=subscriber_id,
            original_price_cents=int(promo_validation["original_price_cents"]),
            final_price_cents=int(promo_validation["final_price_cents"]),
            checkout_type="subscription",
            checkout_item_id=subscription_id,
        )
        if _redeem_err:
            raise HTTPException(status_code=400, detail=_redeem_err)
        sub["promo_code"] = {
            "code_id": promo_validation["code_id"],
            "discount_type": promo_validation.get("discount_type"),
            "discount_cents": int(promo_validation.get("discount_cents") or 0),
            "free_trial_days": int(promo_validation.get("free_trial_days") or 0),
        }
        save_subscription(sub)

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
    # GAP-0355: emit a social alert to the creator that a new subscriber joined
    # (alerts table + bell badge). Best-effort: never break subscription create.
    try:
        from app.services.social_alerts import emit_social_alert
        from app.services.profile import get_profile_identity
        actor_name = get_profile_identity(subscriber_id).get("display_name") or subscriber_id
        emit_social_alert(
            recipient_user_id=plan["creator_id"],
            alert_type="subscription_started",
            actor_user_id=subscriber_id,
            actor_display_name=actor_name,
            title=f"{actor_name} subscribed to you",
            details={"plan_id": plan_id, "subscriber_id": subscriber_id, "subscription_id": subscription_id},
            action_url="/subscriptions",
        )
    except Exception:
        logger.warning("subscription social alert failed creator=%s", plan["creator_id"], exc_info=True)
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

    # GAP-0153: detect subscriber-count milestones in real time at signup.
    try:
        from app.services.milestones import check_milestone

        new_count = count_active_subscribers(plan["creator_id"])
        check_milestone(plan["creator_id"], "subscribers", new_count)
    except Exception:
        logger.warning("check_milestone failed on subscription signup", exc_info=True)

    # ADV-402: attribute this subscription to the subscriber's last ad click
    # (explicit ad_click_id or last-click within 7d) and charge the CPA bid.
    # Only on a real charge (not a free trial). Best-effort: never break signup.
    if status != "trialing":
        try:
            from app.services.ad_attribution import attribute_conversion
            attribute_conversion(
                viewer_sub=subscriber_id,
                conversion_type="subscription",
                conversion_value_cents=int(sub.get("price_cents") or 0),
                ad_click_id=getattr(body, "ad_click_id", "") or "",
            )
        except Exception:
            logger.warning("ad_conversion_attribution_failed subscribe sub=%s", subscriber_id, exc_info=True)

    refresh_subscription_calendar_events(sub, plan)
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
    sub["renewal_policy"] = "cancel_at_period_end" if body.cancel_at_period_end else "manual"
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
    refresh_subscription_calendar_events(sub)
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
    sub["renewal_policy"] = "auto"
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
    refresh_subscription_calendar_events(sub)
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
    if body.renewal_policy:
        sub["renewal_policy"] = body.renewal_policy
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
    refresh_subscription_calendar_events(sub)
    return attach_subscription_profiles(sub)


@router.post("/api/subscriptions/{subscription_id}/trial/convert", response_model=SubscriptionOut)
async def convert_trial(
    subscription_id: str,
    request: Request,
    x_user_id: Optional[str] = Header(default=None),
):
    sub = ddb_get_item(pk_subscription(subscription_id), "META")
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    sub = normalize_subscription(sub)
    user_id = require_user(x_user_id)
    if user_id not in (sub["subscriber_id"], sub["creator_id"]):
        raise HTTPException(status_code=403, detail="Not authorized to convert trial")
    if (sub.get("status") or "").lower() != "trialing":
        raise HTTPException(status_code=400, detail="Subscription is not in trial")
    plan = ddb_get_item(pk_plan(sub["plan_id"]), "META")
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")

    ts = now_ts()
    sub["status"] = "active"
    sub["trial_converted_at"] = ts
    sub["current_period_end"] = ts + interval_seconds(sub["interval"])
    sub["updated_at"] = ts
    save_subscription(sub)
    record_billing_subscription(sub)

    invoice_id = new_id("inv")
    invoice = {
        "invoice_id": invoice_id,
        "subscription_id": subscription_id,
        "subscriber_id": sub["subscriber_id"],
        "provider_invoice_id": new_id("stub_inv"),
        "amount_cents": int(sub["price_cents"]),
        "currency": sub["currency"],
        "status": "paid",
        "period_start": ts,
        "period_end": sub["current_period_end"],
        "created_at": ts,
    }
    recurring = emit_subscription_cycle_order_and_reconcile(subscription=sub, plan=plan, invoice=invoice)
    invoice["recurring_order_id"] = recurring["order_id"]
    save_invoice(invoice)
    record_billing_payment(invoice, subscription_id)
    record_billing_transaction(
        user_sub=sub["subscriber_id"],
        amount_cents=int(invoice["amount_cents"]),
        currency=invoice["currency"],
        description=f"Subscription {sub['plan_id']}",
        status="COMPLETED",
        external_ref=invoice_id,
        metadata={"subscription_id": subscription_id, "creator_id": sub["creator_id"]},
    )

    fee_cents = int(invoice["amount_cents"] * FEE_BPS / 10000)
    charge_entry = {
        "entry_id": new_id("led"),
        "subscription_id": subscription_id,
        "subscriber_id": sub["subscriber_id"],
        "entry_type": "charge",
        "amount_cents": invoice["amount_cents"],
        "currency": invoice["currency"],
        "created_at": ts,
        "metadata": {"invoice_id": invoice_id},
    }
    fee_entry = {
        "entry_id": new_id("led"),
        "subscription_id": subscription_id,
        "subscriber_id": sub["subscriber_id"],
        "entry_type": "fee",
        "amount_cents": fee_cents,
        "currency": invoice["currency"],
        "created_at": ts,
        "metadata": {"invoice_id": invoice_id},
    }
    save_ledger_entry(sub["creator_id"], charge_entry)
    save_ledger_entry(sub["creator_id"], fee_entry)
    _mirror_creator_credit_to_billing(
        sub["creator_id"],
        int(invoice["amount_cents"]) - fee_cents,
        currency=invoice["currency"],
        created_at=ts,
        subscription_id=subscription_id,
        subscriber_id=sub["subscriber_id"],
        invoice_id=invoice_id,
    )

    audit_event(
        "subscription_trial_converted",
        sub["subscriber_id"],
        request,
        outcome="success",
        subscription_id=subscription_id,
        plan_id=sub["plan_id"],
        creator_id=sub["creator_id"],
    )
    refresh_subscription_calendar_events(sub, plan)
    return attach_subscription_profiles(sub)


@router.post("/api/subscriptions/{subscription_id}/change-plan", response_model=SubscriptionOut)
async def change_subscription_plan(
    subscription_id: str,
    body: SubscriptionChangePlanIn,
    request: Request,
    x_user_id: Optional[str] = Header(default=None),
):
    sub = ddb_get_item(pk_subscription(subscription_id), "META")
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    sub = normalize_subscription(sub)
    user_id = require_user(x_user_id)
    if user_id not in (sub["subscriber_id"], sub["creator_id"]):
        raise HTTPException(status_code=403, detail="Not authorized to change plan")
    plan = ddb_get_item(pk_plan(body.plan_id), "META")
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    if plan.get("status") != "active":
        raise HTTPException(status_code=400, detail="Plan is not active")

    interval = _plan_interval(plan, body.interval)
    new_price = _select_plan_price(plan, interval)
    ts = now_ts()

    # SUB-E2 LOCKED ROUTING: an UPGRADE (target price strictly higher) applies
    # IMMEDIATELY and charges the PRORATED DELTA for the remaining period now (real
    # E0 rail + creator credited the delta NET). A DOWNGRADE (target price <=
    # current) is SCHEDULED as a pending_change that the E1 sweeper applies at
    # period end (no immediate money). An explicit effective="period_end" also
    # schedules.
    old_price = int(sub["price_cents"])
    is_upgrade = int(new_price) > old_price
    schedule_at_period_end = (not is_upgrade) or (body.effective == "period_end")

    if schedule_at_period_end:
        apply_at = int(sub.get("current_period_end") or ts)
        sub["pending_change"] = {
            "plan_id": body.plan_id,
            "interval": interval,
            "price_cents": int(new_price),
            "apply_at": apply_at,
            "scheduled_at": ts,
            "direction": "upgrade" if is_upgrade else "downgrade",
        }
        # legacy mirror fields (kept for any back-compat reader)
        sub["pending_plan_id"] = body.plan_id
        sub["pending_interval"] = interval
        sub["pending_price_cents"] = int(new_price)
        sub["pending_apply_at"] = apply_at
        sub["updated_at"] = ts
        save_subscription(sub)
        record_billing_subscription(sub)
        audit_event(
            "subscription_plan_change_scheduled",
            sub["subscriber_id"],
            request,
            outcome="success",
            subscription_id=subscription_id,
            plan_id=body.plan_id,
            effective="period_end",
        )
        refresh_subscription_calendar_events(sub, plan)
        return attach_subscription_profiles(sub)

    # ---- UPGRADE: immediate, prorated DELTA charge via the E0 rail ----
    # delta = (new_price - old_price) * remaining_fraction (>=0 for an upgrade with
    # time left; a fully-elapsed period yields 0 -> switch plan with no charge).
    proration_amount = calculate_proration(
        current_price=old_price,
        new_price=int(new_price),
        now=ts,
        period_start=int(sub.get("start_at") or ts),
        period_end=int(sub.get("current_period_end") or ts),
    )
    if proration_amount < 0:
        proration_amount = 0
    upgrade_pm = None
    upgrade_pi = None
    if proration_amount > 0:
        upgrade_pm = resolve_subscription_payment_method(
            sub["subscriber_id"], body.payment_method_id or sub.get("payment_method_id")
        )
        upgrade_pi = _charge_subscription_payment_intent(
            subscriber_id=sub["subscriber_id"],
            amount_cents=int(proration_amount),
            currency=sub["currency"],
            payment_method_id=upgrade_pm,
            plan_id=body.plan_id,
            subscription_id=subscription_id,
            idempotency_key=f"{subscription_id}:upgrade:{int(sub.get('current_period_end') or ts)}:{body.plan_id}",
        )

    # switch the plan NOW; the cycle they already paid keeps its period end (they
    # only owe the upgrade delta for the remaining time).
    sub["plan_id"] = body.plan_id
    sub["interval"] = interval
    sub["price_cents"] = int(new_price)
    sub["proration_policy"] = body.proration_policy
    if upgrade_pm:
        sub["payment_method_id"] = upgrade_pm
    for _k in ("pending_change", "pending_plan_id", "pending_interval", "pending_price_cents", "pending_apply_at"):
        sub.pop(_k, None)
    sub["updated_at"] = ts
    save_subscription(sub)
    record_billing_subscription(sub)

    if proration_amount > 0:
        invoice_id = body.provider_invoice_id or new_id("inv")
        invoice = {
            "invoice_id": invoice_id,
            "subscription_id": subscription_id,
            "subscriber_id": sub["subscriber_id"],
            "provider": "stripe" if upgrade_pi else "stub",
            "provider_invoice_id": upgrade_pi or body.provider_invoice_id or new_id("stub_inv"),
            "payment_intent_id": upgrade_pi,
            "payment_method_id": upgrade_pm,
            "amount_cents": int(proration_amount),
            "currency": sub["currency"],
            "status": "paid",
            "period_start": ts,
            "period_end": sub.get("current_period_end"),
            "created_at": ts,
            "billing_reason": "subscription_upgrade_proration",
            "is_proration": True,
            "proration_amount_cents": int(proration_amount),
            "proration_period_start": sub.get("start_at"),
            "proration_period_end": sub.get("current_period_end"),
        }
        recurring = emit_subscription_cycle_order_and_reconcile(subscription=sub, plan=plan, invoice=invoice)
        invoice["recurring_order_id"] = recurring["order_id"]
        save_invoice(invoice)
        record_billing_payment(invoice, subscription_id)
        record_billing_transaction(
            user_sub=sub["subscriber_id"],
            amount_cents=int(proration_amount),
            currency=sub["currency"],
            description=f"Subscription upgrade proration {subscription_id}",
            status="COMPLETED",
            external_ref=invoice_id,
            metadata={"subscription_id": subscription_id, "creator_id": sub["creator_id"], "billing_reason": "upgrade_proration"},
        )
        # creator credited the DELTA NET (10% fee) -> withdrawable via the mirror
        fee_cents = int(proration_amount * FEE_BPS / 10000)
        _base = {
            "subscription_id": subscription_id,
            "subscriber_id": sub["subscriber_id"],
            "currency": sub["currency"],
            "created_at": ts,
            "metadata": {"invoice_id": invoice_id, "billing_reason": "upgrade_proration"},
        }
        save_ledger_entry(sub["creator_id"], {**_base, "entry_id": new_id("led"), "entry_type": "charge", "amount_cents": int(proration_amount)})
        save_ledger_entry(sub["creator_id"], {**_base, "entry_id": new_id("led"), "entry_type": "fee", "amount_cents": fee_cents})
        _mirror_creator_credit_to_billing(
            sub["creator_id"],
            int(proration_amount) - fee_cents,
            currency=sub["currency"],
            created_at=ts,
            subscription_id=subscription_id,
            subscriber_id=sub["subscriber_id"],
            invoice_id=invoice_id,
        )

    audit_event(
        "subscription_plan_changed",
        sub["subscriber_id"],
        request,
        outcome="success",
        subscription_id=subscription_id,
        plan_id=body.plan_id,
        proration_amount_cents=proration_amount,
    )
    refresh_subscription_calendar_events(sub, plan)
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
    sub["renewal_policy"] = "manual"
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
    refresh_subscription_calendar_events(sub)
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
    sub["renewal_policy"] = "cancel_at_period_end"
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
    refresh_subscription_calendar_events(sub)
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
    if provider not in ("stub", "paypal", "ccbill"):
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
    sub_plan = ddb_get_item(pk_plan(sub.get("plan_id")), "META") or {"plan_id": sub.get("plan_id")}
    if event_type in ("invoice.proration", "subscription.proration"):
        proration_amount = body.metadata.get("proration_amount_cents")
        if proration_amount is None:
            proration_amount = body.metadata.get("amount_cents") or body.metadata.get("amount")
        try:
            proration_amount = int(proration_amount)
        except (TypeError, ValueError):
            proration_amount = 0
        if proration_amount:
            currency = body.metadata.get("currency", sub.get("currency", "usd"))
            provider_invoice_id = body.metadata.get("provider_invoice_id")
            invoice_id = body.metadata.get("invoice_id") or provider_invoice_id or new_id("inv")
            invoice = {
                "invoice_id": invoice_id,
                "subscription_id": body.subscription_id,
                "subscriber_id": sub["subscriber_id"],
                "provider_invoice_id": provider_invoice_id or new_id("stub_inv"),
                "amount_cents": abs(int(proration_amount)),
                "currency": currency,
                "status": "paid" if proration_amount > 0 else "credited",
                "period_start": body.metadata.get("period_start", ts),
                "period_end": body.metadata.get("period_end", sub.get("current_period_end")),
                "created_at": ts,
                "is_proration": True,
                "proration_amount_cents": int(proration_amount),
                "proration_period_start": body.metadata.get("proration_period_start", sub.get("start_at")),
                "proration_period_end": body.metadata.get("proration_period_end", sub.get("current_period_end")),
            }
            recurring = emit_subscription_cycle_order_and_reconcile(subscription=sub, plan=sub_plan, invoice=invoice)
            invoice["recurring_order_id"] = recurring["order_id"]
            save_invoice(invoice)
            record_billing_payment(invoice, body.subscription_id)
            record_billing_transaction(
                user_sub=sub["subscriber_id"],
                amount_cents=int(proration_amount),
                currency=currency,
                description=f"Subscription proration {body.subscription_id}",
                status="COMPLETED",
                external_ref=invoice_id,
                metadata={"subscription_id": body.subscription_id, "creator_id": sub["creator_id"]},
            )
            entry_type = "proration_charge" if proration_amount > 0 else "proration_credit"
            entry = {
                "entry_id": new_id("led"),
                "subscription_id": body.subscription_id,
                "subscriber_id": sub["subscriber_id"],
                "entry_type": entry_type,
                "amount_cents": abs(int(proration_amount)),
                "currency": currency,
                "created_at": ts,
                "metadata": {"invoice_id": invoice_id, "proration_amount_cents": proration_amount},
            }
            save_ledger_entry(sub["creator_id"], entry)
    elif event_type == "invoice.paid":
        sub["status"] = "active"
        sub["current_period_end"] = ts + interval_seconds(sub.get("interval", "month"))
        sub["auto_renew"] = True
        if sub.get("discount_remaining_months"):
            sub["discount_remaining_months"] = max(0, int(sub["discount_remaining_months"]) - 1)

        amount_cents = body.metadata.get("amount_cents") or body.metadata.get("amount") or sub.get("price_cents")
        try:
            amount_cents = int(amount_cents)
        except (TypeError, ValueError):
            amount_cents = int(sub.get("price_cents") or 0)
        invoice_id = body.invoice_id or body.metadata.get("invoice_id") or body.metadata.get("provider_invoice_id") or new_id("inv")
        invoice = {
            "invoice_id": invoice_id,
            "subscription_id": body.subscription_id,
            "subscriber_id": sub["subscriber_id"],
            "provider_invoice_id": body.metadata.get("provider_invoice_id") or body.invoice_id or new_id("stub_inv"),
            "amount_cents": amount_cents,
            "currency": body.metadata.get("currency", sub.get("currency", "usd")),
            "status": "paid",
            "period_start": body.metadata.get("period_start", ts),
            "period_end": body.metadata.get("period_end", sub.get("current_period_end")),
            "created_at": ts,
        }
        recurring = emit_subscription_cycle_order_and_reconcile(subscription=sub, plan=sub_plan, invoice=invoice)
        invoice["recurring_order_id"] = recurring["order_id"]
        save_invoice(invoice)
        record_billing_payment(invoice, body.subscription_id)
    elif event_type == "invoice.payment_failed":
        sub["status"] = "past_due"
    elif event_type == "subscription.canceled":
        sub["status"] = "canceled"
        sub["cancel_at_period_end"] = True
        sub["auto_renew"] = False

    sub["updated_at"] = ts
    save_subscription(sub)
    return {"ok": True, "event_id": event_id}


# -----------------------------
# SUB-E1 — manual/admin trigger for the recurring renewal + dunning sweep
# (mirrors the moderation/shipment simulate drivers; the periodic task in
# main.py runs it on a wall-clock interval). Admin/root gated.
# -----------------------------
@router.post("/ui/admin/subscriptions/run-renewals")
async def admin_run_renewals(
    request: Request,
    limit: int = Query(default=1000, ge=1, le=5000),
    now_override: Optional[int] = Query(default=None),
    _admin=Depends(require_admin_or_root),
):
    """Drive one renewal/dunning/expiry sweep now. ``now_override`` (unix ts)
    lets an operator/verifier evaluate due-ness against a chosen wall clock.
    Returns the sweep action summary."""
    from app.services.subscription_renewal import run_renewal_sweep

    return run_renewal_sweep(now=now_override, limit=limit)
