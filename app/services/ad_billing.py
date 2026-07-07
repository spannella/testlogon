"""Ad billing engine -- charges, revenue splits, invoices, spending alerts (ADS-007)."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import new_ledger_entry, user_pk

logger = logging.getLogger(__name__)

# Revenue share: platform takes this percentage, creator gets remainder.
# PLATFORM_REVENUE_SHARE_PCT is retained as a legacy default (percent) for the
# admin reporting module (admin_ad_platform.py) and as a fallback. The actual
# per-charge split is driven by the creator's negotiated basis-points rate
# resolved at billing time (GAP-0054).
PLATFORM_REVENUE_SHARE_PCT = 30
# Default creator revenue share in basis points (7000 bps = 70% to creator),
# matching content_ad_controls.DEFAULT_REVENUE_SHARE_BPS.
DEFAULT_CREATOR_REVENUE_SHARE_BPS = 7000
MIN_DEPOSIT_CENTS = 5000  # $50 minimum deposit


def deposit_funds(account_id: str, amount_cents: int, payment_method_id: str = "") -> dict:
    """Add funds to advertiser account balance.

    ADV-101: the payment_method_id is now actually CHARGED via the stripe-mock
    PaymentIntent rail (mirrors billing.charge_once / tips._charge_tip) BEFORE any
    balance credit. A declined card / processor error raises HTTPException(402)
    before any ledger row is written or balance credited -- a failed deposit never
    credits the account.
    """
    if amount_cents < MIN_DEPOSIT_CENTS:
        raise ValueError(f"Minimum deposit is $50")

    # ADV-101: charge the payment method FIRST. Resolve the owner sub so the
    # charge lands on the advertiser's own Stripe customer.
    owner_sub = ""
    try:
        from app.services.ad_accounts import get_ad_account
        _acct = get_ad_account(account_id)
        owner_sub = (_acct or {}).get("owner_sub", "")
    except Exception:
        owner_sub = ""
    payment_intent_id = _charge_deposit(
        owner_sub=owner_sub, account_id=account_id,
        amount_cents=amount_cents, payment_method_id=payment_method_id,
    )

    ts = now_ts()
    entry_id = f"dep_{uuid.uuid4().hex[:12]}"
    month_key = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m")

    # Write billing ledger entry. Omit campaign_id entirely (rather than "")
    # because it is the key of the ByCampaign GSI and DynamoDB rejects empty
    # strings as index keys; a deposit is not tied to a campaign, so it should
    # simply be absent from that sparse index.
    T.ad_billing.put_item(Item={
        "pk": f"ACCT#{account_id}",
        "sk": f"LEDGER#{ts}#{entry_id}",
        "entry_id": entry_id,
        "account_id": account_id,
        "entry_type": "budget_deposit",
        "amount_cents": amount_cents,
        "state": "settled",
        "reason": "Account deposit",
        "meta": {
            "payment_method_id": payment_method_id,
            "stripe_payment_intent_id": payment_intent_id or "",
        },
        "month_key": month_key,
        "created_at": ts,
    })

    # Increment account balance (only reached after a successful charge)
    T.ad_accounts.update_item(
        Key={"pk": f"ACCT#{account_id}", "sk": "META"},
        UpdateExpression="SET balance_cents = if_not_exists(balance_cents, :z) + :amt",
        ExpressionAttributeValues={":z": 0, ":amt": amount_cents},
    )

    return {"ok": True, "entry_id": entry_id, "new_balance_cents": _get_balance(account_id)}


def _charge_deposit(*, owner_sub: str, account_id: str, amount_cents: int,
                    payment_method_id: str) -> Optional[str]:
    """ADV-101: charge an advertiser deposit via the stripe-mock PaymentIntent rail.

    Mirrors app.services.tips._charge_tip / billing.charge_once: off_session +
    confirm with an idempotency_key so a retried deposit never double-charges.

    Returns the PaymentIntent id on success, or None for the dev-stub path
    (Stripe not configured, or no payment method supplied -- preserves the historical
    ledger-only behavior so internal/seed callers without a PM still work).

    Raises HTTPException(402) on a declined card / processor error / non-succeeded
    terminal status so the caller (deposit_funds) never credits the balance.

    stripe-mock nuance: the local stripe-mock cannot truly confirm an off_session
    intent, so when stripe_api_base is overridden we accept the created intent
    unless it is canceled/payment_failed; a real Stripe (no api_base override)
    still requires status == "succeeded" and a real decline surfaces as CardError.
    """
    if not getattr(S, "stripe_secret_key", "") or not payment_method_id:
        return None
    from fastapi import HTTPException
    from app.routers.billing import ensure_stripe_configured, get_or_create_customer
    import stripe

    ensure_stripe_configured()
    customer_id = get_or_create_customer(owner_sub or account_id)
    try:
        pi = stripe.PaymentIntent.create(
            amount=int(amount_cents),
            currency="usd",
            customer=customer_id,
            payment_method=payment_method_id,
            off_session=True,
            confirm=True,
            description="Ad account deposit",
            metadata={
                "app_user_id": owner_sub,
                "purpose": "ad_deposit",
                "account_id": account_id,
            },
            idempotency_key=f"addep:{account_id}:{amount_cents}:{payment_method_id}",
        )
    except stripe.error.CardError as exc:
        logger.info("ad deposit declined for account=%s: %s", account_id, exc)
        raise HTTPException(402, {"code": "payment_failed", "message": str(exc)})
    except stripe.error.StripeError as exc:
        logger.warning("ad deposit stripe error for account=%s: %s", account_id, exc)
        raise HTTPException(402, {"code": "payment_failed",
                                  "message": "Deposit charge failed at the payment processor."})

    status = (pi.get("status") or "").lower()
    charged_ok = status == "succeeded" or (
        bool(getattr(S, "stripe_api_base", "")) and status not in ("canceled", "payment_failed")
    )
    if not charged_ok:
        raise HTTPException(
            402,
            {"code": "payment_failed",
             "message": f"Deposit charge did not succeed (status={status})."},
        )
    return pi.get("id")


def charge_impression(
    *, account_id: str, campaign_id: str, creative_id: str,
    creator_id: str, content_id: str, bid_cpm_cents: int,
) -> dict:
    """Charge advertiser for one impression (CPM model)."""
    charge_cents = max(1, bid_cpm_cents // 1000)
    return _process_charge(
        account_id=account_id, campaign_id=campaign_id,
        entry_type="impression_charge", charge_cents=charge_cents,
        creator_id=creator_id, reason="Ad impression",
        meta={"creative_id": creative_id, "content_id": content_id, "model": "cpm"},
    )


def charge_click(
    *, account_id: str, campaign_id: str, creative_id: str,
    creator_id: str, content_id: str, bid_cpc_cents: int,
) -> dict:
    """Charge advertiser for one click (CPC model)."""
    return _process_charge(
        account_id=account_id, campaign_id=campaign_id,
        entry_type="click_charge", charge_cents=bid_cpc_cents,
        creator_id=creator_id, reason="Ad click",
        meta={"creative_id": creative_id, "content_id": content_id, "model": "cpc"},
    )


def charge_conversion(
    *, account_id: str, campaign_id: str, creative_id: str,
    creator_id: str, content_id: str, bid_cpa_cents: int,
) -> dict:
    """Charge advertiser for one conversion (CPA model)."""
    return _process_charge(
        account_id=account_id, campaign_id=campaign_id,
        entry_type="conversion_charge", charge_cents=bid_cpa_cents,
        creator_id=creator_id, reason="Ad conversion",
        meta={"creative_id": creative_id, "content_id": content_id, "model": "cpa"},
    )


def _process_charge(
    *, account_id: str, campaign_id: str, entry_type: str,
    charge_cents: int, creator_id: str, reason: str, meta: dict,
) -> dict:
    """Process a charge: debit advertiser, split revenue, check budget.

    ADV-102: the balance debit is now a CONDITIONAL write
    (attribute_exists(balance_cents) AND balance_cents >= :amt) executed FIRST.
    If the account cannot cover the charge the debit is rejected and NOTHING else
    is written (no ledger row, no campaign-spend bump, no revenue split) -- the
    balance can never go negative and concurrent charges never oversell.
    """
    ts = now_ts()
    entry_id = f"chg_{uuid.uuid4().hex[:12]}"
    month_key = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m")

    # 1. Debit advertiser balance FIRST, funds-guarded so it can never go negative.
    try:
        T.ad_accounts.update_item(
            Key={"pk": f"ACCT#{account_id}", "sk": "META"},
            UpdateExpression="SET balance_cents = balance_cents - :amt, "
                             "lifetime_spend_cents = if_not_exists(lifetime_spend_cents, :z) + :amt",
            ConditionExpression="attribute_exists(balance_cents) AND balance_cents >= :amt",
            ExpressionAttributeValues={":amt": charge_cents, ":z": 0},
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            logger.info(
                "ad_charge_insufficient_funds account=%s campaign=%s amount=%s",
                account_id, campaign_id, charge_cents,
            )
            return {"ok": False, "reason": "insufficient_funds", "charge_cents": charge_cents}
        raise

    # 2. Write charge to ad_billing ledger (only after a successful debit)
    T.ad_billing.put_item(Item={
        "pk": f"ACCT#{account_id}",
        "sk": f"LEDGER#{ts}#{entry_id}",
        "entry_id": entry_id,
        "account_id": account_id,
        "campaign_id": campaign_id,
        "entry_type": entry_type,
        "amount_cents": charge_cents,
        "state": "settled",
        "reason": reason,
        "meta": meta,
        "month_key": month_key,
        "created_at": ts,
    })

    # 3. Increment campaign spend
    T.ad_campaigns.update_item(
        Key={"pk": f"ACCT#{account_id}", "sk": f"CAMPAIGN#{campaign_id}"},
        UpdateExpression="SET spent_today_cents = if_not_exists(spent_today_cents, :z) + :amt, "
                         "lifetime_spent_cents = if_not_exists(lifetime_spent_cents, :z) + :amt",
        ExpressionAttributeValues={":z": 0, ":amt": charge_cents},
    )

    # 4. Revenue split
    _split_revenue(
        charge_cents=charge_cents, creator_id=creator_id,
        account_id=account_id, meta=meta, ts=ts,
    )

    # 5. Budget check + spending alerts
    _check_budget_and_alert(account_id, campaign_id)

    return {"ok": True, "entry_id": entry_id, "charge_cents": charge_cents}


def _split_revenue(
    *, charge_cents: int, creator_id: str, meta: dict, ts: int, account_id: str = "",
) -> None:
    """Split ad revenue between platform and creator.

    Uses the creator's negotiated per-creator revenue share (basis points) rather
    than a hardcoded platform percentage (GAP-0054). Records an advertiser
    transparency entry after the creator credit so the transparency log is
    populated (GAP-0053). Preserves the platform-revenue ledger write (GAP-0049).
    """
    # Resolve per-creator revenue share in basis points (GAP-0054). Falls back to
    # the platform default if unset or if the lookup fails — billing must never
    # break because of a transparency/revenue-share read.
    creator_bps = DEFAULT_CREATOR_REVENUE_SHARE_BPS
    if creator_id:
        try:
            from app.services.content_ad_controls import get_creator_revenue_share_bps
            creator_bps = get_creator_revenue_share_bps(creator_id)
        except Exception:
            logger.warning("revenue_share_bps_lookup_failed", extra={"creator_id": creator_id})

    creator_share = max(0, (charge_cents * creator_bps) // 10000)
    platform_share = charge_cents - creator_share
    platform_share_pct = (
        (platform_share * 100) // charge_cents if charge_cents > 0 else PLATFORM_REVENUE_SHARE_PCT
    )

    # Credit creator via existing billing ledger
    if creator_share > 0 and creator_id:
        try:
            _sk, credit_item = new_ledger_entry(
                key_name="pk",
                key_value=user_pk(creator_id),
                entry_type="ad_revenue_credit",
                amount_cents=creator_share,
                state="settled",
                reason="Ad revenue share",
                meta={
                    **meta,
                    "platform_share_pct": platform_share_pct,
                    "revenue_share_bps": creator_bps,
                },
            )
            T.billing.put_item(Item=credit_item)
        except Exception:
            logger.warning("ad_revenue_creator_credit_failed", extra={"creator_id": creator_id})

    # Record advertiser transparency (GAP-0053 / ADS-010) — best-effort. This
    # populates the per-advertiser transparency log read by
    # get_advertiser_transparency, which was previously always empty because
    # record_transparency had no call site.
    if creator_id and account_id:
        try:
            from app.services.ad_accounts import get_ad_account
            from app.services.content_ad_controls import record_transparency

            month = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m")
            model = meta.get("model", "")
            acct = get_ad_account(account_id)
            company_name = acct.get("company_name", "") if acct else ""

            record_transparency(
                creator_sub=creator_id,
                account_id=account_id,
                company_name=company_name,
                month=month,
                impressions=1 if model == "cpm" else 0,
                clicks=1 if model == "cpc" else 0,
                revenue_cents=creator_share,
            )
        except Exception:
            logger.warning(
                "transparency_record_failed",
                extra={"creator_id": creator_id, "account_id": account_id},
            )

    # Write platform revenue record to ad_billing table so the platform's
    # share is durably recorded for audit/reconciliation (GAP-0049).
    if platform_share > 0:
        try:
            entry_id = f"rev_{uuid.uuid4().hex[:12]}"
            month_key = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m")
            T.ad_billing.put_item(Item={
                "pk": "PLATFORM#revenue",
                "sk": f"LEDGER#{ts}#{entry_id}",
                "entry_id": entry_id,
                "entry_type": "platform_revenue_credit",
                "amount_cents": platform_share,
                "state": "settled",
                "reason": f"Platform ad revenue share ({platform_share_pct}%)",
                "meta": {
                    **meta,
                    "creator_id": creator_id,
                    "creator_share_cents": creator_share,
                    "charge_cents": charge_cents,
                    "platform_share_pct": platform_share_pct,
                    "revenue_share_bps": creator_bps,
                },
                "month_key": month_key,
                "created_at": ts,
            })
        except Exception:
            logger.warning("ad_revenue_platform_credit_failed", extra={"charge_cents": charge_cents})


def _check_budget_and_alert(account_id: str, campaign_id: str) -> None:
    """Check if campaign budget thresholds are crossed; send alerts + auto-pause."""
    from app.services.ad_campaigns import get_campaign
    from app.services.ad_accounts import get_ad_account

    campaign = get_campaign(account_id, campaign_id)
    if not campaign:
        return

    budget = int(campaign.get("budget_cents", 0))
    spent = int(campaign.get("lifetime_spent_cents", 0))
    if budget <= 0:
        return

    pct = (spent * 100) // budget
    acct = get_ad_account(account_id)
    owner_sub = acct.get("owner_sub", "") if acct else ""

    for threshold in [50, 80, 100]:
        if pct >= threshold:
            alert_sk = f"AD_BUDGET_ALERT#{campaign_id}#{threshold}"
            try:
                T.billing.put_item(
                    Item={
                        "pk": f"USER#{owner_sub}",
                        "sk": alert_sk,
                        "threshold": threshold,
                        "campaign_id": campaign_id,
                        "created_at": now_ts(),
                    },
                    ConditionExpression="attribute_not_exists(pk)",
                )
                # Alert not yet sent -- send it
                try:
                    from app.services.alerts import write_alert
                    write_alert(
                        owner_sub,
                        event="ad_budget_alert",
                        outcome="warning" if threshold < 100 else "critical",
                        title=f"Campaign budget {threshold}% spent",
                        details={
                            "campaign_id": campaign_id,
                            "campaign_name": campaign.get("name", ""),
                            "budget_cents": budget,
                            "spent_cents": spent,
                            "threshold_pct": threshold,
                        },
                    )
                except Exception:
                    pass
                # Webhook: budget spend threshold crossed (ADS-011 / GAP-0055).
                # Inside the conditional-write block so it fires once per threshold.
                try:
                    from app.services.ad_webhooks import emit_ad_event
                    emit_ad_event(
                        "ad.billing.budget_alert",
                        owner_sub,
                        {
                            "account_id": account_id,
                            "campaign_id": campaign_id,
                            "threshold_pct": threshold,
                            "budget_cents": budget,
                            "spent_cents": spent,
                        },
                    )
                except Exception:
                    pass
            except Exception:
                pass  # Alert already sent or write failed

    # Auto-pause if budget exhausted
    if pct >= 100:
        completed = False
        try:
            T.ad_campaigns.update_item(
                Key={"pk": f"ACCT#{account_id}", "sk": f"CAMPAIGN#{campaign_id}"},
                UpdateExpression="SET #s = :completed",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":completed": "completed"},
                ConditionExpression="#s <> :completed",
            )
            completed = True
        except Exception:
            pass  # Already paused/completed
        # Webhook: campaign auto-completed on budget exhaustion. Gated on the
        # conditional write succeeding so it fires only on the transition.
        if completed:
            try:
                from app.services.ad_webhooks import emit_ad_event
                emit_ad_event(
                    "ad.campaign.completed",
                    owner_sub,
                    {
                        "account_id": account_id,
                        "campaign_id": campaign_id,
                        "budget_cents": budget,
                        "spent_cents": spent,
                    },
                )
            except Exception:
                pass


def get_billing_history(account_id: str, limit: int = 50) -> list[dict]:
    """Get billing ledger entries for an account."""
    resp = T.ad_billing.query(
        KeyConditionExpression=Key("pk").eq(f"ACCT#{account_id}") & Key("sk").begins_with("LEDGER#"),
        ScanIndexForward=False,
        Limit=limit,
    )
    return resp.get("Items", [])


def get_campaign_spending(campaign_id: str, limit: int = 100) -> list[dict]:
    """Get spending entries for a specific campaign."""
    resp = T.ad_billing.query(
        IndexName="ByCampaign",
        KeyConditionExpression=Key("campaign_id").eq(campaign_id),
        ScanIndexForward=False,
        Limit=limit,
    )
    return resp.get("Items", [])


def generate_invoice(account_id: str, month: str) -> dict:
    """Generate a monthly invoice summary.

    month format: "YYYY-MM"
    """
    resp = T.ad_billing.query(
        IndexName="ByMonth",
        KeyConditionExpression=Key("month_key").eq(month),
        FilterExpression=Attr("account_id").eq(account_id),
    )
    entries = resp.get("Items", [])

    # Aggregate by campaign and entry type
    campaign_totals: Dict[str, Dict[str, Any]] = {}
    grand_total = 0
    for entry in entries:
        cid = entry.get("campaign_id", "unknown")
        etype = entry.get("entry_type", "unknown")
        amt = int(entry.get("amount_cents", 0))

        if etype in ("impression_charge", "click_charge", "conversion_charge"):
            grand_total += amt
            if cid not in campaign_totals:
                campaign_totals[cid] = {
                    "campaign_id": cid, "impressions": 0,
                    "clicks": 0, "conversions": 0, "total_cents": 0,
                }
            if etype == "impression_charge":
                campaign_totals[cid]["impressions"] += 1
            elif etype == "click_charge":
                campaign_totals[cid]["clicks"] += 1
            elif etype == "conversion_charge":
                campaign_totals[cid]["conversions"] += 1
            campaign_totals[cid]["total_cents"] += amt

    deposits = sum(
        int(e.get("amount_cents", 0))
        for e in entries
        if e.get("entry_type") == "budget_deposit"
    )

    return {
        "account_id": account_id,
        "month": month,
        "campaigns": list(campaign_totals.values()),
        "total_charges_cents": grand_total,
        "total_deposits_cents": deposits,
        "entry_count": len(entries),
    }


def _get_balance(account_id: str) -> int:
    resp = T.ad_accounts.get_item(Key={"pk": f"ACCT#{account_id}", "sk": "META"})
    item = resp.get("Item")
    return int(item.get("balance_cents", 0)) if item else 0
