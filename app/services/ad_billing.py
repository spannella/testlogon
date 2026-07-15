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


def deposit_funds(account_id: str, amount_cents: int, payment_method_id: str = "",
                  *, internal: bool = False) -> dict:
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
    from fastapi import HTTPException
    # ADV3-1 (A1/A2/B9): a PUBLIC deposit MUST be backed by a real charge -- never
    # credit free budget. A missing payment method is a hard 400 (no ledger, no
    # credit). The internal-seed caller (internal=True) keeps the legacy
    # ledger-only path so seeding/back-office top-ups without a card still work.
    if not internal and not payment_method_id:
        raise HTTPException(400, {
            "code": "payment_method_required",
            "message": "A payment method is required to fund an ad account.",
        })

    # ADV3-1: application-level deposit idempotency, claimed BEFORE the charge so a
    # double-fired deposit can neither double-charge nor double-credit -- this holds
    # even against a stripe-mock that does not itself honor the processor
    # idempotency_key (a real Stripe returns the same PaymentIntent for the same
    # key; the mock returns a fresh one). Keyed on the SAME
    # (account, amount, payment_method) tuple the PaymentIntent idempotency_key uses
    # so the app-level guard and the processor guard agree. Released on a failed /
    # again-uncharged charge so a genuine retry (e.g. a different card) can fund.
    idem_key = ""
    if not internal and payment_method_id:
        idem_key = "addep:%s:%s:%s" % (account_id, amount_cents, payment_method_id)
        try:
            T.ad_billing.put_item(
                Item={"pk": f"ACCT#{account_id}", "sk": f"DEPIDEMP#{idem_key}",
                      "entry_type": "deposit_idempotency", "created_at": now_ts()},
                ConditionExpression="attribute_not_exists(sk)",
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                logger.info("ad_deposit_duplicate account=%s key=%s", account_id, idem_key)
                return {"ok": True, "reason": "duplicate",
                        "new_balance_cents": _get_balance(account_id)}
            raise

    def _release_idem():
        if idem_key:
            try:
                T.ad_billing.delete_item(
                    Key={"pk": f"ACCT#{account_id}", "sk": f"DEPIDEMP#{idem_key}"}
                )
            except Exception:
                pass

    # Charge the payment method. A decline / processor error raises 402 (below,
    # inside _charge_deposit) -- release the idem claim first so a retry can fund.
    try:
        payment_intent_id = _charge_deposit(
            owner_sub=owner_sub, account_id=account_id,
            amount_cents=amount_cents, payment_method_id=payment_method_id,
        )
    except Exception:
        _release_idem()
        raise

    if not internal and not payment_intent_id:
        # Stripe unconfigured (dev stub) despite a supplied card: LOUD simulation
        # (uncharged_simulation ledger row + critical alert), never a silent free
        # credit; release the idem claim so a retry can fund once configured.
        _release_idem()
        _record_uncharged_deposit(account_id, amount_cents, payment_method_id)
        raise HTTPException(402, {
            "code": "charge_unavailable",
            "message": "Deposit could not be charged (payment processor unavailable).",
        })

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


def _record_uncharged_deposit(account_id: str, amount_cents: int, payment_method_id: str) -> None:
    """ADV3-1: LOUD degrade for a public deposit that could not be charged because
    the processor rail is unconfigured (dev stub). Writes an ``uncharged_simulation``
    ledger row (NOT a ``budget_deposit`` -- no balance is credited) and emits a
    critical alert so a silent free-credit can never masquerade as a real deposit.
    """
    ts = now_ts()
    entry_id = f"depsim_{uuid.uuid4().hex[:12]}"
    month_key = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m")
    try:
        T.ad_billing.put_item(Item={
            "pk": f"ACCT#{account_id}",
            "sk": f"LEDGER#{ts}#{entry_id}",
            "entry_id": entry_id,
            "account_id": account_id,
            "entry_type": "budget_deposit_uncharged",
            "amount_cents": amount_cents,
            "state": "uncharged_simulation",
            "reason": "Deposit not charged (payment processor unavailable)",
            "meta": {"payment_method_id": payment_method_id, "stripe_payment_intent_id": ""},
            "month_key": month_key,
            "created_at": ts,
        })
    except Exception:
        logger.warning("ad_deposit_uncharged_ledger_failed account=%s", account_id)
    try:
        from app.services.ad_accounts import get_ad_account
        from app.services.alerts import write_alert
        owner_sub = (get_ad_account(account_id) or {}).get("owner_sub", "")
        write_alert(
            owner_sub or account_id,
            event="ad_deposit_uncharged",
            outcome="critical",
            title="Ad deposit could not be charged",
            details={"account_id": account_id, "amount_cents": amount_cents,
                     "reason": "payment_processor_unconfigured"},
        )
    except Exception:
        logger.warning("ad_deposit_uncharged_alert_failed account=%s", account_id)


def charge_impression(
    *, account_id: str, campaign_id: str, creative_id: str,
    creator_id: str, content_id: str, bid_cpm_cents: int,
    idempotency_key: str = "",
    surface: str = "", slot_type: str = "", geo_country: str = "",
) -> dict:
    """Charge advertiser for one impression (CPM model).

    ADV3-9 (D6): surface / slot_type / geo_country are stamped on the ledger meta
    so the analytics rollup can attribute REAL spend into the per-surface and
    per-geo breakdowns (previously spend=0 on every non-creative dimension).
    """
    charge_cents = max(1, bid_cpm_cents // 1000)
    return _process_charge(
        account_id=account_id, campaign_id=campaign_id,
        entry_type="impression_charge", charge_cents=charge_cents,
        creator_id=creator_id, reason="Ad impression",
        meta={"creative_id": creative_id, "content_id": content_id, "model": "cpm",
              "surface": surface, "slot_type": slot_type, "geo_country": geo_country},
        idempotency_key=idempotency_key,
    )


def charge_click(
    *, account_id: str, campaign_id: str, creative_id: str,
    creator_id: str, content_id: str, bid_cpc_cents: int,
    idempotency_key: str = "",
    surface: str = "", slot_type: str = "", geo_country: str = "",
) -> dict:
    """Charge advertiser for one click (CPC model).

    ADV3-9 (D6): surface / slot_type / geo_country stamped on ledger meta for the
    per-surface / per-geo spend breakdown.
    """
    return _process_charge(
        account_id=account_id, campaign_id=campaign_id,
        entry_type="click_charge", charge_cents=bid_cpc_cents,
        creator_id=creator_id, reason="Ad click",
        meta={"creative_id": creative_id, "content_id": content_id, "model": "cpc",
              "surface": surface, "slot_type": slot_type, "geo_country": geo_country},
        idempotency_key=idempotency_key,
    )


def charge_conversion(
    *, account_id: str, campaign_id: str, creative_id: str,
    creator_id: str, content_id: str, bid_cpa_cents: int,
    idempotency_key: str = "", conversion_value_cents: int = 0,
) -> dict:
    """Charge advertiser for one conversion (CPA model).

    ADV-501: conversion_value_cents (the revenue the conversion drove -- e.g. the
    subscription/purchase price) is recorded on the ledger meta so the ROAS
    report can aggregate attributed value straight from the money path.
    """
    return _process_charge(
        account_id=account_id, campaign_id=campaign_id,
        entry_type="conversion_charge", charge_cents=bid_cpa_cents,
        creator_id=creator_id, reason="Ad conversion",
        meta={
            "creative_id": creative_id, "content_id": content_id, "model": "cpa",
            "conversion_value_cents": int(conversion_value_cents or 0),
        },
        idempotency_key=idempotency_key,
    )


def _process_charge(
    *, account_id: str, campaign_id: str, entry_type: str,
    charge_cents: int, creator_id: str, reason: str, meta: dict,
    idempotency_key: str = "",
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

    # ADV-203: idempotency guard. When an idempotency_key is supplied (e.g. a VOD
    # pre-roll completion keyed on ad_click_id) claim a marker BEFORE the debit so
    # a duplicate completion never double-charges. The marker omits campaign_id /
    # month_key so it stays out of the sparse ByCampaign/ByMonth GSIs and the
    # LEDGER# history query. On insufficient funds it is released so a later retry
    # (after the account is funded) can still charge exactly once.
    if idempotency_key:
        try:
            T.ad_billing.put_item(
                Item={
                    "pk": f"ACCT#{account_id}",
                    "sk": f"IDEMP#{idempotency_key}",
                    "entry_type": "charge_idempotency",
                    "created_at": ts,
                },
                ConditionExpression="attribute_not_exists(sk)",
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                logger.info(
                    "ad_charge_duplicate account=%s key=%s", account_id, idempotency_key
                )
                return {"ok": True, "reason": "duplicate", "charge_cents": 0}
            raise

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
            if idempotency_key:
                try:
                    T.ad_billing.delete_item(
                        Key={"pk": f"ACCT#{account_id}", "sk": f"IDEMP#{idempotency_key}"}
                    )
                except Exception:
                    pass
            return {"ok": False, "reason": "insufficient_funds", "charge_cents": charge_cents}
        raise

    # 2. Increment campaign spend -- HARD budget guard (ADV3-2/A4). When the
    #    campaign has a positive budget_cents the spend bump is a CONDITIONAL write
    #    that rejects the charge when it would push lifetime_spent_cents past
    #    budget_cents, so concurrent charges can NEVER overshoot the advertiser's
    #    budget. On rejection we roll the account debit back (refund balance +
    #    back out lifetime_spend), release any idempotency marker, and report
    #    budget_exceeded -- nothing else is written.
    campaign_budget_cents = 0
    try:
        from app.services.ad_campaigns import get_campaign as _gc_budget
        campaign_budget_cents = int((_gc_budget(account_id, campaign_id) or {}).get("budget_cents", 0) or 0)
    except Exception:
        campaign_budget_cents = 0

    _spend_kwargs = {
        "Key": {"pk": f"ACCT#{account_id}", "sk": f"CAMPAIGN#{campaign_id}"},
        "UpdateExpression": "SET spent_today_cents = if_not_exists(spent_today_cents, :z) + :amt, "
                            "lifetime_spent_cents = if_not_exists(lifetime_spent_cents, :z) + :amt",
        "ExpressionAttributeValues": {":z": 0, ":amt": charge_cents},
    }
    if campaign_budget_cents > 0:
        # prior lifetime_spent must leave room for this charge (budget - amt).
        _spend_kwargs["ConditionExpression"] = (
            "attribute_not_exists(lifetime_spent_cents) OR lifetime_spent_cents <= :budget_room"
        )
        _spend_kwargs["ExpressionAttributeValues"][":budget_room"] = campaign_budget_cents - charge_cents

    try:
        T.ad_campaigns.update_item(**_spend_kwargs)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            # Roll back the account debit performed in step 1.
            try:
                T.ad_accounts.update_item(
                    Key={"pk": f"ACCT#{account_id}", "sk": "META"},
                    UpdateExpression="SET balance_cents = if_not_exists(balance_cents, :z) + :amt, "
                                     "lifetime_spend_cents = if_not_exists(lifetime_spend_cents, :z) - :amt",
                    ExpressionAttributeValues={":z": 0, ":amt": charge_cents},
                )
            except Exception:
                logger.warning("ad_budget_guard_rollback_failed account=%s campaign=%s",
                               account_id, campaign_id)
            if idempotency_key:
                try:
                    T.ad_billing.delete_item(
                        Key={"pk": f"ACCT#{account_id}", "sk": f"IDEMP#{idempotency_key}"}
                    )
                except Exception:
                    pass
            logger.info("ad_charge_budget_exceeded account=%s campaign=%s amount=%s budget=%s",
                        account_id, campaign_id, charge_cents, campaign_budget_cents)
            return {"ok": False, "reason": "budget_exceeded", "charge_cents": charge_cents}
        raise

    # 3. Revenue split. Returns the split detail (per-party shares + credit-row
    #    pointers) so it can be denormalized onto the charge ledger row -> the
    #    ADV-502 reversal can back the split out precisely + self-contained.
    split = _split_revenue(
        charge_cents=charge_cents, creator_id=creator_id,
        account_id=account_id, meta=meta, ts=ts,
    ) or {}

    # 4. Write charge to ad_billing ledger (only after a successful debit).
    ledger_meta = {
        **meta,
        "creator_id": creator_id,
        "creator_share_cents": int(split.get("creator_share_cents", 0)),
        "platform_share_cents": int(split.get("platform_share_cents", 0)),
        "creator_credit_sk": split.get("creator_credit_sk", ""),
        "creator_credit_ts": int(split.get("creator_credit_ts", 0)),
        "platform_entry_sk": split.get("platform_entry_sk", ""),
        "member_share_cents": int(split.get("member_share_cents", 0)),
        "syndicate_treasury_share_cents": int(split.get("syndicate_treasury_share_cents", 0)),
        "syndicate_id": split.get("syndicate_id", ""),
        "is_syndicate_split": bool(split.get("is_syndicate_split")),
        "treasury_credit_sk": split.get("treasury_credit_sk", ""),
    }
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
        "meta": ledger_meta,
        "month_key": month_key,
        "created_at": ts,
    })

    # 5. Budget check + spending alerts
    _check_budget_and_alert(account_id, campaign_id)

    return {"ok": True, "entry_id": entry_id, "charge_cents": charge_cents}


def _split_revenue(
    *, charge_cents: int, creator_id: str, meta: dict, ts: int, account_id: str = "",
) -> dict:
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

    # ADV-303/406: a standalone unit (no content owner) books platform-100%;
    # split with a creator only when the ad ran in front of their content.
    if creator_id:
        creator_share = max(0, (charge_cents * creator_bps) // 10000)
    else:
        creator_share = 0
    platform_share = charge_cents - creator_share
    platform_share_pct = (
        (platform_share * 100) // charge_cents if charge_cents > 0 else PLATFORM_REVENUE_SHARE_PCT
    )

    # -- ADV2-704/705 (F7): syndicate-aware 3-way placement split resolution ----
    # DEFAULT (external / non-syndicate advertiser): the content owner keeps the
    # FULL creator_share and the syndicate earns nothing (member_share_cents ==
    # creator_share, treasury_share_cents == 0) -- membership NEVER skims a
    # member's external-ad earnings. SYNDICATE-OWNED ad (the paying account has
    # owner_type=="syndicate") served in front of a CURRENT member's content: the
    # content-owner share is split between the member (configured member_share_bps)
    # and the syndicate treasury (the remainder). Platform's 30% is untouched. The
    # 3-way fires ONLY here (is_syndicate_split).
    member_share_cents = creator_share
    treasury_share_cents = 0
    split_syndicate_id = ""
    if creator_share > 0 and creator_id and account_id:
        try:
            from app.services.ad_accounts import get_ad_account as _get_acct_for_split
            _acct_for_split = _get_acct_for_split(account_id) or {}
        except Exception:
            _acct_for_split = {}
        if str(_acct_for_split.get("owner_type", "")) == "syndicate":
            _synd_for_split = str(_acct_for_split.get("owner_syndicate_id", "") or "")
            _is_mem_for_split = False
            if _synd_for_split:
                try:
                    from app.services.syndicates import is_member as _is_member_for_split
                    _is_mem_for_split = bool(_is_member_for_split(_synd_for_split, creator_id))
                except Exception:
                    _is_mem_for_split = False
            if _synd_for_split and _is_mem_for_split:
                try:
                    from app.services.syndicate_revenue_split import (
                        get_ad_placement_member_share_bps as _member_bps_for_split,
                    )
                    _bps_for_split = int(_member_bps_for_split(_synd_for_split))
                except Exception:
                    _bps_for_split = 7000
                _bps_for_split = max(0, min(10000, _bps_for_split))
                member_share_cents = (creator_share * _bps_for_split) // 10000
                treasury_share_cents = creator_share - member_share_cents
                split_syndicate_id = _synd_for_split

    # ADV-502: capture the credit-row pointers so a later reversal can back them
    # out precisely (creator clawback + platform reversal).
    creator_credit_sk = ""
    creator_credit_ts = 0
    platform_entry_sk = ""

    # Credit creator via existing billing ledger
    if creator_share > 0 and creator_id:
        try:
            _sk, credit_item = new_ledger_entry(
                key_name="pk",
                key_value=user_pk(creator_id),
                # ADV-406: type "credit" so ad-revenue share shows in creator
                # earnings/payouts (creator_earnings filters type=="credit"),
                # Bug#3-safe. Aligns the dev clone with prod.
                entry_type="credit",
                amount_cents=member_share_cents,
                state="settled",
                reason="Ad revenue share",
                meta={
                    **meta,
                    "platform_share_pct": platform_share_pct,
                    "revenue_share_bps": creator_bps,
                },
            )
            T.billing.put_item(Item=credit_item)
            creator_credit_sk = _sk
            creator_credit_ts = int(credit_item.get("ts", ts))
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
                revenue_cents=member_share_cents,
            )
        except Exception:
            logger.warning(
                "transparency_record_failed",
                extra={"creator_id": creator_id, "account_id": account_id},
            )

    # ADV2-705 (F7): credit the syndicate TREASURY its share of the content-owner
    # split (type:"credit"). Fires ONLY for a syndicate-owned ad on a member; for
    # an external advertiser treasury_share_cents == 0 so nothing is written.
    treasury_credit_sk = ""
    if treasury_share_cents > 0 and split_syndicate_id:
        try:
            from app.services import syndicate_treasury as _treasury_for_split
            _tres_res = _treasury_for_split.credit_placement_earning(
                syndicate_id=split_syndicate_id,
                amount_cents=treasury_share_cents,
                member_user_id=creator_id,
                account_id=account_id,
                campaign_id=str(meta.get("campaign_id", "") or ""),
            )
            treasury_credit_sk = str(_tres_res.get("ledger_entry_id", "") or "")
        except Exception:
            logger.warning(
                "ad_revenue_syndicate_treasury_credit_failed",
                extra={"syndicate_id": split_syndicate_id, "amount_cents": treasury_share_cents},
            )

    # Write platform revenue record to ad_billing table so the platform's
    # share is durably recorded for audit/reconciliation (GAP-0049).
    if platform_share > 0:
        try:
            entry_id = f"rev_{uuid.uuid4().hex[:12]}"
            month_key = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m")
            platform_entry_sk = f"LEDGER#{ts}#{entry_id}"
            T.ad_billing.put_item(Item={
                "pk": "PLATFORM#revenue",
                "sk": platform_entry_sk,
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

    return {
        "creator_id": creator_id,
        "creator_share_cents": creator_share,
        "platform_share_cents": platform_share,
        "creator_credit_sk": creator_credit_sk,
        "creator_credit_ts": creator_credit_ts,
        "platform_entry_sk": platform_entry_sk,
        "revenue_share_bps": creator_bps,
        "member_share_cents": member_share_cents,
        "syndicate_treasury_share_cents": treasury_share_cents,
        "syndicate_id": split_syndicate_id,
        "is_syndicate_split": bool(split_syndicate_id),
        "treasury_credit_sk": treasury_credit_sk,
    }


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


# ---------------------------------------------------------------------------
# ADV-502 -- ad-charge refund / reversal (fraud clawback / dispute).
# ---------------------------------------------------------------------------
_REVERSIBLE_ENTRY_TYPES = ("impression_charge", "click_charge", "conversion_charge")


def _find_charge_entry(account_id: str, entry_id: str) -> Optional[dict]:
    """Locate a settled charge ledger row by entry_id under an account (paginated)."""
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": (
            Key("pk").eq(f"ACCT#{account_id}") & Key("sk").begins_with("LEDGER#")
        ),
        "FilterExpression": Attr("entry_id").eq(entry_id),
    }
    while True:
        resp = T.ad_billing.query(**kwargs)
        items = resp.get("Items", [])
        if items:
            return items[0]
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            return None
        kwargs["ExclusiveStartKey"] = lek


def reverse_ad_charge(
    *, account_id: str, entry_id: str, reason: str = "admin_reversal",
    actor: str = "", entry: Optional[dict] = None,
) -> dict:
    """ADV-502: idempotently reverse a settled ad charge.

    Refunds the advertiser balance, backs the charge out of campaign spend, writes
    a ``charge_reversal`` row to the ad_billing ledger, and reverses the revenue
    split: the creator credit is clawed back with entry_type != "credit" (so it can
    NEVER inflate creator earnings -- creator_earnings only sums type=="credit") and
    the original credit row is flipped to state="reversed"; the platform revenue
    record is reversed too. A ``REVERSAL#{entry_id}`` marker (claimed with
    attribute_not_exists) makes it idempotent + guards double-reversal: a second
    call is a no-op returning the stored receipt. Mirrors the TIP-502 pattern.
    """
    from fastapi import HTTPException

    entry = entry or _find_charge_entry(account_id, entry_id)
    if not entry:
        raise HTTPException(404, {"code": "charge_not_found",
                                  "message": f"No ad charge {entry_id} on account {account_id}."})
    etype = str(entry.get("entry_type", ""))
    if etype not in _REVERSIBLE_ENTRY_TYPES:
        raise HTTPException(400, {"code": "not_reversible",
                                  "message": f"Entry {entry_id} ({etype}) is not a reversible charge."})

    amount_cents = int(entry.get("amount_cents", 0) or 0)
    campaign_id = str(entry.get("campaign_id", "") or "")
    emeta = entry.get("meta", {}) or {}
    creator_id = str(emeta.get("creator_id", "") or "")
    creator_share = int(emeta.get("creator_share_cents", 0) or 0)
    platform_share = int(emeta.get("platform_share_cents", 0) or 0)
    creator_credit_sk = str(emeta.get("creator_credit_sk", "") or "")
    platform_entry_sk = str(emeta.get("platform_entry_sk", "") or "")
    # ADV2-RES R1: syndicate 3-way reversal pointers. In a syndicate split the
    # member credit row holds member_share_cents (the treasury took the
    # remainder), so the member clawback == member_share; a non-syndicate
    # reversal keeps clawing the full creator_share UNCHANGED.
    is_syndicate_split = bool(emeta.get("is_syndicate_split"))
    member_share = int(emeta.get("member_share_cents", 0) or 0)
    treasury_share = int(emeta.get("syndicate_treasury_share_cents", 0) or 0)
    split_syndicate_id = str(emeta.get("syndicate_id", "") or "")
    member_clawback = member_share if is_syndicate_split else creator_share
    treasury_debit_planned = treasury_share if is_syndicate_split else 0
    treasury_debited = 0

    ts = now_ts()
    reversal_entry_id = f"rev_{uuid.uuid4().hex[:12]}"
    month_key = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m")

    def _receipt(replay: bool) -> dict:
        return {
            "ok": True, "reversed": True, "entry_id": entry_id,
            "reversal_entry_id": reversal_entry_id, "account_id": account_id,
            "campaign_id": campaign_id, "refunded_cents": amount_cents,
            "creator_clawback_cents": member_clawback if creator_id else 0,
            "platform_reversal_cents": platform_share,
            "treasury_debit_cents": treasury_debited,
            "is_syndicate_split": is_syndicate_split,
            "syndicate_id": split_syndicate_id,
            "idempotent_replay": replay,
        }

    # 1. Claim the reversal marker FIRST -> idempotency + double-reversal guard
    #    (kept out of the LEDGER# history query; mirrors the IDEMP# marker).
    try:
        T.ad_billing.put_item(
            Item={
                "pk": f"ACCT#{account_id}", "sk": f"REVERSAL#{entry_id}",
                "entry_type": "charge_reversal_marker", "reversal_of": entry_id,
                "reversal_entry_id": reversal_entry_id, "amount_cents": amount_cents,
                "creator_clawback_cents": member_clawback if creator_id else 0,
                "platform_reversal_cents": platform_share, "campaign_id": campaign_id,
                "treasury_debit_cents": treasury_debit_planned,
                "is_syndicate_split": is_syndicate_split, "syndicate_id": split_syndicate_id,
                "created_at": ts,
            },
            ConditionExpression="attribute_not_exists(sk)",
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            prior = T.ad_billing.get_item(
                Key={"pk": f"ACCT#{account_id}", "sk": f"REVERSAL#{entry_id}"}
            ).get("Item", {}) or {}
            logger.info("ad_charge_reversal_duplicate account=%s entry=%s", account_id, entry_id)
            return {
                "ok": True, "reversed": True, "entry_id": entry_id,
                "reversal_entry_id": str(prior.get("reversal_entry_id", "")),
                "account_id": account_id, "campaign_id": str(prior.get("campaign_id", "")),
                "refunded_cents": int(prior.get("amount_cents", 0) or 0),
                "creator_clawback_cents": int(prior.get("creator_clawback_cents", 0) or 0),
                "platform_reversal_cents": int(prior.get("platform_reversal_cents", 0) or 0),
                "treasury_debit_cents": int(prior.get("treasury_debit_cents", 0) or 0),
                "is_syndicate_split": bool(prior.get("is_syndicate_split")),
                "syndicate_id": str(prior.get("syndicate_id", "") or ""),
                "idempotent_replay": True,
            }
        raise

    # 2. Refund the advertiser balance + back the charge out of lifetime spend.
    try:
        T.ad_accounts.update_item(
            Key={"pk": f"ACCT#{account_id}", "sk": "META"},
            UpdateExpression="SET balance_cents = if_not_exists(balance_cents, :z) + :amt, "
                             "lifetime_spend_cents = if_not_exists(lifetime_spend_cents, :z) - :amt",
            ExpressionAttributeValues={":z": 0, ":amt": amount_cents},
        )
    except ClientError:
        try:
            T.ad_billing.delete_item(
                Key={"pk": f"ACCT#{account_id}", "sk": f"REVERSAL#{entry_id}"}
            )
        except Exception:
            pass
        raise

    # 3. Back the charge out of campaign spend (best-effort).
    if campaign_id:
        try:
            T.ad_campaigns.update_item(
                Key={"pk": f"ACCT#{account_id}", "sk": f"CAMPAIGN#{campaign_id}"},
                UpdateExpression="SET spent_today_cents = if_not_exists(spent_today_cents, :z) - :amt, "
                                 "lifetime_spent_cents = if_not_exists(lifetime_spent_cents, :z) - :amt",
                ExpressionAttributeValues={":z": 0, ":amt": amount_cents},
            )
        except Exception:
            logger.warning("ad_reversal_campaign_backout_failed campaign=%s", campaign_id)

    # 4. Write the reversal row to the ad_billing ledger (audit/history).
    T.ad_billing.put_item(Item={
        "pk": f"ACCT#{account_id}", "sk": f"LEDGER#{ts}#{reversal_entry_id}",
        "entry_id": reversal_entry_id, "account_id": account_id,
        "campaign_id": campaign_id, "entry_type": "charge_reversal",
        "amount_cents": amount_cents, "state": "settled",
        "reason": f"Charge reversal ({reason})",
        "meta": {
            "reversal_of": entry_id, "reversal_reason": reason, "reversal_actor": actor,
            "original_entry_type": etype, "creator_id": creator_id,
            # ADV3-2/A6: the real clawback is the MEMBER share in a syndicate split
            # (the treasury took the remainder); a non-syndicate reversal claws the
            # full creator_share. member_clawback already encodes both cases.
            "creator_clawback_cents": member_clawback if creator_id else 0,
            "member_clawback_cents": member_clawback if creator_id else 0,
            "treasury_debit_cents": treasury_debit_planned,
            "is_syndicate_split": is_syndicate_split,
            "platform_reversal_cents": platform_share,
        },
        "month_key": month_key, "created_at": ts,
    })

    # 5. Claw back the creator revenue credit WITHOUT inflating earnings:
    #    entry_type != "credit" (creator_earnings only sums type=="credit"), and
    #    flip the original credit row to state="reversed".
    if creator_id and member_clawback > 0:
        try:
            _sk, clawback_item = new_ledger_entry(
                key_name="pk", key_value=user_pk(creator_id),
                entry_type="ad_revenue_reversal",  # != "credit"
                amount_cents=member_clawback, state="settled",
                reason="Ad revenue reversal",
                meta={"reversal_of": entry_id, "reversal_reason": reason,
                      "account_id": account_id, "campaign_id": campaign_id},
            )
            T.billing.put_item(Item=clawback_item)
        except Exception:
            logger.warning("ad_reversal_creator_clawback_failed creator=%s", creator_id)
        if creator_credit_sk:
            try:
                T.billing.update_item(
                    Key={"pk": user_pk(creator_id), "sk": creator_credit_sk},
                    UpdateExpression="SET #s = :r",
                    ConditionExpression="attribute_exists(sk)",
                    ExpressionAttributeNames={"#s": "state"},
                    ExpressionAttributeValues={":r": "reversed"},
                )
            except Exception:
                logger.warning("ad_reversal_credit_flip_failed creator=%s", creator_id)

    # 6. Reverse the platform revenue record (audit symmetry).
    if platform_share > 0:
        try:
            prev_id = f"rev_{uuid.uuid4().hex[:12]}"
            T.ad_billing.put_item(Item={
                "pk": "PLATFORM#revenue", "sk": f"LEDGER#{ts}#{prev_id}",
                "entry_id": prev_id, "entry_type": "platform_revenue_reversal",
                "amount_cents": platform_share, "state": "settled",
                "reason": f"Platform ad revenue reversal ({reason})",
                "meta": {"reversal_of": entry_id, "account_id": account_id,
                         "campaign_id": campaign_id},
                "month_key": month_key, "created_at": ts,
            })
        except Exception:
            logger.warning("ad_reversal_platform_backout_failed")
        if platform_entry_sk:
            try:
                T.ad_billing.update_item(
                    Key={"pk": "PLATFORM#revenue", "sk": platform_entry_sk},
                    UpdateExpression="SET #s = :r",
                    ExpressionAttributeNames={"#s": "state"},
                    ExpressionAttributeValues={":r": "reversed"},
                )
            except Exception:
                pass

    # 7. ADV2-RES R1: syndicate 3-way -> debit the treasury the placement share
    #    it was credited at charge time (mirrors credit_placement_earning, sign
    #    flipped). Non-syndicate reversals never touch a treasury.
    if is_syndicate_split and treasury_share > 0 and split_syndicate_id:
        try:
            from app.services import syndicate_treasury as _tres_rev
            _tres_rev.debit_placement_earning(
                syndicate_id=split_syndicate_id, amount_cents=treasury_share,
                member_user_id=creator_id, account_id=account_id,
                campaign_id=campaign_id, reversal_of=entry_id,
            )
            treasury_debited = treasury_share
        except Exception:
            logger.warning(
                "ad_reversal_treasury_debit_failed syndicate=%s", split_syndicate_id
            )

    logger.info(
        "ad_charge_reversed account=%s entry=%s amount=%s creator=%s "
        "member_clawback=%s treasury_debit=%s",
        account_id, entry_id, amount_cents, creator_id or "-",
        member_clawback, treasury_debited,
    )
    return _receipt(False)
