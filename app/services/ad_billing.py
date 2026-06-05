"""Ad billing engine -- charges, revenue splits, invoices, spending alerts (ADS-007)."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key, Attr

from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import new_ledger_entry, user_pk

logger = logging.getLogger(__name__)

# Revenue share: platform takes this percentage, creator gets remainder
PLATFORM_REVENUE_SHARE_PCT = 30
MIN_DEPOSIT_CENTS = 5000  # $50 minimum deposit


def deposit_funds(account_id: str, amount_cents: int, payment_method_id: str = "") -> dict:
    """Add funds to advertiser account balance."""
    if amount_cents < MIN_DEPOSIT_CENTS:
        raise ValueError(f"Minimum deposit is $50")

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
        "meta": {"payment_method_id": payment_method_id},
        "month_key": month_key,
        "created_at": ts,
    })

    # Increment account balance
    T.ad_accounts.update_item(
        Key={"pk": f"ACCT#{account_id}", "sk": "META"},
        UpdateExpression="SET balance_cents = if_not_exists(balance_cents, :z) + :amt",
        ExpressionAttributeValues={":z": 0, ":amt": amount_cents},
    )

    return {"ok": True, "entry_id": entry_id, "new_balance_cents": _get_balance(account_id)}


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
    """Process a charge: debit advertiser, split revenue, check budget."""
    ts = now_ts()
    entry_id = f"chg_{uuid.uuid4().hex[:12]}"
    month_key = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m")

    # 1. Write charge to ad_billing ledger
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

    # 2. Debit advertiser account balance
    T.ad_accounts.update_item(
        Key={"pk": f"ACCT#{account_id}", "sk": "META"},
        UpdateExpression="SET balance_cents = balance_cents - :amt, "
                         "lifetime_spend_cents = if_not_exists(lifetime_spend_cents, :z) + :amt",
        ExpressionAttributeValues={":amt": charge_cents, ":z": 0},
    )

    # 3. Increment campaign spend
    T.ad_campaigns.update_item(
        Key={"pk": f"ACCT#{account_id}", "sk": f"CAMPAIGN#{campaign_id}"},
        UpdateExpression="SET spent_today_cents = if_not_exists(spent_today_cents, :z) + :amt, "
                         "lifetime_spent_cents = if_not_exists(lifetime_spent_cents, :z) + :amt",
        ExpressionAttributeValues={":z": 0, ":amt": charge_cents},
    )

    # 4. Revenue split
    _split_revenue(charge_cents=charge_cents, creator_id=creator_id, meta=meta, ts=ts)

    # 5. Budget check + spending alerts
    _check_budget_and_alert(account_id, campaign_id)

    return {"ok": True, "entry_id": entry_id, "charge_cents": charge_cents}


def _split_revenue(*, charge_cents: int, creator_id: str, meta: dict, ts: int) -> None:
    """Split ad revenue between platform and creator."""
    platform_share = max(0, (charge_cents * PLATFORM_REVENUE_SHARE_PCT) // 100)
    creator_share = charge_cents - platform_share

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
                meta={**meta, "platform_share_pct": PLATFORM_REVENUE_SHARE_PCT},
            )
            T.billing.put_item(Item=credit_item)
        except Exception:
            logger.warning("ad_revenue_creator_credit_failed", extra={"creator_id": creator_id})

    # Write platform revenue record to ad_billing table so the platform's 30%
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
                "reason": "Platform ad revenue share (30%)",
                "meta": {
                    **meta,
                    "creator_id": creator_id,
                    "creator_share_cents": creator_share,
                    "charge_cents": charge_cents,
                    "platform_share_pct": PLATFORM_REVENUE_SHARE_PCT,
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
            except Exception:
                pass  # Alert already sent or write failed

    # Auto-pause if budget exhausted
    if pct >= 100:
        try:
            T.ad_campaigns.update_item(
                Key={"pk": f"ACCT#{account_id}", "sk": f"CAMPAIGN#{campaign_id}"},
                UpdateExpression="SET #s = :completed",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":completed": "completed"},
                ConditionExpression="#s <> :completed",
            )
        except Exception:
            pass  # Already paused/completed


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
