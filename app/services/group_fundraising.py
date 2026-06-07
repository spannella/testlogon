"""Group advertising campaigns & external fundraising (GROUP-003).

Built on top of GROUP-001 (membership/roles via ``app.services.user_groups``)
and GROUP-004 (treasury via ``app.services.group_treasury``). Fundraisers,
donations, and ad campaigns are stored in the dedicated
``group_fundraising_campaigns`` DDB table. Completed donations credit the
existing group treasury via ``group_treasury.credit_donation``. Campaign
budgets are reserved from the treasury via ``group_treasury.spend_treasury``.

Donations are deterministic in dev/test: a donation is created in ``pending``
status with a mock Stripe payment-intent id and an auto-confirm path so the
treasury credit + ``raised_cents`` increment happen synchronously.
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services import group_treasury
from app.services import user_groups

logger = logging.getLogger(__name__)

# Auto-confirm donations synchronously in dev/test so the treasury credit is
# deterministic (stripe-mock cannot complete off-session Checkout Sessions).
#
# GAP-0218: this MUST be gated on dev_mode. In production a donation must only be
# confirmed (and the treasury credited) by a real Stripe ``payment_intent.succeeded``
# webhook (or the ROOT break-glass endpoint) proving the money actually cleared.
# Auto-confirming in prod would credit the treasury for declined / fraudulent
# payments. Read dynamically (via the helper below) so tests can flip ``S.dev_mode``
# without re-importing the module.
def _auto_confirm_donations() -> bool:
    return bool(S.dev_mode)


def _group_pk(group_id: str) -> str:
    return f"GROUP#{group_id}"


def _fundraiser_pk(fundraiser_id: str) -> str:
    return f"FUNDRAISER#{fundraiser_id}"


# ---------------------------------------------------------------------------
# Fundraiser CRUD
# ---------------------------------------------------------------------------


def _fundraiser_out(item: Dict[str, Any]) -> Dict[str, Any]:
    goal = item.get("goal_cents")
    ends_at = item.get("ends_at")
    return {
        "fundraiser_id": item.get("fundraiser_id", ""),
        "group_id": item.get("group_id", ""),
        "title": item.get("title", ""),
        "description": item.get("description", ""),
        "goal_cents": int(goal) if goal is not None else None,
        "raised_cents": int(item.get("raised_cents", 0)),
        "donation_count": int(item.get("donation_count", 0)),
        "currency": item.get("currency", "usd"),
        "status": item.get("status", "active"),
        "cover_image_url": item.get("cover_image_url"),
        "created_at": int(item.get("created_at", 0)),
        "ends_at": int(ends_at) if ends_at is not None else None,
    }


def create_fundraiser(
    group_id: str,
    admin_id: str,
    title: str,
    description: str = "",
    goal_cents: Optional[int] = None,
    cover_image_url: Optional[str] = None,
    ends_at: Optional[int] = None,
) -> Dict[str, Any]:
    """Create a fundraiser for a group (admin only)."""
    meta = user_groups.get_group_or_404(group_id)
    if meta.get("status") == "dissolved":
        raise HTTPException(status_code=410, detail="This group has been dissolved")
    user_groups.require_admin(group_id, admin_id)

    ts = now_ts()
    fundraiser_id = f"fr_{uuid4().hex[:12]}"
    item: Dict[str, Any] = {
        "pk": _group_pk(group_id),
        "sk": f"FUNDRAISER#{fundraiser_id}",
        "record_type": "fundraiser",
        "fundraiser_id": fundraiser_id,
        "group_id": group_id,
        "title": title.strip(),
        "description": (description or "").strip(),
        "raised_cents": 0,
        "donation_count": 0,
        "currency": "usd",
        "status": "active",
        "created_at": ts,
        "updated_at": ts,
    }
    if goal_cents is not None:
        item["goal_cents"] = int(goal_cents)
    if cover_image_url:
        item["cover_image_url"] = cover_image_url
    if ends_at is not None:
        item["ends_at"] = int(ends_at)

    T.group_fundraising_campaigns.put_item(Item=item)
    # Pointer record so public callers can resolve a fundraiser by id alone.
    T.group_fundraising_campaigns.put_item(Item={
        "pk": _fundraiser_pk(fundraiser_id),
        "sk": "META",
        "record_type": "fundraiser_ptr",
        "fundraiser_id": fundraiser_id,
        "group_id": group_id,
        "created_at": ts,
    })
    logger.info(
        "group_fundraising.fundraiser_created",
        extra={"group_id": group_id, "fundraiser_id": fundraiser_id, "admin_id": admin_id},
    )
    return _fundraiser_out(item)


def _get_fundraiser_item(group_id: str, fundraiser_id: str) -> Optional[Dict[str, Any]]:
    resp = T.group_fundraising_campaigns.get_item(
        Key={"pk": _group_pk(group_id), "sk": f"FUNDRAISER#{fundraiser_id}"}
    )
    return resp.get("Item")


def _find_fundraiser_item(fundraiser_id: str) -> Optional[Dict[str, Any]]:
    """Locate a fundraiser by id alone (used by public endpoints).

    Public callers only have the fundraiser_id, so we resolve the owning
    group via the ``pk=FUNDRAISER#{id}, sk=META`` pointer record written at
    creation, then load the canonical fundraiser record.
    """
    ptr = T.group_fundraising_campaigns.get_item(
        Key={"pk": _fundraiser_pk(fundraiser_id), "sk": "META"}
    ).get("Item")
    if not ptr:
        return None
    group_id = ptr.get("group_id", "")
    return _get_fundraiser_item(group_id, fundraiser_id)


def get_fundraiser(group_id: str, fundraiser_id: str) -> Dict[str, Any]:
    item = _get_fundraiser_item(group_id, fundraiser_id)
    if not item:
        raise HTTPException(status_code=404, detail="Fundraiser not found")
    return _fundraiser_out(item)


def list_fundraisers(group_id: str) -> List[Dict[str, Any]]:
    resp = T.group_fundraising_campaigns.query(
        KeyConditionExpression=Key("pk").eq(_group_pk(group_id))
        & Key("sk").begins_with("FUNDRAISER#"),
    )
    items = [i for i in resp.get("Items", []) if i.get("record_type") == "fundraiser"]
    items.sort(key=lambda i: int(i.get("created_at", 0)), reverse=True)
    return [_fundraiser_out(i) for i in items]


def update_fundraiser(
    group_id: str,
    admin_id: str,
    fundraiser_id: str,
    title: Optional[str] = None,
    description: Optional[str] = None,
    goal_cents: Optional[int] = None,
    status: Optional[str] = None,
    ends_at: Optional[int] = None,
) -> Dict[str, Any]:
    """Update a fundraiser (admin only). Closing = status cancelled/completed."""
    meta = user_groups.get_group_or_404(group_id)
    if meta.get("status") == "dissolved":
        raise HTTPException(status_code=410, detail="This group has been dissolved")
    user_groups.require_admin(group_id, admin_id)

    item = _get_fundraiser_item(group_id, fundraiser_id)
    if not item:
        raise HTTPException(status_code=404, detail="Fundraiser not found")

    ts = now_ts()
    updates: Dict[str, Any] = {"updated_at": ts}
    if title is not None:
        updates["title"] = title.strip()
    if description is not None:
        updates["description"] = description.strip()
    if goal_cents is not None:
        updates["goal_cents"] = int(goal_cents)
    if status is not None:
        updates["status"] = status
    if ends_at is not None:
        updates["ends_at"] = int(ends_at)

    expr_parts, expr_names, expr_values = [], {}, {}
    for i, (k, v) in enumerate(updates.items()):
        expr_parts.append(f"#k{i} = :v{i}")
        expr_names[f"#k{i}"] = k
        expr_values[f":v{i}"] = v

    T.group_fundraising_campaigns.update_item(
        Key={"pk": _group_pk(group_id), "sk": f"FUNDRAISER#{fundraiser_id}"},
        UpdateExpression="SET " + ", ".join(expr_parts),
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_values,
        ConditionExpression="attribute_exists(sk)",
    )
    item.update(updates)
    return _fundraiser_out(item)


def get_public_fundraiser(fundraiser_id: str) -> Dict[str, Any]:
    """Public fundraiser info (no auth). Includes group name."""
    item = _find_fundraiser_item(fundraiser_id)
    if not item:
        raise HTTPException(status_code=404, detail="Fundraiser not found")
    group_id = item.get("group_id", "")
    meta = user_groups.get_group(group_id) or {}
    out = _fundraiser_out(item)
    out["group_name"] = meta.get("name", "")
    return out


# ---------------------------------------------------------------------------
# Donations
# ---------------------------------------------------------------------------


def _donation_out(item: Dict[str, Any], checkout_url: Optional[str] = None) -> Dict[str, Any]:
    out = {
        "donation_id": item.get("donation_id", ""),
        "amount_cents": int(item.get("amount_cents", 0)),
        "donor_name": item.get("donor_name"),
        "status": item.get("status", "pending"),
        "created_at": int(item.get("created_at", 0)),
        "is_external": bool(item.get("is_external", True)),
    }
    if checkout_url is not None:
        out["checkout_url"] = checkout_url
    return out


def create_donation(
    fundraiser_id: str,
    amount_cents: int,
    donor_name: Optional[str] = None,
    donor_email: Optional[str] = None,
    donor_user_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a donation against a fundraiser. Auto-confirms in dev/test."""
    item = _find_fundraiser_item(fundraiser_id)
    if not item:
        raise HTTPException(status_code=404, detail="Fundraiser not found")

    status = item.get("status", "active")
    if status != "active":
        raise HTTPException(
            status_code=400,
            detail="This fundraiser is no longer accepting donations",
        )
    ends_at = item.get("ends_at")
    if ends_at is not None and int(ends_at) <= now_ts():
        raise HTTPException(status_code=400, detail="This fundraiser has ended")

    group_id = item.get("group_id", "")
    ts = now_ts()
    donation_id = f"don_{uuid4().hex[:12]}"
    # Deterministic mock Stripe payment intent + checkout url.
    pi_id = f"pi_mock_{uuid4().hex[:16]}"
    checkout_url = f"/mock/stripe/checkout/{pi_id}"

    donation: Dict[str, Any] = {
        "pk": _fundraiser_pk(fundraiser_id),
        "sk": f"DONATION#{donation_id}",
        "record_type": "donation",
        "donation_id": donation_id,
        "fundraiser_id": fundraiser_id,
        "group_id": group_id,
        "amount_cents": int(amount_cents),
        "currency": "usd",
        "donor_name": donor_name,
        "donor_email": donor_email,
        "donor_user_id": donor_user_id,
        "stripe_payment_intent_id": pi_id,
        "status": "pending",
        "is_external": donor_user_id is None,
        "created_at": ts,
    }
    donation = {k: v for k, v in donation.items() if v is not None}
    T.group_fundraising_campaigns.put_item(Item=donation)

    logger.info(
        "group_fundraising.donation_created",
        extra={
            "fundraiser_id": fundraiser_id,
            "donation_id": donation_id,
            "amount_cents": amount_cents,
        },
    )

    if _auto_confirm_donations():
        confirm_donation(fundraiser_id, donation_id, pi_id)
        donation["status"] = "completed"
    else:
        # Production: leave the donation pending until a real Stripe
        # ``payment_intent.succeeded`` webhook (or the ROOT break-glass endpoint)
        # confirms the charge actually cleared. Treasury is NOT credited here.
        logger.info(
            "group_fundraising.auto_confirm_skipped",
            extra={
                "fundraiser_id": fundraiser_id,
                "donation_id": donation_id,
                "stripe_payment_intent_id": pi_id,
            },
        )

    out = _donation_out(donation, checkout_url=checkout_url)
    return out


def confirm_donation(
    fundraiser_id: str,
    donation_id: str,
    stripe_pi_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Mark donation completed, increment raised_cents, credit treasury."""
    resp = T.group_fundraising_campaigns.get_item(
        Key={"pk": _fundraiser_pk(fundraiser_id), "sk": f"DONATION#{donation_id}"}
    )
    donation = resp.get("Item")
    if not donation:
        raise HTTPException(status_code=404, detail="Donation not found")
    if donation.get("status") == "completed":
        return {"ok": True, "already_confirmed": True}

    group_id = donation.get("group_id", "")
    amount_cents = int(donation.get("amount_cents", 0))
    ts = now_ts()

    # 1. Mark donation completed.
    T.group_fundraising_campaigns.update_item(
        Key={"pk": _fundraiser_pk(fundraiser_id), "sk": f"DONATION#{donation_id}"},
        UpdateExpression="SET #s = :s, confirmed_at = :t",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "completed", ":t": ts},
    )

    # 2. Atomically increment fundraiser raised_cents + donation_count.
    upd = T.group_fundraising_campaigns.update_item(
        Key={"pk": _group_pk(group_id), "sk": f"FUNDRAISER#{fundraiser_id}"},
        UpdateExpression=(
            "SET raised_cents = if_not_exists(raised_cents, :z) + :amt, "
            "donation_count = if_not_exists(donation_count, :z) + :one, "
            "updated_at = :t"
        ),
        ExpressionAttributeValues={":z": 0, ":amt": amount_cents, ":one": 1, ":t": ts},
        ReturnValues="ALL_NEW",
    )
    attrs = upd.get("Attributes", {})
    new_raised = int(attrs.get("raised_cents", amount_cents))
    goal = attrs.get("goal_cents")
    goal_cents = int(goal) if goal is not None else None

    # 3. Credit the group treasury (GROUP-004).
    try:
        group_treasury.credit_donation(
            group_id=group_id,
            amount_cents=amount_cents,
            donor_name=donation.get("donor_name", "") or "",
            donation_id=donation_id,
        )
    except Exception as e:  # treasury must not break donation confirmation
        logger.warning(
            "group_fundraising.treasury_credit_failed",
            extra={"group_id": group_id, "donation_id": donation_id, "error": str(e)},
        )

    # 4. Auto-complete fundraiser if goal reached.
    if goal_cents is not None and new_raised >= goal_cents:
        T.group_fundraising_campaigns.update_item(
            Key={"pk": _group_pk(group_id), "sk": f"FUNDRAISER#{fundraiser_id}"},
            UpdateExpression="SET #s = :s",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": "completed"},
        )

    logger.info(
        "group_fundraising.donation_confirmed",
        extra={
            "fundraiser_id": fundraiser_id,
            "donation_id": donation_id,
            "amount_cents": amount_cents,
            "new_raised_total": new_raised,
            "goal_cents": goal_cents,
            "goal_reached": bool(goal_cents and new_raised >= goal_cents),
        },
    )
    return {"ok": True, "raised_cents": new_raised}


def confirm_donation_by_payment_intent(
    fundraiser_id: str,
    donation_id: str,
    stripe_pi_id: str,
) -> Dict[str, Any]:
    """Confirm a donation from a verified Stripe ``payment_intent.succeeded`` event.

    GAP-0218: this is the production confirmation path. The caller (Stripe webhook
    handler) has already verified the event signature, so reaching here means the
    charge actually cleared. We additionally check that the donation's stored
    ``stripe_payment_intent_id`` matches the event's payment-intent id, so a webhook
    for one donation can never confirm a different one. ``confirm_donation`` itself
    is idempotent (returns ``already_confirmed`` for completed donations), so Stripe
    retries are safe.
    """
    resp = T.group_fundraising_campaigns.get_item(
        Key={"pk": _fundraiser_pk(fundraiser_id), "sk": f"DONATION#{donation_id}"}
    )
    donation = resp.get("Item")
    if not donation:
        raise HTTPException(status_code=404, detail="Donation not found")
    stored_pi = donation.get("stripe_payment_intent_id")
    if stored_pi and stripe_pi_id and stored_pi != stripe_pi_id:
        raise HTTPException(
            status_code=409,
            detail="payment_intent does not match this donation",
        )
    return confirm_donation(fundraiser_id, donation_id, stripe_pi_id=stripe_pi_id)


def list_donations(
    fundraiser_id: str,
    cursor: Optional[str] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    """List donations for a fundraiser, newest first. Admin-only at router."""
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("pk").eq(_fundraiser_pk(fundraiser_id))
        & Key("sk").begins_with("DONATION#"),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if cursor:
        try:
            kwargs["ExclusiveStartKey"] = json.loads(base64.b64decode(cursor).decode())
        except Exception:
            pass

    resp = T.group_fundraising_campaigns.query(**kwargs)
    items = resp.get("Items", [])
    donations = [_donation_out(i) for i in items]
    donations.sort(key=lambda d: d["created_at"], reverse=True)

    next_cursor = None
    has_more = False
    last_key = resp.get("LastEvaluatedKey")
    if last_key:
        has_more = True
        next_cursor = base64.b64encode(json.dumps(last_key).encode()).decode()

    return {"donations": donations, "cursor": next_cursor, "has_more": has_more}


def get_donation_receipt(donation_id: str, fundraiser_id: str) -> Dict[str, Any]:
    """Public receipt for a completed donation."""
    resp = T.group_fundraising_campaigns.get_item(
        Key={"pk": _fundraiser_pk(fundraiser_id), "sk": f"DONATION#{donation_id}"}
    )
    donation = resp.get("Item")
    if not donation:
        raise HTTPException(status_code=404, detail="Donation receipt not found")
    if donation.get("status") != "completed":
        raise HTTPException(
            status_code=400,
            detail="Receipt not available until payment is confirmed",
        )

    group_id = donation.get("group_id", "")
    fundraiser = _get_fundraiser_item(group_id, fundraiser_id) or {}
    meta = user_groups.get_group(group_id) or {}
    return {
        "donation_id": donation_id,
        "amount_cents": int(donation.get("amount_cents", 0)),
        "currency": donation.get("currency", "usd"),
        "donor_name": donation.get("donor_name"),
        "group_name": meta.get("name", ""),
        "fundraiser_title": fundraiser.get("title", ""),
        "created_at": int(donation.get("created_at", 0)),
        "status": donation.get("status", "completed"),
    }


# ---------------------------------------------------------------------------
# Advertising campaigns
# ---------------------------------------------------------------------------


def _campaign_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "campaign_id": item.get("campaign_id", ""),
        "group_id": item.get("group_id", ""),
        "name": item.get("name", ""),
        "status": item.get("status", "active"),
        "daily_budget_cents": int(item.get("daily_budget_cents", 0)),
        "lifetime_budget_cents": int(item.get("lifetime_budget_cents", 0)),
        "spent_cents": int(item.get("spent_cents", 0)),
        "impressions": int(item.get("impressions", 0)),
        "clicks": int(item.get("clicks", 0)),
        "creative_text": item.get("creative_text"),
        "creative_image_url": item.get("creative_image_url"),
        "created_at": int(item.get("created_at", 0)),
    }


def _get_campaign_item(group_id: str, campaign_id: str) -> Optional[Dict[str, Any]]:
    resp = T.group_fundraising_campaigns.get_item(
        Key={"pk": _group_pk(group_id), "sk": f"CAMPAIGN#{campaign_id}"}
    )
    return resp.get("Item")


def create_campaign(
    group_id: str,
    admin_id: str,
    name: str,
    daily_budget_cents: int,
    lifetime_budget_cents: int,
    creative_text: Optional[str] = None,
    creative_image_url: Optional[str] = None,
) -> Dict[str, Any]:
    """Create an ad campaign. Reserves lifetime budget from the treasury."""
    meta = user_groups.get_group_or_404(group_id)
    if meta.get("status") == "dissolved":
        raise HTTPException(status_code=410, detail="This group has been dissolved")
    user_groups.require_admin(group_id, admin_id)

    # Reserve budget from treasury (raises 400 if insufficient).
    ts = now_ts()
    campaign_id = f"camp_{uuid4().hex[:12]}"
    group_treasury.spend_treasury(
        group_id=group_id,
        admin_id=admin_id,
        amount_cents=lifetime_budget_cents,
        reason="Ad campaign budget",
        category="ad_spend",
        reference_id=campaign_id,
    )

    item: Dict[str, Any] = {
        "pk": _group_pk(group_id),
        "sk": f"CAMPAIGN#{campaign_id}",
        "record_type": "campaign",
        "campaign_id": campaign_id,
        "group_id": group_id,
        "name": name.strip(),
        "status": "active",
        "daily_budget_cents": int(daily_budget_cents),
        "lifetime_budget_cents": int(lifetime_budget_cents),
        "spent_cents": 0,
        "impressions": 0,
        "clicks": 0,
        "created_at": ts,
        "updated_at": ts,
    }
    if creative_text:
        item["creative_text"] = creative_text
    if creative_image_url:
        item["creative_image_url"] = creative_image_url

    T.group_fundraising_campaigns.put_item(Item=item)
    logger.info(
        "group_advertising.campaign_created",
        extra={
            "group_id": group_id,
            "campaign_id": campaign_id,
            "admin_id": admin_id,
            "daily_budget_cents": daily_budget_cents,
            "lifetime_budget_cents": lifetime_budget_cents,
        },
    )
    return _campaign_out(item)


def list_campaigns(group_id: str) -> List[Dict[str, Any]]:
    resp = T.group_fundraising_campaigns.query(
        KeyConditionExpression=Key("pk").eq(_group_pk(group_id))
        & Key("sk").begins_with("CAMPAIGN#"),
    )
    items = [i for i in resp.get("Items", []) if i.get("record_type") == "campaign"]
    items.sort(key=lambda i: int(i.get("created_at", 0)), reverse=True)
    return [_campaign_out(i) for i in items]


def update_campaign(
    group_id: str,
    admin_id: str,
    campaign_id: str,
    status: Optional[str] = None,
    daily_budget_cents: Optional[int] = None,
) -> Dict[str, Any]:
    user_groups.require_admin(group_id, admin_id)
    item = _get_campaign_item(group_id, campaign_id)
    if not item:
        raise HTTPException(status_code=404, detail="Campaign not found")

    ts = now_ts()
    updates: Dict[str, Any] = {"updated_at": ts}
    if status is not None:
        updates["status"] = status
    if daily_budget_cents is not None:
        updates["daily_budget_cents"] = int(daily_budget_cents)

    expr_parts, expr_names, expr_values = [], {}, {}
    for i, (k, v) in enumerate(updates.items()):
        expr_parts.append(f"#k{i} = :v{i}")
        expr_names[f"#k{i}"] = k
        expr_values[f":v{i}"] = v

    T.group_fundraising_campaigns.update_item(
        Key={"pk": _group_pk(group_id), "sk": f"CAMPAIGN#{campaign_id}"},
        UpdateExpression="SET " + ", ".join(expr_parts),
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_values,
        ConditionExpression="attribute_exists(sk)",
    )
    item.update(updates)
    return _campaign_out(item)


def get_campaign_stats(group_id: str, campaign_id: str) -> Dict[str, Any]:
    item = _get_campaign_item(group_id, campaign_id)
    if not item:
        raise HTTPException(status_code=404, detail="Campaign not found")

    impressions = int(item.get("impressions", 0))
    clicks = int(item.get("clicks", 0))
    spent = int(item.get("spent_cents", 0))
    lifetime = int(item.get("lifetime_budget_cents", 0))
    daily = int(item.get("daily_budget_cents", 0))
    ctr = round(clicks / impressions, 4) if impressions else 0.0
    return {
        "campaign_id": campaign_id,
        "impressions": impressions,
        "clicks": clicks,
        "ctr": ctr,
        "spent_cents": spent,
        "remaining_cents": max(lifetime - spent, 0),
        "daily_spent_cents": int(item.get("daily_spent_cents", 0)),
        "daily_budget_cents": daily,
        "status": item.get("status", "active"),
    }
