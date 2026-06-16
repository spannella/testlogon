"""Marketing campaign CRUD + attribution (MKT-004, MKT-005, MKT-006, MKT-009)."""
from __future__ import annotations

import hashlib
import secrets
from typing import Optional

from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.models import (
    MarketingCampaignCreateIn,
    MarketingCampaignUpdateIn,
    CampaignAttributionOut,
)

# ---------------------------------------------------------------------------
# State machine (MKT-006)
# ---------------------------------------------------------------------------

_CAMPAIGN_TRANSITIONS: dict[str, set[str]] = {
    "draft": {"scheduled", "active", "archived"},
    "scheduled": {"active", "archived"},
    "active": {"paused", "completed", "archived"},
    "paused": {"active", "archived"},
    "completed": {"archived"},
    "archived": set(),
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_enabled() -> None:
    """Raise HTTP 403 when the marketing campaigns module is disabled."""
    if not S.marketing_campaigns_enabled:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=403,
            detail={"code": "marketing_campaigns_disabled",
                    "message": "Marketing campaigns module is not enabled."},
        )


def _make_campaign_id(owner_id: str, name: str, ts: int) -> str:
    created_bucket = (ts // 3600) * 3600
    raw = f"{owner_id}\x00{name}\x00{created_bucket}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:24]


def _validate_ad_campaign_ref(ad_campaign_id: str) -> None:
    """Validate that the referenced ads campaign exists (ByCampaignId GSI)."""
    try:
        resp = T.ad_campaigns.query(
            IndexName="ByCampaignId",
            KeyConditionExpression=Key("campaign_id").eq(ad_campaign_id),
            Limit=1,
        )
        if not resp.get("Items"):
            from fastapi import HTTPException
            raise HTTPException(
                status_code=422,
                detail={"code": "invalid_ad_campaign_id",
                        "message": f"Ads campaign '{ad_campaign_id}' does not exist."},
            )
    except ClientError:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_ad_campaign_id",
                    "message": f"Ads campaign '{ad_campaign_id}' does not exist."},
        )


def _validate_promo_code_refs(promo_code_ids: list[str]) -> None:
    """Validate each promo code id exists. Raises 422 on first missing code."""
    try:
        from app.services.promo_codes import get_promo_code
        for code_id in promo_code_ids:
            if get_promo_code(code_id) is None:
                from fastapi import HTTPException
                raise HTTPException(
                    status_code=422,
                    detail={"code": "invalid_promo_code_id",
                            "message": f"Promo code '{code_id}' does not exist."},
                )
    except ImportError:
        pass  # promo_codes not available (test isolation)


# ---------------------------------------------------------------------------
# CRUD (MKT-004)
# ---------------------------------------------------------------------------


def create_campaign(owner_id: str, data: MarketingCampaignCreateIn) -> dict:
    """Create a marketing campaign (idempotent within the hour bucket)."""
    _require_enabled()

    if data.ad_campaign_id:
        _validate_ad_campaign_ref(data.ad_campaign_id)
    if data.promo_code_ids:
        _validate_promo_code_refs(data.promo_code_ids)

    ts = now_ts()
    campaign_id = _make_campaign_id(owner_id, data.name, ts)

    item: dict = {
        "pk": f"OWNER#{owner_id}",
        "sk": f"MKTCAMP#{campaign_id}",
        "campaign_id": campaign_id,
        "owner_id": owner_id,
        "name": data.name,
        "objective": data.objective,
        "status": "draft",
        "budget_cents": data.budget_cents,
        "promo_code_ids": list(data.promo_code_ids),
        "contact_list_ids": list(data.contact_list_ids),
        "segment_ids": list(data.segment_ids),
        "created_at": ts,
        "updated_at": ts,
    }
    if data.ad_campaign_id is not None:
        item["ad_campaign_id"] = data.ad_campaign_id
    if data.tracking_code is not None:
        item["tracking_code"] = data.tracking_code
    if data.start_date is not None:
        item["start_date"] = data.start_date
    if data.end_date is not None:
        item["end_date"] = data.end_date

    try:
        T.marketing_campaigns.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            existing = get_campaign(owner_id, campaign_id)
            return existing if existing is not None else item
        raise

    try:
        from app.services.alerts import audit_event
        audit_event(
            "marketing.campaign.created",
            owner_id,
            campaign_id=campaign_id,
            name=data.name,
            objective=data.objective,
        )
    except Exception:
        pass

    return item


def get_campaign(owner_id: str, campaign_id: str) -> Optional[dict]:
    """Return a campaign item or None if not found / different owner."""
    resp = T.marketing_campaigns.get_item(
        Key={"pk": f"OWNER#{owner_id}", "sk": f"MKTCAMP#{campaign_id}"}
    )
    return resp.get("Item")


def get_campaign_by_id(campaign_id: str) -> Optional[dict]:
    """Look up a campaign by campaign_id alone (ByCampaignId GSI)."""
    try:
        resp = T.marketing_campaigns.query(
            IndexName="ByCampaignId",
            KeyConditionExpression=Key("campaign_id").eq(campaign_id),
            Limit=1,
        )
        items = resp.get("Items", [])
        return items[0] if items else None
    except Exception:
        return None


def list_campaigns(
    owner_id: str,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> dict:
    """List campaigns for an owner, newest first."""
    from app.core.cursor import encode_cursor, decode_cursor

    kwargs: dict = {
        "IndexName": "ByOwnerCreatedAt",
        "KeyConditionExpression": Key("owner_id").eq(owner_id),
        "Limit": limit,
        "ScanIndexForward": False,
    }
    if cursor:
        try:
            kwargs["ExclusiveStartKey"] = decode_cursor(cursor)
        except Exception:
            pass

    resp = T.marketing_campaigns.query(**kwargs)
    items = resp.get("Items", [])
    next_cursor = None
    if resp.get("LastEvaluatedKey"):
        next_cursor = encode_cursor(resp["LastEvaluatedKey"])
    return {"campaigns": items, "cursor": next_cursor}


def update_campaign(
    owner_id: str, campaign_id: str, data: MarketingCampaignUpdateIn
) -> dict:
    """Update mutable fields on a campaign. Status changes delegate to transition_campaign."""
    campaign = get_campaign(owner_id, campaign_id)
    if campaign is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Campaign not found")

    _require_enabled()

    # Validate references if changing them
    new_ad_id = data.ad_campaign_id if data.ad_campaign_id is not None else campaign.get("ad_campaign_id")
    if data.ad_campaign_id is not None and data.ad_campaign_id != campaign.get("ad_campaign_id"):
        _validate_ad_campaign_ref(data.ad_campaign_id)
    if data.promo_code_ids is not None:
        _validate_promo_code_refs(data.promo_code_ids)

    # Handle status transition separately
    target_status = data.status
    if target_status and target_status != campaign.get("status"):
        campaign = transition_campaign(owner_id, campaign_id, target_status)

    # Build update expression for non-status fields
    updates = {}
    if data.name is not None:
        updates["name"] = data.name
    if data.objective is not None:
        updates["objective"] = data.objective
    if data.budget_cents is not None:
        updates["budget_cents"] = data.budget_cents
    if data.promo_code_ids is not None:
        updates["promo_code_ids"] = list(data.promo_code_ids)
    if data.contact_list_ids is not None:
        updates["contact_list_ids"] = list(data.contact_list_ids)
    if data.segment_ids is not None:
        updates["segment_ids"] = list(data.segment_ids)
    if data.ad_campaign_id is not None:
        updates["ad_campaign_id"] = data.ad_campaign_id
    if data.tracking_code is not None:
        updates["tracking_code"] = data.tracking_code
    if data.start_date is not None:
        updates["start_date"] = data.start_date
    if data.end_date is not None:
        updates["end_date"] = data.end_date

    if updates:
        ts = now_ts()
        updates["updated_at"] = ts
        set_parts = []
        expr_names = {}
        expr_values = {}
        for i, (k, v) in enumerate(updates.items()):
            placeholder = f"#f{i}"
            val_placeholder = f":v{i}"
            expr_names[placeholder] = k
            expr_values[val_placeholder] = v
            set_parts.append(f"{placeholder} = {val_placeholder}")

        T.marketing_campaigns.update_item(
            Key={"pk": f"OWNER#{owner_id}", "sk": f"MKTCAMP#{campaign_id}"},
            UpdateExpression="SET " + ", ".join(set_parts),
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_values,
        )

        try:
            from app.services.alerts import audit_event
            audit_event("marketing.campaign.updated", owner_id, campaign_id=campaign_id)
        except Exception:
            pass

    return get_campaign(owner_id, campaign_id) or campaign


# ---------------------------------------------------------------------------
# State machine (MKT-006)
# ---------------------------------------------------------------------------


def _validate_transition(current: str, target: str) -> None:
    allowed = _CAMPAIGN_TRANSITIONS.get(current, set())
    if target not in allowed:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=409,
            detail={
                "code": "invalid_transition",
                "message": f"Cannot transition campaign from '{current}' to '{target}'.",
                "allowed": sorted(allowed),
            },
        )


def _check_activation_guards(campaign: dict) -> None:
    """Pre-activation validations run only when transitioning → active."""
    ts = now_ts()
    # End date must be in the future
    end_date = campaign.get("end_date")
    if end_date is not None and end_date < ts:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=422,
            detail={"code": "campaign_end_date_past",
                    "message": "Campaign end_date is in the past."},
        )
    # Start date must not be more than one hour in the past
    start_date = campaign.get("start_date")
    if start_date is not None and start_date < (ts - 3600):
        from fastapi import HTTPException
        raise HTTPException(
            status_code=422,
            detail={"code": "campaign_start_date_stale",
                    "message": "Campaign start_date is more than one hour in the past."},
        )
    # Linked promo codes must be active
    promo_ids = campaign.get("promo_code_ids") or []
    if promo_ids:
        try:
            from app.services.promo_codes import get_promo_code
            for code_id in promo_ids:
                code = get_promo_code(code_id)
                if not code:
                    from fastapi import HTTPException
                    raise HTTPException(
                        status_code=422,
                        detail={"code": "promo_code_not_found",
                                "message": f"Linked promo code '{code_id}' not found."},
                    )
                if not code.get("active", True):
                    from fastapi import HTTPException
                    raise HTTPException(
                        status_code=422,
                        detail={"code": "promo_code_inactive",
                                "message": f"Linked promo code '{code_id}' is not active."},
                    )
                expires_at = code.get("expires_at")
                if expires_at and expires_at < ts:
                    from fastapi import HTTPException
                    raise HTTPException(
                        status_code=422,
                        detail={"code": "promo_code_expired",
                                "message": f"Linked promo code '{code_id}' has expired."},
                    )
        except ImportError:
            pass  # promo_codes not available in test isolation


def transition_campaign(
    owner_id: str,
    campaign_id: str,
    target_status: str,
) -> dict:
    """Transition a campaign status through the state machine."""
    campaign = get_campaign(owner_id, campaign_id)
    if campaign is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Campaign not found")

    _require_enabled()
    current = campaign.get("status", "draft")
    _validate_transition(current, target_status)

    if target_status == "active":
        _check_activation_guards(campaign)

    ts = now_ts()
    T.marketing_campaigns.update_item(
        Key={"pk": f"OWNER#{owner_id}", "sk": f"MKTCAMP#{campaign_id}"},
        UpdateExpression="SET #s = :s, updated_at = :ts",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": target_status, ":ts": ts},
    )

    try:
        from app.services.alerts import audit_event
        audit_event(
            "marketing_campaign.transition",
            owner_id,
            campaign_id=campaign_id,
            from_status=current,
            to_status=target_status,
        )
    except Exception:
        pass

    updated = get_campaign(owner_id, campaign_id)
    return updated if updated is not None else {**campaign, "status": target_status, "updated_at": ts}


# ---------------------------------------------------------------------------
# Ad-campaign + promo-code attach/detach (MKT-005)
# ---------------------------------------------------------------------------


def attach_ad_campaign(owner_id: str, campaign_id: str, ad_campaign_id: str) -> dict:
    """Link an ads campaign to this marketing campaign, storing ad_account_id too."""
    campaign = get_campaign(owner_id, campaign_id)
    if campaign is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Campaign not found")

    _require_enabled()
    _validate_ad_campaign_ref(ad_campaign_id)

    # Resolve account_id via GSI so we can do direct point-gets for attribution
    ad_account_id = None
    try:
        resp = T.ad_campaigns.query(
            IndexName="ByCampaignId",
            KeyConditionExpression=Key("campaign_id").eq(ad_campaign_id),
            Limit=1,
        )
        items = resp.get("Items", [])
        if items:
            # pk="ACCT#{account_id}", extract account_id
            pk_val = items[0].get("pk", "")
            if pk_val.startswith("ACCT#"):
                ad_account_id = pk_val[5:]
    except Exception:
        pass

    update_expr = "SET ad_campaign_id = :cid, updated_at = :ts"
    expr_vals: dict = {":cid": ad_campaign_id, ":ts": now_ts()}
    if ad_account_id:
        update_expr += ", ad_account_id = :aid"
        expr_vals[":aid"] = ad_account_id

    T.marketing_campaigns.update_item(
        Key={"pk": f"OWNER#{owner_id}", "sk": f"MKTCAMP#{campaign_id}"},
        UpdateExpression=update_expr,
        ExpressionAttributeValues=expr_vals,
    )
    return get_campaign(owner_id, campaign_id) or campaign


def detach_ad_campaign(owner_id: str, campaign_id: str) -> dict:
    """Remove the linked ads campaign reference."""
    campaign = get_campaign(owner_id, campaign_id)
    if campaign is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Campaign not found")

    _require_enabled()

    T.marketing_campaigns.update_item(
        Key={"pk": f"OWNER#{owner_id}", "sk": f"MKTCAMP#{campaign_id}"},
        UpdateExpression="REMOVE ad_campaign_id, ad_account_id SET updated_at = :ts",
        ExpressionAttributeValues={":ts": now_ts()},
    )
    return get_campaign(owner_id, campaign_id) or campaign


def attach_promo_code(owner_id: str, campaign_id: str, code_id: str) -> dict:
    """Add a promo code to the campaign's promo_code_ids list (no duplicates)."""
    campaign = get_campaign(owner_id, campaign_id)
    if campaign is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Campaign not found")

    _require_enabled()
    _validate_promo_code_refs([code_id])

    current_ids: list = list(campaign.get("promo_code_ids") or [])
    if code_id not in current_ids:
        current_ids.append(code_id)
        T.marketing_campaigns.update_item(
            Key={"pk": f"OWNER#{owner_id}", "sk": f"MKTCAMP#{campaign_id}"},
            UpdateExpression="SET promo_code_ids = :ids, updated_at = :ts",
            ExpressionAttributeValues={":ids": current_ids, ":ts": now_ts()},
        )
    return get_campaign(owner_id, campaign_id) or campaign


def detach_promo_code(owner_id: str, campaign_id: str, code_id: str) -> dict:
    """Remove a promo code from the campaign's promo_code_ids list."""
    campaign = get_campaign(owner_id, campaign_id)
    if campaign is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Campaign not found")

    _require_enabled()

    current_ids: list = [c for c in (campaign.get("promo_code_ids") or []) if c != code_id]
    T.marketing_campaigns.update_item(
        Key={"pk": f"OWNER#{owner_id}", "sk": f"MKTCAMP#{campaign_id}"},
        UpdateExpression="SET promo_code_ids = :ids, updated_at = :ts",
        ExpressionAttributeValues={":ids": current_ids, ":ts": now_ts()},
    )
    return get_campaign(owner_id, campaign_id) or campaign


# ---------------------------------------------------------------------------
# Attribution rollup (MKT-005)
# ---------------------------------------------------------------------------


def compute_attribution(owner_id: str, campaign_id: str) -> CampaignAttributionOut:
    """Read-only attribution rollup — never writes money."""
    campaign = get_campaign(owner_id, campaign_id)
    if campaign is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Campaign not found")

    ad_spend_cents = 0
    promo_discount_cents = 0
    promo_redemptions = 0
    tracking_visits = 0
    tracking_orders = 0

    # Ad-campaign spend
    ad_campaign_id = campaign.get("ad_campaign_id")
    ad_account_id = campaign.get("ad_account_id")
    if ad_campaign_id and ad_account_id:
        try:
            from app.services.ad_campaigns import get_campaign as get_ad_campaign
            ad_camp = get_ad_campaign(ad_account_id, ad_campaign_id)
            if ad_camp:
                ad_spend_cents = int(ad_camp.get("lifetime_spent_cents") or 0)
        except (ImportError, Exception):
            pass
    elif ad_campaign_id:
        # No stored account_id, try GSI lookup
        try:
            resp = T.ad_campaigns.query(
                IndexName="ByCampaignId",
                KeyConditionExpression=Key("campaign_id").eq(ad_campaign_id),
                Limit=1,
            )
            items = resp.get("Items", [])
            if items:
                ad_spend_cents = int(items[0].get("lifetime_spent_cents") or 0)
        except Exception:
            pass

    # Promo code discount/redemptions
    promo_ids = campaign.get("promo_code_ids") or []
    for code_id in promo_ids:
        try:
            from app.services.promo_codes import get_promo_stats
            stats = get_promo_stats(code_id)
            promo_discount_cents += int(stats.get("total_discount_cents") or 0)
            promo_redemptions += int(stats.get("total_redemptions") or 0)
        except (ImportError, Exception):
            pass

    # Tracking-code visit/order counts
    tracking_code_slug = campaign.get("tracking_code")
    if tracking_code_slug:
        try:
            resp = T.tracking_codes.query(
                KeyConditionExpression=Key("pk").eq(f"TRACK#{tracking_code_slug}"),
            )
            for row in resp.get("Items", []):
                sk = row.get("sk", "")
                if sk.startswith("VISIT#"):
                    tracking_visits += 1
                elif sk.startswith("ORDER#"):
                    tracking_orders += 1
        except Exception:
            # Fall back to denormalized counters on META
            try:
                meta = T.tracking_codes.get_item(
                    Key={"pk": f"TRACK#{tracking_code_slug}", "sk": "META"}
                ).get("Item") or {}
                tracking_visits = int(meta.get("visit_count") or 0)
                tracking_orders = int(meta.get("order_count") or 0)
            except Exception:
                pass

    return CampaignAttributionOut(
        campaign_id=campaign_id,
        ad_spend_cents=ad_spend_cents,
        promo_discount_cents=promo_discount_cents,
        promo_redemptions=promo_redemptions,
        tracking_visits=tracking_visits,
        tracking_orders=tracking_orders,
        as_of=now_ts(),
    )


# ---------------------------------------------------------------------------
# Admin listing (MKT-011)
# ---------------------------------------------------------------------------


def list_campaigns_by_status(status: str, limit: int = 50) -> list[dict]:
    """Admin: list campaigns by status using ByStatusCreatedAt GSI."""
    resp = T.marketing_campaigns.query(
        IndexName="ByStatusCreatedAt",
        KeyConditionExpression=Key("status").eq(status),
        Limit=limit,
        ScanIndexForward=False,
    )
    return resp.get("Items", [])


# ---------------------------------------------------------------------------
# Campaign send (MKT-009)
# ---------------------------------------------------------------------------


def _make_send_id(campaign_id: str, snapshot_ts: int, party_id: str) -> str:
    raw = f"{campaign_id}\x00{snapshot_ts}\x00{party_id}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:24]


def send_campaign(campaign_id: str, owner_id: str, *, now: Optional[int] = None) -> dict:
    """
    Send a campaign to all eligible recipients. Idempotent per (campaign_id, snap_ts, party_id).
    Requires campaign status == 'active'.
    """
    _require_enabled()

    campaign = get_campaign(owner_id, campaign_id)
    if campaign is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Campaign not found")

    if campaign.get("status") != "active":
        from fastapi import HTTPException
        raise HTTPException(
            status_code=422,
            detail={"code": "campaign_not_active",
                    "message": "Only active campaigns can be sent."},
        )

    ts = now or now_ts()
    sent_count = 0
    skipped_count = 0

    # Build the superset of recipient party_ids
    party_ids: set[str] = set()

    # From contact lists
    contact_list_ids = campaign.get("contact_list_ids") or []
    for list_id in contact_list_ids:
        try:
            from app.services.marketing_lists import list_members_for_send
            members = list_members_for_send(list_id)
            for m in members:
                party_ids.add(m["party_id"])
        except (ImportError, Exception):
            pass

    # From segment snapshots (latest snapshot per segment)
    segment_ids = campaign.get("segment_ids") or []
    for segment_id in segment_ids:
        try:
            from app.services.party_segments import list_snapshots, list_snapshot_members
            snaps = list_snapshots(segment_id, owner_id, limit=1)
            if snaps:
                snap = snaps[0]
                snap_id = snap.get("snap_id", "")
                members = list_snapshot_members(
                    segment_id, snap_id, owner_id, include_opted_out=False
                )
                for m in members.get("members", []):
                    party_ids.add(m["party_id"])
        except (ImportError, Exception):
            pass

    # Build tracking URL and promo code string for email body
    tracking_code_slug = campaign.get("tracking_code")
    tracking_url = ""
    if tracking_code_slug:
        tracking_url = f"{S.public_base_url}/ui/marketing/t/{tracking_code_slug}"

    promo_code_str = ""
    promo_ids = campaign.get("promo_code_ids") or []
    if promo_ids:
        try:
            from app.services.promo_codes import get_promo_code
            first_code = get_promo_code(promo_ids[0])
            if first_code:
                promo_code_str = first_code.get("code", "")
        except (ImportError, Exception):
            pass

    campaign_name = campaign.get("name", "Marketing Campaign")

    # Deliver to each recipient
    for party_id in party_ids:
        # Final opt-out check
        try:
            from app.services.cart_reminders import is_user_opted_out
            if is_user_opted_out(party_id):
                skipped_count += 1
                continue
        except (ImportError, Exception):
            pass

        send_id = _make_send_id(campaign_id, ts, party_id)

        # Idempotent dedup record
        try:
            T.marketing_send_log.put_item(
                Item={
                    "pk": f"CAMP#{campaign_id}",
                    "sk": f"SEND#{send_id}",
                    "send_id": send_id,
                    "campaign_id": campaign_id,
                    "party_id": party_id,
                    "sent_at": ts,
                },
                ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                skipped_count += 1
                continue
            raise

        # Get recipient email
        try:
            from app.services.profile import get_profile
            profile = get_profile(party_id)
            email = profile.get("email", "")
        except (ImportError, Exception):
            email = ""

        # Build message body
        body_parts = [f"You are receiving this message as part of: {campaign_name}"]
        if promo_code_str:
            body_parts.append(f"\nPromo code: {promo_code_str}")
        if tracking_url:
            body_parts.append(f"\nLearn more: {tracking_url}")
        body_text = "\n".join(body_parts)

        # Write in-app alert
        try:
            from app.services.alerts import write_alert
            write_alert(
                party_id,
                event="marketing.campaign.send",
                outcome="sent",
                title=f"Message from {campaign_name}",
                details={"campaign_id": campaign_id, "send_id": send_id},
                action_url=tracking_url or S.public_base_url,
            )
        except (ImportError, Exception):
            pass

        # Send email if we have one
        if email:
            try:
                from app.services.alerts import send_alert_email
                send_alert_email(
                    to_emails=[email],
                    subject=f"Message from {campaign_name}",
                    body_text=body_text,
                )
            except (ImportError, Exception):
                pass

        sent_count += 1

    try:
        from app.services.alerts import audit_event
        audit_event(
            "marketing.campaign.sent",
            owner_id,
            campaign_id=campaign_id,
            sent=sent_count,
            skipped=skipped_count,
        )
    except Exception:
        pass

    return {
        "campaign_id": campaign_id,
        "sent_count": sent_count,
        "skipped_count": skipped_count,
        "snapshot_ts": ts,
    }
