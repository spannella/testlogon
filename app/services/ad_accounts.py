"""Advertiser account CRUD and admin review (ADS-001)."""
from __future__ import annotations

import uuid
from typing import Optional

from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts
from app.models import AdAccountCreateIn

# Maximum number of (non-terminal) ad accounts a single user may own (ADS-001).
MAX_ACCOUNTS_PER_USER = 5

# Account statuses that no longer count toward a user's active-account quota.
_TERMINAL_ACCOUNT_STATUSES = {"deleted", "permanently_suspended"}


def _count_active_accounts_by_owner(owner_sub: str) -> int:
    """Count accounts owned by ``owner_sub`` that are not in a terminal state."""
    items = list_accounts_by_owner(owner_sub)
    return sum(
        1 for acct in items if acct.get("status") not in _TERMINAL_ACCOUNT_STATUSES
    )


def create_ad_account(owner_sub: str, data: AdAccountCreateIn) -> dict:
    """Create a new advertiser account in pending_review status.

    Raises ``ValueError`` if the owner already has ``MAX_ACCOUNTS_PER_USER``
    non-terminal ad accounts. Note: this count check is not transactional, so a
    narrow TOCTOU race under high concurrency could allow a user to briefly
    exceed the limit by the number of concurrent requests. This is acceptable
    for a per-user rate limit (not a security invariant).
    """
    if _count_active_accounts_by_owner(owner_sub) >= MAX_ACCOUNTS_PER_USER:
        raise ValueError(
            f"Account limit reached: a user may own at most "
            f"{MAX_ACCOUNTS_PER_USER} ad accounts"
        )

    account_id = f"adacct_{uuid.uuid4().hex[:12]}"
    ts = now_ts()
    item = {
        "pk": f"ACCT#{account_id}",
        "sk": "META",
        "account_id": account_id,
        "owner_sub": owner_sub,
        "owner_type": "user",
        "company_name": data.company_name,
        "billing_email": data.billing_email,
        "status": "pending_review",
        "balance_cents": 0,
        "lifetime_spend_cents": 0,
        "created_at": ts,
        "updated_at": ts,
    }
    T.ad_accounts.put_item(Item=item)
    return item


def get_ad_account(account_id: str) -> Optional[dict]:
    resp = T.ad_accounts.get_item(Key={"pk": f"ACCT#{account_id}", "sk": "META"})
    return resp.get("Item")


def list_accounts_by_owner(owner_sub: str) -> list[dict]:
    resp = T.ad_accounts.query(
        IndexName="ByOwner",
        KeyConditionExpression=Key("owner_sub").eq(owner_sub),
        ScanIndexForward=False,
    )
    return resp.get("Items", [])


def list_accounts_by_status(status: str) -> list[dict]:
    resp = T.ad_accounts.query(
        IndexName="ByStatus",
        KeyConditionExpression=Key("status").eq(status),
        ScanIndexForward=False,
    )
    return resp.get("Items", [])


def review_ad_account(
    account_id: str, reviewer_sub: str, decision: str, notes: str = ""
) -> Optional[dict]:
    acct = get_ad_account(account_id)
    if not acct:
        return None
    new_status = "active" if decision == "approve" else decision  # "reject" or "suspend"
    T.ad_accounts.update_item(
        Key={"pk": f"ACCT#{account_id}", "sk": "META"},
        UpdateExpression="SET #s = :s, reviewed_by = :r, review_notes = :n, updated_at = :u",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": new_status,
            ":r": reviewer_sub,
            ":n": notes,
            ":u": now_ts(),
        },
    )
    return {"ok": True, "status": new_status}


def create_syndicate_ad_account(
    syndicate_id: str, admin_sub: str, data: AdAccountCreateIn
) -> dict:
    """Create a SYNDICATE-owned advertiser account (ADV2-701).

    The account is owned by a syndicate: ``owner_type="syndicate"`` +
    ``owner_syndicate_id=syndicate_id``. ``owner_sub`` is set to the creating
    admin so the existing owner-scoped campaign/creative endpoints, funding
    (deposit_funds resolves the owner card) and self-ad-exclusion all keep
    working unchanged. Callers MUST have already verified admin rights (the
    router gates via ``syndicates._require_admin``). Reuses the advertiser model
    + funding + admin-review lifecycle verbatim; only the ownership tags differ.
    """
    if _count_active_accounts_by_owner(admin_sub) >= MAX_ACCOUNTS_PER_USER:
        raise ValueError(
            f"Account limit reached: a user may own at most "
            f"{MAX_ACCOUNTS_PER_USER} ad accounts"
        )

    account_id = f"adacct_{uuid.uuid4().hex[:12]}"
    ts = now_ts()
    item = {
        "pk": f"ACCT#{account_id}",
        "sk": "META",
        "account_id": account_id,
        "owner_sub": admin_sub,
        "owner_type": "syndicate",
        "owner_syndicate_id": syndicate_id,
        "company_name": data.company_name,
        "billing_email": data.billing_email,
        "status": "pending_review",
        "balance_cents": 0,
        "lifetime_spend_cents": 0,
        "created_at": ts,
        "updated_at": ts,
    }
    T.ad_accounts.put_item(Item=item)
    return item


def list_syndicate_ad_accounts(syndicate_id: str, admin_sub: str) -> list[dict]:
    """List ad accounts owned by ``syndicate_id`` (managed by ``admin_sub``).

    Syndicate accounts carry ``owner_sub == admin_sub`` (the admin), so they
    are enumerable via the ByOwner GSI and then filtered to this syndicate.
    """
    return [
        a
        for a in list_accounts_by_owner(admin_sub)
        if str(a.get("owner_type", "")) == "syndicate"
        and str(a.get("owner_syndicate_id", "")) == str(syndicate_id)
    ]
