"""OFBiz GL chart-of-accounts service (OFB-013, Milestone 4).

Seedable, CRUD-managed GL account definitions. Additive, flag-gated behind
``S.gl_double_entry_enabled`` (default OFF). With the flag off every public
function raises HTTP 404 and the ``gl_accounts`` table is never touched.

SECOPS-007 parity: identical DDB code path dev (moto) and prod (real DDB);
no ``dev_mode`` branch.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

# ESCALATIONS §A row 13 / D1: contra_asset is credit-normal (accumulated
# depreciation etc.). OFB-013 is authoritative for this account class.
ACCOUNT_CLASSES = frozenset(
    {"asset", "liability", "equity", "revenue", "expense", "contra_asset"}
)
NORMAL_BALANCE_FOR_CLASS: Dict[str, str] = {
    "asset": "debit",
    "expense": "debit",
    "contra_asset": "credit",
    "liability": "credit",
    "equity": "credit",
    "revenue": "credit",
}

# Seven default accounts mapping the platform's existing money flows. These
# codes are the contract OFB-014's ACCOUNT_MAPPING references.
DEFAULT_ACCOUNTS: List[Dict[str, Any]] = [
    {"account_code": "1000", "name": "Cash / Bank", "account_class": "asset",
     "description": "Platform operating cash and bank settlements"},
    {"account_code": "1200", "name": "Accounts Receivable", "account_class": "asset",
     "description": "Amounts owed by customers for settled charges"},
    {"account_code": "2000", "name": "Accounts Payable", "account_class": "liability",
     "description": "Platform liabilities to creators and payout recipients"},
    {"account_code": "2100", "name": "Sales Tax Payable", "account_class": "liability",
     "description": "Collected sales tax not yet remitted"},
    {"account_code": "4000", "name": "Sales Revenue", "account_class": "revenue",
     "description": "Settled charges for products, subscriptions, tips"},
    {"account_code": "4900", "name": "Refunds / Returns", "account_class": "revenue",
     "description": "Contra-revenue for refunds and reversals"},
    {"account_code": "5100", "name": "Processor Fees", "account_class": "expense",
     "description": "Payment gateway and processor transaction fees"},
    # FXA-008 — fixed-asset chart accounts (so depreciation/disposal journals
    # post against real accounts and roll up in GL reports).
    {"account_code": "1500", "name": "Fixed Assets", "account_class": "asset",
     "description": "Capitalised fixed-asset cost"},
    {"account_code": "1600", "name": "Accumulated Depreciation", "account_class": "contra_asset",
     "description": "Contra-asset accumulating depreciation against fixed assets"},
    {"account_code": "6100", "name": "Depreciation Expense", "account_class": "expense",
     "description": "Periodic depreciation charge"},
    {"account_code": "4800", "name": "Gain on Disposal", "account_class": "revenue",
     "description": "Gain realised on fixed-asset disposal"},
    {"account_code": "5800", "name": "Loss on Disposal", "account_class": "expense",
     "description": "Loss realised on fixed-asset disposal"},
]


def _flag_on() -> bool:
    return bool(getattr(S, "gl_double_entry_enabled", False))


def _require_enabled() -> None:
    if not _flag_on():
        raise HTTPException(status_code=404, detail="GL double-entry not enabled")


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event

        audit_event(event, user_sub or "system", None, **fields)
    except Exception:
        pass


def _project(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "account_code": item.get("account_code", ""),
        "name": item.get("name", ""),
        "account_class": item.get("account_class", ""),
        "normal_balance": item.get("normal_balance", ""),
        "description": item.get("description"),
        "is_active": bool(item.get("is_active", True)),
        "is_system": bool(item.get("is_system", False)),
        "created_at": int(item.get("created_at", 0) or 0),
        "updated_at": int(item.get("updated_at", 0) or 0),
        "created_by": item.get("created_by", ""),
    }


def seed_chart_of_accounts() -> None:
    """Idempotently write the default accounts (conditional put on the PK).
    Re-running after a restart never overwrites operator-modified rows."""
    if not _flag_on():
        return
    ts = now_ts()
    for acct in DEFAULT_ACCOUNTS:
        item = {
            "account_code": acct["account_code"],
            "sk": "META",
            "name": acct["name"],
            "account_class": acct["account_class"],
            "normal_balance": NORMAL_BALANCE_FOR_CLASS[acct["account_class"]],
            "description": acct.get("description"),
            "is_active": True,
            "is_system": True,
            "gsi_active": "true",
            "created_at": ts,
            "updated_at": ts,
            "created_by": "system",
        }
        try:
            T.gl_accounts.put_item(Item=item, ConditionExpression="attribute_not_exists(account_code)")
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
                raise


def get_account(account_code: str) -> Optional[Dict[str, Any]]:
    _require_enabled()
    resp = T.gl_accounts.get_item(Key={"account_code": account_code, "sk": "META"})
    item = resp.get("Item")
    return _project(item) if item else None


def list_accounts(
    account_class: Optional[str] = None,
    active_only: bool = True,
) -> List[Dict[str, Any]]:
    """List accounts. Uses GSI_CLASS for a class filter; otherwise scans the
    bounded CoA with a FilterExpression on the gsi_active string mirror."""
    _require_enabled()
    out: List[Dict[str, Any]] = []
    if account_class:
        kwargs: Dict[str, Any] = {
            "IndexName": "GSI_CLASS",
            "KeyConditionExpression": Key("account_class").eq(account_class),
        }
        while True:
            resp = T.gl_accounts.query(**kwargs)
            for item in resp.get("Items", []):
                rec = _project(item)
                if active_only and not rec["is_active"]:
                    continue
                out.append(rec)
            lek = resp.get("LastEvaluatedKey")
            if not lek:
                break
            kwargs["ExclusiveStartKey"] = lek
        return out

    scan_kwargs: Dict[str, Any] = {}
    if active_only:
        scan_kwargs["FilterExpression"] = Attr("gsi_active").eq("true")
    while True:
        resp = T.gl_accounts.scan(**scan_kwargs)
        for item in resp.get("Items", []):
            out.append(_project(item))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        scan_kwargs["ExclusiveStartKey"] = lek
    return out


def create_account(
    account_code: str,
    name: str,
    account_class: str,
    description: Optional[str],
    actor_sub: str,
) -> Dict[str, Any]:
    _require_enabled()
    if account_class not in ACCOUNT_CLASSES:
        raise HTTPException(status_code=400, detail="Invalid account_class")
    ts = now_ts()
    item = {
        "account_code": account_code,
        "sk": "META",
        "name": name.strip(),
        "account_class": account_class,
        "normal_balance": NORMAL_BALANCE_FOR_CLASS[account_class],
        "description": (description or None),
        "is_active": True,
        "is_system": False,
        "gsi_active": "true",
        "created_at": ts,
        "updated_at": ts,
        "created_by": actor_sub or "system",
    }
    try:
        T.gl_accounts.put_item(Item=item, ConditionExpression="attribute_not_exists(account_code)")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            raise HTTPException(status_code=409, detail="Account code already exists")
        raise
    _audit("gl_account_created", actor_sub, account_code=account_code, account_class=account_class)
    return _project(item)


def update_account(
    account_code: str,
    name: Optional[str],
    description: Optional[str],
    actor_sub: str,
) -> Dict[str, Any]:
    _require_enabled()
    existing = get_account(account_code)
    if existing is None:
        raise HTTPException(status_code=404, detail="Account not found")
    sets = ["updated_at = :ts"]
    vals: Dict[str, Any] = {":ts": now_ts()}
    names: Dict[str, str] = {}
    if name is not None:
        sets.append("#nm = :nm")
        names["#nm"] = "name"
        vals[":nm"] = name.strip()
    if description is not None:
        sets.append("description = :ds")
        vals[":ds"] = description or None
    kwargs: Dict[str, Any] = {
        "Key": {"account_code": account_code, "sk": "META"},
        "UpdateExpression": "SET " + ", ".join(sets),
        "ConditionExpression": "attribute_exists(account_code)",
        "ExpressionAttributeValues": vals,
    }
    if names:
        kwargs["ExpressionAttributeNames"] = names
    T.gl_accounts.update_item(**kwargs)
    _audit("gl_account_updated", actor_sub, account_code=account_code)
    return get_account(account_code) or existing


def _has_posted_entries(account_code: str) -> bool:
    """Return True if any gl_journal line references this account_code.
    Bounded scan of JL# line items (CoA disable is a rare admin op)."""
    try:
        resp = T.gl_journal.scan(
            FilterExpression=Attr("account_code").eq(account_code) & Attr("SK").begins_with("JL#"),
            Limit=1,
        )
        return bool(resp.get("Items"))
    except Exception:
        return False


def disable_account(account_code: str, actor_sub: str) -> Dict[str, Any]:
    _require_enabled()
    existing = get_account(account_code)
    if existing is None:
        raise HTTPException(status_code=404, detail="Account not found")
    if existing["is_system"]:
        raise HTTPException(status_code=403, detail="Cannot disable a system account")
    if _has_posted_entries(account_code):
        raise HTTPException(status_code=409, detail="Cannot disable account with posted entries")
    T.gl_accounts.update_item(
        Key={"account_code": account_code, "sk": "META"},
        UpdateExpression="SET is_active = :f, gsi_active = :fs, updated_at = :ts",
        ConditionExpression="attribute_exists(account_code)",
        ExpressionAttributeValues={":f": False, ":fs": "false", ":ts": now_ts()},
    )
    _audit("gl_account_disabled", actor_sub, account_code=account_code)
    return get_account(account_code) or existing


def enable_account(account_code: str, actor_sub: str) -> Dict[str, Any]:
    _require_enabled()
    existing = get_account(account_code)
    if existing is None:
        raise HTTPException(status_code=404, detail="Account not found")
    T.gl_accounts.update_item(
        Key={"account_code": account_code, "sk": "META"},
        UpdateExpression="SET is_active = :t, gsi_active = :ts_s, updated_at = :ts",
        ConditionExpression="attribute_exists(account_code)",
        ExpressionAttributeValues={":t": True, ":ts_s": "true", ":ts": now_ts()},
    )
    _audit("gl_account_enabled", actor_sub, account_code=account_code)
    return get_account(account_code) or existing
