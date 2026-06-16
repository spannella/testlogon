"""OpenBankProject — Banks + Accounts + Transactions + Metadata + Co-access.

This module implements ACC-001 through ACC-004. It is an *additive projection*
layered over the existing wallet/ledger in ``T.billing`` — it never forks the
money model:

- The default account is a thin metadata wrapper around the user's existing
  per-user ``WALLET`` row; balance reads call through to
  ``billing_shared.get_wallet_balance`` (no copy of money).
- Per-account transactions are a read-side projection of the existing
  single-entry ``LEDGER#`` rows; no new money rows are written.
- Transaction metadata (tags/comments/narrative/geotag/image) and co-owner
  reverse-index rows live in a separate ``banking_accounts`` table and never
  touch ``T.billing``.

SECOPS-007 dev/prod parity: there is no ``if S.dev_mode:`` branch in business
logic. The only localized dev/prod fork is the S3 image-URL shape in
``_build_image_url`` (mirrors ``messaging.py``).
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any, Dict, List, Optional
from uuid import uuid4

from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import get_wallet_balance, ledger_sk, user_pk

# VEW (account_views) collaborators are imported lazily inside the functions
# that need them (resolve_account_access / GET handlers) behind a try/except
# ImportError guard so ACC-004 ships before VEW is deployed.


def _audit(event: str, user_sub: str, **fields: Any) -> None:
    """Fire-and-forget audit write. Never blocks the mutation it records."""
    try:
        from app.services.alerts import audit_event

        audit_event(event, user_sub, None, **fields)
    except Exception:
        pass


def _account_pk(owner_sub: str) -> str:
    return user_pk(owner_sub)


def _account_sk(account_id: str) -> str:
    return f"ACCOUNT#{account_id}"


def _account_ref_sk(account_id: str) -> str:
    return f"ACCOUNT_REF#{account_id}"


def _meta_pk(account_id: str) -> str:
    return f"ACCOUNT#{account_id}"


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _account_to_dict(item: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a stored account row (Decimal → int/str) for API serialization."""
    return {
        "account_id": item.get("account_id", ""),
        "bank_id": item.get("bank_id", ""),
        "label": item.get("label", ""),
        "account_type": item.get("account_type", ""),
        "product_code": item.get("product_code", "default"),
        "currency": item.get("currency", "usd"),
        "owners": list(item.get("owners", []) or []),
        "is_default": bool(item.get("is_default", False)),
        "wallet_backed": bool(item.get("wallet_backed", False)),
        "iban": item.get("iban"),
        "routing_number": item.get("routing_number"),
        "account_number_masked": item.get("account_number_masked"),
        "attributes": [
            {
                "name": a.get("name", ""),
                "type": a.get("type", "STRING"),
                "value": a.get("value", ""),
            }
            for a in (item.get("attributes", []) or [])
        ],
        "created_at": _to_int(item.get("created_at")),
        "updated_at": _to_int(item.get("updated_at")),
    }


# ──────────────────────────────────────────────────────────────────────────
# Bank catalog
# ──────────────────────────────────────────────────────────────────────────


def _bank_to_dict(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "bank_id": item.get("bank_id", ""),
        "name": item.get("name", ""),
        "short_name": item.get("short_name", item.get("bank_id", "")),
        "logo_url": item.get("logo_url"),
        "website": item.get("website"),
    }


def _ensure_house_bank() -> None:
    """Idempotently seed the configured house bank row if absent."""
    bank_id = S.banking_default_bank_id
    existing = T.banking_accounts.get_item(
        Key={"pk": "BANK", "sk": f"BANK#{bank_id}"}
    ).get("Item")
    if existing:
        return
    T.banking_accounts.put_item(
        Item={
            "pk": "BANK",
            "sk": f"BANK#{bank_id}",
            "bank_id": bank_id,
            "name": S.banking_default_bank_name,
            "short_name": bank_id,
            "created_at": now_ts(),
        }
    )


def list_banks() -> List[Dict[str, Any]]:
    resp = T.banking_accounts.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :p)",
        ExpressionAttributeValues={":pk": "BANK", ":p": "BANK#"},
    )
    return [_bank_to_dict(it) for it in resp.get("Items", [])]


def get_bank(bank_id: str) -> Dict[str, Any]:
    item = T.banking_accounts.get_item(
        Key={"pk": "BANK", "sk": f"BANK#{bank_id}"}
    ).get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Bank not found")
    return _bank_to_dict(item)


# ──────────────────────────────────────────────────────────────────────────
# Default-account bootstrap + account CRUD
# ──────────────────────────────────────────────────────────────────────────


def _query_owned_accounts(owner_sub: str) -> List[Dict[str, Any]]:
    resp = T.banking_accounts.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :p)",
        ExpressionAttributeValues={":pk": _account_pk(owner_sub), ":p": "ACCOUNT#"},
    )
    return resp.get("Items", [])


def ensure_default_account(owner_sub: str) -> Dict[str, Any]:
    """Idempotent lazy bootstrap of the wallet-backed default account."""
    for it in _query_owned_accounts(owner_sub):
        if it.get("is_default"):
            return _account_to_dict(it)

    # Self-seed the house bank so account creation never depends on the seed
    # script running first.
    try:
        _ensure_house_bank()
    except Exception:
        pass

    account_id = uuid4().hex
    ts = now_ts()
    item = {
        "pk": _account_pk(owner_sub),
        "sk": _account_sk(account_id),
        "account_id": account_id,
        "bank_id": S.banking_default_bank_id,
        "label": "Wallet",
        "account_type": "WALLET",
        "product_code": "default",
        "currency": "usd",
        "owners": [owner_sub],
        "is_default": True,
        "wallet_backed": True,
        "iban": None,
        "routing_number": None,
        "account_number_masked": None,
        "attributes": [],
        "created_at": ts,
        "updated_at": ts,
    }
    try:
        T.banking_accounts.put_item(
            Item=item, ConditionExpression="attribute_not_exists(sk)"
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            # Racing caller created the row; re-read and return whatever default exists.
            for it in _query_owned_accounts(owner_sub):
                if it.get("is_default"):
                    return _account_to_dict(it)
        raise
    _audit(
        "banking.account.created",
        owner_sub,
        account_id=account_id,
        account_type="WALLET",
        is_default=True,
    )
    return _account_to_dict(item)


def create_account(
    owner_sub: str,
    *,
    label: str,
    account_type: str,
    bank_id: str,
    product_code: str = "default",
    currency: str = "usd",
    attributes: Optional[List[Dict[str, Any]]] = None,
    iban: Optional[str] = None,
    routing_number: Optional[str] = None,
    account_number_masked: Optional[str] = None,
) -> Dict[str, Any]:
    if account_type == "WALLET":
        raise HTTPException(
            status_code=422,
            detail="account_type WALLET is reserved for the default account",
        )
    # Validate bank exists (raises 404 → re-raise as 422 for unknown bank).
    try:
        get_bank(bank_id)
    except HTTPException:
        raise HTTPException(status_code=422, detail=f"Unknown bank_id: {bank_id}")

    account_id = uuid4().hex
    ts = now_ts()
    item = {
        "pk": _account_pk(owner_sub),
        "sk": _account_sk(account_id),
        "account_id": account_id,
        "bank_id": bank_id,
        "label": label,
        "account_type": account_type,
        "product_code": product_code,
        "currency": currency,
        "owners": [owner_sub],
        "is_default": False,
        "wallet_backed": False,
        "iban": (iban.strip() if isinstance(iban, str) else iban),
        "routing_number": (
            routing_number.strip() if isinstance(routing_number, str) else routing_number
        ),
        "account_number_masked": (
            account_number_masked.strip()
            if isinstance(account_number_masked, str)
            else account_number_masked
        ),
        "attributes": [dict(a) for a in (attributes or [])],
        "created_at": ts,
        "updated_at": ts,
    }
    T.banking_accounts.put_item(Item=item)
    _audit(
        "banking.account.created",
        owner_sub,
        account_id=account_id,
        account_type=account_type,
        is_default=False,
    )
    return _account_to_dict(item)


def _resolve_account_item(account_id: str) -> Optional[Dict[str, Any]]:
    resp = T.banking_accounts.query(
        IndexName="GSI_ACCOUNT_BY_ID",
        KeyConditionExpression="account_id = :id",
        ExpressionAttributeValues={":id": account_id},
    )
    items = resp.get("Items", [])
    # Only account rows (sk begins ACCOUNT#) carry the GSI key; filter defensively.
    for it in items:
        if str(it.get("sk", "")).startswith("ACCOUNT#"):
            return it
    return items[0] if items else None


def get_account(account_id: str, *, requester_sub: str) -> Dict[str, Any]:
    item = _resolve_account_item(account_id)
    if not item:
        raise HTTPException(status_code=404, detail="Account not found")
    owners = list(item.get("owners", []) or [])
    if requester_sub not in owners:
        # 404 (not 403) to avoid confirming the account exists to a stranger.
        raise HTTPException(status_code=404, detail="Account not found")
    return _account_to_dict(item)


def list_accounts(viewer_sub: str) -> List[Dict[str, Any]]:
    # Always make sure the viewer has at least their default account.
    ensure_default_account(viewer_sub)

    out: Dict[str, Dict[str, Any]] = {}
    for it in _query_owned_accounts(viewer_sub):
        acc = _account_to_dict(it)
        out[acc["account_id"]] = acc

    # Co-owned accounts via ACCOUNT_REF# reverse-index rows (written by ACC-004).
    resp = T.banking_accounts.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :p)",
        ExpressionAttributeValues={":pk": _account_pk(viewer_sub), ":p": "ACCOUNT_REF#"},
    )
    for ref in resp.get("Items", []):
        acc_id = ref.get("account_id")
        if not acc_id or acc_id in out:
            continue
        full = _resolve_account_item(acc_id)
        if full:
            acc = _account_to_dict(full)
            out[acc["account_id"]] = acc
    return list(out.values())


def update_account(
    account_id: str,
    owner_sub: str,
    *,
    label: Optional[str] = None,
    attributes: Optional[List[Dict[str, Any]]] = None,
    iban: Optional[str] = None,
    routing_number: Optional[str] = None,
    account_number_masked: Optional[str] = None,
) -> Dict[str, Any]:
    item = _resolve_account_item(account_id)
    if not item:
        raise HTTPException(status_code=404, detail="Account not found")
    if owner_sub not in list(item.get("owners", []) or []):
        raise HTTPException(status_code=403, detail="Not an owner of this account")

    pk = item["pk"]
    sk = item["sk"]
    sets = ["updated_at = :u"]
    values: Dict[str, Any] = {":u": now_ts()}
    names: Dict[str, str] = {}

    if label is not None:
        names["#label"] = "label"
        sets.append("#label = :label")
        values[":label"] = label
    if attributes is not None:
        sets.append("attributes = :attrs")
        values[":attrs"] = [dict(a) for a in attributes]
    if iban is not None:
        sets.append("iban = :iban")
        values[":iban"] = iban.strip() if isinstance(iban, str) else iban
    if routing_number is not None:
        sets.append("routing_number = :rn")
        values[":rn"] = (
            routing_number.strip() if isinstance(routing_number, str) else routing_number
        )
    if account_number_masked is not None:
        sets.append("account_number_masked = :anm")
        values[":anm"] = (
            account_number_masked.strip()
            if isinstance(account_number_masked, str)
            else account_number_masked
        )

    kwargs: Dict[str, Any] = {
        "Key": {"pk": pk, "sk": sk},
        "UpdateExpression": "SET " + ", ".join(sets),
        "ExpressionAttributeValues": values,
        "ConditionExpression": "attribute_exists(sk)",
        "ReturnValues": "ALL_NEW",
    }
    if names:
        kwargs["ExpressionAttributeNames"] = names
    try:
        result = T.banking_accounts.update_item(**kwargs)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            raise HTTPException(status_code=404, detail="Account not found")
        raise
    _audit("banking.account.updated", owner_sub, account_id=account_id)
    return _account_to_dict(result["Attributes"])


def delete_account(account_id: str, owner_sub: str) -> None:
    item = _resolve_account_item(account_id)
    if not item:
        raise HTTPException(status_code=404, detail="Account not found")
    if owner_sub not in list(item.get("owners", []) or []):
        raise HTTPException(status_code=403, detail="Not an owner of this account")
    if item.get("is_default"):
        raise HTTPException(
            status_code=409, detail="Cannot delete the default wallet account"
        )
    T.banking_accounts.delete_item(Key={"pk": item["pk"], "sk": item["sk"]})
    _audit("banking.account.deleted", owner_sub, account_id=account_id)


# ──────────────────────────────────────────────────────────────────────────
# Balance read-through
# ──────────────────────────────────────────────────────────────────────────


def _cents_to_dollars(cents: int) -> float:
    return round(int(cents) / 100.0, 2)


def get_account_balance(account_id: str, *, requester_sub: str) -> Dict[str, Any]:
    acc = get_account(account_id, requester_sub=requester_sub)
    if acc.get("wallet_backed"):
        # Owner partition holds the money; co-owners read the primary owner's wallet.
        primary_owner = acc["owners"][0] if acc.get("owners") else requester_sub
        bal = get_wallet_balance(T.billing, user_pk(primary_owner))
        cents = int(bal.get("wallet_balance_cents", 0))
        dollars = _cents_to_dollars(cents)
        return {
            "currency": bal.get("currency", acc.get("currency", "usd")),
            "current": dollars,
            "available": dollars,
        }
    return {"currency": acc.get("currency", "usd"), "current": 0.0, "available": 0.0}


# ──────────────────────────────────────────────────────────────────────────
# ACC-002 — transaction projection over the billing ledger
# ──────────────────────────────────────────────────────────────────────────


def _sign_for_entry_type(entry_type: str) -> int:
    """Fallback sign derivation for legacy/unstamped ledger rows (audit A4).

    Preferred path uses the persisted ``signed_amount_cents`` on the row; this
    map is only consulted when that field is absent.
    """
    t = (entry_type or "").strip()
    if not t:
        return 1
    if t == "credit" or t.endswith("_credit"):
        return 1
    if t == "debit" or t.endswith("_debit"):
        return -1
    if t.endswith("_charge") or t == "purchase":
        return -1
    if t == "sponsorship_payout":
        return -1
    # adjustment, shipping_refund, invoice_void_reversal, and any unlisted type
    # → credit / positive (canonical refund/adjustment is a positive credit).
    return 1


def _signed_amount_cents(row: Dict[str, Any]) -> int:
    """Prefer the persisted signed_amount_cents (decision D1); fall back to the
    type→sign map only for legacy/unstamped rows."""
    raw = row.get("signed_amount_cents")
    if raw is not None:
        try:
            return int(raw)
        except (TypeError, ValueError):
            pass
    amount = abs(_to_int(row.get("amount_cents")))
    return _sign_for_entry_type(str(row.get("type", ""))) * amount


def _amount_out(cents: int, currency: str) -> Dict[str, str]:
    sign = "-" if cents < 0 else ""
    abs_cents = abs(int(cents))
    return {"currency": currency, "value": f"{sign}{abs_cents // 100}.{abs_cents % 100:02d}"}


def _ledger_row_to_txn(
    row: Dict[str, Any],
    account_id: str,
    new_balance_cents: int,
    currency: str,
) -> Dict[str, Any]:
    amount_unsigned = abs(_to_int(row.get("amount_cents")))
    return {
        "transaction_id": row.get("entry_id", ""),
        "account_id": account_id,
        "type": str(row.get("type", "")),
        "amount": _amount_out(amount_unsigned, currency),
        "status": str(row.get("state", "")),
        "posted_at": _to_int(row.get("ts")),
        "description": str(row.get("reason", "")),
        "provider": row.get("provider"),
        "new_balance": _amount_out(new_balance_cents, currency),
        "has_metadata": False,
        "metadata": None,
    }


def list_account_transactions(
    account_id: str,
    *,
    requester_sub: str,
    from_ts: Optional[int] = None,
    to_ts: Optional[int] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
    order: str = "desc",
) -> Dict[str, Any]:
    acc = get_account(account_id, requester_sub=requester_sub)
    if not acc.get("wallet_backed"):
        return {"transactions": [], "cursor": None}

    limit = max(1, min(int(limit), 200))
    owner_sub = acc["owners"][0] if acc.get("owners") else requester_sub
    pk = user_pk(owner_sub)

    sk_lo = f"LEDGER#{from_ts}" if from_ts is not None else "LEDGER#"
    sk_hi = f"LEDGER#{to_ts}~" if to_ts is not None else "LEDGER#~"

    query_kwargs: Dict[str, Any] = {
        "KeyConditionExpression": "pk = :pk AND sk BETWEEN :lo AND :hi",
        "ExpressionAttributeValues": {":pk": pk, ":lo": sk_lo, ":hi": sk_hi},
        "ScanIndexForward": (order == "asc"),
        "Limit": limit + 1,
    }
    lek = decode_cursor(cursor)
    if lek:
        query_kwargs["ExclusiveStartKey"] = lek

    resp = T.billing.query(**query_kwargs)
    rows = list(resp.get("Items", []))

    next_cursor: Optional[str] = None
    if len(rows) > limit:
        extra = rows.pop()
        # Build a LastEvaluatedKey from the last *returned* row's keys.
        last = rows[-1]
        next_cursor = encode_cursor({"pk": last["pk"], "sk": last["sk"]})
        _ = extra

    if not rows:
        return {"transactions": [], "cursor": None}

    currency = acc.get("currency", "usd")
    bal = get_wallet_balance(T.billing, pk)
    wallet_cents = int(bal.get("wallet_balance_cents", 0))

    # Walk newest-first to compute running new_balance, regardless of order.
    # Tie-break on the full sk (which embeds ts#entry_id) so ordering is
    # deterministic and matches DynamoDB's natural sort even when ts ties.
    newest_first = sorted(rows, key=lambda r: str(r.get("sk", "")), reverse=True)
    balances: Dict[str, int] = {}
    running = wallet_cents
    prev_signed = 0
    for idx, row in enumerate(newest_first):
        if idx == 0:
            running = wallet_cents
        else:
            # new_balance[i] = new_balance[i-1] - signed_amount[i-1]
            running = running - prev_signed
        balances[str(row.get("sk"))] = running
        # Pending/reversed rows did not move the wallet → next older row inherits
        # the same balance (signed contribution = 0).
        state = str(row.get("state", ""))
        prev_signed = _signed_amount_cents(row) if state == "settled" else 0

    # Re-order to requested order and project (sk tie-break for determinism).
    ordered = sorted(
        rows, key=lambda r: str(r.get("sk", "")), reverse=(order != "asc")
    )
    transactions = [
        _ledger_row_to_txn(
            row, account_id, balances.get(str(row.get("sk")), wallet_cents), currency
        )
        for row in ordered
    ]
    return {"transactions": transactions, "cursor": next_cursor}


def get_account_transaction(
    account_id: str,
    transaction_id: str,
    *,
    requester_sub: str,
) -> Dict[str, Any]:
    acc = get_account(account_id, requester_sub=requester_sub)
    if not acc.get("wallet_backed"):
        raise HTTPException(status_code=404, detail="Transaction not found")
    owner_sub = acc["owners"][0] if acc.get("owners") else requester_sub
    pk = user_pk(owner_sub)

    lek: Optional[Dict[str, Any]] = None
    found: Optional[Dict[str, Any]] = None
    while True:
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": "pk = :pk AND begins_with(sk, :p)",
            "FilterExpression": "entry_id = :eid",
            "ExpressionAttributeValues": {
                ":pk": pk,
                ":p": "LEDGER#",
                ":eid": transaction_id,
            },
        }
        if lek:
            kwargs["ExclusiveStartKey"] = lek
        resp = T.billing.query(**kwargs)
        items = resp.get("Items", [])
        if items:
            found = items[0]
            break
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
    if not found:
        raise HTTPException(status_code=404, detail="Transaction not found")

    currency = acc.get("currency", "usd")
    bal = get_wallet_balance(T.billing, pk)
    return _ledger_row_to_txn(
        found, account_id, int(bal.get("wallet_balance_cents", 0)), currency
    )


# ──────────────────────────────────────────────────────────────────────────
# ACC-003 — transaction metadata
# ──────────────────────────────────────────────────────────────────────────

_ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp"}
_MAX_TAGS = 20
_MAX_COMMENTS = 100


def _meta_sk(transaction_id: str, suffix: str) -> str:
    return f"META#{transaction_id}#{suffix}"


def _meta_prefix(transaction_id: str) -> str:
    return f"META#{transaction_id}#"


def _require_metadata_enabled() -> None:
    if not S.banking_account_metadata_enabled:
        raise HTTPException(status_code=404, detail="Not found")


def _banking_bucket() -> str:
    return S.banking_s3_bucket or "banking-images"


def _build_image_url(s3_key: str, bucket: str) -> str:
    if S.dev_mode:
        return f"/mock/s3/{bucket}/{s3_key}"
    from app.core.aws_clients import s3_client

    return s3_client().generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket, "Key": s3_key},
        ExpiresIn=3600,
    )


def _query_metadata_rows(account_id: str, transaction_id: str) -> List[Dict[str, Any]]:
    resp = T.banking_accounts.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :p)",
        ExpressionAttributeValues={
            ":pk": _meta_pk(account_id),
            ":p": _meta_prefix(transaction_id),
        },
    )
    return resp.get("Items", [])


def transaction_has_metadata(account_id: str, transaction_id: str) -> bool:
    resp = T.banking_accounts.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :p)",
        ExpressionAttributeValues={
            ":pk": _meta_pk(account_id),
            ":p": _meta_prefix(transaction_id),
        },
        Select="COUNT",
        Limit=1,
    )
    return int(resp.get("Count", 0)) > 0


def get_transaction_metadata(
    account_id: str,
    transaction_id: str,
    *,
    requester_sub: str,
) -> Dict[str, Any]:
    _require_metadata_enabled()
    get_account_transaction(account_id, transaction_id, requester_sub=requester_sub)

    narrative: Optional[Dict[str, Any]] = None
    geotag: Optional[Dict[str, Any]] = None
    image: Optional[Dict[str, Any]] = None
    tags: List[Dict[str, Any]] = []
    comments: List[Dict[str, Any]] = []

    prefix = _meta_prefix(transaction_id)
    for row in _query_metadata_rows(account_id, transaction_id):
        sk = str(row.get("sk", ""))
        suffix = sk[len(prefix):] if sk.startswith(prefix) else sk
        if suffix == "NARRATIVE":
            narrative = {
                "text": str(row.get("text", "")),
                "author_sub": str(row.get("author_sub", "")),
                "updated_at": _to_int(row.get("updated_at")),
            }
        elif suffix == "GEOTAG":
            geotag = {
                "lat": _to_float(row.get("lat")),
                "lon": _to_float(row.get("lon")),
                "label": row.get("label"),
                "author_sub": str(row.get("author_sub", "")),
                "updated_at": _to_int(row.get("updated_at")),
            }
        elif suffix == "IMAGE":
            bucket = str(row.get("bucket", _banking_bucket()))
            s3_key = str(row.get("s3_key", ""))
            url = row.get("url") or _build_image_url(s3_key, bucket)
            image = {
                "image_id": str(row.get("image_id", "")),
                "url": url,
                "author_sub": str(row.get("author_sub", "")),
                "created_at": _to_int(row.get("created_at")),
            }
        elif suffix.startswith("TAG#"):
            tags.append(
                {
                    "tag_id": suffix[len("TAG#"):],
                    "value": str(row.get("value", "")),
                    "author_sub": str(row.get("author_sub", "")),
                    "created_at": _to_int(row.get("created_at")),
                }
            )
        elif suffix.startswith("COMMENT#"):
            comments.append(
                {
                    "comment_id": suffix[len("COMMENT#"):],
                    "text": str(row.get("text", "")),
                    "author_sub": str(row.get("author_sub", "")),
                    "created_at": _to_int(row.get("created_at")),
                }
            )

    tags.sort(key=lambda t: t["created_at"])
    comments.sort(key=lambda c: c["created_at"])
    return {
        "narrative": narrative,
        "geotag": geotag,
        "image": image,
        "tags": tags,
        "comments": comments,
    }


def put_transaction_narrative(
    account_id: str,
    transaction_id: str,
    *,
    requester_sub: str,
    text: str,
) -> Dict[str, Any]:
    _require_metadata_enabled()
    get_account_transaction(account_id, transaction_id, requester_sub=requester_sub)
    ts = now_ts()
    T.banking_accounts.put_item(
        Item={
            "pk": _meta_pk(account_id),
            "sk": _meta_sk(transaction_id, "NARRATIVE"),
            "text": text,
            "author_sub": requester_sub,
            "updated_at": ts,
        }
    )
    _audit(
        "txn_narrative_updated",
        requester_sub,
        account_id=account_id,
        transaction_id=transaction_id,
    )
    return {"text": text, "author_sub": requester_sub, "updated_at": ts}


def put_transaction_geotag(
    account_id: str,
    transaction_id: str,
    *,
    requester_sub: str,
    lat: float,
    lon: float,
    label: Optional[str] = None,
) -> Dict[str, Any]:
    _require_metadata_enabled()
    get_account_transaction(account_id, transaction_id, requester_sub=requester_sub)
    ts = now_ts()
    T.banking_accounts.put_item(
        Item={
            "pk": _meta_pk(account_id),
            "sk": _meta_sk(transaction_id, "GEOTAG"),
            "lat": Decimal(str(lat)),
            "lon": Decimal(str(lon)),
            "label": label,
            "author_sub": requester_sub,
            "updated_at": ts,
        }
    )
    _audit(
        "txn_geotag_updated",
        requester_sub,
        account_id=account_id,
        transaction_id=transaction_id,
    )
    return {
        "lat": lat,
        "lon": lon,
        "label": label,
        "author_sub": requester_sub,
        "updated_at": ts,
    }


def set_transaction_image(
    account_id: str,
    transaction_id: str,
    *,
    requester_sub: str,
    image_bytes: bytes,
    content_type: str,
    filename: str,
) -> Dict[str, Any]:
    _require_metadata_enabled()
    get_account_transaction(account_id, transaction_id, requester_sub=requester_sub)
    if content_type not in _ALLOWED_IMAGE_TYPES:
        raise HTTPException(
            status_code=422, detail={"code": "unsupported_image_type"}
        )
    if S.banking_image_max_bytes and len(image_bytes) > S.banking_image_max_bytes:
        raise HTTPException(status_code=413, detail={"code": "image_too_large"})

    from app.core.aws_clients import s3_client

    image_id = uuid4().hex
    bucket = _banking_bucket()
    s3_key = f"banking-metadata/{account_id}/{transaction_id}/{image_id}"
    s3_client().put_object(
        Bucket=bucket,
        Key=s3_key,
        Body=image_bytes,
        ContentType=content_type,
        Metadata={"author": requester_sub},
    )
    url = _build_image_url(s3_key, bucket)
    ts = now_ts()
    T.banking_accounts.put_item(
        Item={
            "pk": _meta_pk(account_id),
            "sk": _meta_sk(transaction_id, "IMAGE"),
            "image_id": image_id,
            "s3_key": s3_key,
            "bucket": bucket,
            "url": url,
            "author_sub": requester_sub,
            "created_at": ts,
        }
    )
    _audit(
        "txn_image_set",
        requester_sub,
        account_id=account_id,
        transaction_id=transaction_id,
    )
    return {
        "image_id": image_id,
        "url": url,
        "author_sub": requester_sub,
        "created_at": ts,
    }


def _existing_tag_rows(account_id: str, transaction_id: str) -> List[Dict[str, Any]]:
    resp = T.banking_accounts.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :p)",
        ExpressionAttributeValues={
            ":pk": _meta_pk(account_id),
            ":p": f"{_meta_prefix(transaction_id)}TAG#",
        },
    )
    return resp.get("Items", [])


def add_transaction_tag(
    account_id: str,
    transaction_id: str,
    *,
    requester_sub: str,
    value: str,
) -> Dict[str, Any]:
    _require_metadata_enabled()
    get_account_transaction(account_id, transaction_id, requester_sub=requester_sub)
    norm = value.strip().lower()
    existing = _existing_tag_rows(account_id, transaction_id)
    if len(existing) >= _MAX_TAGS:
        raise HTTPException(status_code=422, detail={"code": "tag_limit_reached"})
    for row in existing:
        if str(row.get("value", "")).strip().lower() == norm:
            raise HTTPException(status_code=409, detail={"code": "tag_exists"})
    tag_id = uuid4().hex
    ts = now_ts()
    T.banking_accounts.put_item(
        Item={
            "pk": _meta_pk(account_id),
            "sk": _meta_sk(transaction_id, f"TAG#{tag_id}"),
            "value": norm,
            "author_sub": requester_sub,
            "created_at": ts,
        }
    )
    _audit(
        "txn_tag_added",
        requester_sub,
        account_id=account_id,
        transaction_id=transaction_id,
    )
    return {
        "tag_id": tag_id,
        "value": norm,
        "author_sub": requester_sub,
        "created_at": ts,
    }


def remove_transaction_tag(
    account_id: str,
    transaction_id: str,
    tag_id: str,
    *,
    requester_sub: str,
) -> None:
    _require_metadata_enabled()
    get_account_transaction(account_id, transaction_id, requester_sub=requester_sub)
    sk = _meta_sk(transaction_id, f"TAG#{tag_id}")
    existing = T.banking_accounts.get_item(
        Key={"pk": _meta_pk(account_id), "sk": sk}
    ).get("Item")
    if not existing:
        raise HTTPException(status_code=404, detail="Tag not found")
    T.banking_accounts.delete_item(Key={"pk": _meta_pk(account_id), "sk": sk})
    _audit(
        "txn_tag_removed",
        requester_sub,
        account_id=account_id,
        transaction_id=transaction_id,
    )


def add_transaction_comment(
    account_id: str,
    transaction_id: str,
    *,
    requester_sub: str,
    text: str,
) -> Dict[str, Any]:
    _require_metadata_enabled()
    get_account_transaction(account_id, transaction_id, requester_sub=requester_sub)
    resp = T.banking_accounts.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :p)",
        ExpressionAttributeValues={
            ":pk": _meta_pk(account_id),
            ":p": f"{_meta_prefix(transaction_id)}COMMENT#",
        },
        Select="COUNT",
    )
    if int(resp.get("Count", 0)) >= _MAX_COMMENTS:
        raise HTTPException(status_code=422, detail={"code": "comment_limit_reached"})
    comment_id = uuid4().hex
    ts = now_ts()
    T.banking_accounts.put_item(
        Item={
            "pk": _meta_pk(account_id),
            "sk": _meta_sk(transaction_id, f"COMMENT#{comment_id}"),
            "text": text,
            "author_sub": requester_sub,
            "created_at": ts,
        }
    )
    _audit(
        "txn_comment_added",
        requester_sub,
        account_id=account_id,
        transaction_id=transaction_id,
    )
    return {
        "comment_id": comment_id,
        "text": text,
        "author_sub": requester_sub,
        "created_at": ts,
    }


def delete_transaction_comment(
    account_id: str,
    transaction_id: str,
    comment_id: str,
    *,
    requester_sub: str,
) -> None:
    _require_metadata_enabled()
    acc = get_account(account_id, requester_sub=requester_sub)
    get_account_transaction(account_id, transaction_id, requester_sub=requester_sub)
    sk = _meta_sk(transaction_id, f"COMMENT#{comment_id}")
    existing = T.banking_accounts.get_item(
        Key={"pk": _meta_pk(account_id), "sk": sk}
    ).get("Item")
    if not existing:
        raise HTTPException(status_code=404, detail="Comment not found")
    # Author OR any account owner may delete.
    is_author = str(existing.get("author_sub", "")) == requester_sub
    is_owner = requester_sub in (acc.get("owners") or [])
    if not (is_author or is_owner):
        raise HTTPException(status_code=404, detail="Comment not found")
    T.banking_accounts.delete_item(Key={"pk": _meta_pk(account_id), "sk": sk})
    _audit(
        "txn_comment_deleted",
        requester_sub,
        account_id=account_id,
        transaction_id=transaction_id,
        comment_author_sub=str(existing.get("author_sub", "")),
    )


# ──────────────────────────────────────────────────────────────────────────
# ACC-004 — account-holder co-access
# ──────────────────────────────────────────────────────────────────────────


def _holder_audit_sk(account_id: str, ts: int, event_id: str) -> str:
    return f"HOLDER_AUDIT#{account_id}#{ts}#{event_id}"


def _write_holder_audit(
    owner_sub: str,
    account_id: str,
    event: str,
    actor_sub: str,
    target_sub: str,
) -> None:
    ts = now_ts()
    event_id = uuid4().hex[:10]
    T.banking_accounts.put_item(
        Item={
            "pk": _account_pk(owner_sub),
            "sk": _holder_audit_sk(account_id, ts, event_id),
            "account_id": account_id,
            "event": event,
            "actor_sub": actor_sub,
            "target_sub": target_sub,
            "ts": ts,
            "event_id": event_id,
        }
    )


def add_account_owner(
    account_id: str,
    caller_sub: str,
    new_owner_sub: str,
) -> Dict[str, Any]:
    item = _resolve_account_item(account_id)
    if not item:
        raise HTTPException(status_code=404, detail="Account not found")
    owners = list(item.get("owners", []) or [])
    if caller_sub not in owners:
        raise HTTPException(status_code=403, detail="Not an owner of this account")
    if new_owner_sub == caller_sub:
        raise HTTPException(status_code=400, detail="Cannot grant co-ownership to self")
    if new_owner_sub in owners:
        raise HTTPException(status_code=400, detail="Already an owner")

    pk = item["pk"]
    sk = item["sk"]
    primary_owner = owners[0] if owners else caller_sub
    ts = now_ts()

    # Reverse-index row so the new owner's list_accounts surfaces the account.
    T.banking_accounts.put_item(
        Item={
            "pk": _account_pk(new_owner_sub),
            "sk": _account_ref_sk(account_id),
            "account_id": account_id,
            "owner_sub": primary_owner,
            "added_by_sub": caller_sub,
            "added_at": ts,
        }
    )
    result = T.banking_accounts.update_item(
        Key={"pk": pk, "sk": sk},
        UpdateExpression="SET owners = list_append(owners, :n), updated_at = :u",
        ExpressionAttributeValues={":n": [new_owner_sub], ":u": ts},
        ConditionExpression="attribute_exists(sk)",
        ReturnValues="ALL_NEW",
    )
    _write_holder_audit(
        primary_owner, account_id, "holder.added", caller_sub, new_owner_sub
    )
    _audit(
        "account.holder.added",
        caller_sub,
        account_id=account_id,
        actor_sub=caller_sub,
        target_sub=new_owner_sub,
    )
    return _account_to_dict(result["Attributes"])


def remove_account_owner(
    account_id: str,
    caller_sub: str,
    target_sub: str,
) -> Dict[str, Any]:
    item = _resolve_account_item(account_id)
    if not item:
        raise HTTPException(status_code=404, detail="Account not found")
    owners = list(item.get("owners", []) or [])
    if caller_sub not in owners:
        raise HTTPException(status_code=403, detail="Not an owner of this account")
    if target_sub not in owners:
        raise HTTPException(status_code=400, detail="Not a current owner")
    if len(owners) == 1 and owners[0] == target_sub:
        raise HTTPException(
            status_code=409, detail="Cannot remove the last account owner"
        )

    pk = item["pk"]
    sk = item["sk"]
    primary_owner = owners[0]
    new_owners = [o for o in owners if o != target_sub]
    ts = now_ts()

    result = T.banking_accounts.update_item(
        Key={"pk": pk, "sk": sk},
        UpdateExpression="SET owners = :o, updated_at = :u",
        ExpressionAttributeValues={":o": new_owners, ":u": ts},
        ConditionExpression="attribute_exists(sk)",
        ReturnValues="ALL_NEW",
    )
    # Delete the co-owner reverse-index row (no-op if absent).
    T.banking_accounts.delete_item(
        Key={"pk": _account_pk(target_sub), "sk": _account_ref_sk(account_id)}
    )
    _write_holder_audit(
        primary_owner, account_id, "holder.removed", caller_sub, target_sub
    )
    _audit(
        "account.holder.removed",
        caller_sub,
        account_id=account_id,
        actor_sub=caller_sub,
        target_sub=target_sub,
    )
    return _account_to_dict(result["Attributes"])


def list_account_holders(
    account_id: str,
    requester_sub: str,
) -> List[Dict[str, Any]]:
    item = _resolve_account_item(account_id)
    if not item:
        raise HTTPException(status_code=404, detail="Account not found")
    owners = list(item.get("owners", []) or [])
    if requester_sub not in owners:
        raise HTTPException(status_code=404, detail="Account not found")

    # added_at for co-owners comes from the reverse-index row; primary owner uses
    # the account's created_at.
    created_at = _to_int(item.get("created_at"))
    holders: List[Dict[str, Any]] = []
    for idx, sub in enumerate(owners):
        added_at = created_at
        if idx > 0:
            ref = T.banking_accounts.get_item(
                Key={"pk": _account_pk(sub), "sk": _account_ref_sk(account_id)}
            ).get("Item")
            if ref:
                added_at = _to_int(ref.get("added_at"))
        holders.append(
            {
                "user_sub": sub,
                "added_at": added_at,
                "is_primary_owner": idx == 0,
            }
        )
    return holders


def resolve_account_access(
    caller_sub: str,
    account_id: str,
    *,
    view_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Unify owner-check + (optional) VEW grant into one authorization primitive.

    Returns {"role": "owner"|"viewer"|None, "view_id": str|None, "grants": dict|None}.
    Never raises 403 for a non-owner — callers raise 404 to prevent enumeration.
    """
    item = _resolve_account_item(account_id)
    if not item:
        return {"role": None, "view_id": None, "grants": None}
    owners = list(item.get("owners", []) or [])
    if caller_sub in owners:
        return {"role": "owner", "view_id": None, "grants": None}

    if S.banking_account_views_enabled and view_id:
        try:
            from app.services.account_views import resolve_active_grant
        except ImportError:
            return {"role": None, "view_id": None, "grants": None}
        grant = resolve_active_grant(caller_sub, "account", account_id, view_id)
        if grant:
            return {
                "role": "viewer",
                "view_id": grant.get("view_id", view_id),
                "grants": grant.get("grants"),
            }
    return {"role": None, "view_id": None, "grants": None}
