"""
POS-009 — Receipt generation for settled POS transactions.

Reuses the existing dependency-free, pure-Python PDF writer
(``app/services/receipts.py:_render_pdf``).  Does NOT fork ``receipts.py`` and
does NOT re-implement the PDF byte-stream builder.

Storage strategy (SECOPS-007 dev/prod parity via the existing receipts pattern):
  - dev (``S.dev_mode``): the rendered PDF is stored base64-encoded on the TXN
    row (``receipt_b64``) and returned inline.  This avoids requiring the
    file-manager ``files`` table / moto-S3 in the hermetic test path and mirrors
    how other dev/prod receipt paths branch (e.g. audit-export inline content).
  - prod: the PDF is uploaded via the existing
    ``filemanager.upload_billing_receipt`` path and the file-manager path is
    stored on the TXN row (``receipt_path``).

Idempotency: ``receipt_id`` is deterministic from ``txn_id``; the TXN row is
updated with a conditional ``attribute_not_exists(receipt_id)`` so a concurrent
second writer reads back the winner's data (first-writer-wins).  Reprints return
the SAME receipt without re-rendering.

This module is imported lazily from ``pos_tender.py`` / the router so the import
graph is undisturbed when ``S.pos_enabled`` is off.
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.receipts import _render_pdf  # reused PDF writer; applies _pdf_escape internally


# ── deterministic receipt id ───────────────────────────────────────────────────

def _pos_receipt_id(txn_id: str) -> str:
    """Deterministic, collision-resistant receipt id derived from txn_id alone."""
    return hashlib.sha256(f"pos_receipt:{txn_id}".encode()).hexdigest()[:16]


def _txn_pk(txn_id: str) -> Dict[str, str]:
    return {"pos_pk": f"TXN#{txn_id}", "pos_sk": "META"}


def _session_pk(session_id: str) -> Dict[str, str]:
    return {"pos_pk": f"SESSION#{session_id}", "pos_sk": "META"}


def _register_pk(register_id: str) -> Dict[str, str]:
    return {"pos_pk": f"REGISTER#{register_id}", "pos_sk": "META"}


def _to_int(v: Any, default: int = 0) -> int:
    try:
        return int(v) if v is not None else default
    except (TypeError, ValueError):
        return default


def _fmt_ts(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%B %d, %Y %H:%M:%S UTC")


def _dollars(cents: int) -> str:
    return f"${cents / 100:.2f}"


# ── payload ─────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class PosReceiptPayload:
    txn_id: str
    session_id: str
    register_id: str
    register_label: str
    store_name: str
    cashier_sub: str
    cashier_name: str
    settled_at: int
    currency: str
    subtotal_cents: int
    discount_cents: int
    tax_cents: int
    total_cents: int
    line_items: List[Dict[str, Any]] = field(default_factory=list)
    tenders: List[Dict[str, Any]] = field(default_factory=list)


def _render_pos_receipt_lines(p: PosReceiptPayload) -> List[str]:
    """Build the human-readable receipt line list (plain strings, NOT escaped).

    ``_render_pdf`` applies ``_pdf_escape`` to every line internally, so callers
    must pass plain strings to avoid double-escaping.
    """
    sep = "-" * 40
    lines: List[str] = ["IN-PERSON SALE RECEIPT", sep]
    if p.store_name:
        lines.append(f"Store     : {p.store_name}")
    lines.append(f"Register  : {p.register_label or p.register_id}")
    lines.append(f"Session   : {p.session_id[:8]}...")
    lines.append(f"Cashier   : {p.cashier_name}")
    lines.append(f"Date      : {_fmt_ts(p.settled_at)}")
    lines.append(f"Txn       : {p.txn_id}")
    lines.append("")

    lines.append("ITEMS")
    lines.append(sep)
    for item in p.line_items:
        name = (
            item.get("name")
            or item.get("item_name")
            or item.get("item_id")
            or item.get("sku")
            or "Item"
        )
        qty = _to_int(item.get("quantity"), 1) or 1
        unit_price = _to_int(item.get("unit_price_cents") or item.get("price_cents"))
        line_total = unit_price * qty
        if qty > 1:
            lines.append(f"  {name}")
            lines.append(f"    Qty: {qty}  x {_dollars(unit_price)}  =  {_dollars(line_total)}")
        else:
            lines.append(f"  {name}  {_dollars(line_total)}")
    lines.append(sep)

    lines.append(f"Subtotal  :  {_dollars(p.subtotal_cents)}")
    if p.discount_cents:
        lines.append(f"Discount  : -{_dollars(p.discount_cents)}")
    if p.tax_cents:
        lines.append(f"Tax       :  {_dollars(p.tax_cents)}")
    lines.append(sep)
    lines.append(f"TOTAL     :  {_dollars(p.total_cents)}")
    lines.append("")

    lines.append("TENDER")
    lines.append(sep)
    for t in p.tenders:
        kind = (t.get("kind") or "cash").lower()
        amount = _to_int(t.get("amount_cents") or t.get("amount_tendered_cents"))
        if kind == "cash":
            lines.append(f"  Cash      :  {_dollars(amount)}")
            change = _to_int(t.get("change_due_cents"))
            if change:
                lines.append(f"  Change    : -{_dollars(change)}")
        elif kind == "card":
            # card_ref format "visa_4242" -> kind "visa", last4 "4242"
            card_ref = t.get("card_ref") or ""
            if "_" in card_ref:
                brand, last4 = card_ref.rsplit("_", 1)
            else:
                brand, last4 = "card", "????"
            lines.append(f"  Card ({brand} ...{last4}) :  {_dollars(amount)}")
        elif kind == "wallet":
            lines.append(f"  Wallet    :  {_dollars(amount)}")
        else:
            lines.append(f"  {kind.title():9}:  {_dollars(amount)}")
    lines.append(sep)
    return lines


# ── data resolution ──────────────────────────────────────────────────────────────

def _load_tenders(session_id: str, txn_id: str) -> List[Dict[str, Any]]:
    """Query all TENDER#{txn_id}* legs for a txn (best-effort, ordered by sk)."""
    tenders: List[Dict[str, Any]] = []
    try:
        resp = T.pos.query(
            KeyConditionExpression="pos_pk = :pk AND begins_with(pos_sk, :prefix)",
            ExpressionAttributeValues={
                ":pk": f"SESSION#{session_id}",
                ":prefix": f"TENDER#{txn_id}",
            },
        )
        tenders = list(resp.get("Items", []))
        while resp.get("LastEvaluatedKey"):
            resp = T.pos.query(
                KeyConditionExpression="pos_pk = :pk AND begins_with(pos_sk, :prefix)",
                ExpressionAttributeValues={
                    ":pk": f"SESSION#{session_id}",
                    ":prefix": f"TENDER#{txn_id}",
                },
                ExclusiveStartKey=resp["LastEvaluatedKey"],
            )
            tenders.extend(resp.get("Items", []))
    except Exception:
        pass
    tenders.sort(key=lambda t: str(t.get("pos_sk", "")))
    return tenders


def _build_payload(txn_item: Dict[str, Any]) -> PosReceiptPayload:
    txn_id = txn_item.get("txn_id", "")
    session_id = txn_item.get("session_id", "")
    cashier_sub = txn_item.get("cashier_sub", "")
    cart_id = txn_item.get("cart_id", "")

    # Session row (best-effort).
    register_id = ""
    try:
        sess = T.pos.get_item(Key=_session_pk(session_id)).get("Item") or {}
        register_id = sess.get("register_id", "")
    except Exception:
        pass

    # Register row (best-effort).
    register_label = ""
    currency = "USD"
    if register_id:
        try:
            reg = T.pos.get_item(Key=_register_pk(register_id)).get("Item") or {}
            register_label = reg.get("label", "")
            currency = reg.get("default_currency", "USD")
        except Exception:
            pass

    # Line items from the bound cart (best-effort; PURCHASED carts are readable).
    line_items: List[Dict[str, Any]] = []
    if cart_id:
        try:
            from app.services.shoppingcart import list_items as list_cart_items  # local import
            line_items = list_cart_items(cashier_sub, cart_id) or []
        except Exception:
            line_items = []

    # Cashier display name (best-effort; get_profile never raises).
    cashier_name = cashier_sub[:8] if cashier_sub else "Unknown"
    try:
        from app.services.profile import get_profile  # local import
        profile = get_profile(cashier_sub) or {}
        cashier_name = profile.get("display_name") or (cashier_sub[:8] if cashier_sub else "Unknown")
    except Exception:
        pass

    tenders = _load_tenders(session_id, txn_id)

    return PosReceiptPayload(
        txn_id=txn_id,
        session_id=session_id,
        register_id=register_id,
        register_label=register_label,
        store_name=getattr(S, "pos_receipt_store_name", "") or "",
        cashier_sub=cashier_sub,
        cashier_name=cashier_name,
        settled_at=_to_int(txn_item.get("updated_at")) or now_ts(),
        currency=currency,
        subtotal_cents=_to_int(txn_item.get("subtotal_cents")),
        discount_cents=_to_int(txn_item.get("discount_cents")),
        tax_cents=_to_int(txn_item.get("tax_cents")),
        total_cents=_to_int(txn_item.get("total_cents")),
        line_items=line_items,
        tenders=tenders,
    )


def _render_bytes(txn_item: Dict[str, Any]) -> bytes:
    payload = _build_payload(txn_item)
    return _render_pdf(_render_pos_receipt_lines(payload))


def _store_and_record(txn_item: Dict[str, Any], pdf: bytes) -> Dict[str, Any]:
    """Persist the PDF (dev: base64 on row; prod: filemanager) + write receipt
    metadata to the TXN row with first-writer-wins idempotency.

    Returns the metadata dict {txn_id, receipt_id, receipt_path, receipt_url,
    generated_at}.
    """
    txn_id = txn_item.get("txn_id", "")
    cashier_sub = txn_item.get("cashier_sub", "")
    receipt_id = _pos_receipt_id(txn_id)
    generated_at = now_ts()

    receipt_path = f"/billing/receipts/{txn_id}.pdf"
    receipt_url: Optional[str] = None
    extra_set = ""
    extra_vals: Dict[str, Any] = {}

    if getattr(S, "dev_mode", False):
        # Dev: inline base64 on the TXN row.
        extra_set = ", receipt_b64 = :b64"
        extra_vals[":b64"] = base64.b64encode(pdf).decode("ascii")
    else:
        # Prod: upload via the existing billing-receipt path.
        try:
            from app.services.filemanager import upload_billing_receipt, build_download_url  # local import
            upload = upload_billing_receipt(cashier_sub, txn_id=txn_id, content=pdf)
            receipt_path = upload["path"]
            receipt_url = build_download_url(receipt_path)
        except HTTPException:
            # require_not_exists 409 on partial-failure re-entry: keep deterministic path.
            try:
                from app.services.filemanager import build_download_url  # local import
                receipt_url = build_download_url(receipt_path)
            except Exception:
                receipt_url = None
        except Exception:
            receipt_url = None

    try:
        T.pos.update_item(
            Key=_txn_pk(txn_id),
            UpdateExpression=(
                "SET receipt_id = :rid, receipt_path = :rp, receipt_generated_at = :rg" + extra_set
            ),
            ConditionExpression="attribute_not_exists(receipt_id)",
            ExpressionAttributeValues={
                ":rid": receipt_id,
                ":rp": receipt_path,
                ":rg": generated_at,
                **extra_vals,
            },
        )
    except ClientError as exc:
        code = exc.response["Error"].get("Code", "")
        if code == "ConditionalCheckFailedException":
            # Concurrent winner already wrote the receipt; return its values.
            fresh = T.pos.get_item(Key=_txn_pk(txn_id)).get("Item", txn_item)
            return _meta_from_item(fresh)
        raise

    return {
        "txn_id": txn_id,
        "receipt_id": receipt_id,
        "receipt_path": receipt_path,
        "receipt_url": receipt_url or receipt_path,
        "generated_at": generated_at,
    }


def _meta_from_item(item: Dict[str, Any]) -> Dict[str, Any]:
    txn_id = item.get("txn_id", "")
    receipt_path = item.get("receipt_path") or f"/billing/receipts/{txn_id}.pdf"
    receipt_url: Optional[str] = None
    if not getattr(S, "dev_mode", False):
        try:
            from app.services.filemanager import build_download_url  # local import
            receipt_url = build_download_url(receipt_path)
        except Exception:
            receipt_url = None
    return {
        "txn_id": txn_id,
        "receipt_id": item.get("receipt_id") or _pos_receipt_id(txn_id),
        "receipt_path": receipt_path,
        "receipt_url": receipt_url or receipt_path,
        "generated_at": _to_int(item.get("receipt_generated_at")),
    }


# ── public API ────────────────────────────────────────────────────────────────

def _load_settled_txn(txn_id: str) -> Dict[str, Any]:
    item = T.pos.get_item(Key=_txn_pk(txn_id)).get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Transaction not found")
    status = item.get("status")
    if status == "voided":
        raise HTTPException(status_code=409, detail="voided transactions have no receipt")
    if status not in ("tendered", "refunded"):
        raise HTTPException(status_code=409, detail="transaction not yet settled")
    return item


def get_or_create_pos_receipt(txn_id: str) -> Dict[str, Any]:
    """Generate (or return the existing) receipt for a settled POS transaction.

    Idempotent: a reprint returns the SAME receipt without re-rendering or a
    duplicate store.  Raises HTTPException(409) for voided / unsettled txns and
    HTTPException(404) if the txn does not exist.
    """
    item = _load_settled_txn(txn_id)
    if item.get("receipt_id"):
        return _meta_from_item(item)
    pdf = _render_bytes(item)
    return _store_and_record(item, pdf)


def get_pos_receipt_bytes(txn_id: str) -> bytes:
    """Return the raw PDF bytes for a settled POS transaction's receipt.

    Re-renders on-the-fly when the stored artifact is missing (e.g. after a dev
    ``just restart`` S3 wipe).  Caller is responsible for a binary-safe response.
    """
    item = _load_settled_txn(txn_id)

    # Dev path: bytes are stored inline.
    b64 = item.get("receipt_b64")
    if b64:
        try:
            return base64.b64decode(b64)
        except Exception:
            pass

    # Prod path: try to fetch from the file-manager / S3.
    receipt_path = item.get("receipt_path")
    if receipt_path and not getattr(S, "dev_mode", False):
        try:
            from app.services.filemanager import download_file  # local import
            result = download_file(item.get("cashier_sub", ""), receipt_path)
            body = result["object"]["Body"]
            data = body.read()
            if data:
                return data
        except Exception:
            pass

    # Fallback: (re)generate. Ensure metadata exists, then render fresh bytes.
    if not item.get("receipt_id"):
        get_or_create_pos_receipt(txn_id)
        item = T.pos.get_item(Key=_txn_pk(txn_id)).get("Item", item)
        b64 = item.get("receipt_b64")
        if b64:
            try:
                return base64.b64decode(b64)
            except Exception:
                pass
    return _render_bytes(item)
