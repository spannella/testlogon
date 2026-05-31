"""Invoice generation and management (FIN-001).

Extends the basic receipt pipeline in ``app/services/receipts.py`` into a full
invoice system: monotonic invoice numbers, an invoices DynamoDB table,
S3-stored PDFs, list/filter/history queries, admin lookup, and (mocked in dev)
email delivery.

This module deliberately reuses the lightweight text-based PDF renderer
pattern from ``receipts.py`` (``_render_pdf``) rather than introducing a new
``fpdf2`` dependency — the rendered document follows the layout in the FIN-001
spec (header, bill-to / seller blocks, line-item table, tax + total).

Money is always integer cents.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from app.core.aws_clients import s3_client
from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

VALID_TYPES = {"tip", "unlock", "subscription", "shop", "deposit"}

_s3 = s3_client()


# --------------------------------------------------------------------------
# Keys / helpers
# --------------------------------------------------------------------------

def _user_pk(user_sub: str) -> str:
    return f"USER#{user_sub}"


def _inv_sk(invoice_number: str) -> str:
    return f"INV#{invoice_number}"


def _s3_key(user_sub: str, invoice_number: str) -> str:
    return f"invoices/{user_sub}/{invoice_number}.pdf"


def _bucket() -> str:
    return S.filemgr_bucket or "filemgr"


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _clean_lek(lek: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Coerce a DynamoDB LastEvaluatedKey into JSON-serializable types.

    GSI numeric sort keys come back as ``Decimal``, which the cursor encoder
    (``json.dumps``) cannot serialize.
    """
    if not lek:
        return None
    out: Dict[str, Any] = {}
    for k, v in lek.items():
        if isinstance(v, Decimal):
            out[k] = int(v)
        else:
            out[k] = v
    return out


def _next_invoice_number() -> str:
    """Atomically increment the global counter and return ``INV-YYYY-NNNNN``."""
    year = datetime.now(timezone.utc).year
    result = T.invoices.update_item(
        Key={"pk": "COUNTER", "sk": "SEQ"},
        UpdateExpression="ADD next_seq :inc",
        ExpressionAttributeValues={":inc": 1},
        ReturnValues="UPDATED_NEW",
    )
    seq = int(result["Attributes"]["next_seq"])
    return f"INV-{year}-{seq:05d}"


# --------------------------------------------------------------------------
# PDF rendering (text-based, reuses the receipts.py pattern)
# --------------------------------------------------------------------------

def _pdf_escape(text: str) -> str:
    return str(text).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _render_pdf(lines: List[str]) -> bytes:
    content_lines = ["BT", "/F1 11 Tf", "72 740 Td"]
    for line in lines:
        content_lines.append(f"({_pdf_escape(line)}) Tj")
        content_lines.append("0 -15 Td")
    content_lines.append("ET")
    content = "\n".join(content_lines)
    content_bytes = content.encode("utf-8")

    objects: List[bytes] = []
    objects.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
    objects.append(b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n")
    objects.append(
        b"3 0 obj\n"
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\n"
        b"endobj\n"
    )
    objects.append(
        b"4 0 obj\n"
        + f"<< /Length {len(content_bytes)} >>\n".encode("utf-8")
        + b"stream\n"
        + content_bytes
        + b"\nendstream\nendobj\n"
    )
    objects.append(b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")

    offsets = [0]
    pdf = bytearray(b"%PDF-1.4\n")
    for obj in objects:
        offsets.append(len(pdf))
        pdf.extend(obj)
    xref_offset = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("utf-8"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("utf-8"))
    pdf.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("utf-8")
    )
    return bytes(pdf)


def _money(cents: int) -> str:
    return f"${cents / 100:.2f}"


def _render_invoice_lines(record: Dict[str, Any]) -> List[str]:
    created = _coerce_int(record.get("created_at"))
    date_str = datetime.fromtimestamp(created, tz=timezone.utc).strftime("%B %d, %Y") if created else ""
    amount = _coerce_int(record.get("amount_cents"))
    tax = _coerce_int(record.get("tax_cents"))
    total = _coerce_int(record.get("total_cents"))
    refunded = str(record.get("status")) == "refunded"

    lines: List[str] = ["INVOICE", "=" * 48]
    if refunded:
        lines.append("*** REFUNDED ***")
    lines.append(f"Invoice : {record.get('invoice_number', '')}")
    lines.append(f"Date    : {date_str}")
    lines.append(f"Type    : {record.get('invoice_type', '')}")
    pm = record.get("payment_method_summary") or ""
    if pm:
        lines.append(f"Payment : {pm}")
    lines.append("")
    lines.append(f"BILL TO : {record.get('buyer_name') or 'Customer'}")
    if record.get("buyer_email"):
        lines.append(f"          {record.get('buyer_email')}")
    lines.append(f"SELLER  : {record.get('seller_name') or 'Platform'}")
    lines.append("")
    lines.append("-" * 48)
    lines.append(f"{'Description':<32}{'Qty':>4}{'Amount':>12}")
    lines.append("-" * 48)
    for li in record.get("line_items") or []:
        desc = str(li.get("description") or "Item")[:30]
        qty = _coerce_int(li.get("quantity"), 1)
        li_amount = _coerce_int(li.get("amount_cents"))
        lines.append(f"{desc:<32}{qty:>4}{_money(li_amount):>12}")
    lines.append("-" * 48)
    lines.append(f"{'Subtotal':<36}{_money(amount):>12}")
    lines.append(f"{'Tax':<36}{_money(tax):>12}")
    total_display = -total if refunded else total
    lines.append(f"{'TOTAL':<36}{_money(total_display):>12}")
    lines.append("")
    lines.append("Thank you for your purchase.")
    return lines


# --------------------------------------------------------------------------
# S3 storage
# --------------------------------------------------------------------------

def _store_pdf(user_sub: str, invoice_number: str, pdf: bytes) -> str:
    key = _s3_key(user_sub, invoice_number)
    try:
        _s3.put_object(Bucket=_bucket(), Key=key, Body=pdf, ContentType="application/pdf")
    except Exception:  # pragma: no cover - best effort in dev
        logger.warning("invoice PDF upload failed for %s", invoice_number, exc_info=True)
    return key


def _fetch_pdf(s3_key: str) -> Optional[bytes]:
    try:
        resp = _s3.get_object(Bucket=_bucket(), Key=s3_key)
        return resp["Body"].read()
    except ClientError:
        return None
    except Exception:  # pragma: no cover
        return None


# --------------------------------------------------------------------------
# Item <-> dict serialization
# --------------------------------------------------------------------------

def _serialize(record: Dict[str, Any]) -> Dict[str, Any]:
    """Coerce a DynamoDB item into JSON-friendly types for InvoiceOut."""
    line_items = []
    for li in record.get("line_items") or []:
        line_items.append({
            "description": str(li.get("description") or ""),
            "quantity": _coerce_int(li.get("quantity"), 1),
            "amount_cents": _coerce_int(li.get("amount_cents")),
        })
    return {
        "invoice_id": str(record.get("invoice_id") or ""),
        "invoice_number": str(record.get("invoice_number") or ""),
        "invoice_type": str(record.get("invoice_type") or ""),
        "user_sub": str(record.get("user_sub") or ""),
        "amount_cents": _coerce_int(record.get("amount_cents")),
        "tax_cents": _coerce_int(record.get("tax_cents")),
        "total_cents": _coerce_int(record.get("total_cents")),
        "currency": str(record.get("currency") or "usd"),
        "status": str(record.get("status") or "generated"),
        "seller_id": str(record.get("seller_id") or ""),
        "seller_name": str(record.get("seller_name") or ""),
        "buyer_name": str(record.get("buyer_name") or ""),
        "buyer_email": str(record.get("buyer_email") or ""),
        "line_items": line_items,
        "payment_method_summary": str(record.get("payment_method_summary") or ""),
        "ledger_entry_id": str(record.get("ledger_entry_id") or ""),
        "created_at": _coerce_int(record.get("created_at")),
    }


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def _existing_for_ledger(user_sub: str, ledger_entry_id: str) -> Optional[Dict[str, Any]]:
    """Idempotency: return an existing invoice for a ledger entry, if any.

    Looks up the per-ledger marker row, then resolves the real invoice record.
    """
    if not ledger_entry_id:
        return None
    resp = T.invoices.get_item(Key={
        "pk": f"USER#{user_sub}#LEDGERMARK",
        "sk": f"LEDGER#{ledger_entry_id}",
    })
    marker = resp.get("Item")
    if not marker:
        return None
    inv_number = marker.get("invoice_number")
    if not inv_number:
        return None
    return _get_raw(user_sub, inv_number)


def create_invoice(
    *,
    user_sub: str,
    invoice_type: str,
    amount_cents: int,
    line_items: List[Dict[str, Any]],
    ledger_entry_id: str = "",
    tax_cents: Optional[int] = None,
    seller_id: str = "",
    seller_name: str = "",
    buyer_name: str = "",
    buyer_email: str = "",
    payment_method_summary: str = "",
    currency: str = "usd",
) -> Optional[Dict[str, Any]]:
    """Create an invoice record, render its PDF, and store it in S3.

    Idempotent on ``ledger_entry_id`` — a duplicate ledger entry returns the
    existing invoice. Returns ``None`` when invoices are disabled, the amount
    is non-positive, or the type is unknown.
    """
    if not S.invoices_enabled:
        return None
    amount_cents = _coerce_int(amount_cents)
    if amount_cents <= 0:
        return None
    if invoice_type not in VALID_TYPES:
        return None

    existing = _existing_for_ledger(user_sub, ledger_entry_id)
    if existing is not None:
        return _serialize(existing)

    if tax_cents is None:
        tax_cents = (amount_cents * max(0, S.invoices_tax_bps)) // 10_000
    tax_cents = _coerce_int(tax_cents)
    total_cents = amount_cents + tax_cents

    invoice_number = _next_invoice_number()
    invoice_id = "inv_" + uuid.uuid4().hex
    created_at = now_ts()

    norm_items: List[Dict[str, Any]] = []
    for li in line_items or []:
        norm_items.append({
            "description": str(li.get("description") or "Item"),
            "quantity": _coerce_int(li.get("quantity"), 1),
            "amount_cents": _coerce_int(li.get("amount_cents")),
        })
    if not norm_items:
        norm_items = [{"description": invoice_type.title(), "quantity": 1, "amount_cents": amount_cents}]

    record: Dict[str, Any] = {
        "pk": _user_pk(user_sub),
        "sk": _inv_sk(invoice_number),
        "invoice_id": invoice_id,
        "invoice_number": invoice_number,
        "user_sub": user_sub,
        "invoice_type": invoice_type,
        "amount_cents": amount_cents,
        "tax_cents": tax_cents,
        "total_cents": total_cents,
        "currency": currency,
        "status": "generated",
        "ledger_entry_id": ledger_entry_id,
        "seller_id": seller_id,
        "seller_name": seller_name,
        "buyer_name": buyer_name,
        "buyer_email": buyer_email,
        "line_items": norm_items,
        "payment_method_summary": payment_method_summary,
        "created_at": created_at,
        "GSI1PK": f"USER#{user_sub}#TYPE#{invoice_type}",
        "GSI1SK": created_at,
        "GSI2PK": "ADMIN_ALL",
        "GSI2SK": created_at,
    }
    pdf = _render_pdf(_render_invoice_lines(record))
    record["s3_key"] = _store_pdf(user_sub, invoice_number, pdf)

    T.invoices.put_item(Item=record)
    if ledger_entry_id:
        # Per-ledger marker row enables O(1) idempotency lookups without a GSI.
        try:
            T.invoices.put_item(Item={
                "pk": f"USER#{user_sub}#LEDGERMARK",
                "sk": f"LEDGER#{ledger_entry_id}",
                "invoice_number": invoice_number,
                "invoice_id": invoice_id,
                "created_at": created_at,
            }, ConditionExpression="attribute_not_exists(pk)")
        except ClientError:
            pass

    logger.info(
        "invoice created number=%s user=%s type=%s total=%s",
        invoice_number, user_sub, invoice_type, total_cents,
    )
    return _serialize(record)


def create_invoice_safe(**kwargs: Any) -> Optional[Dict[str, Any]]:
    """Best-effort wrapper for use inside billing hooks — never raises."""
    try:
        return create_invoice(**kwargs)
    except Exception:  # pragma: no cover - hook must not break the primary flow
        logger.warning("invoice hook failed", exc_info=True)
        return None


def get_invoice(user_sub: str, invoice_number: str) -> Optional[Dict[str, Any]]:
    resp = T.invoices.get_item(Key={"pk": _user_pk(user_sub), "sk": _inv_sk(invoice_number)})
    item = resp.get("Item")
    if not item:
        return None
    return _serialize(item)


def _get_raw(user_sub: str, invoice_number: str) -> Optional[Dict[str, Any]]:
    resp = T.invoices.get_item(Key={"pk": _user_pk(user_sub), "sk": _inv_sk(invoice_number)})
    return resp.get("Item")


def list_invoices(
    *,
    user_sub: str,
    invoice_type: Optional[str] = None,
    date_from: Optional[int] = None,
    date_to: Optional[int] = None,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    limit = max(1, min(int(limit or 50), 200))
    query: Dict[str, Any] = {
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if invoice_type and invoice_type in VALID_TYPES:
        query["IndexName"] = "GSI1"
        query["KeyConditionExpression"] = "GSI1PK = :pk"
        query["ExpressionAttributeValues"] = {":pk": f"USER#{user_sub}#TYPE#{invoice_type}"}
    else:
        query["KeyConditionExpression"] = "pk = :pk AND begins_with(sk, :sk)"
        query["ExpressionAttributeValues"] = {":pk": _user_pk(user_sub), ":sk": "INV#"}

    start_key = decode_cursor(cursor)
    if start_key:
        query["ExclusiveStartKey"] = start_key

    resp = T.invoices.query(**query)
    items = resp.get("Items", [])

    out: List[Dict[str, Any]] = []
    for it in items:
        created = _coerce_int(it.get("created_at"))
        if date_from is not None and created < int(date_from):
            continue
        if date_to is not None and created > int(date_to):
            continue
        out.append(_serialize(it))

    # When not using GSI1 (no type filter) results are sorted by sk (invoice
    # number) — sort by created_at descending for a stable, intuitive order.
    if "IndexName" not in query:
        out.sort(key=lambda r: r["created_at"], reverse=True)

    next_cursor = encode_cursor(_clean_lek(resp.get("LastEvaluatedKey")))
    return {"invoices": out, "next_cursor": next_cursor}


def download_invoice_pdf(user_sub: str, invoice_number: str) -> Optional[bytes]:
    raw = _get_raw(user_sub, invoice_number)
    if not raw:
        return None
    s3_key = raw.get("s3_key")
    pdf = _fetch_pdf(s3_key) if s3_key else None
    if pdf is None:
        # Regenerate from the stored record (S3 cache miss).
        pdf = _render_pdf(_render_invoice_lines(raw))
        _store_pdf(user_sub, invoice_number, pdf)
    return pdf


def email_invoice(user_sub: str, invoice_number: str) -> Dict[str, Any]:
    raw = _get_raw(user_sub, invoice_number)
    if not raw:
        return {"ok": False, "emailed_to": "", "message": "not_found"}

    to_email = raw.get("buyer_email") or ""
    if not to_email:
        try:
            from app.services.profile import get_profile_identity
            ident = get_profile_identity(user_sub)
            to_email = ident.get("email") or user_sub
        except Exception:
            to_email = user_sub

    try:
        from app.services.alerts import send_alert_email
        subject = f"Your invoice {invoice_number}"
        body = "\n".join(_render_invoice_lines(raw))
        send_alert_email([to_email], subject, body)
    except Exception:  # pragma: no cover
        logger.warning("invoice email failed for %s", invoice_number, exc_info=True)

    # Mark emailed (idempotent — repeat calls simply re-set the status).
    try:
        T.invoices.update_item(
            Key={"pk": _user_pk(user_sub), "sk": _inv_sk(invoice_number)},
            UpdateExpression="SET #s = :s, emailed_at = :t",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": "emailed", ":t": now_ts()},
        )
    except Exception:  # pragma: no cover
        pass

    logger.info("invoice emailed number=%s user=%s to=%s", invoice_number, user_sub, to_email)
    return {"ok": True, "emailed_to": to_email, "message": "sent"}


def admin_list_invoices(
    *,
    target_user_sub: Optional[str] = None,
    invoice_type: Optional[str] = None,
    limit: int = 100,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    if target_user_sub:
        return list_invoices(
            user_sub=target_user_sub,
            invoice_type=invoice_type,
            limit=limit,
            cursor=cursor,
        )

    limit = max(1, min(int(limit or 100), 200))
    query: Dict[str, Any] = {
        "IndexName": "GSI2",
        "KeyConditionExpression": "GSI2PK = :pk",
        "ExpressionAttributeValues": {":pk": "ADMIN_ALL"},
        "ScanIndexForward": False,
        "Limit": limit,
    }
    start_key = decode_cursor(cursor)
    if start_key:
        query["ExclusiveStartKey"] = start_key
    resp = T.invoices.query(**query)
    out = [_serialize(it) for it in resp.get("Items", [])]
    if invoice_type and invoice_type in VALID_TYPES:
        out = [r for r in out if r["invoice_type"] == invoice_type]
    return {"invoices": out, "next_cursor": encode_cursor(_clean_lek(resp.get("LastEvaluatedKey")))}
