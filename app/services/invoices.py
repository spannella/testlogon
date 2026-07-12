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

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.aws_clients import s3_client
from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

VALID_TYPES = {"tip", "unlock", "subscription", "shop", "deposit", "b2b"}

# QUO-005: standalone invoice lifecycle.
STANDALONE_STATUSES = {"draft", "sent", "paid", "overdue", "void"}

_ALLOWED_TRANSITIONS: Dict[str, set] = {
    "draft": {"sent", "void"},
    "sent": {"paid", "overdue", "void"},
    "overdue": {"paid", "void"},
    "paid": set(),          # user cannot transition; admin can void (handled inline)
    "void": set(),          # terminal
    "generated": {"void"},  # legacy auto-generated invoices may be voided
    "emailed": {"void"},
}

# Origin statuses an admin may settle via the D5 record-payment path.
_MANUAL_PAYMENT_ORIGINS = {"draft", "sent", "overdue", "generated", "emailed"}

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


def _norm_address(addr: Optional[Dict[str, Any]]) -> Dict[str, str]:
    """INV-001: coerce an address dict to the five-field shape."""
    a = addr or {}
    return {
        "street": str(a.get("street", "")),
        "city": str(a.get("city", "")),
        "state": str(a.get("state", "")),
        "postal_code": str(a.get("postal_code", "")),
        "country": str(a.get("country", "")),
    }


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


def _money(cents: int, symbol: str = "$") -> str:
    return f"{symbol}{cents / 100:.2f}"


def _currency_symbol(record: Dict[str, Any]) -> str:
    """INV-004: resolve the display symbol for the invoice's original currency.

    Fail-open: when the multicurrency-display flag is off, the currency is USD,
    or the registry lookup fails, returns ``"$"`` (today's behaviour). Uses an
    ASCII-safe fallback (the upper-cased ISO code + space) for non-ASCII
    symbols so the text-PDF renderer never emits bytes it can't escape.
    """
    if not S.aos_invoice_multicurrency_display_enabled:
        return "$"
    iso = str(record.get("original_currency") or record.get("currency") or "usd").lower().strip()
    if not iso or iso == "usd":
        return "$"
    try:
        from app.services.crm_currencies import get_currency
        cur = get_currency(iso)
        if cur and cur.get("symbol"):
            sym = str(cur["symbol"])
            if sym.isascii():
                return sym
    except Exception:
        pass
    return f"{iso.upper()} "


def _render_invoice_lines(record: Dict[str, Any]) -> List[str]:
    created = _coerce_int(record.get("created_at"))
    date_str = datetime.fromtimestamp(created, tz=timezone.utc).strftime("%B %d, %Y") if created else ""
    amount = _coerce_int(record.get("amount_cents"))
    tax = _coerce_int(record.get("tax_cents"))
    total = _coerce_int(record.get("total_cents"))
    refunded = str(record.get("status")) == "refunded"
    sym = _currency_symbol(record)
    fields_active = bool(S.aos_invoice_fields_enabled)
    line_list = record.get("line_items") or []
    has_per_line_tax = any(_coerce_int(li.get("tax_rate_bps")) for li in line_list)

    status = str(record.get("status") or "")
    lines: List[str] = ["INVOICE", "=" * 48]
    if refunded:
        lines.append("*** REFUNDED ***")
    if status == "void":
        lines.append("*** VOIDED ***")
    if status == "overdue":
        lines.append("*** OVERDUE ***")
    lines.append(f"Invoice : {record.get('invoice_number', '')}")
    lines.append(f"Date    : {date_str}")
    lines.append(f"Type    : {record.get('invoice_type', '')}")
    if record.get("payment_terms_days"):
        lines.append(f"Terms   : Net {int(record['payment_terms_days'])}")
    if record.get("due_date"):
        due_str = datetime.fromtimestamp(
            _coerce_int(record["due_date"]), tz=timezone.utc
        ).strftime("%B %d, %Y")
        lines.append(f"Due     : {due_str}")
    pm = record.get("payment_method_summary") or ""
    if pm:
        lines.append(f"Payment : {pm}")
    lines.append("")
    lines.append(f"BILL TO : {record.get('buyer_name') or 'Customer'}")
    if record.get("buyer_email"):
        lines.append(f"          {record.get('buyer_email')}")
    lines.append(f"SELLER  : {record.get('seller_name') or 'Platform'}")
    if fields_active:
        ba = record.get("billing_address") or {}
        if ba:
            lines.append("BILLING ADDRESS:")
            lines.append(f"  {ba.get('street','')}")
            lines.append(f"  {ba.get('city','')}, {ba.get('state','')} {ba.get('postal_code','')}")
            lines.append(f"  {ba.get('country','')}")
        sa = record.get("shipping_address") or {}
        if sa and sa != ba:
            lines.append("SHIPPING ADDRESS:")
            lines.append(f"  {sa.get('street','')}")
            lines.append(f"  {sa.get('city','')}, {sa.get('state','')} {sa.get('postal_code','')}")
            lines.append(f"  {sa.get('country','')}")
    lines.append("")
    lines.append("-" * 48)
    if has_per_line_tax:
        lines.append(f"{'Description':<23}{'Qty':>4}{'Tax Rate':>9}{'Amount':>12}")
    else:
        lines.append(f"{'Description':<32}{'Qty':>4}{'Amount':>12}")
    lines.append("-" * 48)
    for li in line_list:
        qty = _coerce_int(li.get("quantity"), 1)
        li_amount = _coerce_int(li.get("amount_cents"))
        if has_per_line_tax:
            desc = str(li.get("description") or "Item")[:21]
            rate_str = f"{_coerce_int(li.get('tax_rate_bps')) / 100:.1f}%"
            lines.append(f"{desc:<23}{qty:>4}{rate_str:>9}{_money(li_amount, sym):>12}")
        else:
            desc = str(li.get("description") or "Item")[:30]
            lines.append(f"{desc:<32}{qty:>4}{_money(li_amount, sym):>12}")
    lines.append("-" * 48)
    lines.append(f"{'Subtotal':<36}{_money(amount, sym):>12}")
    if fields_active:
        discount = _coerce_int(record.get("discount_cents"))
        shipping = _coerce_int(record.get("shipping_cents"))
        if discount > 0:
            lines.append(f"{'Discount':<36}{'-' + _money(discount, sym):>12}")
        if shipping > 0:
            lines.append(f"{'Shipping':<36}{_money(shipping, sym):>12}")
    lines.append(f"{'Tax':<36}{_money(tax, sym):>12}")
    for b in record.get("tax_breakdown") or []:
        b_name = str(b.get("name") or "Tax")
        b_rate = _coerce_int(b.get("rate_bps")) / 100
        b_tax = _coerce_int(b.get("tax_cents"))
        label = f"  {b_name} ({b_rate:.1f}%)"[:36]
        lines.append(f"{label:<36}{_money(b_tax, sym):>12}")
    total_display = -total if refunded else total
    lines.append(f"{'TOTAL':<36}{_money(total_display, sym):>12}")
    # INV-004: USD-equivalent footer for non-USD invoices.
    if S.aos_invoice_multicurrency_display_enabled:
        orig = str(record.get("original_currency") or "").lower().strip()
        snapshot = record.get("exchange_rate_snapshot")
        usd_amt = _coerce_int(record.get("usd_amount_cents"))
        if orig and orig != "usd" and snapshot is not None:
            lines.append("")
            lines.append(f"USD equivalent : {_money(usd_amt)}")
            lines.append(f"Exchange rate  : 1 {orig.upper()} = {float(snapshot):.6f} USD")
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
            "unit_price_cents": _coerce_int(li.get("unit_price_cents")),
            "tax_rate_bps": _coerce_int(li.get("tax_rate_bps")),
            "tax_cents": _coerce_int(li.get("tax_cents")),
        })
    due_date = record.get("due_date")
    voided_at = record.get("voided_at")
    payment_terms = record.get("payment_terms_days")
    snapshot = record.get("exchange_rate_snapshot")
    tax_breakdown = [
        {
            "name": str(b.get("name") or ""),
            "rate_bps": _coerce_int(b.get("rate_bps")),
            "tax_cents": _coerce_int(b.get("tax_cents")),
        }
        for b in (record.get("tax_breakdown") or [])
    ]
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
        "aos_quote_id": str(record.get("aos_quote_id") or ""),
        "payment_terms_days": _coerce_int(payment_terms) if payment_terms is not None else None,
        "due_date": _coerce_int(due_date) if due_date is not None else None,
        "voided_at": _coerce_int(voided_at) if voided_at is not None else None,
        # INV-001
        "discount_cents": _coerce_int(record.get("discount_cents")),
        "shipping_cents": _coerce_int(record.get("shipping_cents")),
        "billing_address": record.get("billing_address") or None,
        "shipping_address": record.get("shipping_address") or None,
        # INV-003
        "original_currency": str(record.get("original_currency") or ""),
        "original_amount_cents": _coerce_int(record.get("original_amount_cents")),
        "usd_amount_cents": _coerce_int(record.get("usd_amount_cents")),
        "exchange_rate_snapshot": (float(snapshot) if snapshot is not None else None),
        # INV-006
        "tax_breakdown": tax_breakdown,
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
    aos_quote_id: str = "",
    # INV-001: extended AOS invoice fields (no-op when flag off).
    unit_price_cents_per_item: Optional[List[int]] = None,
    discount_cents: int = 0,
    shipping_cents: int = 0,
    billing_address: Optional[Dict[str, Any]] = None,
    shipping_address: Optional[Dict[str, Any]] = None,
    # INV-006: per-line tax (no-op when flag off).
    per_line_tax: bool = False,
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

    invoice_number = _next_invoice_number()
    invoice_id = "inv_" + uuid.uuid4().hex
    created_at = now_ts()

    # --- INV-006: line-item normalisation + per-line tax computation ---------
    per_line_tax_active = bool(S.aos_per_line_tax_enabled and per_line_tax)
    fields_active = bool(S.aos_invoice_fields_enabled)
    total_line_tax = 0
    tax_accumulator: Dict[int, Dict[str, Any]] = {}

    norm_items: List[Dict[str, Any]] = []
    for idx, li in enumerate(line_items or []):
        norm_item: Dict[str, Any] = {
            "description": str(li.get("description") or "Item"),
            "quantity": _coerce_int(li.get("quantity"), 1),
            "amount_cents": _coerce_int(li.get("amount_cents")),
        }
        line_amount = norm_item["amount_cents"]

        if fields_active and unit_price_cents_per_item:
            upc = unit_price_cents_per_item[idx] if idx < len(unit_price_cents_per_item) else 0
            norm_item["unit_price_cents"] = max(0, _coerce_int(upc))

        raw_bps = 0
        tax_name = ""
        if per_line_tax_active:
            raw_bps = _coerce_int(li.get("tax_rate_bps"))
            tax_rate_id = str(li.get("tax_rate_id") or "")
            if not raw_bps and tax_rate_id and S.crm_tax_rates_enabled:
                try:
                    from app.services.crm_tax_rates import get_tax_rate
                    tr = get_tax_rate(tax_rate_id)
                    if tr and tr.get("is_active"):
                        raw_bps = _coerce_int(tr.get("rate_bps"))
                        tax_name = str(tr.get("name") or "")
                except Exception:
                    pass  # fail-open: treat as 0% if lookup errors
            raw_bps = min(max(0, raw_bps), 10_000)
            if not tax_name and raw_bps:
                tax_name = f"{raw_bps / 100:.2f}% Tax"
            line_tax = (line_amount * raw_bps) // 10_000
            norm_item["tax_rate_bps"] = raw_bps
            norm_item["tax_cents"] = line_tax
            if raw_bps:
                total_line_tax += line_tax
                bucket = tax_accumulator.setdefault(
                    raw_bps, {"name": tax_name, "rate_bps": raw_bps, "tax_cents": 0}
                )
                bucket["tax_cents"] += line_tax

        norm_items.append(norm_item)
    if not norm_items:
        norm_items = [{"description": invoice_type.title(), "quantity": 1, "amount_cents": amount_cents}]

    # --- tax total resolution -----------------------------------------------
    if per_line_tax_active and total_line_tax > 0:
        if tax_cents is None:
            tax_cents = total_line_tax
    else:
        if tax_cents is None:
            tax_cents = (amount_cents * max(0, S.invoices_tax_bps)) // 10_000
    tax_cents = _coerce_int(tax_cents)

    # --- INV-001: discount / shipping / total -------------------------------
    if fields_active:
        discount_cents = max(0, _coerce_int(discount_cents))
        shipping_cents = max(0, _coerce_int(shipping_cents))
        if discount_cents > amount_cents:
            logger.warning(
                "discount_cents %s capped at subtotal %s for user=%s",
                discount_cents, amount_cents, user_sub,
            )
            discount_cents = amount_cents
        total_cents = amount_cents + tax_cents + shipping_cents - discount_cents
    else:
        discount_cents = 0
        shipping_cents = 0
        total_cents = amount_cents + tax_cents

    # --- INV-003: snapshot USD equivalent at transaction time ----------------
    _original_currency = (currency or "usd").lower().strip()
    _original_amount = amount_cents
    _usd_amount = amount_cents
    _rate_snapshot = None
    if (
        S.crm_currencies_enabled
        and S.aos_invoice_currency_conversion_enabled
        and _original_currency != "usd"
    ):
        try:
            from app.services.crm_currencies import convert_amount as _cvt
            from app.services.crm_currencies import get_exchange_rate as _rate
            _rate_snapshot = _rate(_original_currency, "usd")
            _usd_amount = _cvt(amount_cents, _original_currency, "usd")
        except Exception:
            logger.warning(
                "currency conversion failed for %s invoice type=%s currency=%s",
                user_sub, invoice_type, _original_currency, exc_info=True,
            )
            _rate_snapshot = None
            _usd_amount = amount_cents

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
        "aos_quote_id": aos_quote_id,
        "created_at": created_at,
        "GSI1PK": f"USER#{user_sub}#TYPE#{invoice_type}",
        "GSI1SK": created_at,
        "GSI2PK": "ADMIN_ALL",
        "GSI2SK": created_at,
    }
    if fields_active:
        record["discount_cents"] = discount_cents
        record["shipping_cents"] = shipping_cents
        if billing_address:
            record["billing_address"] = _norm_address(billing_address)
        if shipping_address:
            record["shipping_address"] = _norm_address(shipping_address)
    if tax_accumulator:
        record["tax_breakdown"] = list(tax_accumulator.values())
    # INV-003 snapshot fields (always written so _serialize/InvoiceOut stay
    # consistent across flag states).
    record["original_currency"] = _original_currency
    record["original_amount_cents"] = _original_amount
    record["usd_amount_cents"] = _usd_amount
    if _rate_snapshot is not None:
        record["exchange_rate_snapshot"] = _rate_snapshot
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


# --------------------------------------------------------------------------
# QUO-005: standalone invoice lifecycle (draft/sent/paid/overdue/void),
# manual B2B creation, admin offline-payment recording (D5), overdue checker.
# Money reconciliations: D1 (signed_amount_cents), D5 (record-payment).
# --------------------------------------------------------------------------

def _require_standalone_enabled() -> None:
    if not S.aos_standalone_invoices_enabled:
        raise HTTPException(404, "Standalone invoices not enabled")


def update_invoice_status(
    user_sub: str,
    invoice_number: str,
    new_status: str,
    *,
    admin: bool = False,
    payment_ref: str = "",
    request: Any = None,
) -> Dict[str, Any]:
    """Transition an invoice through the standalone lifecycle, enforcing the
    allowed-transition graph and performing the canonical money side effects:

    * ``sent``/``overdue`` -> ``paid`` (owner): positive ``b2b_invoice_payment``
      ledger credit + ``apply_balance_delta(+total)`` (D1).
    * ``paid`` -> ``void`` (admin only): canonical refund/void combo — positive
      ``adjustment`` (``signed_amount_cents=-total``, D1) +
      ``apply_balance_delta(-total)`` + ``settle_or_reverse_ledger(original)``.
      Never writes a negative ``amount_cents`` (audit A4).
    """
    from app.services import billing_shared
    from app.services.alerts import audit_event

    item = _get_raw(user_sub, invoice_number)
    if not item:
        raise HTTPException(404, "Invoice not found")
    old_status = str(item.get("status") or "generated")

    if new_status not in _ALLOWED_TRANSITIONS.get(old_status, set()):
        # paid->void only allowed for admins; surface a clearer 409 in that case.
        if new_status == "void" and old_status == "paid":
            pass  # handled below (admin gate)
        else:
            raise HTTPException(
                409,
                {"code": "invalid_transition", "from": old_status, "to": new_status},
            )
    if new_status == "void" and old_status == "paid" and not admin:
        raise HTTPException(409, "paid invoices may only be voided by an admin")

    total_cents = _coerce_int(item.get("total_cents"))
    currency = str(item.get("currency") or "usd")
    pk = item["pk"]
    ts = now_ts()

    set_parts = ["#s = :s", "updated_at = :t"]
    expr_names = {"#s": "status"}
    expr_values: Dict[str, Any] = {":s": new_status, ":t": ts}
    remove_parts: List[str] = []

    # --- sent/overdue -> paid: positive inbound payment credit (D1) ---
    if new_status == "paid":
        led_sk, led_item = billing_shared.new_ledger_entry(
            key_name="pk",
            key_value=pk,
            entry_type="b2b_invoice_payment",
            amount_cents=total_cents,
            signed_amount_cents=+total_cents,  # D1: inbound payment = credit
            state="settled",
            reason=f"manual payment for {invoice_number}",
            meta={"invoice_number": invoice_number},
            extra={"payment_ref": payment_ref, "currency": currency},
        )
        billing_shared.ddb_put(T.billing, led_item)
        billing_shared.apply_balance_delta(
            T.billing, pk, {"payments_settled_cents": +total_cents}, currency=currency,
        )
        set_parts.append("paid_at = :pa")
        expr_values[":pa"] = ts
        remove_parts.extend(["GSI3PK", "GSI3SK"])

    # --- paid -> void: canonical refund/void combo (D1, A4) ---
    elif new_status == "void":
        if old_status == "paid" and not item.get("void_reversal_ledger_sk"):
            led_sk, led_item = billing_shared.new_ledger_entry(
                key_name="pk",
                key_value=pk,
                entry_type="adjustment",
                amount_cents=total_cents,           # positive unsigned (A4)
                signed_amount_cents=-total_cents,   # D1: void reversal = debit direction
                state="settled",
                reason="void",
                meta={"invoice_number": invoice_number},
                extra={"provider": str(item.get("provider") or ""), "currency": currency},
            )
            billing_shared.ddb_put(T.billing, led_item)
            billing_shared.apply_balance_delta(
                T.billing, pk, {"payments_settled_cents": -total_cents}, currency=currency,
            )
            original_sk = item.get("ledger_entry_id")
            if original_sk:
                try:
                    billing_shared.settle_or_reverse_ledger(
                        T.billing, "pk", pk, original_sk, "reversed",
                    )
                except Exception:  # pragma: no cover
                    logger.warning("void: original ledger reverse failed", exc_info=True)
            set_parts.append("void_reversal_ledger_sk = :vsk")
            expr_values[":vsk"] = led_sk
        set_parts.append("voided_at = :va")
        expr_values[":va"] = ts
        remove_parts.extend(["GSI3PK", "GSI3SK"])

    # --- draft/generated/emailed -> sent: enroll in overdue scanner ---
    elif new_status == "sent":
        due_date = item.get("due_date")
        if due_date is not None and S.aos_standalone_invoices_enabled:
            set_parts.append("GSI3PK = :g3pk")
            set_parts.append("GSI3SK = :g3sk")
            expr_values[":g3pk"] = "STATUS#sent"
            expr_values[":g3sk"] = _coerce_int(due_date)

    elif new_status == "overdue":
        remove_parts.extend(["GSI3PK", "GSI3SK"])

    update_expr = "SET " + ", ".join(set_parts)
    # only REMOVE attributes that actually exist (DDB ignores missing, but keep clean)
    actual_removes = [r for r in remove_parts if r in item]
    if actual_removes:
        update_expr += " REMOVE " + ", ".join(actual_removes)

    T.invoices.update_item(
        Key={"pk": pk, "sk": _inv_sk(invoice_number)},
        UpdateExpression=update_expr,
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_values,
    )
    audit_event(
        "invoice.status_changed", user_sub, request,
        invoice_number=invoice_number, old_status=old_status, new_status=new_status,
    )
    updated = _get_raw(user_sub, invoice_number)
    return _serialize(updated or item)


def create_manual_invoice(
    *,
    admin_user_sub: str,
    buyer_user_sub: str = "",
    buyer_name: str,
    buyer_email: str,
    billing_address: Optional[Dict[str, Any]] = None,
    line_items: List[Dict[str, Any]],
    currency: str = "usd",
    payment_terms_days: int = 30,
    notes: str = "",
) -> Dict[str, Any]:
    from app.services.alerts import audit_event

    payment_terms_days = _coerce_int(payment_terms_days, 30)
    if not (1 <= payment_terms_days <= 365):
        raise HTTPException(422, "payment_terms_days must be in [1, 365]")
    if not line_items:
        raise HTTPException(422, "at least one line item is required")

    norm_items: List[Dict[str, Any]] = []
    amount_cents = 0
    for li in line_items:
        qty = _coerce_int(li.get("quantity"), 1)
        unit = _coerce_int(li.get("unit_price_cents"))
        li_total = unit * qty
        amount_cents += li_total
        norm_items.append({
            "description": str(li.get("description") or "Item"),
            "quantity": qty,
            "unit_price_cents": unit,
            "amount_cents": li_total,
            "tax_rate_bps": _coerce_int(li.get("tax_rate_bps")),
        })
    tax_cents = (amount_cents * max(0, S.invoices_tax_bps)) // 10_000
    total_cents = amount_cents + tax_cents

    invoice_number = _next_invoice_number()
    invoice_id = "inv_" + uuid.uuid4().hex
    created_at = now_ts()
    owner_sub = buyer_user_sub if buyer_user_sub else admin_user_sub
    due_date = created_at + payment_terms_days * 86400

    record: Dict[str, Any] = {
        "pk": _user_pk(owner_sub),
        "sk": _inv_sk(invoice_number),
        "invoice_id": invoice_id,
        "invoice_number": invoice_number,
        "user_sub": owner_sub,
        "invoice_type": "b2b",
        "amount_cents": amount_cents,
        "tax_cents": tax_cents,
        "total_cents": total_cents,
        "currency": (currency or "usd").lower(),
        "status": "draft",
        "ledger_entry_id": "",
        "buyer_name": buyer_name,
        "buyer_email": buyer_email,
        "billing_address": dict(billing_address or {}),
        "line_items": norm_items,
        "payment_method_summary": "",
        "payment_terms_days": payment_terms_days,
        "due_date": due_date,
        "notes": notes or "",
        "created_by_admin": admin_user_sub,
        "created_at": created_at,
        "GSI1PK": f"USER#{owner_sub}#TYPE#b2b",
        "GSI1SK": created_at,
        "GSI2PK": "ADMIN_ALL",
        "GSI2SK": created_at,
    }
    pdf = _render_pdf(_render_invoice_lines(record))
    record["s3_key"] = _store_pdf(owner_sub, invoice_number, pdf)
    T.invoices.put_item(Item=record)
    audit_event(
        "invoice.manual_created", admin_user_sub,
        invoice_number=invoice_number, buyer_email=buyer_email,
    )
    return _serialize(record)


def record_external_payment(
    *,
    admin_user_sub: str,
    owner_user_sub: str,
    invoice_number: str,
    amount_cents: int,
    reference: str = "",
    reason: str = "",
    request: Any = None,
) -> Dict[str, Any]:
    """D5: admin records an OFFLINE/external payment (bank transfer, cheque,
    cash, wire). No provider/Stripe SDK call — money is recorded as already
    received out-of-band. Idempotent + money-safe."""
    from app.services import billing_shared
    from app.services.alerts import audit_event

    amount_cents = _coerce_int(amount_cents)
    if amount_cents < 1:
        raise HTTPException(422, "amount_cents must be >= 1")

    item = _get_raw(owner_user_sub, invoice_number)
    if not item:
        raise HTTPException(404, "Invoice not found")
    old_status = str(item.get("status") or "generated")
    total_cents = _coerce_int(item.get("total_cents"))

    # idempotency / money safety
    if old_status == "paid" or item.get("external_payment_ledger_sk"):
        raise HTTPException(409, {"code": "already_paid", "invoice_number": invoice_number})
    if old_status == "void":
        raise HTTPException(409, {"code": "invalid_state", "from": "void"})
    if old_status not in _MANUAL_PAYMENT_ORIGINS:
        raise HTTPException(
            409, {"code": "invalid_transition", "from": old_status, "to": "paid"},
        )

    mismatch = amount_cents != total_cents
    pk = item["pk"]
    currency = str(item.get("currency") or "usd")
    ts = now_ts()

    meta: Dict[str, Any] = {
        "invoice_number": invoice_number,
        "method": "external",
        "reference": reference,
        "recorded_by": admin_user_sub,
    }
    if mismatch:
        meta["amount_mismatch"] = True
        meta["expected_cents"] = total_cents

    led_sk, led_item = billing_shared.new_ledger_entry(
        key_name="pk",
        key_value=pk,
        entry_type="invoice_payment_external",
        amount_cents=amount_cents,            # positive, unsigned (display)
        signed_amount_cents=+amount_cents,    # D1: inbound payment = credit
        state="settled",
        reason=reason or f"external payment for {invoice_number}",
        meta=meta,
        extra={"provider": "external", "currency": currency},
    )
    billing_shared.ddb_put(T.billing, led_item)
    billing_shared.apply_balance_delta(
        T.billing, pk, {"payments_settled_cents": +amount_cents}, currency=currency,
    )

    T.invoices.update_item(
        Key={"pk": pk, "sk": _inv_sk(invoice_number)},
        UpdateExpression=(
            "SET #s = :s, paid_at = :pa, updated_at = :t, "
            "external_payment_ledger_sk = :lsk, external_payment_reference = :ref "
            "REMOVE GSI3PK, GSI3SK"
        ),
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": "paid", ":pa": ts, ":t": ts, ":lsk": led_sk, ":ref": reference,
        },
    )
    audit_event(
        "invoice.payment_recorded_external", admin_user_sub, request,
        invoice_number=invoice_number, owner_user_sub=owner_user_sub,
        amount_cents=amount_cents, reference=reference, method="external",
        amount_mismatch=mismatch, ledger_sk=led_sk,
    )
    updated = _get_raw(owner_user_sub, invoice_number)
    return _serialize(updated or item)


def check_overdue_invoices() -> int:
    """Scan GSI3 for sent invoices past their due_date and mark them overdue.
    Returns the count processed. No-op when the flag is off."""
    if not S.aos_standalone_invoices_enabled:
        return 0
    now = now_ts()
    count = 0
    lek = None
    while True:
        kwargs: Dict[str, Any] = {
            "IndexName": "GSI3",
            "KeyConditionExpression": "GSI3PK = :pk AND GSI3SK < :now",
            "ExpressionAttributeValues": {":pk": "STATUS#sent", ":now": now},
        }
        if lek:
            kwargs["ExclusiveStartKey"] = lek
        resp = T.invoices.query(**kwargs)
        for item in resp.get("Items", []):
            owner = str(item.get("user_sub") or "")
            number = str(item.get("invoice_number") or "")
            if not owner or not number:
                continue
            try:
                update_invoice_status(owner, number, "overdue")
                count += 1
            except Exception:  # pragma: no cover
                logger.warning("overdue transition failed for %s", number, exc_info=True)
                continue
            to_email = item.get("buyer_email") or ""
            if to_email:
                try:
                    from app.services.alerts import send_alert_email
                    body = "\n".join(["*** OVERDUE ***"] + _render_invoice_lines(item))
                    send_alert_email([to_email], f"Invoice {number} is now overdue", body)
                except Exception:  # pragma: no cover
                    pass
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
    return count


async def _invoice_overdue_loop() -> None:
    try:
        from app.services.job_registry import register_task
        register_task(
            "invoice_overdue_checker",
            S.aos_invoice_overdue_check_interval_seconds,
            enabled=True,
            description="Marks sent invoices past due_date as overdue",
        )
    except Exception:  # pragma: no cover
        pass
    while True:
        try:
            check_overdue_invoices()
        except Exception:  # pragma: no cover
            logger.exception("invoice_overdue_checker error")
        await asyncio.sleep(S.aos_invoice_overdue_check_interval_seconds)


def start_invoice_overdue_checker_task() -> None:
    if not S.aos_invoice_overdue_checker_enabled:
        try:
            from app.services.job_registry import register_task
            register_task(
                "invoice_overdue_checker",
                S.aos_invoice_overdue_check_interval_seconds,
                enabled=False,
                description="Marks sent invoices past due_date as overdue",
            )
        except Exception:  # pragma: no cover
            pass
        return
    asyncio.ensure_future(_invoice_overdue_loop())
