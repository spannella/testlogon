from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import ddb_query_pk, user_pk
from app.services.filemanager import build_download_url, upload_billing_receipt
from app.services.profile import get_profile
from app.services.purchase_history import get_transaction_item, set_receipt_info


@dataclass(frozen=True)
class ReceiptPayload:
    txn_id: str
    status: str
    amount: str
    currency: str
    created_at: int
    completed_at: Optional[int]
    description: Optional[str]
    external_ref: Optional[str]
    merchant_id: Optional[str]
    profile: Dict[str, Any]
    payment_record: Optional[Dict[str, Any]]


def _pdf_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _format_address(addr: Optional[Dict[str, Any]]) -> List[str]:
    if not addr:
        return []
    parts = [
        addr.get("line1"),
        addr.get("line2"),
        addr.get("city"),
        addr.get("state"),
        addr.get("postal_code"),
        addr.get("country"),
    ]
    return [str(part) for part in parts if part]


def _render_pdf(lines: List[str]) -> bytes:
    content_lines = ["BT", "/F1 12 Tf", "72 720 Td"]
    for line in lines:
        content_lines.append(f"({_pdf_escape(line)}) Tj")
        content_lines.append("0 -16 Td")
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
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode(
            "utf-8"
        )
    )
    return bytes(pdf)


def _find_payment_record(user_sub: str, txn_id: str) -> Optional[Dict[str, Any]]:
    items = ddb_query_pk(T.billing, user_pk(user_sub))
    for item in items:
        if item.get("sk", "").startswith("PAY#") and item.get("purchase_txn_id") == txn_id:
            return item
    return None


def _build_receipt_payload(txn_item: Dict[str, Any]) -> ReceiptPayload:
    user_sub = txn_item["user_sub"]
    profile = get_profile(user_sub)
    payment_record = _find_payment_record(user_sub, txn_item["txn_id"])
    return ReceiptPayload(
        txn_id=txn_item["txn_id"],
        status=txn_item.get("status", ""),
        amount=str(txn_item.get("amount", "")),
        currency=str(txn_item.get("currency", "")),
        created_at=int(txn_item.get("created_at", 0)),
        completed_at=txn_item.get("completed_at"),
        description=txn_item.get("description"),
        external_ref=txn_item.get("external_ref"),
        merchant_id=txn_item.get("merchant_id"),
        profile=profile,
        payment_record=payment_record,
    )


def _render_receipt_lines(payload: ReceiptPayload) -> List[str]:
    lines = [
        "Receipt",
        f"Transaction ID: {payload.txn_id}",
        f"Status: {payload.status}",
        f"Amount: {payload.amount} {payload.currency.upper()}",
        f"Created At: {payload.created_at}",
    ]
    if payload.completed_at:
        lines.append(f"Completed At: {payload.completed_at}")
    if payload.description:
        lines.append(f"Description: {payload.description}")
    if payload.external_ref:
        lines.append(f"External Ref: {payload.external_ref}")
    if payload.merchant_id:
        lines.append(f"Merchant: {payload.merchant_id}")

    name = payload.profile.get("display_name") or "Customer"
    lines.append(f"Bill To: {name}")
    email = payload.profile.get("displayed_email")
    if email:
        lines.append(f"Email: {email}")
    address_lines = _format_address(payload.profile.get("mailing_address"))
    if address_lines:
        lines.append("Address:")
        lines.extend([f"  {line}" for line in address_lines])

    if payload.payment_record:
        payment_id = payload.payment_record.get("payment_intent_id") or payload.payment_record.get("external_id")
        if payment_id:
            lines.append(f"Payment ID: {payment_id}")
        method = payload.payment_record.get("payment_method_type") or payload.payment_record.get("kind")
        if method:
            lines.append(f"Payment Method: {method}")
    return lines


def get_or_create_receipt(user_sub: str, txn_id: str) -> Dict[str, Any]:
    txn_item = get_transaction_item(user_sub, txn_id)
    receipt_path = txn_item.get("receipt_path")
    receipt_generated_at = txn_item.get("receipt_generated_at")
    if receipt_path:
        generated_at = int(receipt_generated_at) if receipt_generated_at else now_ts()
        return {
            "txn_id": txn_id,
            "receipt_path": receipt_path,
            "receipt_url": build_download_url(receipt_path),
            "generated_at": generated_at,
        }

    payload = _build_receipt_payload(txn_item)
    pdf = _render_pdf(_render_receipt_lines(payload))
    upload = upload_billing_receipt(user_sub, txn_id=txn_id, content=pdf)
    generated_at = now_ts()
    set_receipt_info(user_sub, txn_id, upload["path"], generated_at)
    return {
        "txn_id": txn_id,
        "receipt_path": upload["path"],
        "receipt_url": build_download_url(upload["path"]),
        "generated_at": generated_at,
    }
