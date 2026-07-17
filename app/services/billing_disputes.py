"""
Billing Disputes service — BILLING-001.

Manages the dispute / chargeback lifecycle alongside the refund-request flow.
A dispute can be filed by a customer (self-service "I dispute this charge") or
ingested from a payment-provider webhook (e.g. Stripe charge.dispute.created).

Status lifecycle:
    open -> under_review (evidence submitted) -> resolved (won | lost | accepted)

Storage: the BillingDisputes DynamoDB table (T.billing_disputes) with GSIs for
admin status queue, provider view, and per-user history. This is a NEW table and
service — distinct from the pre-existing PaymentIncident infrastructure.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.billing_shared import ddb_put, user_pk
from app.services.alerts import audit_event, write_alert

logger = logging.getLogger(__name__)

_VALID_RESOLUTIONS = ("won", "lost", "accepted")


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

def _dp_pk(dispute_id: str) -> str:
    return f"DISPUTE#{dispute_id}"


def _gen_dispute_id() -> str:
    return f"dp_{uuid.uuid4().hex[:12]}"


def _to_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "dispute_id": item.get("dispute_id", ""),
        "provider": item.get("provider", "manual"),
        "provider_dispute_id": item.get("provider_dispute_id") or None,
        "user_id": item.get("user_id") or None,
        "amount_cents": int(item.get("amount_cents", 0)),
        "currency": item.get("currency", "USD"),
        "reason": item.get("reason", ""),
        "status": item.get("status", ""),
        "evidence_submitted": bool(item.get("evidence_submitted", False)),
        "evidence_text": item.get("evidence_text") or None,
        "resolution": item.get("resolution") or None,
        "admin_notes": item.get("admin_notes") or None,
        "transaction_entry_id": item.get("transaction_entry_id") or None,
        "created_at": int(item.get("created_at", 0)),
        "updated_at": int(item.get("updated_at", 0)) or None,
        "deadline_at": int(item.get("deadline_at", 0)) or None,
    }


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------

def file_dispute(
    user_id: str,
    amount_cents: int,
    reason: str,
    currency: str = "USD",
    transaction_entry_id: Optional[str] = None,
    provider: str = "manual",
    provider_dispute_id: Optional[str] = None,
    source: str = "user",
    charge_type: str = "",
    charge_ref: str = "",
    linked_dispute_id: str = "",
    request_obj: Any = None,
) -> Dict[str, Any]:
    """File a new dispute. Returns the created item dict.

    DISP-001: the unified dispute record spans both origins via ``source`` in
    {user, processor}. ``charge_type`` (tip|message|subscription|ad|ecom|vod) +
    ``charge_ref`` locate the underlying charge for the reversal-rail dispatcher;
    ``rail_marker``/``resolution`` are stamped on resolution; ``linked_dispute_id``
    cross-links a user<->processor dispute on the same charge. Existing stub rows
    default ``source=user`` and empty charge_* (no behavior change).
    """
    if not S.billing_disputes_enabled:
        raise HTTPException(404, "Billing disputes are not enabled")

    if amount_cents <= 0:
        raise HTTPException(400, "Dispute amount must be positive")

    # If a transaction is referenced, validate it exists and belongs to the user.
    if transaction_entry_id:
        pk = user_pk(user_id)
        items = T.billing.query(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": pk},
        ).get("Items", [])
        ledger_entry = None
        for it in items:
            sk = it.get("sk", "")
            if sk.startswith("LEDGER#") and it.get("entry_id") == transaction_entry_id:
                ledger_entry = it
                break
        if not ledger_entry:
            raise HTTPException(404, "Transaction not found")
        original_amount = int(ledger_entry.get("amount_cents", 0))
        if original_amount > 0 and amount_cents > original_amount:
            raise HTTPException(400, "Dispute amount exceeds original transaction amount")

    dispute_id = _gen_dispute_id()
    ts = now_ts()
    deadline = ts + S.billing_disputes_default_deadline_days * 86400
    item = {
        "pk": _dp_pk(dispute_id),
        "sk": "META",
        "dispute_id": dispute_id,
        "provider": provider,
        "provider_dispute_id": provider_dispute_id or "",
        "provider_scope": f"PROVIDER#{provider}",
        "user_id": user_id,
        "user_scope": f"USER#{user_id}",
        "amount_cents": int(amount_cents),
        "currency": currency,
        "reason": reason,
        "status": "open",
        "status_scope": "STATUS#open",
        "evidence_submitted": False,
        "evidence_text": "",
        "evidence_files": [],
        "resolution": "",
        "admin_notes": "",
        "transaction_entry_id": transaction_entry_id or "",
        # DISP-001: unified dispute record fields (source discriminator + charge
        # linkage + resolution/rail markers). source_scope backs a BySource GSI.
        "source": source or "user",
        "source_scope": f"SOURCE#{source or 'user'}",
        "charge_type": charge_type or "",
        "charge_ref": charge_ref or transaction_entry_id or "",
        "linked_dispute_id": linked_dispute_id or "",
        "rail_marker": "",
        "created_at": ts,
        "updated_at": ts,
        "deadline_at": deadline,
    }

    try:
        ddb_put(T.billing_disputes, item, condition_expression="attribute_not_exists(pk)")
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise HTTPException(409, "Duplicate dispute")
        raise

    audit_event(
        "billing_dispute_filed",
        user_id,
        request_obj,
        outcome="success",
        dispute_id=dispute_id,
        amount_cents=int(amount_cents),
        provider=provider,
    )
    return item


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------

def get_dispute(dispute_id: str) -> Optional[Dict[str, Any]]:
    resp = T.billing_disputes.get_item(Key={"pk": _dp_pk(dispute_id), "sk": "META"})
    return resp.get("Item")


def list_user_disputes(user_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    try:
        resp = T.billing_disputes.query(
            IndexName="ByUserCreatedAt",
            KeyConditionExpression="user_scope = :us",
            ExpressionAttributeValues={":us": f"USER#{user_id}"},
            ScanIndexForward=False,
            Limit=min(limit, 100),
        )
        return resp.get("Items", [])
    except ClientError:
        return []


def list_disputes_by_status(status: str = "open", limit: int = 50) -> List[Dict[str, Any]]:
    try:
        resp = T.billing_disputes.query(
            IndexName="ByStatusCreatedAt",
            KeyConditionExpression="status_scope = :ss",
            ExpressionAttributeValues={":ss": f"STATUS#{status}"},
            ScanIndexForward=False,
            Limit=min(limit, 100),
        )
        return resp.get("Items", [])
    except ClientError:
        return []


# ---------------------------------------------------------------------------
# Admin actions
# ---------------------------------------------------------------------------

def submit_evidence(
    dispute_id: str,
    admin_id: str,
    evidence_text: str,
    evidence_files: Optional[List[str]] = None,
    request_obj: Any = None,
) -> Dict[str, Any]:
    """Submit dispute evidence (admin). Transitions open -> under_review."""
    item = get_dispute(dispute_id)
    if not item:
        raise HTTPException(404, "Dispute not found")
    if item.get("status") not in ("open", "under_review"):
        raise HTTPException(400, f"Dispute is not actionable (status={item.get('status')})")

    ts = now_ts()
    T.billing_disputes.update_item(
        Key={"pk": _dp_pk(dispute_id), "sk": "META"},
        UpdateExpression=(
            "SET #s = :s, status_scope = :ss, evidence_submitted = :es, "
            "evidence_text = :et, evidence_files = :ef, updated_at = :t"
        ),
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": "under_review",
            ":ss": "STATUS#under_review",
            ":es": True,
            ":et": evidence_text,
            ":ef": evidence_files or [],
            ":t": ts,
        },
    )

    audit_event(
        "billing_dispute_evidence_submitted",
        admin_id,
        request_obj,
        outcome="success",
        dispute_id=dispute_id,
    )

    item["status"] = "under_review"
    item["evidence_submitted"] = True
    item["evidence_text"] = evidence_text
    item["evidence_files"] = evidence_files or []
    item["updated_at"] = ts
    return item


def resolve_dispute(
    dispute_id: str,
    admin_id: str,
    resolution: str,
    notes: Optional[str] = None,
    request_obj: Any = None,
) -> Dict[str, Any]:
    """Resolve a dispute (admin). resolution in {won, lost, accepted}."""
    if resolution not in _VALID_RESOLUTIONS:
        raise HTTPException(400, "Invalid resolution")

    item = get_dispute(dispute_id)
    if not item:
        raise HTTPException(404, "Dispute not found")
    if item.get("status") == "resolved":
        raise HTTPException(400, "Dispute is already resolved")

    ts = now_ts()
    user_id = item.get("user_id", "")
    T.billing_disputes.update_item(
        Key={"pk": _dp_pk(dispute_id), "sk": "META"},
        UpdateExpression=(
            "SET #s = :s, status_scope = :ss, resolution = :r, "
            "admin_notes = :an, admin_user_id = :aid, updated_at = :t, resolved_at = :t"
        ),
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": "resolved",
            ":ss": "STATUS#resolved",
            ":r": resolution,
            ":an": notes or "",
            ":aid": admin_id,
            ":t": ts,
        },
    )

    if user_id:
        write_alert(
            user_id,
            event="dispute_resolved",
            outcome="info",
            title=f"Your dispute was resolved ({resolution})",
            details={"dispute_id": dispute_id, "resolution": resolution},
        )

    audit_event(
        "billing_dispute_resolved",
        admin_id,
        request_obj,
        outcome="success",
        dispute_id=dispute_id,
        resolution=resolution,
        admin_notes=notes or "",
    )

    item["status"] = "resolved"
    item["resolution"] = resolution
    item["admin_notes"] = notes or ""
    item["updated_at"] = ts
    return item
