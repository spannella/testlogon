"""Bulk payout & refund tools service (FIN-017).

Admin tooling to process many pending payouts or refund requests in one batch
operation. This service ONLY orchestrates the existing single-item services
(``creator_payouts`` and ``refund_requests``) in bulk — it does not re-implement
payout/refund logic or hand-roll ledger writes. The single-item services handle
status transitions and ledger entries (refunds write a credit ledger entry via
``billing_shared``).

A batch record is persisted in the ``bulk_payout_batches`` table with per-item
results and a summary, supporting a dry-run preview, execute, and history.

Determinism for E2E: real provider calls are gated behind
``S.bulk_payout_use_real_provider`` (default ``False``). When false, the reused
single-item services already perform status + ledger updates with no external
provider call, which is exactly the deterministic behaviour we want.
"""
from __future__ import annotations

import uuid
from typing import Any, Optional

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

from app.services.creator_payouts import (
    approve_payout,
    complete_payout,
    reject_payout,
    list_payouts_admin,
)
from app.services.refund_requests import (
    get_request,
    approve_request,
    reject_request,
    list_pending_requests,
)


KIND_PAYOUT = "payout"
KIND_REFUND = "refund"
_VALID_KINDS = (KIND_PAYOUT, KIND_REFUND)

# Pending state per kind (payouts use "requested"; refunds use "pending").
_PAYOUT_PENDING = "requested"
_REFUND_PENDING = "pending"

STATUS_PREVIEW = "preview"
STATUS_COMPLETED = "completed"
STATUS_COMPLETED_WITH_ERRORS = "completed_with_errors"

_GSI_ALL = "BATCH"


def _validate_kind(kind: str) -> None:
    if kind not in _VALID_KINDS:
        raise ValueError(f"kind must be one of {_VALID_KINDS}")


# --------------------------------------------------------------------------
# Raw lookups (read-only; reuse the existing single-item storage)
# --------------------------------------------------------------------------

def _lookup_payout(ref_id: str) -> Optional[dict]:
    resp = T.creator_payouts.get_item(Key={"payout_id": ref_id})
    return resp.get("Item")


def _lookup_refund(ref_id: str) -> Optional[dict]:
    return get_request(ref_id)


def _payout_fields(raw: dict) -> tuple[int, str]:
    return int(raw.get("amount_cents", 0)), raw.get("user_id", "")


def _refund_fields(raw: dict) -> tuple[int, str]:
    return int(raw.get("amount_cents", 0)), raw.get("requester_user_id", "")


# --------------------------------------------------------------------------
# Eligibility listing
# --------------------------------------------------------------------------

def list_eligible(kind: str, limit: int = 100) -> list[dict]:
    """List pending payouts or refund requests eligible for bulk action."""
    _validate_kind(kind)
    out: list[dict] = []
    if kind == KIND_PAYOUT:
        rows = list_payouts_admin(status=_PAYOUT_PENDING, limit=limit).get("items", [])
        for r in rows:
            out.append({
                "ref_id": r.get("payout_id", ""),
                "amount_cents": int(r.get("amount_cents", 0)),
                "recipient": r.get("user_id", ""),
                "currency": "usd",
                "status": r.get("status", _PAYOUT_PENDING),
                "created_at": int(r.get("created_at", 0)),
            })
        return out
    rows = list_pending_requests(status=_REFUND_PENDING, limit=limit)
    for r in rows:
        out.append({
            "ref_id": r.get("refund_request_id", ""),
            "amount_cents": int(r.get("amount_cents", 0)),
            "recipient": r.get("requester_user_id", ""),
            "currency": (r.get("currency", "usd") or "usd").lower(),
            "status": r.get("status", _REFUND_PENDING),
            "created_at": int(r.get("created_at", 0)),
        })
    return out


# --------------------------------------------------------------------------
# Per-item validation
# --------------------------------------------------------------------------

def _validate_item(kind: str, ref_id: str) -> dict:
    """Validate a single ref_id. Returns a per-item map.

    status is ``pending`` (eligible) or ``skipped`` (ineligible).
    """
    if kind == KIND_PAYOUT:
        raw = _lookup_payout(ref_id)
        pending_state = _PAYOUT_PENDING
        field_getter = _payout_fields
    else:
        raw = _lookup_refund(ref_id)
        pending_state = _REFUND_PENDING
        field_getter = _refund_fields

    if not raw:
        return {
            "ref_id": ref_id,
            "amount_cents": 0,
            "recipient": "",
            "status": "skipped",
            "reason": f"{kind} not found",
        }
    amount, recipient = field_getter(raw)
    status = raw.get("status")
    if status != pending_state:
        return {
            "ref_id": ref_id,
            "amount_cents": amount,
            "recipient": recipient,
            "status": "skipped",
            "reason": f"{kind} is not pending (status={status})",
        }
    if amount <= 0:
        return {
            "ref_id": ref_id,
            "amount_cents": amount,
            "recipient": recipient,
            "status": "skipped",
            "reason": "amount must be positive",
        }
    return {
        "ref_id": ref_id,
        "amount_cents": amount,
        "recipient": recipient,
        "status": "pending",
        "reason": "",
    }


def _validate_items(kind: str, ref_ids: list[str]) -> list[dict]:
    seen: set[str] = set()
    out: list[dict] = []
    for ref_id in ref_ids:
        if ref_id in seen:
            out.append({
                "ref_id": ref_id,
                "amount_cents": 0,
                "recipient": "",
                "status": "skipped",
                "reason": "duplicate ref_id in batch",
            })
            continue
        seen.add(ref_id)
        out.append(_validate_item(kind, ref_id))
    return out


def _summary(items: list[dict]) -> dict:
    eligible = [i for i in items if i["status"] == "pending"]
    ineligible = [i for i in items if i["status"] == "skipped"]
    total = sum(int(i["amount_cents"]) for i in eligible)
    return {
        "item_count": len(items),
        "eligible_count": len(eligible),
        "ineligible_count": len(ineligible),
        "total_cents": total,
    }


# --------------------------------------------------------------------------
# Batch record persistence
# --------------------------------------------------------------------------

def _persist_batch(
    batch_id: str,
    created_by: str,
    kind: str,
    status: str,
    items: list[dict],
    created_at: int,
    success_count: int = 0,
    failure_count: int = 0,
) -> dict:
    summary = _summary(items)
    item = {
        "batch_id": batch_id,
        "created_at": created_at,
        "created_by": created_by,
        "kind": kind,
        "status": status,
        "item_count": summary["item_count"],
        "success_count": int(success_count),
        "failure_count": int(failure_count),
        "total_cents": summary["total_cents"],
        "items": items,
        "gsi_all": _GSI_ALL,
    }
    T.bulk_payout_batches.put_item(Item=item)
    return _batch_to_out(item)


def _batch_to_out(item: dict) -> dict:
    return {
        "batch_id": item.get("batch_id"),
        "created_at": int(item.get("created_at", 0)),
        "created_by": item.get("created_by"),
        "kind": item.get("kind"),
        "status": item.get("status"),
        "item_count": int(item.get("item_count", 0)),
        "success_count": int(item.get("success_count", 0)),
        "failure_count": int(item.get("failure_count", 0)),
        "total_cents": int(item.get("total_cents", 0)),
        "items": [
            {
                "ref_id": i.get("ref_id"),
                "amount_cents": int(i.get("amount_cents", 0)),
                "recipient": i.get("recipient", "") or "",
                "status": i.get("status", "pending"),
                "reason": i.get("reason", "") or "",
            }
            for i in item.get("items", [])
        ],
    }


def get_batch(batch_id: str) -> Optional[dict]:
    resp = T.bulk_payout_batches.get_item(Key={"batch_id": batch_id})
    item = resp.get("Item")
    return _batch_to_out(item) if item else None


def list_batches(limit: int = 50) -> list[dict]:
    resp = T.bulk_payout_batches.query(
        IndexName="gsi_all-created_at-index",
        KeyConditionExpression="gsi_all = :all",
        ExpressionAttributeValues={":all": _GSI_ALL},
        ScanIndexForward=False,
        Limit=limit,
    )
    return [_batch_to_out(i) for i in resp.get("Items", [])]


# --------------------------------------------------------------------------
# Preview (dry run)
# --------------------------------------------------------------------------

def preview_batch(created_by: str, kind: str, ref_ids: list[str]) -> dict:
    """Dry-run: validate each ref_id and persist a preview batch."""
    _validate_kind(kind)
    items = _validate_items(kind, ref_ids)
    batch_id = f"bpb_{uuid.uuid4().hex}"
    return _persist_batch(
        batch_id=batch_id,
        created_by=created_by,
        kind=kind,
        status=STATUS_PREVIEW,
        items=items,
        created_at=now_ts(),
    )


# --------------------------------------------------------------------------
# Execute
# --------------------------------------------------------------------------

def _process_one(kind: str, ref_id: str, admin_sub: str) -> None:
    """Process a single eligible item via the existing single-item service.

    The reused service performs the status transition (+ ledger write for
    refunds). When ``bulk_payout_use_real_provider`` is False (default / E2E) no
    external provider is contacted — the service's own mock-friendly path runs.
    Raises on failure (already-processed, not-found, etc.).
    """
    if S.bulk_payout_use_real_provider:
        # Real provider integration would go here (Stripe/PayPal off-session).
        # Not exercised in dev/E2E; the deterministic path below is used instead.
        pass
    if kind == KIND_PAYOUT:
        # requested -> approved -> completed (complete_payout auto-advances in dev)
        approve_payout(ref_id, admin_sub)
        complete_payout(ref_id)
    else:
        approve_request(ref_id, admin_sub, notes="Bulk batch approval")


def execute_batch(
    admin_sub: str,
    kind: Optional[str] = None,
    ref_ids: Optional[list[str]] = None,
    batch_id: Optional[str] = None,
) -> dict:
    """Execute a batch.

    Accepts either an existing ``batch_id`` (re-execute a prior preview) OR an
    inline ``{kind, ref_ids}``. Re-validates every item, then processes each
    eligible one, capturing per-item success/failure. Continues on failure.
    """
    created_at = now_ts()

    if batch_id:
        existing = T.bulk_payout_batches.get_item(Key={"batch_id": batch_id}).get("Item")
        if not existing:
            raise ValueError("batch not found")
        if existing.get("status") in (STATUS_COMPLETED, STATUS_COMPLETED_WITH_ERRORS):
            raise ValueError("batch already executed")
        kind = existing.get("kind")
        ref_ids = [i.get("ref_id") for i in existing.get("items", [])]
        created_by = existing.get("created_by", admin_sub)
        created_at = int(existing.get("created_at", created_at))
    else:
        if not kind or ref_ids is None:
            raise ValueError("must provide either batch_id or kind+ref_ids")
        batch_id = f"bpb_{uuid.uuid4().hex}"
        created_by = admin_sub

    _validate_kind(kind)

    # Re-validate at execute time (status may have changed since preview).
    validated = _validate_items(kind, ref_ids)

    results: list[dict] = []
    success_count = 0
    failure_count = 0
    for v in validated:
        if v["status"] == "skipped":
            results.append(v)
            continue
        try:
            _process_one(kind, v["ref_id"], admin_sub)
            results.append({
                "ref_id": v["ref_id"],
                "amount_cents": int(v["amount_cents"]),
                "recipient": v["recipient"],
                "status": "success",
                "reason": "",
            })
            success_count += 1
        except Exception as e:  # noqa: BLE001 - capture per-item failure
            results.append({
                "ref_id": v["ref_id"],
                "amount_cents": int(v["amount_cents"]),
                "recipient": v["recipient"],
                "status": "failed",
                "reason": str(e),
            })
            failure_count += 1

    final_status = STATUS_COMPLETED if failure_count == 0 else STATUS_COMPLETED_WITH_ERRORS

    return _persist_batch(
        batch_id=batch_id,
        created_by=created_by,
        kind=kind,
        status=final_status,
        items=results,
        created_at=created_at,
        success_count=success_count,
        failure_count=failure_count,
    )
