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

import csv as _csv
import io as _io
import logging
import re as _re
import uuid
from typing import Any, Optional

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

from app.services.billing_shared import (
    user_pk,
    ddb_put,
    apply_balance_delta,
    new_ledger_entry,
)
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

logger = logging.getLogger(__name__)


KIND_PAYOUT = "payout"
KIND_REFUND = "refund"
_VALID_KINDS = (KIND_PAYOUT, KIND_REFUND)

# Pending state per kind (payouts use "requested"; refunds use "pending").
_PAYOUT_PENDING = "requested"
_REFUND_PENDING = "pending"

STATUS_PREVIEW = "preview"
STATUS_COMPLETED = "completed"
STATUS_COMPLETED_WITH_ERRORS = "completed_with_errors"
STATUS_UNDONE = "undone"

_GSI_ALL = "BATCH"

# GAP-0212: a completed batch may be reversed within this window (seconds).
UNDO_WINDOW_SECONDS = 300  # 5 minutes

# GAP-0213: CSV import limits + ref_id format guard (reject injection/garbage).
_CSV_MAX_ROWS = 500
_CSV_MAX_BYTES = 5 * 1024 * 1024  # 5 MB hard cap
_REF_ID_PATTERN = _re.compile(r"^[A-Za-z0-9_\-]{6,128}$")


class CsvImportError(ValueError):
    """Raised when an uploaded payout/refund CSV fails validation."""


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
    # GAP-0212: open a reversal window only for completed batches. Preview
    # batches and undone batches carry no undo window.
    undo_expires_at = (
        now_ts() + UNDO_WINDOW_SECONDS
        if status in (STATUS_COMPLETED, STATUS_COMPLETED_WITH_ERRORS)
        else None
    )
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
        "undo_expires_at": undo_expires_at,
    }
    T.bulk_payout_batches.put_item(Item=item)
    return _batch_to_out(item)


def _batch_to_out(item: dict) -> dict:
    undo_expires_at = item.get("undo_expires_at")
    undo_performed_at = item.get("undo_performed_at")
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
        "undo_expires_at": int(undo_expires_at) if undo_expires_at is not None else None,
        "undo_performed_at": (
            int(undo_performed_at) if undo_performed_at is not None else None
        ),
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


# --------------------------------------------------------------------------
# Undo (GAP-0212) — reverse a completed batch within the undo window
# --------------------------------------------------------------------------

def _reverse_payout(ref_id: str, admin_sub: str) -> None:
    """Reverse a payout that ``execute_batch`` already advanced.

    ``execute_batch`` drives a payout ``requested -> approved -> completed``.
    The single-item ``reject_payout`` only operates on the ``requested`` state,
    so a completed payout needs an explicit terminal reversal. We mark it
    ``reversed`` and stamp who/when. Dev/prod parity (SECOPS-007): this is a
    pure DDB status transition with no provider branching — identical in both
    environments. When ``bulk_payout_use_real_provider`` is True the real
    provider clawback would be wired in alongside this transition.
    """
    resp = T.creator_payouts.get_item(Key={"payout_id": ref_id})
    item = resp.get("Item")
    if not item:
        raise LookupError("payout not found")
    status = item.get("status", "")
    if status == "requested":
        # Never advanced past pending — the standard reject path applies.
        reject_payout(ref_id, admin_sub, reason="Bulk batch undo")
        return
    if status not in ("approved", "processing", "completed"):
        raise ValueError(f"payout not reversible (status={status})")
    T.creator_payouts.update_item(
        Key={"payout_id": ref_id},
        UpdateExpression=(
            "SET #s = :status, updated_at = :now, "
            "reverted_by = :admin, reverted_at = :now"
        ),
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":status": "reversed",
            ":now": now_ts(),
            ":admin": admin_sub,
        },
    )


def _reverse_refund(ref_id: str, admin_sub: str) -> None:
    """Reverse a refund that ``execute_batch`` already approved.

    ``approve_request`` credits the buyer's wallet (a ``refund_credit`` ledger
    entry + ``payments_settled_cents -= amount`` balance delta) and moves the
    request to ``approved``. ``reject_request`` only works on a ``pending``
    request, so an approved refund needs the credit reversed. We write a
    compensating ``refund_reversal`` debit ledger entry, undo the exact balance
    delta that ``approve_request`` applied (``payments_settled_cents += amount``),
    and mark the request ``reversed``.

    Dev/prod parity (SECOPS-007): ledger writes go through the same
    ``billing_shared`` helpers used by ``approve_request`` — no mock branching.
    """
    item = get_request(ref_id)
    if not item:
        raise LookupError("refund request not found")
    status = item.get("status", "")
    if status == "pending":
        reject_request(ref_id, admin_sub, "Bulk batch undo")
        return
    if status != "approved":
        raise ValueError(f"refund not reversible (status={status})")

    amount = int(item.get("amount_cents", 0))
    user_id = item.get("requester_user_id", "")
    currency = (item.get("currency", "usd") or "usd").lower()
    pk = user_pk(user_id)

    if amount > 0 and user_id:
        _, reversal_item = new_ledger_entry(
            key_name="pk",
            key_value=pk,
            entry_type="refund_reversal",
            amount_cents=amount,
            state="settled",
            reason="Refund reversed (bulk batch undo)",
            meta={"refund_request_id": ref_id, "reversed_by": admin_sub},
        )
        ddb_put(T.billing, reversal_item)
        # Undo the exact delta ``approve_request`` applied (it did
        # ``payments_settled_cents -= amount``).
        apply_balance_delta(
            T.billing, pk, {"payments_settled_cents": amount}, currency=currency
        )

    from app.services.refund_requests import _rr_pk  # local import: internal helper

    T.refund_requests.update_item(
        Key={"pk": _rr_pk(ref_id), "sk": "META"},
        UpdateExpression=(
            "SET #s = :s, status_scope = :ss, updated_at = :t, "
            "reverted_by = :admin, reverted_at = :t"
        ),
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":s": "reversed",
            ":ss": "STATUS#reversed",
            ":t": now_ts(),
            ":admin": admin_sub,
        },
    )


def undo_batch(batch_id: str, admin_sub: str) -> dict:
    """Reverse all successful items in a completed batch within the undo window.

    Raises ``ValueError`` if the batch is not found, is not completed, the undo
    window has expired, or the batch was already undone. Per-item reversal
    failures are captured (status ``undo_failed``) and do not abort the batch.
    """
    existing = T.bulk_payout_batches.get_item(Key={"batch_id": batch_id}).get("Item")
    if not existing:
        raise ValueError("batch not found")

    # Check already-undone first so the clearer message wins (an undone batch's
    # status is STATUS_UNDONE, which would otherwise trip the completed guard).
    if existing.get("undo_performed_at") or existing.get("status") == STATUS_UNDONE:
        raise ValueError("batch has already been undone")

    status = existing.get("status")
    if status not in (STATUS_COMPLETED, STATUS_COMPLETED_WITH_ERRORS):
        raise ValueError(f"batch is not in a completed state (status={status})")

    undo_expires_at = existing.get("undo_expires_at")
    if undo_expires_at is None or now_ts() > int(undo_expires_at):
        raise ValueError("undo window has expired")

    kind = existing.get("kind")
    items = existing.get("items", [])
    reversal_results: list[dict] = []

    for item in items:
        if item.get("status") != "success":
            # Skipped/failed items were never processed — leave them untouched.
            reversal_results.append(dict(item))
            continue
        ref_id = item.get("ref_id", "")
        try:
            if kind == KIND_PAYOUT:
                _reverse_payout(ref_id, admin_sub)
            else:
                _reverse_refund(ref_id, admin_sub)
            reversal_results.append({**item, "status": "undone", "reason": ""})
        except Exception as e:  # noqa: BLE001 - capture per-item reversal failure
            logger.warning(
                "undo_item_failed batch_id=%s kind=%s ref_id=%s err=%s",
                batch_id, kind, ref_id, e,
            )
            reversal_results.append({**item, "status": "undo_failed", "reason": str(e)})

    undo_ts = now_ts()
    T.bulk_payout_batches.update_item(
        Key={"batch_id": batch_id},
        UpdateExpression=(
            "SET #st = :st, undo_performed_at = :uat, "
            "undo_performed_by = :uby, undo_expires_at = :ue, #it = :items"
        ),
        ExpressionAttributeNames={"#st": "status", "#it": "items"},
        ExpressionAttributeValues={
            ":st": STATUS_UNDONE,
            ":uat": undo_ts,
            ":uby": admin_sub,
            ":ue": None,
            ":items": reversal_results,
        },
    )
    updated = T.bulk_payout_batches.get_item(Key={"batch_id": batch_id}).get("Item", {})
    return _batch_to_out(updated)


# --------------------------------------------------------------------------
# CSV import (GAP-0213) — parse + validate a payout/refund CSV
# --------------------------------------------------------------------------

def parse_payout_csv(file_bytes: bytes, kind: str) -> list[str]:
    """Parse a payout/refund CSV and return a validated, deduplicated ref_id list.

    Expected columns: ``ref_id`` (required); ``amount_cents`` / ``recipient_email``
    optional and informational only (the backend re-validates each ref_id against
    its DB record in ``preview_batch`` / ``execute_batch``).

    Security: rows whose ``ref_id`` does not match ``_REF_ID_PATTERN`` are silently
    dropped (CSV-injection / formula payloads never reach the execute path). A hard
    cap of ``_CSV_MAX_ROWS`` valid rows prevents resource exhaustion.

    Pure function — no AWS calls, no environment branching (SECOPS-007).
    Raises ``CsvImportError`` on format errors.
    """
    _validate_kind(kind)

    if len(file_bytes) > _CSV_MAX_BYTES:
        raise CsvImportError("file too large (max 5 MB)")

    try:
        text = file_bytes.decode("utf-8-sig")  # tolerate Excel BOM
    except UnicodeDecodeError as exc:
        raise CsvImportError("file must be UTF-8 encoded") from exc

    reader = _csv.DictReader(_io.StringIO(text))
    if not reader.fieldnames:
        raise CsvImportError("CSV has no header row")

    field_map = {f: (f or "").strip().lower() for f in reader.fieldnames}
    if "ref_id" not in field_map.values():
        raise CsvImportError(
            f"CSV must have a 'ref_id' column. Found: {list(reader.fieldnames)}"
        )

    ref_ids: list[str] = []
    seen: set[str] = set()
    skipped_invalid = 0

    for row in reader:
        normalized = {field_map.get(k, k): (v or "").strip() for k, v in row.items()}
        ref_id = normalized.get("ref_id", "").strip()
        if not ref_id:
            continue
        if not _REF_ID_PATTERN.match(ref_id):
            skipped_invalid += 1
            continue
        if ref_id in seen:
            continue
        seen.add(ref_id)
        ref_ids.append(ref_id)
        if len(ref_ids) > _CSV_MAX_ROWS:
            raise CsvImportError(
                f"CSV exceeds maximum of {_CSV_MAX_ROWS} rows. "
                "Split into smaller batches."
            )

    if not ref_ids:
        raise CsvImportError("no valid ref_id values found in CSV")

    if skipped_invalid:
        logger.info("csv_import_skipped_rows kind=%s count=%s", kind, skipped_invalid)

    return ref_ids
