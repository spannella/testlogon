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

# Legacy/processor-track admin resolutions (won|lost|accepted) — kept for
# back-compat with the pre-existing evidence/resolve admin path. The USER-track
# resolution vocabulary (refunded|partial|denied) drives the E0 dispatcher and is
# defined in dispute_lifecycle.RESOLUTIONS.
_VALID_RESOLUTIONS = ("won", "lost", "accepted")

# Map a legacy admin resolution -> the user-track resolution the dispatcher wants.
_LEGACY_RESOLUTION_MAP = {"lost": "refunded", "won": "denied", "accepted": "refunded"}


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
        # DISP-010/011/012 surfaced fields.
        "charge_type": item.get("charge_type") or None,
        "charge_ref": item.get("charge_ref") or None,
        "recipient_id": item.get("creator_id") or item.get("recipient_id") or None,
        "reason_detail": item.get("reason_detail") or None,
        "respond_by": int(item.get("respond_by", 0)) or None,
        "moved_cents": int(item.get("moved_cents", 0)) or None,
        "creator_response": item.get("creator_response") or None,
        "linked_dispute_id": item.get("linked_dispute_id") or None,
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
    recipient_id: str = "",
    reason_detail: str = "",
    linked_dispute_id: str = "",
    open_window: bool = True,
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

    from app.services import dispute_lifecycle as DL
    from app.services import dispute_dispatch as DD

    # If a transaction is referenced, validate it exists and belongs to the user.
    ledger_entry = None
    if transaction_entry_id:
        pk = user_pk(user_id)
        items = T.billing.query(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": pk},
        ).get("Items", [])
        for it in items:
            sk = it.get("sk", "")
            if sk.startswith("LEDGER#") and it.get("entry_id") == transaction_entry_id:
                ledger_entry = it
                break
        if not ledger_entry:
            raise HTTPException(404, "Transaction not found")
        original_amount = int(ledger_entry.get("amount_cents", 0))
        if original_amount > 0 and amount_cents > abs(original_amount):
            raise HTTPException(400, "Dispute amount exceeds original transaction amount")

    # DISP-014 charge auto-detection: when the caller passed only a
    # transaction_entry_id (dispute-from-receipt), infer charge_type / charge_ref
    # / recipient from the ledger debit so the reversal rail can fire on resolve.
    if source == "user" and transaction_entry_id and not charge_type:
        det = DL.detect_charge_from_entry(user_id, transaction_entry_id)
        if det:
            charge_type = det.get("charge_type") or charge_type
            charge_ref = charge_ref or det.get("charge_ref") or ""
            recipient_id = recipient_id or (det.get("recipient_id") or "")

    eff_charge_ref = charge_ref or transaction_entry_id or ""

    # DISP-010: reason gating per charge type (only for classified user disputes).
    if source == "user" and charge_type:
        DL.validate_reason(reason, charge_type)

    # DISP-014 pre-open guards (dedup + refund-then-dispute) — only for a
    # classified user dispute keyed on a charge_ref.
    if source == "user" and eff_charge_ref:
        # (a) refund-then-dispute: the charge's reversal mutex already claimed ->
        #     the charge was already reversed (a user refund or a chargeback). Block.
        if charge_type:
            anchor = user_id  # payer partition (all rails anchor on the payer)
            mk = T.billing.get_item(
                Key={"pk": user_pk(anchor), "sk": DD._mutex_sk(charge_type, eff_charge_ref)}
            ).get("Item")
            if mk:
                raise HTTPException(409, {"code": "already_reversed",
                                          "message": "This charge was already refunded or charged back; it cannot be disputed."})
        # (b) dedup: one open (non-terminal) dispute per charge_ref for this user.
        for d in list_user_disputes(user_id, limit=100):
            if str(d.get("charge_ref") or "") == eff_charge_ref and \
               str(d.get("status") or "") in DL.NON_TERMINAL_STATES:
                raise HTTPException(409, {"code": "duplicate_open_dispute",
                                          "message": "An open dispute already exists for this charge."})

    # DISP-041: serial-disputer guard. Rate-limit the payer (per-30d cap -> 429)
    # and classify a repeat offender as "serial" so the auto-refund fast-path is
    # suppressed (a serial disputer always lands in the admin queue). Only for
    # real user-filed disputes.
    serial_disputer = False
    if source == "user":
        try:
            from app.services import dispute_fraud as DF
            _gstats = DF.guard_new_dispute(user_id, actor="file_dispute")
            serial_disputer = bool(_gstats.get("serial_disputer"))
        except HTTPException:
            raise
        except Exception:
            logger.warning("file_dispute: serial-disputer guard failed for %s", user_id, exc_info=True)

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
        "charge_ref": eff_charge_ref,
        # DISP-011/012: the counterpart creator/seller (who gets the response
        # window + clawback) + the free-text detail behind the reason enum.
        "recipient_id": recipient_id or "",
        "creator_id": recipient_id or "",
        "reason_detail": reason_detail or "",
        "responses": [],
        "respond_by": 0,
        "linked_dispute_id": linked_dispute_id or "",
        "rail_marker": "",
        "serial_disputer": serial_disputer,
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

    # DISP-050: ack the payer AND alert the creator/seller (tappable push, default-on).
    try:
        from app.services import dispute_notify as DN
        DN.notify_opened(
            dispute_id=dispute_id,
            payer_id=user_id,
            recipient_id=recipient_id or None,
            amount_cents=int(amount_cents),
            reason=reason,
            charge_type=charge_type or "",
        )
    except Exception:
        logger.warning("file_dispute: notify_opened failed for %s", dispute_id, exc_info=True)

    # DISP-012: open the creator/seller response window (or auto-skip to the admin
    # queue per policy). Only for classified user disputes with a counterpart.
    if open_window and source == "user" and charge_type:
        try:
            win = DL.open_response_window(
                dispute_id=dispute_id,
                creator_id=recipient_id or None,
                reason=reason,
                amount_cents=int(amount_cents),
                force_manual_review=serial_disputer,
            )
            item["status"] = win.get("status", item["status"])
            item["status_scope"] = f"STATUS#{item['status']}"
            if win.get("respond_by"):
                item["respond_by"] = win["respond_by"]
        except Exception:
            logger.warning("file_dispute: open_response_window failed for %s", dispute_id, exc_info=True)

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
    override_amount_cents: Optional[int] = None,
    request_obj: Any = None,
) -> Dict[str, Any]:
    """DISP-013: resolve a USER dispute — the core money-moving fix.

    ``resolution`` is one of the user-track outcomes ``refunded|partial|denied``
    (legacy ``won|lost|accepted`` are accepted + mapped for the old admin path):

      * refunded -> DISP-003 full reversal on the charge's rail (buyer refunded,
        creator clawed back, VOD/entitlement revoked).
      * partial  -> DISP-003 with ``override_amount_cents`` (ecom/subscription
        only; tip/ad/vod reject partial in v1).
      * denied   -> NO ledger move; just a terminal state + payer notification.

    The state flip is guarded (DISP-005 ``guarded_dispute_transition``): the rail
    fires ONLY when this call is the winning transition into ``resolved`` (a
    concurrent double-resolve / withdraw-vs-resolve yields exactly one money
    move). The rail is idempotent AND cross-track mutex'd, so a redelivered
    resolve never double-debits.
    """
    from app.services import dispute_lifecycle as DL
    from app.services import dispute_dispatch as DD

    res = (resolution or "").strip().lower()
    if res in _VALID_RESOLUTIONS:  # legacy won|lost|accepted -> user-track
        res = _LEGACY_RESOLUTION_MAP.get(res, res)
    if res not in DL.RESOLUTIONS:
        raise HTTPException(400, {"code": "invalid_resolution",
                                  "message": f"resolution must be one of {sorted(DL.RESOLUTIONS)}."})

    item = get_dispute(dispute_id)
    if not item:
        raise HTTPException(404, "Dispute not found")
    frm = str(item.get("status") or "")
    if frm in DL.TERMINAL_STATES:
        raise HTTPException(409, {"code": "dispute_terminal",
                                  "message": f"Dispute is already {frm}."})

    charge_type = str(item.get("charge_type") or "")
    charge_ref = str(item.get("charge_ref") or item.get("transaction_entry_id") or "")
    payer_id = str(item.get("user_id") or "")
    recipient_id = str(item.get("creator_id") or item.get("recipient_id") or "")
    amount_cents = int(item.get("amount_cents", 0) or 0)

    # partial requires an override amount within the disputed amount.
    partial_amount = None
    if res == DL.RESOLUTION_PARTIAL:
        partial_amount = int(override_amount_cents if override_amount_cents is not None else 0)
        if partial_amount <= 0 or partial_amount > amount_cents:
            raise HTTPException(400, {"code": "invalid_partial_amount",
                                      "message": f"partial refund amount must be 1..{amount_cents} cents."})

    ts = now_ts()

    # -- STEP 1: guarded flip -> resolved (DISP-005). Money moves ONLY if we win. --
    changed, updated = DD.guarded_dispute_transition(
        dispute_id, DL.STATE_RESOLVED,
        expected_from=list(DL.NON_TERMINAL_STATES),
        extra={
            "resolution": res,
            "admin_notes": notes or "",
            "admin_user_id": admin_id,
            "resolved_at": ts,
            "resolution_amount_cents": (partial_amount if partial_amount is not None else
                                        (amount_cents if res == DL.RESOLUTION_REFUNDED else 0)),
        },
    )
    if not changed:
        # Lost the race (already resolved/withdrawn) — return the stored record,
        # NO money move (idempotent).
        return updated

    rail_receipt: Dict[str, Any] = {}
    moved_cents = 0
    # -- STEP 2: drive the real rail (refunded/partial). denied moves zero. --
    if res in (DL.RESOLUTION_REFUNDED, DL.RESOLUTION_PARTIAL):
        if not charge_type or not charge_ref:
            # Can't dispatch without a classified charge — record + surface, but
            # DON'T silently claim a refund happened.
            logger.warning("resolve_dispute %s refunded but unclassified (type=%r ref=%r)",
                           dispute_id, charge_type, charge_ref)
            raise HTTPException(422, {"code": "unclassified_charge",
                                      "message": "Cannot refund: dispute has no charge_type/charge_ref to reverse."})
        try:
            rail_receipt = DD.dispatch_reversal(
                charge_type=charge_type,
                charge_ref=charge_ref,
                payer_id=payer_id or None,
                recipient_id=recipient_id or None,
                override_amount_cents=partial_amount,
                reason=f"dispute:{dispute_id}",
                actor=admin_id,
            )
        except HTTPException:
            # The rail rejected (e.g. partial-unsupported). Roll the status back to
            # under_review so an admin can re-decide; NEVER leave it "resolved" with
            # no money moved.
            _rollback_to_review(dispute_id, ts)
            raise
        moved_cents = int(
            rail_receipt.get("clawback_cents")
            or rail_receipt.get("creator_clawback_cents")
            or rail_receipt.get("refunded_cents")
            or (partial_amount if partial_amount is not None else amount_cents)
        )
        # stamp the rail marker back onto the dispute record (audit linkage).
        try:
            T.billing_disputes.update_item(
                Key={"pk": _dp_pk(dispute_id), "sk": "META"},
                UpdateExpression="SET rail_marker = :rm, rail_receipt = :rr, moved_cents = :mc",
                ExpressionAttributeValues={
                    ":rm": f"{charge_type}:{charge_ref}",
                    ":rr": {k: v for k, v in rail_receipt.items()
                            if isinstance(v, (str, int, float, bool))},
                    ":mc": int(moved_cents),
                },
            )
        except Exception:
            logger.warning("resolve_dispute: rail_marker stamp failed for %s", dispute_id, exc_info=True)

        # DISP-040: a user dispute resolved in the buyer's favor (refunded/partial)
        # is the same abuse signal as a chargeback -- feed the fraud engine (once
        # per charge, idempotent). Best-effort; never blocks the resolution.
        try:
            from app.services import dispute_fraud as DF
            if payer_id:
                DF.record_dispute_fraud_signal(
                    payer_id=payer_id,
                    amount_cents=int(moved_cents),
                    tx_id=dispute_id,
                    kind="user_refund",
                    signal_ref=f"userref:{charge_type}:{charge_ref}" if charge_ref else f"userref:{dispute_id}",
                    actor=admin_id,
                )
        except Exception:
            logger.warning("resolve_dispute: fraud-signal hook failed for %s", dispute_id, exc_info=True)

    # -- STEP 3: DISP-050 notify BOTH parties per the terminal outcome (tappable push). --
    try:
        from app.services import dispute_notify as DN
        DN.notify_resolved(
            dispute_id=dispute_id,
            payer_id=payer_id or None,
            recipient_id=recipient_id or None,
            resolution=res,
            moved_cents=int(moved_cents),
        )
    except Exception:
        logger.warning("resolve_dispute: notify_resolved failed for %s", dispute_id, exc_info=True)

    audit_event(
        "billing_dispute_resolved", admin_id, request_obj, outcome="success",
        dispute_id=dispute_id, resolution=res, admin_notes=notes or "",
        moved_cents=int(moved_cents), charge_type=charge_type, charge_ref=charge_ref,
    )

    updated["resolution"] = res
    updated["admin_notes"] = notes or ""
    updated["moved_cents"] = int(moved_cents)
    updated["updated_at"] = ts
    return updated


def _rollback_to_review(dispute_id: str, ts: int) -> None:
    """Undo a resolved flip when the rail refused to move money — put the dispute
    back in the admin queue rather than leave a phantom 'resolved' with no ledger
    effect."""
    try:
        T.billing_disputes.update_item(
            Key={"pk": _dp_pk(dispute_id), "sk": "META"},
            UpdateExpression="SET #s = :s, status_scope = :ss, resolution = :r, updated_at = :t",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": "under_review", ":ss": "STATUS#under_review",
                                       ":r": "", ":t": ts},
        )
    except Exception:
        logger.warning("resolve_dispute: rollback_to_review failed for %s", dispute_id, exc_info=True)


def withdraw_dispute(
    dispute_id: str,
    user_id: str,
    request_obj: Any = None,
) -> Dict[str, Any]:
    """DISP-011: the payer withdraws their own open dispute (guarded, terminal).
    Mutually exclusive with resolve via the guarded transition."""
    from app.services import dispute_lifecycle as DL
    from app.services import dispute_dispatch as DD

    item = get_dispute(dispute_id)
    if not item:
        raise HTTPException(404, "Dispute not found")
    if str(item.get("user_id") or "") != user_id:
        raise HTTPException(404, "Dispute not found")
    if str(item.get("status") or "") in DL.TERMINAL_STATES:
        raise HTTPException(409, {"code": "dispute_terminal", "message": "Dispute is already closed."})

    changed, updated = DD.guarded_dispute_transition(
        dispute_id, DL.STATE_WITHDRAWN,
        expected_from=list(DL.NON_TERMINAL_STATES),
        extra={"withdrawn_at": now_ts(), "withdrawn_by": user_id},
    )
    if changed:
        recipient = str(item.get("creator_id") or item.get("recipient_id") or "")
        if recipient:
            write_alert(recipient, event="dispute_withdrawn", outcome="info",
                        title="A payment dispute was withdrawn",
                        details={"dispute_id": dispute_id})
        audit_event("billing_dispute_withdrawn", user_id, request_obj, outcome="success",
                    dispute_id=dispute_id)
    return updated


# ---------------------------------------------------------------------------
# DISP-021 - Creator/seller RESPOND surface
# ---------------------------------------------------------------------------

# The states in which a creator can still act on / see a dispute against them.
_CREATOR_ACTIONABLE_STATES = ("needs_response", "under_review", "escalated")


def list_creator_disputes(creator_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    """DISP-021: the inbound queue for a creator/seller - every non-terminal
    dispute where they are the counterparty (creator_id/recipient_id).

    There is no per-creator GSI (no schema change on prod), so this pages the
    actionable status GSIs and filters to this creator. Queues are small; newest
    first; de-duplicated by dispute_id.
    """
    seen: Dict[str, Dict[str, Any]] = {}
    for st in _CREATOR_ACTIONABLE_STATES:
        try:
            resp = T.billing_disputes.query(
                IndexName="ByStatusCreatedAt",
                KeyConditionExpression="status_scope = :ss",
                ExpressionAttributeValues={":ss": f"STATUS#{st}"},
                ScanIndexForward=False,
                Limit=100,
            )
        except ClientError:
            continue
        for it in resp.get("Items", []):
            rid = str(it.get("creator_id") or it.get("recipient_id") or "")
            if rid and rid == creator_id:
                did = str(it.get("dispute_id") or "")
                if did and did not in seen:
                    seen[did] = it
    rows = sorted(seen.values(), key=lambda x: int(x.get("created_at", 0)), reverse=True)
    return rows[:min(limit, 100)]


def creator_respond(
    dispute_id: str,
    creator_id: str,
    response_text: str,
    evidence_files: Optional[List[str]] = None,
    request_obj: Any = None,
) -> Dict[str, Any]:
    """DISP-021: authorize + record a creator/seller rebuttal.

    The caller MUST be the dispute counterparty (creator_id/recipient_id) - a
    non-counterparty is 404'd (no enumeration). Delegates to the lifecycle
    record_creator_response which appends the auditable rebuttal and (if still
    in-window) advances needs_response -> under_review.
    """
    from app.services import dispute_lifecycle as DL

    item = get_dispute(dispute_id)
    if not item:
        raise HTTPException(404, "Dispute not found")
    rid = str(item.get("creator_id") or item.get("recipient_id") or "")
    if not rid or rid != creator_id:
        # Do not reveal the dispute to a non-counterparty.
        raise HTTPException(404, "Dispute not found")

    updated = DL.record_creator_response(
        dispute_id=dispute_id,
        creator_id=creator_id,
        response_text=response_text,
        evidence_files=evidence_files or [],
    )
    audit_event("billing_dispute_creator_respond_api", creator_id, request_obj,
                outcome="success", dispute_id=dispute_id)
    return updated


# ---------------------------------------------------------------------------
# DISP-022 - Admin queue enrichment (rail preview + clawback + linked incident)
# ---------------------------------------------------------------------------

def _rail_preview(item: Dict[str, Any]) -> Dict[str, Any]:
    """Best-effort, MONEY-SAFE preview of what a refunded resolution would do:
    which rail fires, the counterparty clawed back, the gross charge amount, and
    whether a partial refund is even supported for this charge type. NEVER moves
    money (pure resolve_charge read). Any lookup failure degrades to a minimal
    preview rather than raising."""
    from app.services import dispute_dispatch as DD

    charge_type = str(item.get("charge_type") or "")
    charge_ref = str(item.get("charge_ref") or item.get("transaction_entry_id") or "")
    payer_id = str(item.get("user_id") or "") or None
    recipient_id = str(item.get("creator_id") or item.get("recipient_id") or "") or None
    amount_cents = int(item.get("amount_cents", 0) or 0)

    preview: Dict[str, Any] = {
        "charge_type": charge_type or None,
        "charge_ref": charge_ref or None,
        "rail": None,
        "rail_available": False,
        "partial_supported": False,
        "clawback_recipient_id": recipient_id,
        "clawback_cents": amount_cents,
        "gross_cents": None,
        "note": "",
    }
    if not charge_type or not charge_ref:
        preview["note"] = "Unclassified charge - cannot auto-refund; deny or classify first."
        return preview

    _RAIL_NAMES = {
        "tip": "reverse_tip_by_payment_id", "message": "reverse_tip_by_payment_id (pay-to-message)",
        "subscription": "_reverse_subscription_charge", "ad": "reverse_ad_charge",
        "ecom": "refund_requests", "vod": "reverse_vod_purchase",
    }
    preview["rail"] = _RAIL_NAMES.get(charge_type)
    preview["rail_available"] = charge_type in DD._RAIL
    try:
        params = DD.resolve_charge(charge_ref, charge_type,
                                   payer_id=payer_id, recipient_id=recipient_id)
        preview["partial_supported"] = bool(params.get("partial_capable"))
        if params.get("recipient_id"):
            preview["clawback_recipient_id"] = params.get("recipient_id")
        if params.get("gross_cents") is not None:
            preview["gross_cents"] = int(params.get("gross_cents") or 0)
    except HTTPException as exc:
        preview["note"] = str(getattr(exc, "detail", "") or "charge not resolvable")
    except Exception:
        logger.warning("_rail_preview: resolve_charge failed for %s", item.get("dispute_id"), exc_info=True)
        preview["note"] = "charge lookup failed"
    return preview


def _linked_incident(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """DISP-022: surface the linked processor PaymentIncident (if any) so the
    admin sees both tracks under one charge. linked_dispute_id is stamped as
    incident:{incident_id} by the cross-track link (DISP-042). Read-only."""
    linked = str(item.get("linked_dispute_id") or item.get("mooted_incident_id") or "")
    incident_id = ""
    if linked.startswith("incident:"):
        incident_id = linked.split("incident:", 1)[1]
    elif item.get("mooted_incident_id"):
        incident_id = str(item.get("mooted_incident_id"))
    if not incident_id:
        return None
    out: Dict[str, Any] = {"incident_id": incident_id, "status": None, "provider": None}
    try:
        from app.services.payment_incidents_store import DynamoPaymentIncidentRepository
        inc = DynamoPaymentIncidentRepository().get_incident(incident_id)
        if inc:
            out["status"] = inc.get("status")
            out["provider"] = inc.get("provider")
            out["provider_incident_id"] = inc.get("provider_incident_id")
    except Exception:
        logger.warning("_linked_incident: incident lookup failed for %s", incident_id, exc_info=True)
    return out


def admin_dispute_view(item: Dict[str, Any]) -> Dict[str, Any]:
    """DISP-022: the admin-facing dispute payload - the standard _to_out plus the
    rail preview, linked processor incident, creator rebuttal thread, and the
    serial-disputer flag the admin needs to decide."""
    out = _to_out(item)
    out["rail_preview"] = _rail_preview(item)
    out["linked_incident"] = _linked_incident(item)
    out["responses"] = item.get("responses") or []
    out["creator_response"] = item.get("creator_response") or None
    out["serial_disputer"] = bool(item.get("serial_disputer", False))
    out["evidence_files"] = item.get("evidence_files") or []
    out["source"] = item.get("source") or "user"
    return out
