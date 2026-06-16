"""Ticket bounty escrow subsystem (TBT-001..TBT-008).

Escrow-backed ticket bounties: a ticket owner funds a bounty (wallet → escrow),
any user can claim it, the claimant submits work, an admin approves (escrow →
assignee) or rejects, and the poster (or an admin) can cancel for a full refund
at any pre-payout state.

Money safety:
- The poster's wallet is debited exactly once, atomically with escrow creation,
  via ``transact_write_items`` (group_treasury pattern).
- The assignee is credited exactly once at approval; refunds credit the poster's
  wallet exactly once at cancel. Both gate on the escrow row's ``escrow_status``
  (single authoritative idempotency key).
- Ledger entries reuse ``billing_shared`` (never forked). Each carries a signed
  ``signed_amount_cents`` (audit D1: escrow debit negative, payout/refund credit
  positive).

Dev/prod parity (SECOPS-007): no ``dev_mode`` branch anywhere. The same
``T.billing`` / ``T.tickets`` code path runs against DynamoDB Local (moto) in dev
and real DynamoDB in prod.
"""
from __future__ import annotations

from typing import Any, Optional

from botocore.exceptions import ClientError
from fastapi import HTTPException, Request

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services import billing_shared as bs
from app.services.tickets import (
    STORE,
    _act_sk,
    _status_index_pk,
    _ticket_pk,
    _updated_index_sk,
    bounty_id_for_ticket,
)

ESCROW_SK = "ESCROW"


# ---------------------------------------------------------------------------
# Feature gate (mirrors app/services/inventory.py:50-56)
# ---------------------------------------------------------------------------
def _bounties_enabled() -> bool:
    return bool(getattr(S, "ticket_bounties_enabled", False))


def _require_bounties_enabled() -> None:
    if not _bounties_enabled():
        raise HTTPException(status_code=404, detail="Ticket bounties are not enabled")


# ---------------------------------------------------------------------------
# Domain error → HTTP mapping
# ---------------------------------------------------------------------------
class TicketBountyError(Exception):
    def __init__(self, http_status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.http_status = http_status
        self.code = code
        self.message = message


def _bounty_pk(bounty_id: str) -> str:
    return f"BOUNTY#{bounty_id}"


def _escrow_key(bounty_id: str) -> dict[str, str]:
    return {"pk": _bounty_pk(bounty_id), "sk": ESCROW_SK}


def _get_escrow(bounty_id: str) -> Optional[dict[str, Any]]:
    return T.billing.get_item(Key=_escrow_key(bounty_id)).get("Item")


# ---------------------------------------------------------------------------
# Atomic transact helpers (mirror group_treasury._transact_client/_to_ddb_item)
# ---------------------------------------------------------------------------
def _transact_client() -> Any:
    import boto3

    resource_client = T.billing.meta.client
    endpoint = resource_client.meta.endpoint_url
    region = resource_client.meta.region_name
    creds = resource_client._request_signer._credentials
    kwargs: dict[str, Any] = {"region_name": region, "endpoint_url": endpoint}
    if creds is not None:
        frozen = creds.get_frozen_credentials()
        kwargs["aws_access_key_id"] = frozen.access_key
        kwargs["aws_secret_access_key"] = frozen.secret_key
        if frozen.token:
            kwargs["aws_session_token"] = frozen.token
    return boto3.client("dynamodb", **kwargs)


def _to_ddb_item(item: dict[str, Any]) -> dict[str, Any]:
    from boto3.dynamodb.types import TypeSerializer

    serializer = TypeSerializer()
    return {k: serializer.serialize(v) for k, v in item.items() if v is not None}


def _audit(event: str, actor_sub: str, request: Optional[Request], **fields: Any) -> None:
    try:
        from app.services.alerts import audit_event

        audit_event(event, actor_sub, request, **fields)
    except Exception:
        pass


def _notify(user_sub: str, *, event: str, title: str, details: dict[str, Any]) -> None:
    try:
        from app.services.alerts import write_alert

        write_alert(user_sub, event=event, outcome="info", title=title, details=details)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# TBT-003 — post_bounty (atomic escrow hold)
# ---------------------------------------------------------------------------
def post_bounty(
    *,
    ticket_id: str,
    poster_sub: str,
    amount_cents: int,
    currency: str = "usd",
    request: Optional[Request] = None,
) -> dict[str, Any]:
    _require_bounties_enabled()

    ticket = STORE.get_ticket(ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    if ticket.get("owner_sub") != poster_sub:
        raise HTTPException(status_code=403, detail="Only the ticket owner may post a bounty")
    if ticket.get("status") != "open":
        raise HTTPException(status_code=400, detail="Bounty may only be posted on open tickets")
    existing_bounty_status = ticket.get("bounty_status")
    if existing_bounty_status not in (None, "cancelled"):
        raise HTTPException(status_code=409, detail="Ticket already has an active bounty")

    amount_cents = int(amount_cents)
    if amount_cents < S.ticket_bounty_min_cents:
        raise HTTPException(status_code=400, detail=f"Minimum bounty is {S.ticket_bounty_min_cents} cents")
    if amount_cents > S.ticket_bounty_max_cents:
        raise HTTPException(status_code=400, detail=f"Maximum bounty is {S.ticket_bounty_max_cents} cents")
    if currency != "usd":
        raise HTTPException(status_code=400, detail="Only USD bounties are supported in v1")

    # Fraud + freeze gate (charge path). Service-level — no router import.
    from app.services import fraud_detection as fd

    if fd.is_frozen(poster_sub):
        raise HTTPException(status_code=403, detail="Account is frozen")
    ip = request.client.host if request is not None and request.client else None
    verdict = fd.evaluate_transaction(
        user_id=poster_sub, amount_cents=amount_cents, entry_type="bounty_hold",
        tx_id=ticket_id, ip_address=ip,
    )
    if verdict.get("action") == "block":
        raise HTTPException(status_code=403, detail="Transaction blocked by fraud detection")

    # Repost (after cancel) gets a collision-free bounty_id. bounty_repost_count
    # is TRACKED but UNENFORCED (audit D3 — no repost cap in v1).
    prior_reposts = int(ticket.get("bounty_repost_count") or 0)
    if existing_bounty_status == "cancelled":
        repost_count = prior_reposts + 1
        bounty_id = bounty_id_for_ticket(f"{ticket_id}#repost#{repost_count}")
    else:
        repost_count = prior_reposts
        bounty_id = bounty_id_for_ticket(ticket_id)

    ts = now_ts()
    poster_pk = bs.user_pk(poster_sub)
    ledger_sk, ledger_item = bs.new_ledger_entry(
        key_name="pk",
        key_value=poster_pk,
        entry_type="debit",
        amount_cents=amount_cents,
        state="pending",
        reason="bounty_escrow",
        meta={"bounty_id": bounty_id, "ticket_id": ticket_id, "escrow_state": "held"},
        # audit D1: escrow debit is a NEGATIVE signed amount.
        extra={"signed_amount_cents": -amount_cents},
    )

    escrow_item = {
        "pk": _bounty_pk(bounty_id),
        "sk": ESCROW_SK,
        "bounty_id": bounty_id,
        "ticket_id": ticket_id,
        "poster_sub": poster_sub,
        "amount_cents": amount_cents,
        "currency": currency,
        "escrow_status": "held",
        "created_at": ts,
        "ledger_sk": ledger_sk,
        "ledger_date": bs.ledger_date_for_ts(ts),
    }

    wallet_update = {
        "Update": {
            "TableName": T.billing.name,
            "Key": _to_ddb_item({"pk": poster_pk, "sk": bs.WALLET_SK}),
            "UpdateExpression": "SET wallet_balance_cents = wallet_balance_cents + :neg, updated_at = :t",
            "ConditionExpression": "wallet_balance_cents >= :amt",
            "ExpressionAttributeValues": _to_ddb_item({":neg": -amount_cents, ":amt": amount_cents, ":t": ts}),
        }
    }
    escrow_put = {
        "Put": {
            "TableName": T.billing.name,
            "Item": _to_ddb_item(escrow_item),
            "ConditionExpression": "attribute_not_exists(pk)",
        }
    }
    ledger_put = {
        "Put": {
            "TableName": T.billing.name,
            "Item": _to_ddb_item(ledger_item),
            "ConditionExpression": "attribute_not_exists(sk)",
        }
    }

    try:
        _transact_client().transact_write_items(TransactItems=[wallet_update, escrow_put, ledger_put])
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code == "TransactionCanceledException":
            reasons = exc.response.get("CancellationReasons", []) or []
            if reasons and reasons[0].get("Code") == "ConditionalCheckFailed":
                raise HTTPException(status_code=402, detail="Insufficient wallet balance")
            if len(reasons) > 1 and reasons[1].get("Code") == "ConditionalCheckFailed":
                # Escrow already exists — idempotent replay; converge ticket state.
                _converge_ticket_funded(
                    ticket=ticket, bounty_id=bounty_id, amount_cents=amount_cents,
                    currency=currency, repost_count=repost_count, ts=ts,
                )
                return STORE.get_ticket(ticket_id) or {}
        raise

    _converge_ticket_funded(
        ticket=ticket, bounty_id=bounty_id, amount_cents=amount_cents,
        currency=currency, repost_count=repost_count, ts=ts,
    )

    STORE._table.put_item(Item={
        "pk": _ticket_pk(ticket_id),
        "sk": _act_sk(ts, f"act_{__import__('uuid').uuid4().hex[:12]}"),
        "entity_type": "ticket_activity",
        "ticket_id": ticket_id,
        "activity_id": f"act_{__import__('uuid').uuid4().hex[:12]}",
        "activity_type": "bounty_posted",
        "actor_sub": poster_sub,
        "created_at": ts,
    })
    _audit("bounty_posted", poster_sub, request,
           ticket_id=ticket_id, bounty_id=bounty_id, amount_cents=amount_cents)
    return STORE.get_ticket(ticket_id) or {}


def _converge_ticket_funded(
    *, ticket: dict[str, Any], bounty_id: str, amount_cents: int,
    currency: str, repost_count: int, ts: int,
) -> None:
    ticket_id = ticket["ticket_id"]
    created_at = int(ticket.get("created_at", ts) or ts)
    STORE._table.update_item(
        Key=_meta_item_key_for(ticket_id),
        UpdateExpression=(
            "SET bounty_id = :bid, bounty_amount_cents = :amt, bounty_currency = :cur, "
            "bounty_status = :bs, bounty_funded_at = :fat, bounty_repost_count = :rc, "
            "updated_at = :t, gsi_bounty_pk = :gbpk, gsi_bounty_sk = :gbsk"
        ),
        ExpressionAttributeValues={
            ":bid": bounty_id,
            ":amt": amount_cents,
            ":cur": currency,
            ":bs": "funded",
            ":fat": ts,
            ":rc": int(repost_count),
            ":t": ts,
            ":gbpk": "BOUNTY#OPEN",
            ":gbsk": created_at,
        },
    )


def _meta_item_key_for(ticket_id: str) -> dict[str, str]:
    return {"pk": _ticket_pk(ticket_id), "sk": "META"}


# ---------------------------------------------------------------------------
# TBT-005 — claim / unclaim
# ---------------------------------------------------------------------------
def claim_bounty(*, ticket_id: str, claimer_sub: str) -> dict[str, Any]:
    _require_bounties_enabled()
    ticket = STORE.get_ticket(ticket_id)
    if not ticket:
        raise TicketBountyError(404, "ticket_not_found", "Ticket not found")
    if ticket.get("bounty_status") != "funded":
        raise TicketBountyError(409, "bounty_not_funded", "Bounty is not open for claiming")
    bounty_id = ticket.get("bounty_id")
    escrow = _get_escrow(bounty_id) if bounty_id else None
    if not escrow or escrow.get("escrow_status") != "held":
        raise TicketBountyError(409, "escrow_not_held", "Escrow is not held")

    ts = now_ts()
    try:
        STORE._table.update_item(
            Key=_meta_item_key_for(ticket_id),
            UpdateExpression=(
                "SET claimed_by_sub = :claimer, claimed_at = :ts, "
                "assigned_to_sub = :claimer, assigned_by = :claimer, assigned_at = :ts, "
                "bounty_status = :claimed, #status = :in_progress, updated_at = :ts, "
                "version = version + :one, "
                "gsi2pk = :gsi2pk, gsi2sk = :gsi2sk, gsi3pk = :gsi3pk, gsi3sk = :gsi3sk, gsi1sk = :gsi1sk "
                "REMOVE gsi_bounty_pk, gsi_bounty_sk"
            ),
            ConditionExpression="attribute_not_exists(claimed_by_sub) AND bounty_status = :funded",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":claimer": claimer_sub,
                ":ts": ts,
                ":claimed": "claimed",
                ":funded": "funded",
                ":in_progress": "in_progress",
                ":one": 1,
                ":gsi2pk": _status_index_pk("in_progress"),
                ":gsi2sk": _updated_index_sk(ts, ticket_id),
                ":gsi3pk": f"ASSIGNEE#{claimer_sub}",
                ":gsi3sk": _updated_index_sk(ts, ticket_id),
                ":gsi1sk": _updated_index_sk(ts, ticket_id),
            },
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            raise TicketBountyError(409, "already_claimed", "This bounty has already been claimed")
        raise

    _write_bounty_activity(ticket_id=ticket_id, actor_sub=claimer_sub, ts=ts,
                           activity_type="bounty_claimed", assignee_sub=claimer_sub)
    _audit("bounty_claimed", claimer_sub, None, ticket_id=ticket_id, bounty_id=bounty_id)
    return STORE.get_ticket(ticket_id) or {}


def unclaim_bounty(*, ticket_id: str, claimer_sub: str) -> dict[str, Any]:
    _require_bounties_enabled()
    ticket = STORE.get_ticket(ticket_id)
    if not ticket:
        raise TicketBountyError(404, "ticket_not_found", "Ticket not found")
    if ticket.get("bounty_status") != "claimed":
        raise TicketBountyError(409, "not_claimed", "Bounty is not in a claimed state")
    if ticket.get("claimed_by_sub") != claimer_sub:
        raise TicketBountyError(403, "not_claimant", "Only the current claimant may unclaim")

    ts = now_ts()
    created_at = int(ticket.get("created_at", ts) or ts)
    try:
        STORE._table.update_item(
            Key=_meta_item_key_for(ticket_id),
            UpdateExpression=(
                "SET bounty_status = :funded, #status = :open, "
                "gsi_bounty_pk = :bounty_open, gsi_bounty_sk = :created_at, "
                "assigned_to_sub = :none, assigned_by = :none, assigned_at = :none, "
                "updated_at = :ts, version = version + :one, "
                "gsi2pk = :gsi2pk, gsi2sk = :gsi2sk, gsi3pk = :gsi3pk, gsi3sk = :gsi3sk, gsi1sk = :gsi1sk "
                "REMOVE claimed_by_sub, claimed_at"
            ),
            ConditionExpression="claimed_by_sub = :claimer AND bounty_status = :claimed",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":funded": "funded",
                ":claimed": "claimed",
                ":open": "open",
                ":bounty_open": "BOUNTY#OPEN",
                ":created_at": created_at,
                ":none": None,
                ":claimer": claimer_sub,
                ":ts": ts,
                ":one": 1,
                ":gsi2pk": _status_index_pk("open"),
                ":gsi2sk": _updated_index_sk(ts, ticket_id),
                ":gsi3pk": "ASSIGNEE#unassigned",
                ":gsi3sk": _updated_index_sk(ts, ticket_id),
                ":gsi1sk": _updated_index_sk(ts, ticket_id),
            },
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            raise TicketBountyError(409, "unclaim_conflict", "Concurrent state change; retry")
        raise

    _write_bounty_activity(ticket_id=ticket_id, actor_sub=claimer_sub, ts=ts,
                           activity_type="bounty_unclaimed")
    _audit("bounty_unclaimed", claimer_sub, None, ticket_id=ticket_id)
    return STORE.get_ticket(ticket_id) or {}


def _write_bounty_activity(*, ticket_id: str, actor_sub: str, ts: int, activity_type: str,
                           assignee_sub: Optional[str] = None) -> None:
    act_id = f"act_{__import__('uuid').uuid4().hex[:12]}"
    item = {
        "pk": _ticket_pk(ticket_id),
        "sk": _act_sk(ts, act_id),
        "entity_type": "ticket_activity",
        "ticket_id": ticket_id,
        "activity_id": act_id,
        "activity_type": activity_type,
        "actor_sub": actor_sub,
        "created_at": ts,
    }
    if assignee_sub is not None:
        item["assignee_sub"] = assignee_sub
    STORE._table.put_item(Item=item)


# ---------------------------------------------------------------------------
# TBT-006 — submit / approve / reject
# ---------------------------------------------------------------------------
def submit_bounty(*, ticket_id: str, claimer_sub: str) -> dict[str, Any]:
    _require_bounties_enabled()
    ticket = STORE.get_ticket(ticket_id)
    if not ticket:
        raise TicketBountyError(404, "ticket_not_found", "Ticket not found")
    if ticket.get("bounty_status") != "claimed":
        raise TicketBountyError(409, "bounty_wrong_state", "Bounty is not in a claimed state")
    if ticket.get("claimed_by_sub") != claimer_sub:
        raise TicketBountyError(403, "not_claimant", "Only the claimant may submit")
    try:
        updated = STORE.update_status(
            ticket_id=ticket_id, actor_sub=claimer_sub, status="done", is_admin=False,
        )
    except Exception as exc:  # TicketStateError → conflict
        raise TicketBountyError(409, "bounty_wrong_state", str(exc))
    if not updated:
        raise TicketBountyError(404, "ticket_not_found", "Ticket not found")
    _audit("bounty_submitted", claimer_sub, None, ticket_id=ticket_id)
    return updated


def approve_bounty(*, ticket_id: str, admin_sub: str, request: Optional[Request] = None) -> dict[str, Any]:
    _require_bounties_enabled()
    ticket = STORE.get_ticket(ticket_id)
    if not ticket:
        raise TicketBountyError(404, "ticket_not_found", "Ticket not found")
    bounty_id = ticket.get("bounty_id")
    escrow = _get_escrow(bounty_id) if bounty_id else None
    if not escrow:
        raise TicketBountyError(409, "escrow_not_found", "Escrow record not found")
    # Idempotent replay: escrow already released → return current ticket no-op,
    # regardless of the ticket's bounty_status (it is already paid_out).
    if escrow.get("escrow_status") == "released":
        return STORE.get_ticket(ticket_id) or {}
    if ticket.get("bounty_status") != "submitted":
        raise TicketBountyError(409, "bounty_wrong_state", "Bounty is not awaiting approval")
    if escrow.get("escrow_status") != "held":
        raise TicketBountyError(409, "bounty_wrong_state", "Escrow is not held")

    assignee_sub = ticket.get("claimed_by_sub")
    if not assignee_sub:
        raise TicketBountyError(409, "no_claimant", "No claimant to pay out")

    amount_cents = int(escrow["amount_cents"])
    fee_bps = int(S.ticket_bounty_fee_bps)
    fee_cents = amount_cents * fee_bps // 10000
    net_cents = amount_cents - fee_cents

    ts = now_ts()
    assignee_pk = bs.user_pk(assignee_sub)
    poster_pk = bs.user_pk(escrow["poster_sub"])
    payout_sk, payout_item = bs.new_ledger_entry(
        key_name="pk",
        key_value=assignee_pk,
        entry_type="credit",
        amount_cents=net_cents,
        state="settled",
        reason="bounty_payout",
        meta={"bounty_id": bounty_id, "ticket_id": ticket_id, "fee_cents": fee_cents, "approved_by": admin_sub},
        # audit D1: payout credit is a POSITIVE signed amount.
        extra={"signed_amount_cents": net_cents},
    )

    escrow_update = {
        "Update": {
            "TableName": T.billing.name,
            "Key": _to_ddb_item(_escrow_key(bounty_id)),
            "UpdateExpression": (
                "SET escrow_status = :released, released_to = :to, released_by = :by, "
                "released_at = :ts, payout_ledger_sk = :psk, fee_cents = :fee, net_cents = :net"
            ),
            "ConditionExpression": "escrow_status = :held",
            "ExpressionAttributeValues": _to_ddb_item({
                ":released": "released", ":held": "held", ":to": assignee_sub,
                ":by": admin_sub, ":ts": ts, ":psk": payout_sk, ":fee": fee_cents, ":net": net_cents,
            }),
        }
    }
    wallet_credit = {
        "Update": {
            "TableName": T.billing.name,
            "Key": _to_ddb_item({"pk": assignee_pk, "sk": bs.WALLET_SK}),
            "UpdateExpression": (
                "SET wallet_balance_cents = if_not_exists(wallet_balance_cents, :z) + :net, "
                "currency = :c, updated_at = :ts"
            ),
            "ExpressionAttributeValues": _to_ddb_item({":z": 0, ":net": net_cents, ":c": "usd", ":ts": ts}),
        }
    }
    payout_put = {
        "Put": {
            "TableName": T.billing.name,
            "Item": _to_ddb_item(payout_item),
            "ConditionExpression": "attribute_not_exists(sk)",
        }
    }
    poster_settle = {
        "Update": {
            "TableName": T.billing.name,
            "Key": _to_ddb_item({"pk": poster_pk, "sk": escrow["ledger_sk"]}),
            "UpdateExpression": "SET #s = :s",
            "ExpressionAttributeNames": {"#s": "state"},
            "ExpressionAttributeValues": _to_ddb_item({":s": "settled_released"}),
        }
    }

    try:
        _transact_client().transact_write_items(
            TransactItems=[escrow_update, wallet_credit, payout_put, poster_settle]
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code == "TransactionCanceledException":
            fresh = _get_escrow(bounty_id)
            if fresh and fresh.get("escrow_status") == "released":
                return STORE.get_ticket(ticket_id) or {}
        raise

    # Flip ticket to paid_out (terminal). Direct update — not via update_status.
    STORE._table.update_item(
        Key=_meta_item_key_for(ticket_id),
        UpdateExpression=(
            "SET bounty_status = :bs, #status = :st, bounty_paid_at = :ts, updated_at = :ts, "
            "version = version + :one, gsi2pk = :gsi2pk, gsi2sk = :gsi2sk"
        ),
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":bs": "paid_out", ":st": "paid_out", ":ts": ts, ":one": 1,
            ":gsi2pk": _status_index_pk("paid_out"), ":gsi2sk": _updated_index_sk(ts, ticket_id),
        },
    )

    if fee_cents > 0:
        try:
            _, fee_item = bs.new_ledger_entry(
                key_name="pk", key_value="PLATFORM#ESCROW", entry_type="credit",
                amount_cents=fee_cents, state="settled", reason="bounty_fee",
                meta={"bounty_id": bounty_id, "ticket_id": ticket_id},
                extra={"signed_amount_cents": fee_cents},
            )
            T.billing.put_item(Item=fee_item)
        except Exception:
            pass

    _write_bounty_activity(ticket_id=ticket_id, actor_sub=admin_sub, ts=ts,
                           activity_type="bounty_approved", assignee_sub=assignee_sub)
    _audit("bounty_released", admin_sub, request,
           ticket_id=ticket_id, bounty_id=bounty_id, net_cents=net_cents)
    _notify(assignee_sub, event="bounty_awarded", title="Bounty awarded",
            details={"ticket_id": ticket_id, "net_cents": net_cents})
    return STORE.get_ticket(ticket_id) or {}


def reject_bounty(*, ticket_id: str, admin_sub: str, reason: str) -> dict[str, Any]:
    _require_bounties_enabled()
    ticket = STORE.get_ticket(ticket_id)
    if not ticket:
        raise TicketBountyError(404, "ticket_not_found", "Ticket not found")
    if ticket.get("bounty_status") != "submitted":
        raise TicketBountyError(409, "bounty_wrong_state", "Bounty is not awaiting approval")

    ts = now_ts()
    # No money moves; escrow stays held. Revert to claimed / in_progress.
    STORE._table.update_item(
        Key=_meta_item_key_for(ticket_id),
        UpdateExpression=(
            "SET bounty_status = :bs, #status = :st, bounty_reject_reason = :r, bounty_rejected_at = :ts, "
            "updated_at = :ts, version = version + :one, gsi2pk = :gsi2pk, gsi2sk = :gsi2sk"
        ),
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":bs": "claimed", ":st": "in_progress", ":r": reason, ":ts": ts, ":one": 1,
            ":gsi2pk": _status_index_pk("in_progress"), ":gsi2sk": _updated_index_sk(ts, ticket_id),
        },
    )
    _write_bounty_activity(ticket_id=ticket_id, actor_sub=admin_sub, ts=ts,
                           activity_type="bounty_rejected")
    _audit("bounty_rejected", admin_sub, None, ticket_id=ticket_id, reason=reason)
    claimant = ticket.get("claimed_by_sub")
    if claimant:
        _notify(claimant, event="bounty_rejected", title="Bounty rejected",
                details={"ticket_id": ticket_id, "reason": reason})
    return STORE.get_ticket(ticket_id) or {}


# ---------------------------------------------------------------------------
# TBT-007 — cancel + refund → poster
# ---------------------------------------------------------------------------
def cancel_bounty(
    *, ticket_id: str, actor_sub: str, reason: str = "", is_admin: bool = False,
    request: Optional[Request] = None,
) -> dict[str, Any]:
    _require_bounties_enabled()
    ticket = STORE.get_ticket(ticket_id)
    if not ticket:
        raise TicketBountyError(404, "ticket_not_found", "Ticket not found")
    bounty_id = ticket.get("bounty_id")
    if not bounty_id:
        raise TicketBountyError(409, "ticket_has_no_bounty", "Ticket has no bounty")
    escrow = _get_escrow(bounty_id)
    if not escrow:
        raise TicketBountyError(409, "escrow_not_found", "Escrow record not found")

    escrow_status = escrow.get("escrow_status")
    if escrow_status == "released":
        raise TicketBountyError(409, "bounty_already_paid_out", "Cannot cancel a paid-out bounty")
    if escrow_status == "refunded":
        return STORE.get_ticket(ticket_id) or {}

    poster_sub = escrow["poster_sub"]
    bounty_status = ticket.get("bounty_status")
    is_poster = actor_sub == poster_sub
    if not is_admin and not is_poster:
        raise TicketBountyError(403, "forbidden", "Not authorized to cancel this bounty")
    if is_poster and not is_admin and bounty_status != "funded":
        raise TicketBountyError(403, "poster_cannot_cancel_after_claim",
                                "Poster may only cancel while the bounty is unclaimed")

    amount_cents = int(escrow["amount_cents"])
    ts = now_ts()
    poster_pk = bs.user_pk(poster_sub)
    refund_sk, refund_item = bs.new_ledger_entry(
        key_name="pk",
        key_value=poster_pk,
        entry_type="adjustment",
        amount_cents=amount_cents,
        state="settled",
        reason="bounty_refund",
        meta={"bounty_id": bounty_id, "ticket_id": ticket_id, "refund_reason": reason, "refunded_by": actor_sub},
        # audit D1: refund credit is a POSITIVE signed amount.
        extra={"signed_amount_cents": amount_cents},
    )

    escrow_update = {
        "Update": {
            "TableName": T.billing.name,
            "Key": _to_ddb_item(_escrow_key(bounty_id)),
            "UpdateExpression": (
                "SET escrow_status = :refunded, refunded_at = :ts, refund_ledger_sk = :rsk, "
                "refunded_by = :by, refund_reason = :reason"
            ),
            "ConditionExpression": "escrow_status = :held",
            "ExpressionAttributeValues": _to_ddb_item({
                ":refunded": "refunded", ":held": "held", ":ts": ts, ":rsk": refund_sk,
                ":by": actor_sub, ":reason": reason,
            }),
        }
    }
    refund_put = {
        "Put": {
            "TableName": T.billing.name,
            "Item": _to_ddb_item(refund_item),
            "ConditionExpression": "attribute_not_exists(sk)",
        }
    }
    wallet_credit = {
        "Update": {
            "TableName": T.billing.name,
            "Key": _to_ddb_item({"pk": poster_pk, "sk": bs.WALLET_SK}),
            "UpdateExpression": (
                "SET wallet_balance_cents = if_not_exists(wallet_balance_cents, :z) + :amt, "
                "currency = :c, updated_at = :ts"
            ),
            "ExpressionAttributeValues": _to_ddb_item({":z": 0, ":amt": amount_cents, ":c": "usd", ":ts": ts}),
        }
    }

    try:
        _transact_client().transact_write_items(TransactItems=[escrow_update, refund_put, wallet_credit])
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code == "TransactionCanceledException":
            fresh = _get_escrow(bounty_id)
            if fresh and fresh.get("escrow_status") == "refunded":
                return STORE.get_ticket(ticket_id) or {}
            if fresh and fresh.get("escrow_status") == "released":
                raise TicketBountyError(409, "bounty_already_paid_out", "Cannot cancel a paid-out bounty")
        raise

    # Reverse the original poster debit (best-effort, outside the transaction).
    try:
        bs.settle_or_reverse_ledger(T.billing, "pk", poster_pk, escrow["ledger_sk"], "reversed")
    except Exception:
        pass

    # Flip ticket to cancelled + drop off the board.
    STORE._table.update_item(
        Key=_meta_item_key_for(ticket_id),
        UpdateExpression=(
            "SET bounty_status = :bs, #status = :st, bounty_cancelled_at = :ts, updated_at = :ts, "
            "version = version + :one, gsi2pk = :gsi2pk, gsi2sk = :gsi2sk "
            "REMOVE gsi_bounty_pk, gsi_bounty_sk"
        ),
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":bs": "cancelled", ":st": "cancelled", ":ts": ts, ":one": 1,
            ":gsi2pk": _status_index_pk("cancelled"), ":gsi2sk": _updated_index_sk(ts, ticket_id),
        },
    )
    _write_bounty_activity(ticket_id=ticket_id, actor_sub=actor_sub, ts=ts,
                           activity_type="bounty_cancelled")
    _notify(poster_sub, event="bounty_cancelled", title="Bounty refunded",
            details={"ticket_id": ticket_id, "amount_cents": amount_cents, "reason": reason})
    claimant = ticket.get("claimed_by_sub")
    if claimant and claimant != poster_sub:
        _notify(claimant, event="bounty_cancelled_claimant", title="Active bounty cancelled",
                details={"ticket_id": ticket_id})
    _audit("bounty_cancelled", actor_sub, request,
           ticket_id=ticket_id, bounty_id=bounty_id, amount_cents=amount_cents,
           reason=reason, is_admin=is_admin)
    return STORE.get_ticket(ticket_id) or {}


# ---------------------------------------------------------------------------
# TBT-008 — bounty board (read-only)
# ---------------------------------------------------------------------------
def _project_bounty_header(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "ticket_id": row.get("ticket_id", ""),
        "subject": row.get("subject", ""),
        "owner_sub": row.get("owner_sub", ""),
        "status": row.get("status", "open"),
        "labels": list(row.get("labels") or []),
        "created_at": int(row.get("created_at", 0) or 0),
        "updated_at": int(row.get("updated_at", 0) or 0),
        "bounty_amount_cents": int(row.get("bounty_amount_cents") or 0),
        "bounty_currency": row.get("bounty_currency", "usd"),
        "bounty_status": row.get("bounty_status"),
        "bounty_id": row.get("bounty_id"),
        "bounty_funded_at": (
            int(row["bounty_funded_at"]) if row.get("bounty_funded_at") is not None else None
        ),
    }


def list_open_bounties(*, limit: int = 25, cursor: Optional[str] = None) -> dict[str, Any]:
    _require_bounties_enabled()
    page_limit = max(1, min(int(limit or 25), 100))
    headers, next_cursor = STORE._query_headers_by_index(
        index_name=S.tickets_bounty_index_name,
        pk="BOUNTY#OPEN",
        key_expr="gsi_bounty_pk = :pk",
        limit=page_limit,
        cursor=cursor,
    )
    return {
        "items": [_project_bounty_header(row) for row in headers],
        "next_cursor": next_cursor,
    }
