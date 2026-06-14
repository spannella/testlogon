"""
POS router — /ui/pos/* endpoints.

Mounted unconditionally in app/main.py; every handler calls _require_enabled()
to return 404 when S.pos_enabled is False.  Follows the pattern established by
app/routers/inventory.py and app/routers/returns_rma.py.
"""
from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from app.services.sessions import require_ui_session
from app.auth.policy import require_admin_or_root_csrf
from app.services.pos_register import (
    _require_enabled,
    create_register,
    get_register,
    open_session,
    get_open_session,
    get_session,
    close_session,
    bind_txn_draft,
    get_txn_draft,
    add_line_item,
    set_line_item_qty,
    remove_line_item,
    list_txn_items,
)
from app.services.pos_tender import (
    tender_cash,
    tender_card,
    tender_wallet,
    void_txn,
    refund_txn,
    get_session_report,
    list_session_txns,
)
from app.services.pos_reports import session_report
from app.services.pos_receipt import (
    get_or_create_pos_receipt,
    get_pos_receipt_bytes,
)
from app.models import (
    RegisterConfig,
    RegisterCreateIn,
    RegisterSessionOut,
    OpenSessionIn,
    CloseSessionIn,
    PosTransactionOut,
    PosTxnDraftOut,
    PosBindTxnIn,
    PosAddLineItemIn,
    PosSetLineQtyIn,
    PosCashTenderIn,
    PosCardTenderIn,
    PosWalletTenderIn,
    PosTxnVoidIn,
    RefundTxnIn,
    PosSessionReportOut,
    ReceiptLinkOut,
    SessionReportOut,
)

pos_router = APIRouter(prefix="/ui/pos", tags=["pos"])


# ── registers ─────────────────────────────────────────────────────────────────

@pos_router.post("/registers", response_model=RegisterConfig)
async def create_register_endpoint(
    body: RegisterCreateIn,
    session: Dict[str, Any] = Depends(require_admin_or_root_csrf),
) -> Dict[str, Any]:
    _require_enabled()
    return create_register(
        user_sub=session["user_sub"],
        label=body.label,
        location_id=body.location_id,
        default_currency=body.default_currency,
    )


@pos_router.get("/registers/{register_id}", response_model=RegisterConfig)
async def get_register_endpoint(
    register_id: str,
    session: Dict[str, Any] = Depends(require_ui_session),
) -> Dict[str, Any]:
    _require_enabled()
    reg = get_register(register_id)
    if not reg:
        raise HTTPException(status_code=404, detail="Register not found")
    return reg


# ── sessions ──────────────────────────────────────────────────────────────────

@pos_router.post("/sessions", response_model=RegisterSessionOut)
async def open_session_endpoint(
    body: OpenSessionIn,
    session: Dict[str, Any] = Depends(require_ui_session),
) -> Dict[str, Any]:
    _require_enabled()
    return open_session(
        cashier_sub=session["user_sub"],
        register_id=body.register_id,
        opening_float_cents=body.opening_float_cents,
        idempotency_key=body.idempotency_key,
    )


@pos_router.get("/registers/{register_id}/open-session", response_model=RegisterSessionOut)
async def get_open_session_endpoint(
    register_id: str,
    session: Dict[str, Any] = Depends(require_ui_session),
) -> Dict[str, Any]:
    _require_enabled()
    result = get_open_session(register_id)
    if not result:
        raise HTTPException(status_code=404, detail="No open session for this register")
    return result


@pos_router.get("/sessions/{session_id}", response_model=RegisterSessionOut)
async def get_session_endpoint(
    session_id: str,
    session: Dict[str, Any] = Depends(require_ui_session),
) -> Dict[str, Any]:
    _require_enabled()
    result = get_session(session_id)
    if not result:
        raise HTTPException(status_code=404, detail="Session not found")
    return result


@pos_router.post("/sessions/{session_id}/close", response_model=RegisterSessionOut)
async def close_session_endpoint(
    session_id: str,
    body: CloseSessionIn,
    session: Dict[str, Any] = Depends(require_ui_session),
) -> Dict[str, Any]:
    _require_enabled()
    # Ownership check: cashier may only close their own session unless admin/root.
    sess = get_session(session_id)
    if sess is None:
        raise HTTPException(status_code=404, detail="Session not found")

    from app.auth.roles import Role
    user_role = session.get("role", Role.USER)
    is_admin = hasattr(user_role, "value") and user_role.value >= Role.ADMIN.value
    if not is_admin and sess.get("cashier_sub") != session["user_sub"]:
        raise HTTPException(status_code=403, detail="You may only close your own session")

    return close_session(
        session_id=session_id,
        counted_cash_cents=body.counted_cash_cents,
        actor_sub=session["user_sub"],
    )


# ── session reports ───────────────────────────────────────────────────────────

@pos_router.get("/sessions/{session_id}/report", response_model=PosSessionReportOut)
async def session_report_endpoint(
    session_id: str,
    session: Dict[str, Any] = Depends(require_admin_or_root_csrf),
) -> Dict[str, Any]:
    _require_enabled()
    return get_session_report(session_id)


@pos_router.get("/sessions/{session_id}/report/x", response_model=SessionReportOut)
async def session_x_report_endpoint(
    session_id: str,
    session: Dict[str, Any] = Depends(require_ui_session),
) -> Dict[str, Any]:
    _require_enabled()
    return session_report(
        session_id,
        "x",
        cashier_sub=session["user_sub"],
        role=session.get("role", "user"),
    )


@pos_router.get("/sessions/{session_id}/report/z", response_model=SessionReportOut)
async def session_z_report_endpoint(
    session_id: str,
    session: Dict[str, Any] = Depends(require_ui_session),
) -> Dict[str, Any]:
    _require_enabled()
    return session_report(
        session_id,
        "z",
        cashier_sub=session["user_sub"],
        role=session.get("role", "user"),
    )


@pos_router.get("/sessions/{session_id}/transactions", response_model=List[PosTransactionOut])
async def list_session_txns_endpoint(
    session_id: str,
    session: Dict[str, Any] = Depends(require_ui_session),
) -> List[Dict[str, Any]]:
    _require_enabled()
    return list_session_txns(session_id)


# ── transaction drafts (cart binding + line items) ────────────────────────────

@pos_router.post("/sessions/{session_id}/txns", response_model=PosTxnDraftOut)
async def bind_txn_endpoint(
    session_id: str,
    body: PosBindTxnIn,
    session: Dict[str, Any] = Depends(require_ui_session),
) -> Dict[str, Any]:
    _require_enabled()
    return bind_txn_draft(
        cashier_sub=session["user_sub"],
        session_id=session_id,
        correlation_id=body.correlation_id,
    )


@pos_router.get("/txns/{txn_id}", response_model=PosTxnDraftOut)
async def get_txn_endpoint(
    txn_id: str,
    session: Dict[str, Any] = Depends(require_ui_session),
) -> Dict[str, Any]:
    _require_enabled()
    return get_txn_draft(cashier_sub=session["user_sub"], txn_id=txn_id)


# ── receipt (POS-009) ─────────────────────────────────────────────────────────

def _require_txn_owner_or_admin(txn_id: str, session: Dict[str, Any]) -> None:
    """Cashier may only access their own txn's receipt; admin/root any."""
    from app.core.tables import T
    from app.auth.roles import Role

    item = T.pos.get_item(Key={"pos_pk": f"TXN#{txn_id}", "pos_sk": "META"}).get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Transaction not found")
    user_role = session.get("role", Role.USER)
    role_val = getattr(user_role, "value", user_role)
    is_admin = role_val in ("admin", "root")
    if not is_admin and item.get("cashier_sub") != session["user_sub"]:
        raise HTTPException(status_code=403, detail="You may only access your own receipts")


@pos_router.get("/txns/{txn_id}/receipt", response_model=ReceiptLinkOut)
async def get_txn_receipt_endpoint(
    txn_id: str,
    session: Dict[str, Any] = Depends(require_ui_session),
) -> Dict[str, Any]:
    _require_enabled()
    _require_txn_owner_or_admin(txn_id, session)
    return get_or_create_pos_receipt(txn_id)


@pos_router.get("/txns/{txn_id}/receipt/pdf")
async def get_txn_receipt_pdf_endpoint(
    txn_id: str,
    session: Dict[str, Any] = Depends(require_ui_session),
) -> Response:
    _require_enabled()
    _require_txn_owner_or_admin(txn_id, session)
    pdf_bytes = get_pos_receipt_bytes(txn_id)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="pos-receipt-{txn_id}.pdf"',
        },
    )


@pos_router.post("/txns/{txn_id}/lines")
async def add_line_item_endpoint(
    txn_id: str,
    body: PosAddLineItemIn,
    session: Dict[str, Any] = Depends(require_ui_session),
) -> Dict[str, Any]:
    _require_enabled()
    return add_line_item(
        cashier_sub=session["user_sub"],
        txn_id=txn_id,
        sku=body.sku,
        name=body.name,
        unit_price_cents=body.unit_price_cents,
        item_id=body.item_id,
        category_id=body.category_id,
        quantity=body.quantity,
    )


@pos_router.get("/txns/{txn_id}/lines")
async def list_txn_lines_endpoint(
    txn_id: str,
    session: Dict[str, Any] = Depends(require_ui_session),
) -> List[Dict[str, Any]]:
    _require_enabled()
    return list_txn_items(cashier_sub=session["user_sub"], txn_id=txn_id)


@pos_router.patch("/txns/{txn_id}/lines/{sku}")
async def set_line_qty_endpoint(
    txn_id: str,
    sku: str,
    body: PosSetLineQtyIn,
    session: Dict[str, Any] = Depends(require_ui_session),
) -> Dict[str, Any]:
    _require_enabled()
    return set_line_item_qty(
        cashier_sub=session["user_sub"],
        txn_id=txn_id,
        sku=sku,
        quantity=body.quantity,
    )


@pos_router.delete("/txns/{txn_id}/lines/{sku}")
async def remove_line_item_endpoint(
    txn_id: str,
    sku: str,
    decrement: int = 1,
    session: Dict[str, Any] = Depends(require_ui_session),
) -> Dict[str, Any]:
    _require_enabled()
    return remove_line_item(
        cashier_sub=session["user_sub"],
        txn_id=txn_id,
        sku=sku,
        decrement=decrement,
    )


# ── tender / void / refund ────────────────────────────────────────────────────

@pos_router.post("/sessions/{session_id}/transactions/{txn_id}/tender-cash",
                 response_model=PosTransactionOut)
async def tender_cash_endpoint(
    session_id: str,
    txn_id: str,
    body: PosCashTenderIn,
    session: Dict[str, Any] = Depends(require_ui_session),
) -> Dict[str, Any]:
    _require_enabled()
    return tender_cash(
        session_id=session_id,
        txn_id=txn_id,
        cashier_sub=session["user_sub"],
        amount_tendered_cents=body.amount_tendered_cents,
        idempotency_key=body.idempotency_key,
    )


@pos_router.post("/sessions/{session_id}/transactions/{txn_id}/tender-card",
                 response_model=PosTransactionOut)
async def tender_card_endpoint(
    session_id: str,
    txn_id: str,
    body: PosCardTenderIn,
    session: Dict[str, Any] = Depends(require_ui_session),
) -> Dict[str, Any]:
    _require_enabled()
    return tender_card(
        session_id=session_id,
        txn_id=txn_id,
        cashier_sub=session["user_sub"],
        amount_tendered_cents=body.amount_tendered_cents,
        payment_method_id=body.payment_method_id,
        idempotency_key=body.idempotency_key,
        card_kind=body.card_kind,
        last4=body.last4,
    )


@pos_router.post("/sessions/{session_id}/transactions/{txn_id}/tender-wallet",
                 response_model=PosTransactionOut)
async def tender_wallet_endpoint(
    session_id: str,
    txn_id: str,
    body: PosWalletTenderIn,
    session: Dict[str, Any] = Depends(require_ui_session),
) -> Dict[str, Any]:
    _require_enabled()
    return tender_wallet(
        session_id=session_id,
        txn_id=txn_id,
        cashier_sub=session["user_sub"],
        amount_tendered_cents=body.amount_tendered_cents,
        idempotency_key=body.idempotency_key,
    )


@pos_router.post("/txns/{txn_id}/void", response_model=PosTransactionOut)
async def void_txn_endpoint(
    txn_id: str,
    body: PosTxnVoidIn,
    session: Dict[str, Any] = Depends(require_ui_session),
) -> Dict[str, Any]:
    _require_enabled()
    return void_txn(
        txn_id=txn_id,
        cashier_sub=session["user_sub"],
        reason=body.reason,
    )


@pos_router.post("/txns/{txn_id}/refund", response_model=PosTransactionOut)
async def refund_txn_endpoint(
    txn_id: str,
    body: RefundTxnIn,
    session: Dict[str, Any] = Depends(require_ui_session),
) -> Dict[str, Any]:
    _require_enabled()
    return refund_txn(
        txn_id=txn_id,
        cashier_sub=session["user_sub"],
        reason=body.reason,
    )
