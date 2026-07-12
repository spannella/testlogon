"""Hotel folios + payments router (QloApps PMS vertical, HTL-032).

Prefix: ``/ui/hotels``.  Flag-gated (``HOTEL_PMS_ENABLED``, default OFF —
reused from HTL-001, no new master flag).  Every handler calls
``_require_enabled()`` first; when the flag is off all endpoints return 404
and the platform is byte-for-byte unchanged.

Auth split (mirrors app/routers/inventory.py pattern):
  * Read endpoints  (GET folio / folio PDF)  → ``require_ui_session``
  * Write endpoints (open/lines/addons/deposit/payments/close)
                                             → ``require_admin_or_root_csrf``

Route-ordering: GET bare folio declared first, then explicit literal-suffix
POST routes (/open, /lines, /addons, /deposit, /payments, /close) and GET
/pdf — no catch-all path param (CLAUDE.md KYC-/templates-before-/{case_id}
lesson).

Binary-safe PDF: ``Response(media_type="application/pdf")`` — NOT
``PlainTextResponse`` (CLAUDE.md GAP-0209 lesson).
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root_csrf
from app.models import (
    DepositPolicyIn,
    FolioAddonIn,
    FolioLineIn,
    FolioOut,
    FolioPaymentIn,
    TakeDepositIn,
)
from app.services import hotel_folios as folios
from app.services.sessions import require_ui_session

hotel_folios_router = APIRouter(prefix="/ui/hotels", tags=["hotel-folios"])

# Path template shared by all folio endpoints
_FOLIO = "/{hotel_id}/reservations/{rid}/folio"


def _require_enabled() -> None:
    """Delegate to service flag check (raises 404 when flag is off)."""
    folios._require_enabled()


# ---------------------------------------------------------------------------
# Router-local helpers
# ---------------------------------------------------------------------------


def _resolve_reservation(hotel_id: str, rid: str) -> Dict[str, Any]:
    """Resolve the HTL-018 reservation (forward dep, Tier-2).

    Isolated in a single function so the forward coupling lives in one place
    and tests can patch it easily (HTL-032 §4.3).

    Returns the reservation dict; raises 404 if absent or under a different
    hotel.
    """
    try:
        from app.services import hotel_reservations as resv  # forward dep (Tier-2)
        reservation = resv.get_reservation(rid)
    except Exception:
        reservation = None

    if not reservation or reservation.get("hotel_id") != hotel_id:
        raise HTTPException(status_code=404, detail="Reservation not found")
    return reservation  # type: ignore[return-value]


def _assert_scope(
    folio: Dict[str, Any],
    hotel_id: str,
    session: Dict[str, Any],
) -> None:
    """Enforce hotel isolation + guest ownership on read endpoints (§5.4).

    Admin/root sessions may read any folio under the matching hotel.
    Guest sessions may only read their own folio.
    """
    if folio.get("hotel_id") != hotel_id:
        raise HTTPException(status_code=404, detail="Folio not found")
    role = str(session.get("role", "")).lower()
    if role not in ("admin", "root"):
        if folio.get("guest_sub") != session.get("user_sub"):
            raise HTTPException(status_code=403, detail="Not authorized for this folio")


# ---------------------------------------------------------------------------
# Endpoints (declaration order: GET bare read first, then literal-suffix POSTs,
# then GET /pdf last — all literal segments, no catch-all /{action} param)
# ---------------------------------------------------------------------------


@hotel_folios_router.get(_FOLIO, response_model=FolioOut)
async def get_folio(
    hotel_id: str,
    rid: str,
    session: Dict = Depends(require_ui_session),
) -> FolioOut:
    """Read the folio; auto-opens it on first read (idempotent, HTL-029 §5.1).

    Accessible to the guest (``require_ui_session``) — ``_assert_scope``
    enforces ownership for non-admin callers.
    """
    _require_enabled()
    folio = folios.get_folio(rid)
    if folio is None:
        reservation = _resolve_reservation(hotel_id, rid)
        folio = folios.open_folio(reservation, user_sub=session["user_sub"])
    _assert_scope(folio, hotel_id, session)
    return FolioOut(**folio)


@hotel_folios_router.post(_FOLIO + "/open", response_model=FolioOut)
async def open_folio(
    hotel_id: str,
    rid: str,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> FolioOut:
    """Explicitly open/seed the folio for a reservation (admin only).

    Idempotent — a re-open returns the existing folio without re-seeding lines.
    """
    _require_enabled()
    reservation = _resolve_reservation(hotel_id, rid)
    folio = folios.open_folio(reservation, user_sub=user.sub)
    return FolioOut(**folio)


@hotel_folios_router.post(_FOLIO + "/lines", response_model=FolioOut)
async def add_line(
    hotel_id: str,
    rid: str,
    body: FolioLineIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> FolioOut:
    """Add an arbitrary charge line to the folio (admin only)."""
    _require_enabled()
    folios.add_line_item(
        rid,
        line_type=body.line_type,
        description=body.description,
        quantity=body.quantity,
        unit_price_cents=body.unit_price_cents,
        sku=body.sku,
        user_sub=user.sub,
    )
    return FolioOut(**folios.get_folio(rid))


@hotel_folios_router.post(_FOLIO + "/addons", response_model=FolioOut)
async def add_addon(
    hotel_id: str,
    rid: str,
    body: FolioAddonIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> FolioOut:
    """Attach a catalog add-on SKU to the folio (admin only).

    Price is resolved server-side from the catalog (anti-tamper).
    """
    _require_enabled()
    folios.add_addon_to_folio(
        rid,
        sku=body.sku,
        quantity=body.quantity,
        user_sub=user.sub,
    )
    return FolioOut(**folios.get_folio(rid))


@hotel_folios_router.post(_FOLIO + "/deposit-policy", response_model=FolioOut)
async def set_deposit_policy(
    hotel_id: str,
    rid: str,
    body: DepositPolicyIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> FolioOut:
    """Set or update the deposit policy on an open folio (admin only)."""
    _require_enabled()
    folio = folios.set_deposit_policy(
        rid,
        kind=body.kind,
        pct_bps=body.pct_bps,
        fixed_cents=body.fixed_cents,
        user_sub=user.sub,
    )
    return FolioOut(**folio)


@hotel_folios_router.post(_FOLIO + "/deposit", response_model=FolioOut)
async def take_deposit(
    hotel_id: str,
    rid: str,
    body: TakeDepositIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> FolioOut:
    """Atomically hold a deposit against the guest's wallet (admin only).

    Uses DynamoDB transact_write_items (wallet debit + escrow put + ledger put).
    Idempotent: a second call for the same reservation returns 409
    ``"Deposit already held"``.
    """
    _require_enabled()
    folios.take_deposit(rid, amount_cents=body.amount_cents, user_sub=user.sub)
    return FolioOut(**folios.get_folio(rid))


@hotel_folios_router.post(_FOLIO + "/payments", response_model=FolioOut)
async def record_payment(
    hotel_id: str,
    rid: str,
    body: FolioPaymentIn,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> FolioOut:
    """Record a payment against the folio (admin only).

    ``method="wallet"`` deducts exactly ``amount_cents`` once from the guest
    wallet.  External/cash/check methods are informational (no wallet move).
    """
    _require_enabled()
    folios.record_folio_payment(
        rid,
        amount_cents=body.amount_cents,
        method=body.method,
        reference=body.reference,
        user_sub=user.sub,
    )
    return FolioOut(**folios.get_folio(rid))


@hotel_folios_router.post(_FOLIO + "/close", response_model=FolioOut)
async def close_folio(
    hotel_id: str,
    rid: str,
    user: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> FolioOut:
    """Close an open folio (admin only).

    Idempotent under replay (already-closed is a no-op success).
    """
    _require_enabled()
    folio = folios.close_folio(rid, user_sub=user.sub)
    return FolioOut(**folio)


@hotel_folios_router.get(_FOLIO + "/pdf")
async def folio_pdf(
    hotel_id: str,
    rid: str,
    session: Dict = Depends(require_ui_session),
) -> Response:
    """Download the folio as a binary-safe PDF.

    Uses ``Response(media_type="application/pdf")`` — NOT ``PlainTextResponse``
    (CLAUDE.md GAP-0209 lesson: PlainTextResponse would UTF-8 re-encode and
    corrupt the ``%PDF`` bytes).
    """
    _require_enabled()
    folio = folios.get_folio(rid)
    if folio is None:
        raise HTTPException(status_code=404, detail="Folio not found")
    _assert_scope(folio, hotel_id, session)
    pdf = folios.render_folio_pdf(rid)
    if not pdf:
        raise HTTPException(status_code=404, detail="Folio PDF not available")
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="folio-{rid}.pdf"'},
    )
