"""CUS-003: Cards as a managed resource — list/status lifecycle + attributes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from app.core.settings import S
from app.models import (
    CardAttributeOut,
    CardAttributeSetIn,
    CardListOut,
    CardOut,
    CardStatusUpdateIn,
)
from app.services.sessions import require_ui_session

router = APIRouter(tags=["cards"])


def _require_flag() -> None:
    obp_ok = getattr(S, "open_bank_project_enabled", False)
    cus_ok = getattr(S, "customer_entity_enabled", False)
    if not (obp_ok and cus_ok):
        raise HTTPException(status_code=404, detail="customer_entity_not_enabled")


def _get_store():
    try:
        from app.services.cards_resource import CardResourceStore
        return CardResourceStore()
    except ImportError:
        raise HTTPException(status_code=503, detail="cards_service_unavailable")


def _card_dict_to_out(d: dict) -> CardOut:
    return CardOut(
        card_id=d["card_id"],
        brand=d.get("brand"),
        last4=d.get("last4"),
        exp_month=d.get("exp_month"),
        exp_year=d.get("exp_year"),
        label=d.get("label"),
        is_default=bool(d.get("is_default", False)),
        card_status=d.get("card_status", "ACTIVE"),
        card_version=int(d.get("card_version", 1)),
        created_at=int(d["created_at"]) if d.get("created_at") is not None else None,
    )


# ---------------------------------------------------------------------------
# List cards
# ---------------------------------------------------------------------------

@router.get("/ui/cards", response_model=CardListOut)
def list_cards(ctx: dict = Depends(require_ui_session)) -> CardListOut:
    _require_flag()
    store = _get_store()
    cards = store.list_cards(ctx["user_sub"])
    return CardListOut(cards=[_card_dict_to_out(c) for c in cards])


# ---------------------------------------------------------------------------
# Attribute sub-routes — before /{card_id} to avoid capture
# ---------------------------------------------------------------------------

@router.get("/ui/cards/{card_id}/attributes", response_model=list[CardAttributeOut])
def list_card_attributes(
    card_id: str,
    ctx: dict = Depends(require_ui_session),
) -> list[CardAttributeOut]:
    _require_flag()
    store = _get_store()
    attrs = store.list_card_attributes(ctx["user_sub"], card_id)
    return [
        CardAttributeOut(
            attribute_id=a["attribute_id"],
            name=a["name"],
            type=a["type"],
            value=a["value"],
            created_at=int(a["created_at"]) if a.get("created_at") is not None else None,
        )
        for a in attrs
    ]


@router.put("/ui/cards/{card_id}/attributes", response_model=CardAttributeOut)
def set_card_attribute(
    card_id: str,
    body: CardAttributeSetIn,
    request: Request,
    ctx: dict = Depends(require_ui_session),
) -> CardAttributeOut:
    _require_flag()
    store = _get_store()
    result = store.set_card_attribute(
        ctx["user_sub"],
        card_id,
        body.name,
        body.type,
        body.value,
        actor_sub=ctx["user_sub"],
        request=request,
    )
    return CardAttributeOut(
        attribute_id=result["attribute_id"],
        name=result["name"],
        type=result["type"],
        value=result["value"],
        created_at=int(result["created_at"]) if result.get("created_at") is not None else None,
    )


@router.delete("/ui/cards/{card_id}/attributes/{name}", status_code=200)
def delete_card_attribute(
    card_id: str,
    name: str,
    request: Request,
    ctx: dict = Depends(require_ui_session),
) -> dict:
    _require_flag()
    store = _get_store()
    store.delete_card_attribute(ctx["user_sub"], card_id, name, actor_sub=ctx["user_sub"], request=request)
    return {"ok": True}


# ---------------------------------------------------------------------------
# Status update
# ---------------------------------------------------------------------------

@router.patch("/ui/cards/{card_id}/status", response_model=CardOut)
def update_card_status(
    card_id: str,
    body: CardStatusUpdateIn,
    request: Request,
    ctx: dict = Depends(require_ui_session),
) -> CardOut:
    _require_flag()
    from app.services.cards_resource import CardNotFoundError, CardConflictError, CardIllegalTransitionError
    store = _get_store()
    try:
        result = store.set_card_status(
            ctx["user_sub"],
            card_id,
            body.status,
            expected_version=body.expected_version,
            actor_sub=ctx["user_sub"],
            request=request,
        )
    except CardNotFoundError:
        raise HTTPException(status_code=404)
    except CardConflictError:
        raise HTTPException(status_code=409, detail={"code": "card_update_conflict"})
    except CardIllegalTransitionError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": "card_illegal_transition", "detail": str(exc)},
        )
    if result is None:
        raise HTTPException(status_code=404)
    return _card_dict_to_out(result)
