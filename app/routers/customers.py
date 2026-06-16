"""CUS-001 + CUS-002: Customer entity + user-link + message thread router."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root
from app.auth.roles import Role, normalize_role
from app.core.settings import S
from app.models import (
    CustomerAttributeOut,
    CustomerAttributeSetIn,
    CustomerCreateIn,
    CustomerLinkIn,
    CustomerLinkOut,
    CustomerListOut,
    CustomerMessageCreateIn,
    CustomerMessageListOut,
    CustomerMessageOut,
    CustomerOut,
    CustomerPatchIn,
)
from app.services.sessions import require_ui_session

router = APIRouter(tags=["customers"])


def _require_flag() -> None:
    """Check umbrella OBP flag AND per-series customer_entity flag."""
    obp_ok = getattr(S, "open_bank_project_enabled", False)
    cus_ok = getattr(S, "customer_entity_enabled", False)
    if not (obp_ok and cus_ok):
        raise HTTPException(status_code=404, detail="customer_entity_not_enabled")


def _item_to_out(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "customer_id": item["customer_id"],
        "customer_number": item["customer_number"],
        "legal_name": item["legal_name"],
        "date_of_birth": item.get("date_of_birth"),
        "mobile_phone": item.get("mobile_phone"),
        "email": item.get("email"),
        "kyc_status": item.get("kyc_status", "none"),
        "branch_id": item.get("branch_id"),
        "created_at": int(item["created_at"]),
        "updated_at": int(item["updated_at"]),
        "version": int(item["version"]),
    }


def _get_store():
    try:
        from app.services.customers import CustomerStore
        return CustomerStore()
    except ImportError:
        raise HTTPException(status_code=503, detail="customers_service_unavailable")


def _get_msg_store():
    try:
        from app.services.customer_messages import CustomerMessageStore
        return CustomerMessageStore()
    except ImportError:
        raise HTTPException(status_code=503, detail="customer_messages_service_unavailable")


def _assert_message_access(ctx: dict, customer_id: str) -> None:
    """Permit ADMIN/ROOT unconditionally; permit the linked USER."""
    role = normalize_role(ctx.get("role", "user"))
    if role in (Role.ADMIN, Role.ROOT):
        return
    try:
        store = _get_store()
        ref = store.resolve_customer_for_user(ctx["user_sub"])
    except Exception:
        ref = None
    if not ref or ref.get("customer_id") != customer_id:
        raise HTTPException(status_code=403, detail={"code": "customer_access_forbidden"})


# ---------------------------------------------------------------------------
# CUS-002: /me — must be BEFORE /{customer_id}
# ---------------------------------------------------------------------------

@router.get("/ui/customers/me", response_model=CustomerOut)
def get_my_customer(ctx: dict = Depends(require_ui_session)) -> CustomerOut:
    _require_flag()
    store = _get_store()
    customer_ref = store.resolve_customer_for_user(ctx["user_sub"])
    if not customer_ref:
        raise HTTPException(status_code=404, detail={"code": "customer_not_linked"})
    customer = store.get_customer(customer_ref["customer_id"])
    if not customer:
        raise HTTPException(status_code=404)
    return CustomerOut(**_item_to_out(customer))


# ---------------------------------------------------------------------------
# CUS-001: List + Create
# ---------------------------------------------------------------------------

@router.get("/ui/customers", response_model=CustomerListOut)
def list_customers(
    branch_id: str | None = None,
    cursor: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> CustomerListOut:
    _require_flag()
    store = _get_store()
    if branch_id:
        items, next_cursor = store.list_by_branch(branch_id, cursor=cursor, limit=limit)
    else:
        items, next_cursor = store._list_all(cursor=cursor, limit=limit)
    return CustomerListOut(
        customers=[CustomerOut(**_item_to_out(c)) for c in items],
        cursor=next_cursor,
    )


@router.post("/ui/customers", response_model=CustomerOut, status_code=201)
def create_customer(
    body: CustomerCreateIn,
    request: Request,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> CustomerOut:
    _require_flag()
    store = _get_store()
    item = store.create_customer(
        legal_name=body.legal_name,
        date_of_birth=body.date_of_birth,
        mobile_phone=body.mobile_phone,
        email=body.email,
        branch_id=body.branch_id,
        actor_sub=user.sub,
        request=request,
    )
    return CustomerOut(**_item_to_out(item))


# ---------------------------------------------------------------------------
# CUS-001: Attribute sub-routes — must be BEFORE /{customer_id}
# ---------------------------------------------------------------------------

@router.get("/ui/customers/{customer_id}/attributes", response_model=list[CustomerAttributeOut])
def list_attributes(
    customer_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> list[CustomerAttributeOut]:
    _require_flag()
    store = _get_store()
    items = store.list_attributes(customer_id)
    return [
        CustomerAttributeOut(
            attribute_id=it["attribute_id"],
            name=it["name"],
            type=it["type"],
            value=it["value"],
            created_at=int(it["created_at"]),
        )
        for it in items
    ]


@router.put("/ui/customers/{customer_id}/attributes", response_model=CustomerAttributeOut)
def set_attribute(
    customer_id: str,
    body: CustomerAttributeSetIn,
    request: Request,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> CustomerAttributeOut:
    _require_flag()
    from app.services.customers import CustomerNotFoundError, CustomerAttributeValidationError
    store = _get_store()
    try:
        item = store.set_attribute(
            customer_id,
            name=body.name,
            type=body.type,
            value=body.value,
            actor_sub=user.sub,
            request=request,
        )
    except CustomerNotFoundError:
        raise HTTPException(status_code=404)
    except CustomerAttributeValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return CustomerAttributeOut(
        attribute_id=item["attribute_id"],
        name=item["name"],
        type=item["type"],
        value=item["value"],
        created_at=int(item["created_at"]),
    )


@router.delete("/ui/customers/{customer_id}/attributes/{attribute_id}", status_code=200)
def delete_attribute(
    customer_id: str,
    attribute_id: str,
    request: Request,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> dict:
    _require_flag()
    store = _get_store()
    store.delete_attribute(customer_id, attribute_id, actor_sub=user.sub, request=request)
    return {"ok": True}


# ---------------------------------------------------------------------------
# CUS-002: Link endpoints — /{customer_id}/link + /links
# ---------------------------------------------------------------------------

@router.post("/ui/customers/{customer_id}/link", response_model=CustomerLinkOut)
def link_customer_user(
    customer_id: str,
    body: CustomerLinkIn,
    request: Request,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> CustomerLinkOut:
    _require_flag()
    from app.services.customers import CustomerLinkConflictError
    store = _get_store()
    customer = store.get_customer(customer_id)
    if not customer:
        raise HTTPException(status_code=404)
    try:
        result = store.link_user(customer_id, body.user_sub, actor_sub=user.sub)
    except CustomerLinkConflictError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": "customer_already_linked", "existing_customer_id": exc.existing_customer_id},
        )
    try:
        from app.services.alerts import audit_event
        audit_event("customer.linked", user.sub, request, customer_id=customer_id, linked_user_sub=body.user_sub)
    except Exception:
        pass
    return CustomerLinkOut(
        customer_id=result.get("customer_id", customer_id),
        user_sub=result.get("user_sub", body.user_sub),
        linked_at=int(result.get("linked_at", 0)),
        linked_by=result.get("linked_by", user.sub),
    )


@router.get("/ui/customers/{customer_id}/links", response_model=list[CustomerLinkOut])
def list_customer_links(
    customer_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> list[CustomerLinkOut]:
    _require_flag()
    store = _get_store()
    links = store.list_links(customer_id)
    return [
        CustomerLinkOut(
            customer_id=lnk.get("customer_id", customer_id),
            user_sub=lnk.get("user_sub", ""),
            linked_at=int(lnk.get("linked_at", 0)),
            linked_by=lnk.get("linked_by", ""),
        )
        for lnk in links
    ]


# ---------------------------------------------------------------------------
# CUS-002: Message thread endpoints
# ---------------------------------------------------------------------------

@router.post("/ui/customers/{customer_id}/messages", response_model=CustomerMessageOut)
def post_customer_message(
    customer_id: str,
    body: CustomerMessageCreateIn,
    request: Request,
    ctx: dict = Depends(require_ui_session),
) -> CustomerMessageOut:
    _require_flag()
    _assert_message_access(ctx, customer_id)
    role = normalize_role(ctx.get("role", "user"))
    author_role = "STAFF" if role in (Role.ADMIN, Role.ROOT) else "CUSTOMER"
    msg_store = _get_msg_store()
    msg = msg_store.post_message(
        customer_id,
        author_sub=ctx["user_sub"],
        author_role=author_role,  # type: ignore[arg-type]
        body=body.body,
    )
    try:
        from app.services.alerts import audit_event
        audit_event(
            "customer.message_sent", ctx["user_sub"], request,
            customer_id=customer_id,
            message_id=msg["message_id"],
            author_role=author_role,
        )
    except Exception:
        pass
    return CustomerMessageOut(
        message_id=msg["message_id"],
        author_sub=msg["author_sub"],
        author_role=msg["author_role"],
        body=msg["body"],
        created_at=int(msg["created_at"]),
    )


@router.get("/ui/customers/{customer_id}/messages", response_model=CustomerMessageListOut)
def list_customer_messages(
    customer_id: str,
    cursor: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    newest_first: bool = False,
    ctx: dict = Depends(require_ui_session),
) -> CustomerMessageListOut:
    _require_flag()
    _assert_message_access(ctx, customer_id)
    msg_store = _get_msg_store()
    result = msg_store.list_messages(customer_id, cursor=cursor, limit=limit, newest_first=newest_first)
    messages = [
        CustomerMessageOut(
            message_id=m["message_id"],
            author_sub=m["author_sub"],
            author_role=m["author_role"],
            body=m["body"],
            created_at=int(m["created_at"]),
        )
        for m in result.get("messages", [])
    ]
    return CustomerMessageListOut(messages=messages, cursor=result.get("cursor"))


# ---------------------------------------------------------------------------
# CUS-001: Get + Patch — LAST to avoid capturing /me, /link, /messages
# ---------------------------------------------------------------------------

@router.get("/ui/customers/{customer_id}", response_model=CustomerOut)
def get_customer(
    customer_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> CustomerOut:
    _require_flag()
    store = _get_store()
    item = store.get_customer(customer_id)
    if not item:
        raise HTTPException(status_code=404)
    return CustomerOut(**_item_to_out(item))


@router.patch("/ui/customers/{customer_id}", response_model=CustomerOut)
def patch_customer(
    customer_id: str,
    body: CustomerPatchIn,
    request: Request,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> CustomerOut:
    _require_flag()
    from app.services.customers import CustomerNotFoundError, CustomerConflictError
    store = _get_store()
    fields = body.model_dump(exclude={"expected_version"}, exclude_none=True)
    try:
        item = store.update_customer(
            customer_id=customer_id,
            expected_version=body.expected_version,
            actor_sub=user.sub,
            request=request,
            **fields,
        )
    except CustomerNotFoundError:
        raise HTTPException(status_code=404)
    except CustomerConflictError:
        raise HTTPException(status_code=409, detail={"code": "customer_update_conflict"})
    return CustomerOut(**_item_to_out(item))
