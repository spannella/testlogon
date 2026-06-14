"""CUS-004: Financial Products + Collections router."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root
from app.core.settings import S
from app.models import (
    FinancialProductCreateIn,
    FinancialProductListOut,
    FinancialProductOut,
    FinancialProductPatchIn,
    ProductAttributeListOut,
    ProductAttributeOut,
    ProductAttributeSetIn,
    ProductCollectionListOut,
    ProductCollectionMemberIn,
    ProductCollectionOut,
    ProductCollectionUpsertIn,
)

router = APIRouter(tags=["financial-products"])


def _require_flag() -> None:
    obp_ok = getattr(S, "open_bank_project_enabled", False)
    fp_ok = getattr(S, "financial_products_enabled", False)
    if not (obp_ok and fp_ok):
        raise HTTPException(status_code=404, detail="Financial products not enabled.")


def _get_store():
    try:
        from app.services.financial_products import FinancialProductStore
        return FinancialProductStore()
    except ImportError:
        raise HTTPException(status_code=503, detail="financial_products_service_unavailable")


def _product_out(item: dict) -> FinancialProductOut:
    return FinancialProductOut(
        product_code=item["product_code"],
        name=item["name"],
        parent_product_code=item.get("parent_product_code"),
        category=item.get("category"),
        family=item.get("family"),
        super_family=item.get("super_family"),
        more_info_url=item.get("more_info_url"),
        description=item.get("description"),
        created_at=int(item["created_at"]),
        updated_at=int(item["updated_at"]),
        version=int(item["version"]),
    )


def _collection_out(item: dict) -> ProductCollectionOut:
    return ProductCollectionOut(
        collection_code=item["collection_code"],
        name=item["name"],
        product_codes=item.get("product_codes", []),
        updated_at=int(item["updated_at"]),
    )


# ---------------------------------------------------------------------------
# Collections — declared BEFORE /{product_code} to avoid route capture
# ---------------------------------------------------------------------------

@router.get("/ui/financial-products/collections", response_model=ProductCollectionListOut)
def list_collections(
    cursor: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> ProductCollectionListOut:
    _require_flag()
    store = _get_store()
    items, next_cursor = store.list_collections(limit=limit, cursor=cursor)
    return ProductCollectionListOut(
        items=[_collection_out(i) for i in items],
        cursor=next_cursor,
    )


@router.put("/ui/financial-products/collections/{collection_code}", response_model=ProductCollectionOut)
def upsert_collection(
    collection_code: str,
    body: ProductCollectionUpsertIn,
    request: Request,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> ProductCollectionOut:
    _require_flag()
    store = _get_store()
    item = store.upsert_collection(
        collection_code,
        name=body.name,
        product_codes=body.product_codes,
    )
    try:
        from app.services.alerts import audit_event
        audit_event("product.collection_updated", user.sub, request, collection_code=collection_code)
    except Exception:
        pass
    return _collection_out(item)


@router.get("/ui/financial-products/collections/{collection_code}", response_model=ProductCollectionOut)
def get_collection(
    collection_code: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> ProductCollectionOut:
    _require_flag()
    from app.services.financial_products import CollectionNotFoundError
    store = _get_store()
    try:
        item = store.get_collection(collection_code)
    except CollectionNotFoundError:
        raise HTTPException(status_code=404)
    return _collection_out(item)


@router.post("/ui/financial-products/collections/{collection_code}/members", response_model=ProductCollectionOut)
def add_to_collection(
    collection_code: str,
    body: ProductCollectionMemberIn,
    request: Request,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> ProductCollectionOut:
    _require_flag()
    from app.services.financial_products import CollectionNotFoundError
    store = _get_store()
    try:
        item = store.add_to_collection(collection_code, body.product_code)
    except CollectionNotFoundError:
        raise HTTPException(status_code=404)
    try:
        from app.services.alerts import audit_event
        audit_event("product.collection_updated", user.sub, request, collection_code=collection_code)
    except Exception:
        pass
    return _collection_out(item)


@router.delete("/ui/financial-products/collections/{collection_code}/members/{product_code}", response_model=ProductCollectionOut)
def remove_from_collection(
    collection_code: str,
    product_code: str,
    request: Request,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> ProductCollectionOut:
    _require_flag()
    from app.services.financial_products import CollectionNotFoundError
    store = _get_store()
    try:
        item = store.remove_from_collection(collection_code, product_code)
    except CollectionNotFoundError:
        raise HTTPException(status_code=404)
    try:
        from app.services.alerts import audit_event
        audit_event("product.collection_updated", user.sub, request, collection_code=collection_code)
    except Exception:
        pass
    return _collection_out(item)


# ---------------------------------------------------------------------------
# Product list + create
# ---------------------------------------------------------------------------

@router.post("/ui/financial-products", response_model=FinancialProductOut, status_code=201)
def create_product(
    body: FinancialProductCreateIn,
    request: Request,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> FinancialProductOut:
    _require_flag()
    from app.services.financial_products import ProductAlreadyExistsError
    store = _get_store()
    try:
        item = store.create_product(
            product_code=body.product_code,
            name=body.name,
            parent_product_code=body.parent_product_code,
            category=body.category,
            family=body.family,
            super_family=body.super_family,
            more_info_url=body.more_info_url,
            description=body.description,
        )
    except ProductAlreadyExistsError:
        raise HTTPException(status_code=409, detail="Product already exists.")
    try:
        from app.services.alerts import audit_event
        audit_event("product.created", user.sub, request, product_code=body.product_code)
    except Exception:
        pass
    return _product_out(item)


@router.get("/ui/financial-products", response_model=FinancialProductListOut)
def list_products(
    category: str | None = None,
    cursor: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> FinancialProductListOut:
    _require_flag()
    store = _get_store()
    items, next_cursor = store.list_products(category=category, limit=limit, cursor=cursor)
    return FinancialProductListOut(
        items=[_product_out(i) for i in items],
        cursor=next_cursor,
    )


# ---------------------------------------------------------------------------
# Product attribute sub-routes — before /{product_code}
# ---------------------------------------------------------------------------

@router.put("/ui/financial-products/{product_code}/attributes", response_model=ProductAttributeOut)
def set_product_attribute(
    product_code: str,
    body: ProductAttributeSetIn,
    request: Request,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> ProductAttributeOut:
    _require_flag()
    store = _get_store()
    item = store.set_attribute(
        product_code,
        name=body.name,
        type=body.type,
        value=body.value,
    )
    try:
        from app.services.alerts import audit_event
        audit_event("product.attribute_set", user.sub, request, product_code=product_code)
    except Exception:
        pass
    return ProductAttributeOut(
        attribute_id=item["attribute_id"],
        name=item["name"],
        type=item["type"],
        value=item["value"],
        created_at=int(item["created_at"]),
    )


@router.get("/ui/financial-products/{product_code}/attributes", response_model=ProductAttributeListOut)
def list_product_attributes(
    product_code: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> ProductAttributeListOut:
    _require_flag()
    store = _get_store()
    items = store.list_attributes(product_code)
    return ProductAttributeListOut(
        attributes=[
            ProductAttributeOut(
                attribute_id=it["attribute_id"],
                name=it["name"],
                type=it["type"],
                value=it["value"],
                created_at=int(it["created_at"]),
            )
            for it in items
        ]
    )


@router.delete("/ui/financial-products/{product_code}/attributes/{attribute_id}", status_code=200)
def delete_product_attribute(
    product_code: str,
    attribute_id: str,
    request: Request,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> dict:
    _require_flag()
    store = _get_store()
    store.delete_attribute(product_code, attribute_id)
    try:
        from app.services.alerts import audit_event
        audit_event("product.attribute_deleted", user.sub, request, product_code=product_code)
    except Exception:
        pass
    return {"ok": True}


# ---------------------------------------------------------------------------
# Product get / patch / delete — LAST to avoid capture
# ---------------------------------------------------------------------------

@router.get("/ui/financial-products/{product_code}", response_model=FinancialProductOut)
def get_product(
    product_code: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> FinancialProductOut:
    _require_flag()
    from app.services.financial_products import ProductNotFoundError
    store = _get_store()
    try:
        item = store.get_product(product_code)
    except ProductNotFoundError:
        raise HTTPException(status_code=404)
    return _product_out(item)


@router.patch("/ui/financial-products/{product_code}", response_model=FinancialProductOut)
def update_product(
    product_code: str,
    body: FinancialProductPatchIn,
    request: Request,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> FinancialProductOut:
    _require_flag()
    from app.services.financial_products import ProductNotFoundError, ProductConflictError
    store = _get_store()
    fields = body.model_dump(exclude={"expected_version"}, exclude_none=True)
    try:
        item = store.update_product(
            product_code,
            expected_version=body.expected_version,
            actor_sub=user.sub,
            **fields,
        )
    except ProductNotFoundError:
        raise HTTPException(status_code=404)
    except ProductConflictError:
        raise HTTPException(status_code=409, detail={"code": "product_update_conflict"})
    try:
        from app.services.alerts import audit_event
        audit_event("product.updated", user.sub, request, product_code=product_code)
    except Exception:
        pass
    return _product_out(item)


@router.delete("/ui/financial-products/{product_code}", status_code=200)
def delete_product(
    product_code: str,
    request: Request,
    user: AuthenticatedUser = Depends(require_admin_or_root),
) -> dict:
    _require_flag()
    from app.services.financial_products import ProductNotFoundError
    store = _get_store()
    try:
        store.get_product(product_code)  # verify it exists
    except ProductNotFoundError:
        raise HTTPException(status_code=404)
    store.delete_product(product_code)
    try:
        from app.services.alerts import audit_event
        audit_event("product.deleted", user.sub, request, product_code=product_code)
    except Exception:
        pass
    return {"ok": True}
