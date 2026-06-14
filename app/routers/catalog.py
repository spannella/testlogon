from __future__ import annotations

import base64
import importlib.util
import json
import re
import time
import uuid
from urllib.parse import quote, unquote
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.core.tables import T
from app.core.settings import S
from app.models import (
    CatalogCategoryCreateIn,
    CatalogCategoryListOut,
    CatalogCategoryOut,
    CatalogItemCreateIn,
    CatalogItemListOut,
    CatalogItemOut,
    CatalogItemPatchIn,
    CatalogReorderReq,
    CatalogReviewCreateIn,
    CatalogReviewListOut,
    CatalogReviewOut,
    CatalogStockAdjustIn,
    CatalogStockOut,
)
from app.services.filemanager import download_file, upload_catalog_image
from app.services.api_key_policy_enforcement import maybe_enforce_api_key_route_policy
from app.services.geo_check import check_geo_access
from app.services.sessions import require_ui_session
from app.services.subscription_access import can_access_creator

router = APIRouter(prefix="/ui/catalog", tags=["catalog"], dependencies=[Depends(maybe_enforce_api_key_route_policy)])

_MULTIPART_AVAILABLE = importlib.util.find_spec("multipart") is not None


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ulid_like() -> str:
    return f"{int(time.time() * 1000)}_{uuid.uuid4().hex}"


def cat_pk(category_id: str) -> str:
    return f"CAT#{category_id}"


def item_pk(item_id: str) -> str:
    return f"ITEM#{item_id}"


def item_sk(item_id: str) -> str:
    return f"ITEM#{item_id}"


def review_sk(review_id: str) -> str:
    return f"REVIEW#{review_id}"


def ddb_to_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _catalog_tokens(text: str) -> list[str]:
    return [t for t in re.findall(r"[a-z0-9@._-]+", (text or "").lower()) if t]


def _catalog_matches(query_tokens: list[str], item: dict) -> bool:
    if not query_tokens:
        return False
    haystack = " ".join(
        [
            str(item.get("name", "")).lower(),
            str(item.get("description", "") or "").lower(),
        ]
    )
    return all(token in haystack for token in query_tokens)


def _compute_stock_status(item: dict) -> str:
    sc = item.get("stock_count")
    if sc is None:
        return "unlimited"
    sc = int(sc)
    if sc <= 0:
        return "out_of_stock"
    threshold = int(item.get("low_stock_threshold") or S.catalog_default_low_stock_threshold)
    if sc <= threshold:
        return "low_stock"
    return "in_stock"


def _catalog_item_out(item: dict) -> CatalogItemOut:
    sc = item.get("stock_count")
    pos = item.get("position")
    return CatalogItemOut(
        category_id=item["category_id"],
        item_id=item["item_id"],
        name=item["name"],
        description=item.get("description"),
        price_cents=ddb_to_int(item["price_cents"]),
        currency=item.get("currency", "USD"),
        image_urls=item.get("image_urls", []),
        attributes=item.get("attributes", {}),
        creator_id=item.get("creator_id"),
        created_at=item["created_at"],
        updated_at=item["updated_at"],
        stock_count=int(sc) if sc is not None else None,
        stock_status=_compute_stock_status(item),
        low_stock_threshold=int(item.get("low_stock_threshold") or S.catalog_default_low_stock_threshold),
        stock_updated_at=item.get("stock_updated_at"),
        position=int(pos) if pos is not None else None,
    )


def _ecm_enrich_item(item: dict, ctx: dict) -> CatalogItemOut:
    """ECM-004: enrich a raw catalog item dict with variant topology when flag is on.

    Falls back to _catalog_item_out unchanged on any error or when the flag is off.
    This is the single enrichment call-site; _safe_upstream is inside enrich_catalog_item.
    """
    try:
        from app.services.store_integration import enrich_catalog_item
        return enrich_catalog_item(item, viewer=ctx)
    except Exception:
        return _catalog_item_out(item)


def _ecm_apply_batch_availability(items: List[CatalogItemOut]) -> List[CatalogItemOut]:
    """ECM-005: batch live availability enrichment; returns list unchanged on any error."""
    try:
        from app.services.store_integration import (
            availability_for_skus,
            _apply_live_availability,
        )
        skus = [it.item_id for it in items]
        avail_map = availability_for_skus(skus)
        if not avail_map:
            return items
        return [_apply_live_availability(it, avail_map) for it in items]
    except Exception:
        return items


def _item_geo_blocked(request: Request, item: dict) -> bool:
    """Return True if the viewer's resolved country is blocked from this item.

    Reads the per-item ``geo_mode``/``geo_countries`` stored inline on the
    catalog item record (GEO-001 stores catalog geo rules on the item itself,
    not a separate table). Delegates the allow/block decision to the shared
    ``check_geo_access`` helper used by video/broadcast endpoints. Items with no
    geo rule (``geo_mode`` absent) are never blocked.
    """
    geo_mode = item.get("geo_mode")
    if not geo_mode:
        return False
    try:
        check_geo_access(request, geo_mode, item.get("geo_countries"))
    except HTTPException:
        return True
    return False


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _b64d(token: str) -> bytes:
    pad = "=" * ((4 - (len(token) % 4)) % 4)
    return base64.urlsafe_b64decode((token + pad).encode("utf-8"))


def encode_next_token(last_evaluated_key: Optional[Dict[str, Any]]) -> Optional[str]:
    if not last_evaluated_key:
        return None
    raw = json.dumps(last_evaluated_key, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return _b64e(raw)


def decode_next_token(token: Optional[str]) -> Optional[Dict[str, Any]]:
    if not token:
        return None
    try:
        raw = _b64d(token)
        obj = json.loads(raw.decode("utf-8"))
        if not isinstance(obj, dict):
            raise ValueError("token not dict")
        return obj
    except Exception as exc:  # pragma: no cover - defensive
        raise HTTPException(status_code=400, detail="Invalid next_token") from exc


def _catalog_image_url(path: str) -> str:
    return f"{S.public_base_url}/ui/catalog/images?path={quote(path, safe='')}"


def _query_page(
    *,
    pk: str,
    sk_begins: str,
    limit: int,
    start_key: Optional[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("PK").eq(pk) & Key("SK").begins_with(sk_begins),
        "Limit": limit,
    }
    if start_key:
        kwargs["ExclusiveStartKey"] = start_key
    resp = T.catalog.query(**kwargs)
    return resp.get("Items", []), resp.get("LastEvaluatedKey")


def _gsi_categories_page(limit: int, start_key: Optional[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    kwargs: Dict[str, Any] = {
        "IndexName": "GSI1",
        "KeyConditionExpression": Key("GSI1PK").eq("CATS"),
        "Limit": limit,
    }
    if start_key:
        kwargs["ExclusiveStartKey"] = start_key
    resp = T.catalog.query(**kwargs)
    return resp.get("Items", []), resp.get("LastEvaluatedKey")


def _scan_categories(limit: int, start_key: Optional[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    kwargs: Dict[str, Any] = {"Limit": limit}
    if start_key:
        kwargs["ExclusiveStartKey"] = start_key
    resp = T.catalog.scan(**kwargs)
    items = [item for item in resp.get("Items", []) if item.get("entity") == "category"]
    return items, resp.get("LastEvaluatedKey")


def _stream_catalog_image(path: str) -> StreamingResponse:
    result = download_file("catalog", path)
    node = result["node"]
    obj = result["object"]

    def gen():
        body = obj["Body"]
        while True:
            chunk = body.read(1024 * 1024)
            if not chunk:
                break
            yield chunk

    return StreamingResponse(
        gen(),
        media_type=node.get("content_type", "application/octet-stream"),
        headers={"Content-Disposition": f'inline; filename="{node["name"]}"'},
    )


def _get_category_meta(category_id: str) -> Dict[str, Any]:
    item = T.catalog.get_item(Key={"PK": cat_pk(category_id), "SK": "META"}).get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Category not found.")
    return item


def _require_category_owner(category_id: str, user_id: str) -> Dict[str, Any]:
    item = _get_category_meta(category_id)
    creator_id = item.get("creator_id")
    if creator_id and creator_id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to manage this category.")
    return item


def _get_item_meta(item_id: str) -> Dict[str, Any]:
    items, _ = _query_page(pk=item_pk(item_id), sk_begins="ITEM#", limit=1, start_key=None)
    return items[0] if items else {}


@router.post("/categories", response_model=CatalogCategoryOut)
async def create_category(body: CatalogCategoryCreateIn, ctx=Depends(require_ui_session)):
    category_id = body.category_id or uuid.uuid4().hex
    item = {
        "PK": cat_pk(category_id),
        "SK": "META",
        "entity": "category",
        "category_id": category_id,
        "name": body.name,
        "description": body.description,
        "creator_id": ctx["user_sub"],
        "created_at": now_iso(),
        "GSI1PK": "CATS",
        "GSI1SK": f"{body.name.lower()}#{category_id}",
    }
    try:
        T.catalog.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise HTTPException(status_code=409, detail="Category already exists.") from exc
        raise HTTPException(status_code=500, detail="Catalog storage error.") from exc
    return CatalogCategoryOut(
        category_id=category_id,
        name=body.name,
        description=body.description,
        creator_id=item.get("creator_id"),
        created_at=item["created_at"],
    )


@router.get("/categories", response_model=CatalogCategoryListOut)
async def list_categories(
    ctx=Depends(require_ui_session),
    page_size: int = Query(default=50, ge=1, le=200),
    next_token: Optional[str] = Query(default=None),
):
    start_key = decode_next_token(next_token)
    try:
        items, lek = _gsi_categories_page(page_size, start_key)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ValidationException":
            raise HTTPException(status_code=500, detail="Catalog storage error.") from exc
        items, lek = _scan_categories(page_size, start_key)
    out = [
        CatalogCategoryOut(
            category_id=item["category_id"],
            name=item["name"],
            description=item.get("description"),
            creator_id=item.get("creator_id"),
            created_at=item["created_at"],
        )
        for item in items
        if item.get("entity") == "category"
        and (
            not item.get("creator_id")
            or can_access_creator(ctx["user_sub"], item.get("creator_id"))
        )
    ]
    return CatalogCategoryListOut(items=out, next_token=encode_next_token(lek))


@router.delete("/categories/{category_id}")
async def delete_category(
    category_id: str,
    cascade: bool = Query(default=False, description="Delete items in the category before removing it."),
    ctx=Depends(require_ui_session),
):
    _require_category_owner(category_id, ctx["user_sub"])
    if cascade:
        items, _ = _query_page(pk=cat_pk(category_id), sk_begins="ITEM#", limit=200, start_key=None)
        with T.catalog.batch_writer() as batch:
            for item in items:
                batch.delete_item(Key={"PK": item["PK"], "SK": item["SK"]})
        for item in items:
            item_id = item.get("item_id")
            if not item_id:
                continue
            reviews, _ = _query_page(pk=item_pk(item_id), sk_begins="REVIEW#", limit=200, start_key=None)
            with T.catalog.batch_writer() as batch:
                for review in reviews:
                    batch.delete_item(Key={"PK": review["PK"], "SK": review["SK"]})
    else:
        existing, _ = _query_page(pk=cat_pk(category_id), sk_begins="ITEM#", limit=1, start_key=None)
        if existing:
            raise HTTPException(status_code=409, detail="Category has items. Use cascade=true to delete.")
    T.catalog.delete_item(Key={"PK": cat_pk(category_id), "SK": "META"})
    return {"ok": True}


@router.post("/categories/{category_id}/items", response_model=CatalogItemOut)
async def create_item(
    category_id: str,
    body: CatalogItemCreateIn,
    ctx=Depends(require_ui_session),
):
    category = _require_category_owner(category_id, ctx["user_sub"])
    item_id = body.item_id or ulid_like()
    now = now_iso()
    item: Dict[str, Any] = {
        "PK": cat_pk(category_id),
        "SK": item_sk(item_id),
        "entity": "item",
        "category_id": category_id,
        "item_id": item_id,
        "creator_id": category.get("creator_id"),
        "name": body.name,
        "description": body.description,
        "price_cents": int(body.price_cents),
        "currency": body.currency,
        "image_urls": body.image_urls,
        "attributes": body.attributes,
        "created_at": now,
        "updated_at": now,
    }
    if body.stock_count is not None:
        item["stock_count"] = body.stock_count
        item["stock_updated_at"] = now
    if body.low_stock_threshold is not None:
        item["low_stock_threshold"] = body.low_stock_threshold
    try:
        T.catalog.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise HTTPException(status_code=409, detail="Item already exists.") from exc
        raise HTTPException(status_code=500, detail="Catalog storage error.") from exc
    return _catalog_item_out(item)


@router.get("/categories/{category_id}/items", response_model=CatalogItemListOut)
async def list_items(
    category_id: str,
    request: Request,
    ctx=Depends(require_ui_session),
    page_size: int = Query(default=50, ge=1, le=200),
    next_token: Optional[str] = Query(default=None),
):
    category = _get_category_meta(category_id)
    creator_id = category.get("creator_id")
    if creator_id and not can_access_creator(ctx["user_sub"], creator_id):
        raise HTTPException(status_code=403, detail="Subscription required to view this catalog.")
    start_key = decode_next_token(next_token)
    items, lek = _query_page(pk=cat_pk(category_id), sk_begins="ITEM#", limit=page_size, start_key=start_key)
    out: List[CatalogItemOut] = []
    for item in items:
        if item.get("entity") != "item":
            continue
        # GEO-001 (GAP-0216): drop items the viewer's region is blocked from.
        if _item_geo_blocked(request, item):
            continue
        out.append(_ecm_enrich_item(item, ctx))
    # ECM-005: batch live availability enrichment when flag on
    out = _ecm_apply_batch_availability(out)
    # Sort by position (items without position sorted to end)
    out.sort(key=lambda x: (x.position is None, x.position if x.position is not None else 0))
    return CatalogItemListOut(items=out, next_token=encode_next_token(lek))


@router.patch("/items/reorder")
async def reorder_catalog_items(
    body: CatalogReorderReq,
    ctx=Depends(require_ui_session),
):
    """Set display order for catalog items.

    Accepts an ordered list of item IDs. Each item's `position` field
    is set to its index in the list (0-based). Items not in the list
    retain their current position.

    Only items owned by the authenticated user are updated.
    Non-owned items are silently skipped.
    """
    user_sub = ctx["user_sub"]
    results = []
    for idx, item_id in enumerate(body.item_ids):
        try:
            item = _find_item_by_id(item_id)
            if not item:
                results.append({"item_id": item_id, "ok": False, "error": "not_found"})
                continue
            # Verify ownership via category
            category_id = item.get("category_id")
            if category_id:
                cat_meta = T.catalog.get_item(Key={"PK": cat_pk(category_id), "SK": "META"}).get("Item")
                creator_id = cat_meta.get("creator_id") if cat_meta else None
                if creator_id and creator_id != user_sub:
                    results.append({"item_id": item_id, "ok": False, "error": "not_owner"})
                    continue

            T.catalog.update_item(
                Key={"PK": item["PK"], "SK": item["SK"]},
                UpdateExpression="SET #pos = :pos",
                ExpressionAttributeNames={"#pos": "position"},
                ExpressionAttributeValues={":pos": idx},
            )
            results.append({"item_id": item_id, "ok": True})
        except Exception as e:
            results.append({"item_id": item_id, "ok": False, "error": str(e)})

    return {"ok": True, "results": results}


@router.get("/items/search", response_model=CatalogItemListOut)
async def search_items(
    request: Request,
    q: str = Query(..., min_length=1, max_length=200),
    ctx=Depends(require_ui_session),
    page_size: int = Query(default=50, ge=1, le=200),
    next_token: Optional[str] = Query(default=None),
):
    start_key = decode_next_token(next_token)
    query_tokens = _catalog_tokens(q)
    matches: List[CatalogItemOut] = []
    last_evaluated: Optional[Dict[str, Any]] = start_key

    while len(matches) < page_size:
        kwargs: Dict[str, Any] = {"Limit": 200}
        if last_evaluated:
            kwargs["ExclusiveStartKey"] = last_evaluated
        resp = T.catalog.scan(**kwargs)
        items = resp.get("Items", [])
        for item in items:
            if item.get("entity") != "item":
                continue
            # GEO-001 (GAP-0216): silently exclude geo-blocked items from search.
            if _item_geo_blocked(request, item):
                continue
            if _catalog_matches(query_tokens, item):
                matches.append(_ecm_enrich_item(item, ctx))
                if len(matches) >= page_size:
                    break
        last_evaluated = resp.get("LastEvaluatedKey")
        if not last_evaluated:
            break

    matches = _ecm_apply_batch_availability(matches)
    return CatalogItemListOut(items=matches, next_token=encode_next_token(last_evaluated))


@router.get("/images")
async def get_catalog_image(
    path: str = Query(..., description="Catalog image path"),
    ctx=Depends(require_ui_session),
):
    decoded = unquote(path)
    if not decoded.startswith("/catalog/items/"):
        raise HTTPException(status_code=400, detail="Invalid catalog image path")
    parts = decoded.strip("/").split("/")
    item_id = parts[2] if len(parts) > 2 else None
    if item_id:
        item_meta = _get_item_meta(item_id)
        creator_id = item_meta.get("creator_id")
        if creator_id and not can_access_creator(ctx["user_sub"], creator_id):
            raise HTTPException(status_code=403, detail="Subscription required to view this catalog image.")
    return _stream_catalog_image(decoded)


@router.patch("/categories/{category_id}/items/{item_id}", response_model=CatalogItemOut)
async def update_item(
    category_id: str,
    item_id: str,
    body: CatalogItemPatchIn,
    ctx=Depends(require_ui_session),
):
    _require_category_owner(category_id, ctx["user_sub"])
    updates: List[str] = []
    values: Dict[str, Any] = {":updated_at": now_iso()}
    names: Dict[str, str] = {"#updated_at": "updated_at"}
    updates.append("#updated_at = :updated_at")

    if body.name is not None:
        names["#name"] = "name"
        values[":name"] = body.name
        updates.append("#name = :name")
    if body.description is not None:
        names["#description"] = "description"
        values[":description"] = body.description
        updates.append("#description = :description")
    if body.price_cents is not None:
        names["#price_cents"] = "price_cents"
        values[":price_cents"] = int(body.price_cents)
        updates.append("#price_cents = :price_cents")
    if body.currency is not None:
        names["#currency"] = "currency"
        values[":currency"] = body.currency
        updates.append("#currency = :currency")
    if body.image_urls is not None:
        names["#image_urls"] = "image_urls"
        values[":image_urls"] = body.image_urls
        updates.append("#image_urls = :image_urls")
    if body.attributes is not None:
        names["#attributes"] = "attributes"
        values[":attributes"] = body.attributes
        updates.append("#attributes = :attributes")
    if body.stock_count is not None:
        names["#stock_count"] = "stock_count"
        values[":stock_count"] = body.stock_count
        updates.append("#stock_count = :stock_count")
        names["#stock_updated_at"] = "stock_updated_at"
        values[":stock_updated_at"] = now_iso()
        updates.append("#stock_updated_at = :stock_updated_at")
    if body.low_stock_threshold is not None:
        names["#low_stock_threshold"] = "low_stock_threshold"
        values[":low_stock_threshold"] = body.low_stock_threshold
        updates.append("#low_stock_threshold = :low_stock_threshold")

    if len(updates) == 1:
        raise HTTPException(status_code=400, detail="No fields to update.")

    try:
        resp = T.catalog.update_item(
            Key={"PK": cat_pk(category_id), "SK": item_sk(item_id)},
            ConditionExpression="attribute_exists(PK) AND attribute_exists(SK)",
            UpdateExpression="SET " + ", ".join(updates),
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
            ReturnValues="ALL_NEW",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise HTTPException(status_code=404, detail="Item not found.") from exc
        raise HTTPException(status_code=500, detail="Catalog storage error.") from exc

    item = resp.get("Attributes")
    if not item:
        raise HTTPException(status_code=404, detail="Item not found.")
    return _catalog_item_out(item)


async def _catalog_upload_unavailable(ctx=Depends(require_ui_session)):
    raise HTTPException(501, "python-multipart is required for uploads")


if _MULTIPART_AVAILABLE:
    @router.post("/categories/{category_id}/items/{item_id}/images/upload", response_model=CatalogItemOut)
    async def upload_item_image(
        category_id: str,
        item_id: str,
        file: UploadFile = File(...),
        ctx=Depends(require_ui_session),
    ):
        _require_category_owner(category_id, ctx["user_sub"])
        if not S.filemgr_table_name or not S.filemgr_bucket:
            raise HTTPException(status_code=501, detail="file manager not configured")
        content = await file.read()
        result = upload_catalog_image(
            item_id,
            file_name=file.filename or "upload.bin",
            content=content,
            content_type=file.content_type,
        )
        image_url = _catalog_image_url(result["path"])
        now = now_iso()
        try:
            resp = T.catalog.update_item(
                Key={"PK": cat_pk(category_id), "SK": item_sk(item_id)},
                ConditionExpression="attribute_exists(PK) AND attribute_exists(SK)",
                UpdateExpression=(
                    "SET #image_urls = list_append(if_not_exists(#image_urls, :empty), :new), "
                    "#updated_at = :updated_at"
                ),
                ExpressionAttributeNames={"#image_urls": "image_urls", "#updated_at": "updated_at"},
                ExpressionAttributeValues={":new": [image_url], ":empty": [], ":updated_at": now},
                ReturnValues="ALL_NEW",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise HTTPException(status_code=404, detail="Item not found.") from exc
            raise HTTPException(status_code=500, detail="Catalog storage error.") from exc
        item = resp.get("Attributes")
        if not item:
            raise HTTPException(status_code=404, detail="Item not found.")
        return _catalog_item_out(item)
else:
    router.post("/categories/{category_id}/items/{item_id}/images/upload")(_catalog_upload_unavailable)


# GAP-0347 / SHOP-001: once-per-hour low-stock alert dedup window.
_LOW_STOCK_SENTINEL_TTL_SECONDS = 3600  # 1 hour


def _check_low_stock_alert(item: dict, new_stock: int) -> None:
    if not S.catalog_stock_alerts_enabled:
        return
    threshold = int(item.get("low_stock_threshold") or S.catalog_default_low_stock_threshold)
    if new_stock > threshold or new_stock < 0:
        return
    creator_id = item.get("creator_id")
    if not creator_id:
        return

    # GAP-0347: per-item once-per-hour dedup. A conditional put of a sparse
    # sentinel row (no GSI1PK/GSI1SK/item_id so it never pollutes listings or
    # the ByItemId GSI) acts as an atomic test-and-set. If the put succeeds the
    # window is fresh → fire the alert; ConditionalCheckFailed means a recent
    # alert already fired within the TTL window → suppress. The sentinel carries
    # ttl_epoch (= now+3600) so DynamoDB TTL reclaims it after the window.
    item_id = str(item.get("item_id") or "unknown")
    sentinel_pk = f"LOWSTOCK_ALERT_SENTINEL#{creator_id}"
    sentinel_sk = f"LOWSTOCK#{item_id}"
    try:
        T.catalog.put_item(
            Item={
                "PK": sentinel_pk,
                "SK": sentinel_sk,
                "entity": "lowstock_alert_sentinel",
                "ttl_epoch": int(time.time()) + _LOW_STOCK_SENTINEL_TTL_SECONDS,
            },
            ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            # A recent alert already fired in this window — suppress.
            return
        # Unexpected DDB error: suppress to avoid breaking the stock adjustment.
        return
    except Exception:
        return

    try:
        from app.services.alerts import write_alert
    except Exception:
        return
    try:
        write_alert(
            creator_id,
            event="catalog.low_stock",
            outcome="warning",
            title=f"Low stock: {item.get('name', 'Unknown item')} ({new_stock} remaining)",
            details={
                "item_id": item.get("item_id"),
                "item_name": item.get("name"),
                "stock_count": new_stock,
                "threshold": threshold,
            },
        )
    except Exception:
        pass


def _find_item_by_id(item_id: str) -> Optional[Dict[str, Any]]:
    """Find a catalog item by item_id via the ByItemId GSI (O(1) query).

    GAP-0348 / SHOP-001: replaces a full-table scan. Catalog item rows carry
    item_id as a top-level attribute, so they are indexed by the ByItemId GSI.
    Review rows also carry item_id, hence the FilterExpression on entity="item".
    """
    resp = T.catalog.query(
        IndexName="ByItemId",
        KeyConditionExpression=Key("item_id").eq(item_id),
        FilterExpression="entity = :ent",
        ExpressionAttributeValues={":ent": "item"},
    )
    items = resp.get("Items", [])
    if items:
        return items[0]
    return None


@router.patch("/items/{item_id}/stock", response_model=CatalogStockOut)
async def adjust_stock(
    item_id: str,
    body: CatalogStockAdjustIn,
    ctx=Depends(require_ui_session),
):
    item = _find_item_by_id(item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found.")
    category_id = item["category_id"]
    _require_category_owner(category_id, ctx["user_sub"])

    now = now_iso()
    key = {"PK": item["PK"], "SK": item["SK"]}

    if body.absolute is not None:
        try:
            resp = T.catalog.update_item(
                Key=key,
                UpdateExpression="SET stock_count = :val, stock_updated_at = :now",
                ConditionExpression="attribute_exists(PK)",
                ExpressionAttributeValues={":val": body.absolute, ":now": now},
                ReturnValues="ALL_NEW",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise HTTPException(status_code=404, detail="Item not found.") from exc
            raise HTTPException(status_code=500, detail="Stock update error.") from exc
        updated = resp.get("Attributes", {})
        new_stock = int(updated.get("stock_count", 0))
        _check_low_stock_alert(updated, new_stock)
    else:
        delta = body.delta
        if delta < 0:
            try:
                resp = T.catalog.update_item(
                    Key=key,
                    UpdateExpression="SET stock_count = stock_count + :delta, stock_updated_at = :now",
                    ConditionExpression="attribute_exists(PK) AND stock_count >= :abs_delta",
                    ExpressionAttributeValues={
                        ":delta": delta,
                        ":abs_delta": abs(delta),
                        ":now": now,
                    },
                    ReturnValues="ALL_NEW",
                )
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                    current = item.get("stock_count")
                    current_val = int(current) if current is not None else 0
                    raise HTTPException(
                        status_code=409,
                        detail=f"Insufficient stock: current={current_val}, requested_delta={delta}",
                    ) from exc
                raise HTTPException(status_code=500, detail="Stock update error.") from exc
            updated = resp.get("Attributes", {})
            new_stock = int(updated.get("stock_count", 0))
            _check_low_stock_alert(updated, new_stock)
        else:
            try:
                resp = T.catalog.update_item(
                    Key=key,
                    UpdateExpression="SET stock_count = if_not_exists(stock_count, :zero) + :delta, stock_updated_at = :now",
                    ConditionExpression="attribute_exists(PK)",
                    ExpressionAttributeValues={
                        ":delta": delta,
                        ":zero": 0,
                        ":now": now,
                    },
                    ReturnValues="ALL_NEW",
                )
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                    raise HTTPException(status_code=404, detail="Item not found.") from exc
                raise HTTPException(status_code=500, detail="Stock update error.") from exc
            updated = resp.get("Attributes", {})
            new_stock = int(updated.get("stock_count", 0))

    sc = updated.get("stock_count")
    return CatalogStockOut(
        item_id=item_id,
        stock_count=int(sc) if sc is not None else None,
        stock_status=_compute_stock_status(updated),
        low_stock_threshold=int(updated.get("low_stock_threshold") or S.catalog_default_low_stock_threshold),
        stock_updated_at=updated.get("stock_updated_at"),
    )


@router.delete("/categories/{category_id}/items/{item_id}")
async def delete_item(
    category_id: str,
    item_id: str,
    cascade_reviews: bool = Query(default=True, description="Delete item reviews before removing item."),
    ctx=Depends(require_ui_session),
):
    _require_category_owner(category_id, ctx["user_sub"])
    if cascade_reviews:
        reviews, _ = _query_page(pk=item_pk(item_id), sk_begins="REVIEW#", limit=200, start_key=None)
        with T.catalog.batch_writer() as batch:
            for review in reviews:
                batch.delete_item(Key={"PK": review["PK"], "SK": review["SK"]})
    else:
        reviews, _ = _query_page(pk=item_pk(item_id), sk_begins="REVIEW#", limit=1, start_key=None)
        if reviews:
            raise HTTPException(status_code=409, detail="Item has reviews. Use cascade_reviews=true to delete.")
    T.catalog.delete_item(Key={"PK": cat_pk(category_id), "SK": item_sk(item_id)})
    return {"ok": True}


@router.get("/items/{item_id}/reviews", response_model=CatalogReviewListOut)
async def list_reviews(
    item_id: str,
    ctx=Depends(require_ui_session),
    page_size: int = Query(default=50, ge=1, le=200),
    next_token: Optional[str] = Query(default=None),
):
    item_meta = _get_item_meta(item_id)
    creator_id = item_meta.get("creator_id")
    if creator_id and not can_access_creator(ctx["user_sub"], creator_id):
        raise HTTPException(status_code=403, detail="Subscription required to view reviews.")
    start_key = decode_next_token(next_token)
    items, lek = _query_page(pk=item_pk(item_id), sk_begins="REVIEW#", limit=page_size, start_key=start_key)
    out: List[CatalogReviewOut] = []
    for item in items:
        if item.get("entity") != "review":
            continue
        out.append(
            CatalogReviewOut(
                item_id=item["item_id"],
                review_id=item["review_id"],
                rating=ddb_to_int(item["rating"]),
                title=item.get("title"),
                body=item.get("body"),
                reviewer=item.get("reviewer"),
                created_at=item["created_at"],
            )
        )
    return CatalogReviewListOut(items=out, next_token=encode_next_token(lek))


@router.post("/items/{item_id}/reviews", response_model=CatalogReviewOut)
async def add_review(
    item_id: str,
    body: CatalogReviewCreateIn,
    ctx=Depends(require_ui_session),
):
    item_meta = _get_item_meta(item_id)
    creator_id = item_meta.get("creator_id")
    if creator_id and not can_access_creator(ctx["user_sub"], creator_id):
        raise HTTPException(status_code=403, detail="Subscription required to review.")
    review_id = body.review_id or ulid_like()
    item = {
        "PK": item_pk(item_id),
        "SK": review_sk(review_id),
        "entity": "review",
        "item_id": item_id,
        "review_id": review_id,
        "rating": int(body.rating),
        "title": body.title,
        "body": body.body,
        "reviewer": body.reviewer,
        "created_at": now_iso(),
    }
    try:
        T.catalog.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise HTTPException(status_code=409, detail="Review already exists.") from exc
        raise HTTPException(status_code=500, detail="Catalog storage error.") from exc
    return CatalogReviewOut(
        item_id=item_id,
        review_id=review_id,
        rating=item["rating"],
        title=item.get("title"),
        body=item.get("body"),
        reviewer=item.get("reviewer"),
        created_at=item["created_at"],
    )


@router.delete("/items/{item_id}/reviews/{review_id}")
async def delete_review(
    item_id: str,
    review_id: str,
    ctx=Depends(require_ui_session),
):
    T.catalog.delete_item(Key={"PK": item_pk(item_id), "SK": review_sk(review_id)})
    return {"ok": True}


# ─── Bulk Operations (UX-004) ────────────────────────────────────────────────


class CatalogBulkDeleteReq(BaseModel):
    item_ids: List[str] = Field(..., min_length=1, max_length=50)


class CatalogBulkUpdateReq(BaseModel):
    item_ids: List[str] = Field(..., min_length=1, max_length=50)
    updates: Dict[str, Any] = Field(..., min_length=1)


@router.post("/items/bulk-delete")
async def bulk_delete_items(
    body: CatalogBulkDeleteReq,
    ctx=Depends(require_ui_session),
):
    """Bulk-delete catalog items. Only items owned by the authenticated user are processed."""
    user_sub = ctx["user_sub"]
    results = []
    for item_id in body.item_ids:
        try:
            item = _find_item_by_id(item_id)
            if not item:
                results.append({"item_id": item_id, "ok": False, "error": "not_found"})
                continue
            creator_id = item.get("creator_id")
            if creator_id and creator_id != user_sub:
                results.append({"item_id": item_id, "ok": False, "error": "not_owner"})
                continue
            T.catalog.delete_item(Key={"PK": item["PK"], "SK": item["SK"]})
            results.append({"item_id": item_id, "ok": True})
        except Exception as e:
            results.append({"item_id": item_id, "ok": False, "error": str(e)})

    succeeded = sum(1 for r in results if r["ok"])
    failed = sum(1 for r in results if not r["ok"])
    return {"results": results, "succeeded": succeeded, "failed": failed}


@router.post("/items/bulk-update")
async def bulk_update_items(
    body: CatalogBulkUpdateReq,
    ctx=Depends(require_ui_session),
):
    """Bulk-update catalog items. Applies the same updates dict to all specified items."""
    user_sub = ctx["user_sub"]
    allowed_fields = {"visibility", "category", "description", "name"}
    update_fields = {k: v for k, v in body.updates.items() if k in allowed_fields}
    if not update_fields:
        raise HTTPException(status_code=422, detail="No valid update fields provided")

    results = []
    for item_id in body.item_ids:
        try:
            item = _find_item_by_id(item_id)
            if not item:
                results.append({"item_id": item_id, "ok": False, "error": "not_found"})
                continue
            creator_id = item.get("creator_id")
            if creator_id and creator_id != user_sub:
                results.append({"item_id": item_id, "ok": False, "error": "not_owner"})
                continue

            updates: List[str] = ["#updated_at = :updated_at"]
            values: Dict[str, Any] = {":updated_at": now_iso()}
            names: Dict[str, str] = {"#updated_at": "updated_at"}
            for field_name, value in update_fields.items():
                attr_name = f"#{field_name}"
                attr_val = f":{field_name}"
                names[attr_name] = field_name
                values[attr_val] = value
                updates.append(f"{attr_name} = {attr_val}")

            T.catalog.update_item(
                Key={"PK": item["PK"], "SK": item["SK"]},
                UpdateExpression="SET " + ", ".join(updates),
                ExpressionAttributeNames=names,
                ExpressionAttributeValues=values,
            )
            results.append({"item_id": item_id, "ok": True})
        except Exception as e:
            results.append({"item_id": item_id, "ok": False, "error": str(e)})

    succeeded = sum(1 for r in results if r["ok"])
    failed = sum(1 for r in results if not r["ok"])
    return {"results": results, "succeeded": succeeded, "failed": failed}


# ---------------------------------------------------------------------------
# PRD-006 / PRD-007 / PRD-012 — OFBiz Catalog Depth endpoints
# All gated on S.product_depth_enabled via each service's _require_enabled().
# Routes are APPENDED here — no existing routes are modified.
# ---------------------------------------------------------------------------

def _require_item_owner(item_id: str, user_sub: str) -> Dict[str, Any]:
    """Resolve a catalog item by item_id and assert the caller owns it.
    Raises 404 if not found, 403 if wrong owner.
    """
    item = _find_item_by_id(item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Catalog item not found.")
    creator_id = item.get("creator_id")
    if creator_id and creator_id != user_sub:
        raise HTTPException(status_code=403, detail="Not authorized to manage this item.")
    return item


@router.post("/feature-categories")
async def create_feature_category_endpoint(body: Dict[str, Any], ctx=Depends(require_ui_session)):
    from app.services.product_features import create_feature_category as _svc
    return _svc(
        name=body["name"],
        user_sub=ctx["user_sub"],
        feature_category_id=body.get("feature_category_id"),
        description=body.get("description"),
    )


@router.get("/feature-categories")
async def list_feature_categories_endpoint(include_values: bool = False, ctx=Depends(require_ui_session)):
    from app.services.product_features import list_feature_categories as _svc
    items = _svc(ctx["user_sub"], include_values=include_values)
    return {"feature_categories": items, "count": len(items)}


@router.delete("/feature-categories/{fc_id}", status_code=204)
async def delete_feature_category_endpoint(fc_id: str, ctx=Depends(require_ui_session)):
    from app.services.product_features import delete_feature_category as _svc
    _svc(fc_id, ctx["user_sub"])


@router.post("/feature-categories/{fc_id}/values")
async def add_feature_value_endpoint(fc_id: str, body: Dict[str, Any], ctx=Depends(require_ui_session)):
    from app.services.product_features import add_feature_value as _svc
    return _svc(
        fc_id=fc_id,
        name=body["name"],
        user_sub=ctx["user_sub"],
        price_delta_cents=int(body.get("price_delta_cents", 0)),
        position=int(body.get("position", 0)),
    )


@router.delete("/feature-categories/{fc_id}/values/{fv_id}", status_code=204)
async def delete_feature_value_endpoint(fc_id: str, fv_id: str, ctx=Depends(require_ui_session)):
    from app.services.product_features import delete_feature_value as _svc
    _svc(fc_id, fv_id, ctx["user_sub"])


@router.post("/items/{item_id}/product-type")
async def set_product_type_endpoint(item_id: str, body: Dict[str, Any], ctx=Depends(require_ui_session)):
    _require_item_owner(item_id, ctx["user_sub"])
    from app.services.product_variants import set_product_type as _svc
    return _svc(item_id, body.get("product_type", "standalone"), ctx["user_sub"])


@router.get("/items/{item_id}/product-type")
async def get_product_type_endpoint(item_id: str, ctx=Depends(require_ui_session)):
    from app.services.product_variants import get_product_type as _svc
    pt = _svc(item_id)
    return {"item_id": item_id, "product_type": pt or "standalone"}


@router.post("/items/{item_id}/feature-categories")
async def attach_feature_category_endpoint(item_id: str, body: Dict[str, Any], ctx=Depends(require_ui_session)):
    from app.services.product_features import attach_feature_category_to_product as _svc
    _require_item_owner(item_id, ctx["user_sub"])
    return _svc(item_id, body["feature_category_id"], ctx["user_sub"])


@router.delete("/items/{item_id}/feature-categories/{fc_id}", status_code=204)
async def detach_feature_category_endpoint(item_id: str, fc_id: str, ctx=Depends(require_ui_session)):
    from app.services.product_features import detach_feature_category_from_product as _svc
    _require_item_owner(item_id, ctx["user_sub"])
    _svc(item_id, fc_id, ctx["user_sub"])


@router.get("/items/{item_id}/features")
async def list_item_features_endpoint(item_id: str, ctx=Depends(require_ui_session)):
    from app.services.product_features import list_product_features as _svc
    features = _svc(item_id)
    return {"item_id": item_id, "features": features, "count": len(features)}


@router.post("/items/{item_id}/variants")
async def create_variant_endpoint(item_id: str, body: Dict[str, Any], ctx=Depends(require_ui_session)):
    from app.services.product_variants import create_variant as _svc
    _require_item_owner(item_id, ctx["user_sub"])
    return _svc(
        parent_item_id=item_id,
        feature_values=body["feature_values"],
        user_sub=ctx["user_sub"],
        sku_override=body.get("sku_override"),
    )


@router.get("/items/{item_id}/variants")
async def list_variants_endpoint(item_id: str, limit: int = 100, ctx=Depends(require_ui_session)):
    from app.services.product_variants import list_variants as _svc
    items, _ = _svc(item_id, limit=limit)
    return {"item_id": item_id, "variants": items, "count": len(items)}


@router.delete("/items/{item_id}/variants/{variant_id}", status_code=204)
async def delete_variant_endpoint(item_id: str, variant_id: str, ctx=Depends(require_ui_session)):
    from app.services.product_variants import delete_variant as _svc
    _require_item_owner(item_id, ctx["user_sub"])
    _svc(item_id, variant_id, ctx["user_sub"])


@router.put("/items/{item_id}/price-components")
async def set_price_components_endpoint(item_id: str, body: Dict[str, Any], ctx=Depends(require_ui_session)):
    from app.services.product_price_components import set_price_components as _svc
    from app.models import ProductPriceComponentIn, PriceTypeEnum
    _require_item_owner(item_id, ctx["user_sub"])
    price_type = body["price_type"]
    components = [ProductPriceComponentIn(**c) for c in body.get("components", [])]
    results = _svc(item_id=item_id, price_type=price_type, components=components, creator_id=ctx["user_sub"])
    return {"item_id": item_id, "price_type": price_type, "components": [r.model_dump() for r in results]}


@router.post("/items/{item_id}/price-components")
async def add_price_component_endpoint(item_id: str, body: Dict[str, Any], ctx=Depends(require_ui_session)):
    from app.services.product_price_components import set_price_component as _svc
    from app.models import ProductPriceComponentIn
    _require_item_owner(item_id, ctx["user_sub"])
    comp = ProductPriceComponentIn(**body)
    result = _svc(item_id=item_id, creator_id=ctx["user_sub"], body=comp)
    return result.model_dump()


@router.get("/items/{item_id}/price-components")
async def list_price_components_endpoint(item_id: str, price_type: Optional[str] = None, ctx=Depends(require_ui_session)):
    from app.services.product_price_components import list_price_components as _svc
    results = _svc(item_id, price_type=price_type)
    return {"item_id": item_id, "components": [r.model_dump() for r in results], "count": len(results)}


@router.get("/items/{item_id}/effective-price")
async def get_effective_price_endpoint(item_id: str, price_type: str = "DEFAULT", as_of: Optional[int] = None, ctx=Depends(require_ui_session)):
    from app.services.product_price_components import resolve_effective_price as _svc
    ts = as_of if as_of is not None else int(__import__("time").time())
    result = _svc(item_id, as_of=ts, price_type=price_type)
    return result.model_dump()
