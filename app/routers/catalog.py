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
from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import StreamingResponse

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
    CatalogReviewCreateIn,
    CatalogReviewListOut,
    CatalogReviewOut,
)
from app.services.filemanager import download_file, upload_catalog_image
from app.services.sessions import require_ui_session
from app.services.subscription_access import can_access_creator

router = APIRouter(prefix="/ui/catalog", tags=["catalog"])

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


def _catalog_item_out(item: dict) -> CatalogItemOut:
    return CatalogItemOut(
        category_id=item["category_id"],
        item_id=item["item_id"],
        name=item["name"],
        description=item.get("description"),
        price_cents=ddb_to_int(item["price_cents"]),
        currency=item.get("currency", "USD"),
        image_urls=item.get("image_urls", []),
        attributes=item.get("attributes", {}),
        created_at=item["created_at"],
        updated_at=item["updated_at"],
    )


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
    item = {
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
    try:
        T.catalog.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise HTTPException(status_code=409, detail="Item already exists.") from exc
        raise HTTPException(status_code=500, detail="Catalog storage error.") from exc
    return CatalogItemOut(**item)


@router.get("/categories/{category_id}/items", response_model=CatalogItemListOut)
async def list_items(
    category_id: str,
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
        out.append(
            CatalogItemOut(
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
            )
        )
    return CatalogItemListOut(items=out, next_token=encode_next_token(lek))


@router.get("/items/search", response_model=CatalogItemListOut)
async def search_items(
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
            if _catalog_matches(query_tokens, item):
                matches.append(_catalog_item_out(item))
                if len(matches) >= page_size:
                    break
        last_evaluated = resp.get("LastEvaluatedKey")
        if not last_evaluated:
            break

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
    )


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
        )
else:
    router.post("/categories/{category_id}/items/{item_id}/images/upload")(_catalog_upload_unavailable)


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
