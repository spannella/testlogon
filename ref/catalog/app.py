import os
import time
import json
import uuid
import base64
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError
from fastapi import FastAPI, Header, HTTPException, Depends, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, constr

# ============================================================
# Config
# ============================================================

APP_TITLE = "Shopping Catalog API (DynamoDB + Streams + Pagination + Cascades + SSE)"
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
DDB_TABLE = os.environ.get("DDB_TABLE", "shopping_catalog")
AUTO_CREATE_TABLE = os.environ.get("AUTO_CREATE_TABLE", "1") == "1"

# Minimal Bearer token gate (presence required). Replace with real JWT validation.
REQUIRE_BEARER = os.environ.get("REQUIRE_BEARER", "1") == "1"

# DynamoDB Streams poller settings
STREAM_POLL_ENABLED = os.environ.get("STREAM_POLL_ENABLED", "1") == "1"
STREAM_POLL_INTERVAL_SEC = float(os.environ.get("STREAM_POLL_INTERVAL_SEC", "0.75"))
STREAM_MAX_RECORDS = int(os.environ.get("STREAM_MAX_RECORDS", "500"))

# SSE keepalive
SSE_KEEPALIVE_SEC = float(os.environ.get("SSE_KEEPALIVE_SEC", "10"))

# Cascade job settings
CASCADE_JOB_MAX_SECONDS = float(os.environ.get("CASCADE_JOB_MAX_SECONDS", "60"))
CASCADE_BATCH_WRITE_CHUNK = int(os.environ.get("CASCADE_BATCH_WRITE_CHUNK", "25"))  # DynamoDB max per batch API call

ddb = boto3.resource("dynamodb", region_name=AWS_REGION)
ddb_client = boto3.client("dynamodb", region_name=AWS_REGION)
streams_client = boto3.client("dynamodbstreams", region_name=AWS_REGION)

app = FastAPI(title=APP_TITLE)

# ============================================================
# Helpers: Auth
# ============================================================

def require_auth(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    if not REQUIRE_BEARER:
        return {"sub": "dev", "token": None}
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing/invalid Authorization header (Bearer token required).")
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Empty bearer token.")
    return {"sub": "user", "token": token}

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def ulid_like() -> str:
    return f"{int(time.time()*1000)}_{uuid.uuid4().hex}"

# ============================================================
# DynamoDB Single-Table Layout
# ============================================================
# Table: shopping_catalog
# PK (S), SK (S)
#
# Category:
#   PK = "CAT#{category_id}"
#   SK = "META"
#
# Item:
#   PK = "CAT#{category_id}"
#   SK = "ITEM#{item_id}"
#
# Review:
#   PK = "ITEM#{item_id}"
#   SK = "REVIEW#{review_id}"
#
# GSI1 for listing categories:
#   GSI1PK = "CATS"
#   GSI1SK = "{category_name_lower}#{category_id}"
#
# ============================================================

def cat_pk(category_id: str) -> str:
    return f"CAT#{category_id}"

def item_pk(item_id: str) -> str:
    return f"ITEM#{item_id}"

def item_sk(item_id: str) -> str:
    return f"ITEM#{item_id}"

def review_sk(review_id: str) -> str:
    return f"REVIEW#{review_id}"

def table():
    return ddb.Table(DDB_TABLE)

# ============================================================
# Pagination helpers (encode/decode LastEvaluatedKey)
# ============================================================

def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

def _b64d(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))

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
    except Exception:
        raise HTTPException(400, "Invalid next_token.")

# ============================================================
# Models
# ============================================================

CategoryId = constr(min_length=1, max_length=80)
ItemId = constr(min_length=1, max_length=80)
ReviewId = constr(min_length=1, max_length=120)

class PageOut(BaseModel):
    next_token: Optional[str] = None

class CategoryCreate(BaseModel):
    category_id: Optional[CategoryId] = None
    name: constr(min_length=1, max_length=200)
    description: Optional[constr(max_length=2000)] = None

class CategoryOut(BaseModel):
    category_id: str
    name: str
    description: Optional[str] = None
    created_at: str

class CategoryListOut(PageOut):
    items: List[CategoryOut]

class ItemCreate(BaseModel):
    item_id: Optional[ItemId] = None
    name: constr(min_length=1, max_length=200)
    description: Optional[constr(max_length=5000)] = None
    price_cents: int = Field(ge=0, le=10_000_000_00)
    currency: constr(min_length=3, max_length=8) = Field(default="USD")
    image_urls: List[constr(min_length=1, max_length=2000)] = Field(default_factory=list)
    attributes: Dict[str, Any] = Field(default_factory=dict)

class ItemPatch(BaseModel):
    name: Optional[constr(min_length=1, max_length=200)] = None
    description: Optional[constr(max_length=5000)] = None
    price_cents: Optional[int] = Field(default=None, ge=0, le=10_000_000_00)
    currency: Optional[constr(min_length=3, max_length=8)] = None
    image_urls: Optional[List[constr(min_length=1, max_length=2000)]] = None
    attributes: Optional[Dict[str, Any]] = None

class ItemOut(BaseModel):
    category_id: str
    item_id: str
    name: str
    description: Optional[str] = None
    price_cents: int
    currency: str
    image_urls: List[str]
    attributes: Dict[str, Any]
    created_at: str
    updated_at: str

class ItemListOut(PageOut):
    items: List[ItemOut]

class ReviewCreate(BaseModel):
    review_id: Optional[ReviewId] = None
    rating: int = Field(ge=1, le=5)
    title: Optional[constr(max_length=200)] = None
    body: Optional[constr(max_length=5000)] = None
    reviewer: Optional[constr(max_length=200)] = None

class ReviewOut(BaseModel):
    item_id: str
    review_id: str
    rating: int
    title: Optional[str] = None
    body: Optional[str] = None
    reviewer: Optional[str] = None
    created_at: str

class ReviewListOut(PageOut):
    items: List[ReviewOut]

# ============================================================
# Table bootstrap
# ============================================================

def ensure_table():
    try:
        existing = ddb_client.describe_table(TableName=DDB_TABLE)
        return existing["Table"]
    except ddb_client.exceptions.ResourceNotFoundException:
        if not AUTO_CREATE_TABLE:
            raise

    ddb_client.create_table(
        TableName=DDB_TABLE,
        BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[
            {"AttributeName": "PK", "AttributeType": "S"},
            {"AttributeName": "SK", "AttributeType": "S"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "S"},
        ],
        KeySchema=[
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI1",
                "KeySchema": [
                    {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        StreamSpecification={
            "StreamEnabled": True,
            "StreamViewType": "NEW_AND_OLD_IMAGES",
        },
    )
    waiter = ddb_client.get_waiter("table_exists")
    waiter.wait(TableName=DDB_TABLE)
    return ddb_client.describe_table(TableName=DDB_TABLE)["Table"]

# ============================================================
# SSE event bus + DynamoDB Streams poller
# ============================================================

_subs_lock = threading.Lock()
_subscribers: Dict[str, "queue.Queue[Dict[str, Any]]"] = {}

# avoid importing queue at top to keep typing simple in runtime
import queue  # noqa

_stream_stop = threading.Event()

def _broadcast(evt: Dict[str, Any]):
    """
    Broadcast event to all SSE subscribers.
    evt should be JSON-serializable.
    """
    with _subs_lock:
        for q in _subscribers.values():
            try:
                q.put_nowait(evt)
            except Exception:
                # If a queue is full or broken, drop
                pass

def _get_latest_stream_arn() -> Optional[str]:
    try:
        desc = ddb_client.describe_table(TableName=DDB_TABLE)["Table"]
        return desc.get("LatestStreamArn")
    except Exception:
        return None

def _ddb_attr_to_plain(attr: Dict[str, Any]) -> Any:
    """
    Converts a DynamoDB Streams AttributeValue (typed dict) to a plain Python object
    for common types we use.
    """
    if not isinstance(attr, dict) or len(attr) != 1:
        return attr
    (t, v), = attr.items()
    if t == "S":
        return v
    if t == "N":
        # Could be int/float; most of ours are ints
        return int(v) if v.isdigit() or (v.startswith("-") and v[1:].isdigit()) else float(v)
    if t == "BOOL":
        return bool(v)
    if t == "NULL":
        return None
    if t == "M":
        return {k: _ddb_attr_to_plain(val) for k, val in v.items()}
    if t == "L":
        return [_ddb_attr_to_plain(x) for x in v]
    return v

def _image_to_plain(img: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not img:
        return None
    return {k: _ddb_attr_to_plain(v) for k, v in img.items()}

def _classify_stream_event(event_name: str, new_img: Optional[Dict[str, Any]], old_img: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Convert raw streams record into domain event for clients.
    """
    newp = _image_to_plain(new_img)
    oldp = _image_to_plain(old_img)

    ent = None
    if newp and isinstance(newp, dict):
        ent = newp.get("entity")
    elif oldp and isinstance(oldp, dict):
        ent = oldp.get("entity")

    # Categories
    if ent == "category":
        if event_name == "INSERT":
            return {"type": "category_created", "ts": now_iso(), "category": {"category_id": newp["category_id"], "name": newp["name"]}}
        if event_name == "REMOVE":
            return {"type": "category_deleted", "ts": now_iso(), "category": {"category_id": oldp["category_id"], "name": oldp.get("name")}}
        if event_name == "MODIFY":
            return {"type": "category_updated", "ts": now_iso(), "category": {"category_id": newp["category_id"], "name": newp["name"]}}

    # Items
    if ent == "item":
        if event_name == "INSERT":
            return {
                "type": "item_created",
                "ts": now_iso(),
                "item": {"category_id": newp["category_id"], "item_id": newp["item_id"], "name": newp["name"], "price_cents": newp["price_cents"], "currency": newp["currency"]},
            }
        if event_name == "REMOVE":
            return {
                "type": "item_deleted",
                "ts": now_iso(),
                "item": {"category_id": oldp["category_id"], "item_id": oldp["item_id"], "name": oldp.get("name")},
            }
        if event_name == "MODIFY":
            return {
                "type": "item_updated",
                "ts": now_iso(),
                "item": {"category_id": newp["category_id"], "item_id": newp["item_id"], "name": newp["name"], "price_cents": newp["price_cents"], "currency": newp["currency"]},
            }

    # Reviews
    if ent == "review":
        if event_name == "INSERT":
            return {"type": "review_added", "ts": now_iso(), "review": {"item_id": newp["item_id"], "review_id": newp["review_id"], "rating": newp["rating"]}}
        if event_name == "REMOVE":
            return {"type": "review_removed", "ts": now_iso(), "review": {"item_id": oldp["item_id"], "review_id": oldp["review_id"]}}

    return None

def _streams_poll_loop():
    stream_arn = _get_latest_stream_arn()
    if not stream_arn:
        _broadcast({"type": "stream_error", "ts": now_iso(), "detail": "No stream ARN found (is Streams enabled?)"})
        return

    shard_iterators: Dict[str, str] = {}

    while not _stream_stop.is_set():
        try:
            resp = streams_client.describe_stream(StreamArn=stream_arn)
            shards = resp.get("StreamDescription", {}).get("Shards", [])

            for sh in shards:
                shard_id = sh["ShardId"]
                if shard_id not in shard_iterators:
                    it = streams_client.get_shard_iterator(
                        StreamArn=stream_arn,
                        ShardId=shard_id,
                        ShardIteratorType="LATEST",
                    )["ShardIterator"]
                    shard_iterators[shard_id] = it

            for shard_id, it in list(shard_iterators.items()):
                if not it:
                    continue
                rec = streams_client.get_records(ShardIterator=it, Limit=STREAM_MAX_RECORDS)
                shard_iterators[shard_id] = rec.get("NextShardIterator")

                for r in rec.get("Records", []):
                    event_name = r.get("eventName")
                    dyn = r.get("dynamodb", {})
                    new_img = dyn.get("NewImage")
                    old_img = dyn.get("OldImage")

                    evt = _classify_stream_event(event_name, new_img, old_img)
                    if evt:
                        _broadcast(evt)

        except Exception as e:
            _broadcast({"type": "stream_error", "ts": now_iso(), "detail": str(e)})

        time.sleep(STREAM_POLL_INTERVAL_SEC)

@app.get("/events")
def sse_events(
    _: Dict[str, Any] = Depends(require_auth),
    event_type: Optional[str] = Query(default=None, description="Optional filter, e.g. item_created"),
    category_id: Optional[str] = Query(default=None, description="Optional filter for item events"),
    item_id: Optional[str] = Query(default=None, description="Optional filter for review events"),
):
    """
    Server-Sent Events stream for realtime catalog updates.
    Clients can filter by type/category_id/item_id to reduce chatter.
    """

    client_id = uuid.uuid4().hex
    q: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=2000)

    with _subs_lock:
        _subscribers[client_id] = q

    def _matches(evt: Dict[str, Any]) -> bool:
        if event_type and evt.get("type") != event_type:
            return False
        if category_id:
            it = evt.get("item")
            if isinstance(it, dict):
                if it.get("category_id") != category_id:
                    return False
            else:
                # only item_* events have category_id
                return False
        if item_id:
            rv = evt.get("review")
            if isinstance(rv, dict):
                if rv.get("item_id") != item_id:
                    return False
            else:
                return False
        return True

    def gen():
        try:
            # Initial hello
            hello = {"type": "hello", "ts": now_iso(), "client_id": client_id}
            yield f"event: hello\ndata: {json.dumps(hello)}\n\n"

            last_keepalive = time.time()
            while True:
                try:
                    evt = q.get(timeout=1.0)
                    if _matches(evt):
                        yield f"event: {evt.get('type','message')}\ndata: {json.dumps(evt)}\n\n"
                except queue.Empty:
                    pass

                # keepalive
                nowt = time.time()
                if nowt - last_keepalive >= SSE_KEEPALIVE_SEC:
                    ka = {"type": "keepalive", "ts": now_iso()}
                    yield f"event: keepalive\ndata: {json.dumps(ka)}\n\n"
                    last_keepalive = nowt

        finally:
            with _subs_lock:
                _subscribers.pop(client_id, None)

    return StreamingResponse(gen(), media_type="text/event-stream")

# ============================================================
# DDB helpers for cascades and pagination
# ============================================================

def _query_page(
    *,
    pk: str,
    sk_begins: Optional[str],
    limit: int,
    start_key: Optional[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    expr_vals = {":pk": pk}
    if sk_begins is None:
        raise ValueError("sk_begins required for this helper")
    expr_vals[":pref"] = sk_begins

    kwargs = dict(
        KeyConditionExpression="PK = :pk AND begins_with(SK, :pref)",
        ExpressionAttributeValues=expr_vals,
        Limit=limit,
    )
    if start_key:
        kwargs["ExclusiveStartKey"] = start_key

    resp = table().query(**kwargs)
    return resp.get("Items", []), resp.get("LastEvaluatedKey")

def _gsi1_categories_page(limit: int, start_key: Optional[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    kwargs = dict(
        IndexName="GSI1",
        KeyConditionExpression="GSI1PK = :pk",
        ExpressionAttributeValues={":pk": "CATS"},
        Limit=limit,
    )
    if start_key:
        kwargs["ExclusiveStartKey"] = start_key
    resp = table().query(**kwargs)
    return resp.get("Items", []), resp.get("LastEvaluatedKey")

def _batch_delete(keys: List[Dict[str, str]]) -> int:
    """
    Batch delete by keys (PK, SK). Uses batch_writer (handles retries).
    Returns count deleted attempted.
    """
    if not keys:
        return 0
    cnt = 0
    with table().batch_writer() as bw:
        for k in keys:
            bw.delete_item(Key={"PK": k["PK"], "SK": k["SK"]})
            cnt += 1
    return cnt

# ============================================================
# Cascade delete jobs
# ============================================================

_jobs_lock = threading.Lock()
_jobs: Dict[str, Dict[str, Any]] = {}

def _job_create(kind: str, payload: Dict[str, Any]) -> str:
    job_id = ulid_like()
    with _jobs_lock:
        _jobs[job_id] = {
            "job_id": job_id,
            "kind": kind,
            "payload": payload,
            "status": "queued",
            "created_at": now_iso(),
            "updated_at": now_iso(),
            "progress": {"deleted": 0},
            "error": None,
        }
    return job_id

def _job_update(job_id: str, **updates):
    with _jobs_lock:
        j = _jobs.get(job_id)
        if not j:
            return
        j.update(updates)
        j["updated_at"] = now_iso()

@app.get("/jobs/{job_id}")
def get_job(job_id: str, _: Dict[str, Any] = Depends(require_auth)):
    with _jobs_lock:
        j = _jobs.get(job_id)
        if not j:
            raise HTTPException(404, "Job not found.")
        return j

def _cascade_delete_item_and_reviews(job_id: str, category_id: str, item_id: str):
    """
    Deletes:
      - all reviews for item (PK=ITEM#{item_id})
      - the item itself (PK=CAT#{category_id}, SK=ITEM#{item_id})
    """
    start = time.time()
    deleted = 0

    # delete reviews in pages
    pk_reviews = item_pk(item_id)
    lek = None
    while True:
        if time.time() - start > CASCADE_JOB_MAX_SECONDS:
            raise TimeoutError("Cascade job exceeded max seconds; retry or increase CASCADE_JOB_MAX_SECONDS.")
        items, lek = _query_page(pk=pk_reviews, sk_begins="REVIEW#", limit=200, start_key=lek)
        keys = [{"PK": it["PK"], "SK": it["SK"]} for it in items if it.get("entity") == "review"]
        deleted += _batch_delete(keys)
        _job_update(job_id, progress={"deleted": deleted})
        if not lek:
            break

    # delete item
    table().delete_item(Key={"PK": cat_pk(category_id), "SK": item_sk(item_id)})
    deleted += 1
    _job_update(job_id, progress={"deleted": deleted})

def _cascade_delete_category(job_id: str, category_id: str):
    """
    Deletes:
      - all items in category (PK=CAT#{category_id}, SK begins ITEM#)
      - all reviews for each item (PK=ITEM#{item_id}, SK begins REVIEW#)
      - category meta (PK=CAT#{category_id}, SK=META)
    """
    start = time.time()
    deleted = 0
    pk_cat = cat_pk(category_id)

    # Ensure category exists
    cat = table().get_item(Key={"PK": pk_cat, "SK": "META"}).get("Item")
    if not cat:
        raise KeyError("Category not found.")

    # iterate items in category
    lek = None
    item_ids: List[str] = []
    while True:
        if time.time() - start > CASCADE_JOB_MAX_SECONDS:
            raise TimeoutError("Cascade job exceeded max seconds; retry or increase CASCADE_JOB_MAX_SECONDS.")
        items, lek = _query_page(pk=pk_cat, sk_begins="ITEM#", limit=200, start_key=lek)
        for it in items:
            if it.get("entity") == "item":
                item_ids.append(it["item_id"])
        if not lek:
            break

    # delete each item's reviews + item
    for iid in item_ids:
        if time.time() - start > CASCADE_JOB_MAX_SECONDS:
            raise TimeoutError("Cascade job exceeded max seconds; retry or increase CASCADE_JOB_MAX_SECONDS.")
        _cascade_delete_item_and_reviews(job_id, category_id, iid)
        # cascade helper updates job progress, but we keep our own counter too
        with _jobs_lock:
            deleted = _jobs.get(job_id, {}).get("progress", {}).get("deleted", deleted)

    # delete category META last
    table().delete_item(Key={"PK": pk_cat, "SK": "META"})
    deleted += 1
    _job_update(job_id, progress={"deleted": deleted})

def _job_worker(job_id: str, fn, *args):
    _job_update(job_id, status="running")
    try:
        fn(job_id, *args)
        _job_update(job_id, status="done")
    except Exception as e:
        _job_update(job_id, status="error", error=str(e))

# ============================================================
# API: Categories
# ============================================================

@app.post("/categories", response_model=CategoryOut)
def create_category(body: CategoryCreate, _: Dict[str, Any] = Depends(require_auth)):
    category_id = body.category_id or ulid_like()
    pk = cat_pk(category_id)

    item = {
        "PK": pk,
        "SK": "META",
        "entity": "category",
        "category_id": category_id,
        "name": body.name,
        "name_lc": body.name.lower(),
        "description": body.description,
        "created_at": now_iso(),
        "GSI1PK": "CATS",
        "GSI1SK": f"{body.name.lower()}#{category_id}",
    }

    try:
        table().put_item(Item=item, ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise HTTPException(409, "Category already exists.")
        raise HTTPException(500, f"DDB error: {e}")

    return CategoryOut(category_id=category_id, name=body.name, description=body.description, created_at=item["created_at"])

@app.get("/categories", response_model=CategoryListOut)
def list_categories(
    _: Dict[str, Any] = Depends(require_auth),
    page_size: int = Query(default=50, ge=1, le=200),
    next_token: Optional[str] = Query(default=None),
):
    start_key = decode_next_token(next_token)
    try:
        items, lek = _gsi1_categories_page(page_size, start_key)
        out: List[CategoryOut] = []
        for it in items:
            if it.get("entity") != "category":
                continue
            out.append(CategoryOut(
                category_id=it["category_id"],
                name=it["name"],
                description=it.get("description"),
                created_at=it["created_at"],
            ))
        return CategoryListOut(items=out, next_token=encode_next_token(lek))
    except ClientError as e:
        raise HTTPException(500, f"DDB error: {e}")

@app.delete("/categories/{category_id}")
def delete_category(
    category_id: str,
    cascade: bool = Query(default=True, description="If true, delete category items and reviews too (recommended)."),
    _: Dict[str, Any] = Depends(require_auth),
):
    pk = cat_pk(category_id)

    # If not cascading, enforce empty category
    if not cascade:
        resp = table().query(
            KeyConditionExpression="PK = :pk AND begins_with(SK, :prefix)",
            ExpressionAttributeValues={":pk": pk, ":prefix": "ITEM#"},
            Limit=1,
        )
        if resp.get("Count", 0) > 0:
            raise HTTPException(409, "Category not empty. Use cascade=true or delete items first.")
        try:
            table().delete_item(Key={"PK": pk, "SK": "META"}, ConditionExpression="attribute_exists(PK) AND attribute_exists(SK)")
            return {"ok": True}
        except ClientError as e:
            if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise HTTPException(404, "Category not found.")
            raise HTTPException(500, f"DDB error: {e}")

    # Cascade via background job
    job_id = _job_create("cascade_delete_category", {"category_id": category_id})
    t = threading.Thread(target=_job_worker, args=(job_id, _cascade_delete_category, category_id), daemon=True)
    t.start()
    return {"ok": True, "job_id": job_id}

# ============================================================
# API: Items
# ============================================================

@app.post("/categories/{category_id}/items", response_model=ItemOut)
def add_item_to_category(category_id: str, body: ItemCreate, _: Dict[str, Any] = Depends(require_auth)):
    # ensure category exists
    pk_cat = cat_pk(category_id)
    cat = table().get_item(Key={"PK": pk_cat, "SK": "META"}).get("Item")
    if not cat:
        raise HTTPException(404, "Category not found.")

    item_id = body.item_id or ulid_like()
    pk = pk_cat
    sk = item_sk(item_id)
    ts = now_iso()

    item = {
        "PK": pk,
        "SK": sk,
        "entity": "item",
        "category_id": category_id,
        "item_id": item_id,
        "name": body.name,
        "description": body.description,
        "price_cents": int(body.price_cents),
        "currency": body.currency,
        "image_urls": list(body.image_urls),
        "attributes": body.attributes,
        "created_at": ts,
        "updated_at": ts,
    }

    try:
        table().put_item(Item=item, ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise HTTPException(409, "Item already exists in this category.")
        raise HTTPException(500, f"DDB error: {e}")

    return ItemOut(**item)

@app.get("/categories/{category_id}/items", response_model=ItemListOut)
def list_items_in_category(
    category_id: str,
    _: Dict[str, Any] = Depends(require_auth),
    page_size: int = Query(default=50, ge=1, le=200),
    next_token: Optional[str] = Query(default=None),
):
    pk = cat_pk(category_id)
    start_key = decode_next_token(next_token)
    try:
        items, lek = _query_page(pk=pk, sk_begins="ITEM#", limit=page_size, start_key=start_key)
        out: List[ItemOut] = []
        for it in items:
            if it.get("entity") != "item":
                continue
            out.append(ItemOut(**it))
        return ItemListOut(items=out, next_token=encode_next_token(lek))
    except ClientError as e:
        raise HTTPException(500, f"DDB error: {e}")

@app.patch("/categories/{category_id}/items/{item_id}", response_model=ItemOut)
def edit_item(category_id: str, item_id: str, body: ItemPatch, _: Dict[str, Any] = Depends(require_auth)):
    pk = cat_pk(category_id)
    sk = item_sk(item_id)

    updates = []
    names = {}
    values = {}

    def set_attr(attr: str, val: Any):
        an = f"#{attr}"
        av = f":{attr}"
        names[an] = attr
        values[av] = val
        updates.append(f"{an} = {av}")

    if body.name is not None:
        set_attr("name", body.name)
    if body.description is not None:
        set_attr("description", body.description)
    if body.price_cents is not None:
        set_attr("price_cents", int(body.price_cents))
    if body.currency is not None:
        set_attr("currency", body.currency)
    if body.image_urls is not None:
        set_attr("image_urls", list(body.image_urls))
    if body.attributes is not None:
        set_attr("attributes", body.attributes)

    set_attr("updated_at", now_iso())

    if not updates:
        raise HTTPException(400, "No fields to update.")

    try:
        resp = table().update_item(
            Key={"PK": pk, "SK": sk},
            ConditionExpression="attribute_exists(PK) AND attribute_exists(SK)",
            UpdateExpression="SET " + ", ".join(updates),
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
            ReturnValues="ALL_NEW",
        )
        it = resp.get("Attributes")
        if not it:
            raise HTTPException(404, "Item not found.")
        return ItemOut(**it)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise HTTPException(404, "Item not found.")
        raise HTTPException(500, f"DDB error: {e}")

@app.delete("/categories/{category_id}/items/{item_id}")
def delete_item_from_category(
    category_id: str,
    item_id: str,
    cascade: bool = Query(default=True, description="If true, delete item reviews too (recommended)."),
    _: Dict[str, Any] = Depends(require_auth),
):
    if not cascade:
        # enforce no reviews
        resp = table().query(
            KeyConditionExpression="PK = :pk AND begins_with(SK, :prefix)",
            ExpressionAttributeValues={":pk": item_pk(item_id), ":prefix": "REVIEW#"},
            Limit=1,
        )
        if resp.get("Count", 0) > 0:
            raise HTTPException(409, "Item has reviews. Use cascade=true or remove reviews first.")
        table().delete_item(Key={"PK": cat_pk(category_id), "SK": item_sk(item_id)})
        return {"ok": True}

    job_id = _job_create("cascade_delete_item", {"category_id": category_id, "item_id": item_id})
    t = threading.Thread(target=_job_worker, args=(job_id, _cascade_delete_item_and_reviews, category_id, item_id), daemon=True)
    t.start()
    return {"ok": True, "job_id": job_id}

# ============================================================
# API: Reviews
# ============================================================

@app.get("/items/{item_id}/reviews", response_model=ReviewListOut)
def list_item_reviews(
    item_id: str,
    _: Dict[str, Any] = Depends(require_auth),
    page_size: int = Query(default=50, ge=1, le=200),
    next_token: Optional[str] = Query(default=None),
):
    pk = item_pk(item_id)
    start_key = decode_next_token(next_token)
    try:
        items, lek = _query_page(pk=pk, sk_begins="REVIEW#", limit=page_size, start_key=start_key)
        out: List[ReviewOut] = []
        for it in items:
            if it.get("entity") != "review":
                continue
            out.append(ReviewOut(
                item_id=it["item_id"],
                review_id=it["review_id"],
                rating=int(it["rating"]),
                title=it.get("title"),
                body=it.get("body"),
                reviewer=it.get("reviewer"),
                created_at=it["created_at"],
            ))
        return ReviewListOut(items=out, next_token=encode_next_token(lek))
    except ClientError as e:
        raise HTTPException(500, f"DDB error: {e}")

@app.post("/items/{item_id}/reviews", response_model=ReviewOut)
def add_item_review(item_id: str, body: ReviewCreate, _: Dict[str, Any] = Depends(require_auth)):
    review_id = body.review_id or ulid_like()
    pk = item_pk(item_id)
    sk = review_sk(review_id)

    item = {
        "PK": pk,
        "SK": sk,
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
        table().put_item(Item=item, ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise HTTPException(409, "Review already exists.")
        raise HTTPException(500, f"DDB error: {e}")

    return ReviewOut(
        item_id=item_id,
        review_id=review_id,
        rating=item["rating"],
        title=item.get("title"),
        body=item.get("body"),
        reviewer=item.get("reviewer"),
        created_at=item["created_at"],
    )

@app.delete("/items/{item_id}/reviews/{review_id}")
def remove_item_review(item_id: str, review_id: str, _: Dict[str, Any] = Depends(require_auth)):
    try:
        table().delete_item(
            Key={"PK": item_pk(item_id), "SK": review_sk(review_id)},
            ConditionExpression="attribute_exists(PK) AND attribute_exists(SK)",
        )
        return {"ok": True}
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise HTTPException(404, "Review not found.")
        raise HTTPException(500, f"DDB error: {e}")

# ============================================================
# Health / Startup / Shutdown
# ============================================================

@app.get("/health")
def health():
    return {"ok": True, "table": DDB_TABLE, "region": AWS_REGION}

@app.on_event("startup")
def on_startup():
    ensure_table()
    if STREAM_POLL_ENABLED:
        t = threading.Thread(target=_streams_poll_loop, daemon=True)
        t.start()

@app.on_event("shutdown")
def on_shutdown():
    _stream_stop.set()
