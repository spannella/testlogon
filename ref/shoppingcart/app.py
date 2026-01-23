import os
import time
import json
import uuid
import threading
import asyncio
from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional, List, Dict, Any, Set

import boto3
from botocore.exceptions import ClientError

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, conint

# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
DDB_TABLE = os.environ["DDB_TABLE"]  # required

# Strongly recommended for multi-instance correctness:
EVENTS_TABLE = os.environ.get("EVENTS_TABLE", "")  # optional but recommended
ENABLE_STREAM_CONSUMER = os.environ.get("ENABLE_STREAM_CONSUMER", "1").lower() in ("1", "true", "yes")

STREAM_POLL_SECONDS = float(os.environ.get("STREAM_POLL_SECONDS", "0.5"))
SSE_HEARTBEAT_SECONDS = float(os.environ.get("SSE_HEARTBEAT_SECONDS", "10"))
SSE_QUEUE_MAX = int(os.environ.get("SSE_QUEUE_MAX", "2000"))  # per-connection queue
EVENT_RETENTION_SECONDS = int(os.environ.get("EVENT_RETENTION_SECONDS", "3600"))  # if writing events table

ddb = boto3.resource("dynamodb", region_name=AWS_REGION)
ddb_client = boto3.client("dynamodb", region_name=AWS_REGION)
streams_client = boto3.client("dynamodbstreams", region_name=AWS_REGION)

tbl = ddb.Table(DDB_TABLE)
events_tbl = ddb.Table(EVENTS_TABLE) if EVENTS_TABLE else None

app = FastAPI(title="Shopping Cart (FastAPI + DynamoDB + Streams + SSE)", version="1.1.0")


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def gen_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"

def user_pk(user_id: str) -> str:
    return f"USER#{user_id}"

def cart_sk(cart_id: str) -> str:
    return f"CART#{cart_id}"

def item_sk(cart_id: str, sku: str) -> str:
    return f"CART#{cart_id}#ITEM#{sku}"

def cart_event_pk(cart_id: str) -> str:
    return f"CART#{cart_id}"

def event_sk(created_at_iso: str, ev_id: str) -> str:
    # ISO timestamps sort lexicographically; prefix to make it explicit.
    return f"TS#{created_at_iso}#EV#{ev_id}"

def is_open_cart(cart: Dict[str, Any]) -> bool:
    return cart.get("status") == "OPEN"

def ddb_to_int(x: Any) -> int:
    if isinstance(x, Decimal):
        return int(x)
    return int(x)

def price_to_decimal_cents(cents: int) -> Decimal:
    return Decimal(int(cents))

def safe_user_id(x_user_id: Optional[str]) -> str:
    if not x_user_id or not x_user_id.strip():
        raise HTTPException(status_code=400, detail="Missing X-User-Id header")
    return x_user_id.strip()

def compute_cart_total_cents_from_items(items: List[Dict[str, Any]]) -> int:
    total = 0
    for it in items:
        qty = ddb_to_int(it.get("quantity", 0))
        unit = ddb_to_int(it.get("unit_price_cents", 0))
        total += qty * unit
    return total


# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------
class StartCartResponse(BaseModel):
    cart_id: str
    status: str
    created_at: str

class CartSummary(BaseModel):
    cart_id: str
    status: str
    created_at: str
    purchased_at: Optional[str] = None
    purchased_total_cents: Optional[int] = None

class AddItemRequest(BaseModel):
    sku: str = Field(..., min_length=1, max_length=128)
    name: str = Field(..., min_length=1, max_length=256)
    quantity: conint(ge=1, le=1_000) = 1
    unit_price_cents: conint(ge=0, le=1_000_000_00)

class ItemView(BaseModel):
    sku: str
    name: str
    quantity: int
    unit_price_cents: int
    line_total_cents: int
    updated_at: str

class ListItemsResponse(BaseModel):
    cart_id: str
    items: List[ItemView]

class CartTotalResponse(BaseModel):
    cart_id: str
    total_cents: int
    currency: str = "USD"

class PurchaseResponse(BaseModel):
    cart_id: str
    order_id: str
    purchased_at: str
    purchased_total_cents: int
    currency: str = "USD"


# -----------------------------------------------------------------------------
# DynamoDB accessors
# -----------------------------------------------------------------------------
def get_cart(user_id: str, cart_id: str) -> Optional[Dict[str, Any]]:
    try:
        resp = tbl.get_item(Key={"PK": user_pk(user_id), "SK": cart_sk(cart_id)})
        return resp.get("Item")
    except ClientError as e:
        raise HTTPException(status_code=500, detail=f"DynamoDB error: {e.response['Error']['Message']}")

def list_cart_items_raw(user_id: str, cart_id: str) -> List[Dict[str, Any]]:
    pk = user_pk(user_id)
    prefix = f"CART#{cart_id}#ITEM#"
    try:
        resp = tbl.query(
            KeyConditionExpression="PK = :pk AND begins_with(SK, :skpref)",
            ExpressionAttributeValues={":pk": pk, ":skpref": prefix},
        )
        return resp.get("Items", [])
    except ClientError as e:
        raise HTTPException(status_code=500, detail=f"DynamoDB error: {e.response['Error']['Message']}")


# -----------------------------------------------------------------------------
# Real-time fanout hub (in-memory, per server instance)
# -----------------------------------------------------------------------------
class CartHub:
    """
    In-memory pubsub per cart_id. This keeps multiple browser sessions in sync
    IF they are connected to the same FastAPI instance.

    For multi-instance deployments, also enable EVENTS_TABLE and have SSE clients
    fall back to reading missed events from the events table using Last-Event-ID.
    """
    def __init__(self):
        self._lock = asyncio.Lock()
        self._subs: Dict[str, Set[asyncio.Queue]] = {}

    async def subscribe(self, cart_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=SSE_QUEUE_MAX)
        async with self._lock:
            self._subs.setdefault(cart_id, set()).add(q)
        return q

    async def unsubscribe(self, cart_id: str, q: asyncio.Queue):
        async with self._lock:
            s = self._subs.get(cart_id)
            if not s:
                return
            s.discard(q)
            if not s:
                self._subs.pop(cart_id, None)

    async def publish(self, cart_id: str, event: Dict[str, Any]):
        # best-effort; if a client's queue is full, drop the event for that client
        async with self._lock:
            subs = list(self._subs.get(cart_id, set()))
        for q in subs:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                # drop to avoid blocking; client can re-sync using /items + /total
                pass

hub = CartHub()


# -----------------------------------------------------------------------------
# API: Start cart
# -----------------------------------------------------------------------------
@app.post("/carts", response_model=StartCartResponse)
def start_cart(x_user_id: Optional[str] = Header(default=None, convert_underscores=False)):
    user_id = safe_user_id(x_user_id)
    cart_id = gen_id("cart")
    created_at = now_iso()

    item = {
        "PK": user_pk(user_id),
        "SK": cart_sk(cart_id),
        "entity_type": "cart",
        "cart_id": cart_id,
        "status": "OPEN",
        "created_at": created_at,
        "updated_at": created_at,
        "currency": "USD",
    }

    try:
        tbl.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
        )
    except ClientError as e:
        msg = e.response["Error"]["Message"]
        raise HTTPException(status_code=500, detail=f"Failed to create cart: {msg}")

    return StartCartResponse(cart_id=cart_id, status="OPEN", created_at=created_at)


# -----------------------------------------------------------------------------
# API: List carts
# -----------------------------------------------------------------------------
@app.get("/carts", response_model=List[CartSummary])
def list_carts(
    x_user_id: Optional[str] = Header(default=None, convert_underscores=False),
    status: Optional[str] = None,
    limit: int = 50,
):
    user_id = safe_user_id(x_user_id)
    limit = max(1, min(limit, 200))

    try:
        resp = tbl.query(
            KeyConditionExpression="PK = :pk AND begins_with(SK, :skpref)",
            ExpressionAttributeValues={":pk": user_pk(user_id), ":skpref": "CART#"},
            Limit=limit,
        )
        carts = []
        for it in resp.get("Items", []):
            if it.get("entity_type") != "cart":
                continue
            if status and it.get("status") != status:
                continue
            carts.append(
                CartSummary(
                    cart_id=it["cart_id"],
                    status=it["status"],
                    created_at=it["created_at"],
                    purchased_at=it.get("purchased_at"),
                    purchased_total_cents=(ddb_to_int(it["purchased_total_cents"]) if "purchased_total_cents" in it else None),
                )
            )
        carts.sort(key=lambda x: x.created_at, reverse=True)
        return carts
    except ClientError as e:
        raise HTTPException(status_code=500, detail=f"DynamoDB error: {e.response['Error']['Message']}")


# -----------------------------------------------------------------------------
# API: Delete cart (and all items)
# -----------------------------------------------------------------------------
@app.delete("/carts/{cart_id}")
def delete_cart(cart_id: str, x_user_id: Optional[str] = Header(default=None, convert_underscores=False)):
    user_id = safe_user_id(x_user_id)

    cart = get_cart(user_id, cart_id)
    if not cart:
        raise HTTPException(status_code=404, detail="Cart not found")
    if cart.get("status") == "PURCHASED":
        raise HTTPException(status_code=409, detail="Cannot delete a purchased cart")

    items = list_cart_items_raw(user_id, cart_id)
    pk = user_pk(user_id)

    try:
        with tbl.batch_writer() as bw:
            for it in items:
                bw.delete_item(Key={"PK": pk, "SK": it["SK"]})
            bw.delete_item(Key={"PK": pk, "SK": cart_sk(cart_id)})
    except ClientError as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete cart: {e.response['Error']['Message']}")

    return {"ok": True, "cart_id": cart_id, "deleted_items": len(items)}


# -----------------------------------------------------------------------------
# API: Add item (upsert)
# -----------------------------------------------------------------------------
@app.post("/carts/{cart_id}/items", response_model=ItemView)
def add_item(
    cart_id: str,
    req: AddItemRequest,
    x_user_id: Optional[str] = Header(default=None, convert_underscores=False),
):
    user_id = safe_user_id(x_user_id)
    cart = get_cart(user_id, cart_id)
    if not cart:
        raise HTTPException(status_code=404, detail="Cart not found")
    if not is_open_cart(cart):
        raise HTTPException(status_code=409, detail="Cart is not OPEN")

    pk = user_pk(user_id)
    sk = item_sk(cart_id, req.sku)
    updated_at = now_iso()

    # Upsert: if exists, ADD quantity; else it creates quantity
    try:
        resp = tbl.update_item(
            Key={"PK": pk, "SK": sk},
            UpdateExpression=(
                "SET entity_type = :etype, cart_id = :cid, sku = :sku, #nm = :nm, "
                "unit_price_cents = :unit, updated_at = :ua "
                "ADD quantity :q"
            ),
            ExpressionAttributeNames={"#nm": "name"},
            ExpressionAttributeValues={
                ":etype": "cart_item",
                ":cid": cart_id,
                ":sku": req.sku,
                ":nm": req.name,
                ":unit": price_to_decimal_cents(req.unit_price_cents),
                ":ua": updated_at,
                ":q": price_to_decimal_cents(req.quantity),
            },
            ReturnValues="ALL_NEW",
        )
    except ClientError as e:
        raise HTTPException(status_code=500, detail=f"Failed to add item: {e.response['Error']['Message']}")

    it = resp["Attributes"]
    qty = ddb_to_int(it.get("quantity", 0))
    unit = ddb_to_int(it.get("unit_price_cents", 0))
    return ItemView(
        sku=it["sku"],
        name=it["name"],
        quantity=qty,
        unit_price_cents=unit,
        line_total_cents=qty * unit,
        updated_at=it["updated_at"],
    )


# -----------------------------------------------------------------------------
# API: Remove item (decrement or delete)
# -----------------------------------------------------------------------------
@app.delete("/carts/{cart_id}/items/{sku}")
def remove_item(
    cart_id: str,
    sku: str,
    quantity: int = 1,
    x_user_id: Optional[str] = Header(default=None, convert_underscores=False),
):
    user_id = safe_user_id(x_user_id)
    if quantity < 1 or quantity > 1000:
        raise HTTPException(status_code=400, detail="quantity must be 1..1000")

    cart = get_cart(user_id, cart_id)
    if not cart:
        raise HTTPException(status_code=404, detail="Cart not found")
    if not is_open_cart(cart):
        raise HTTPException(status_code=409, detail="Cart is not OPEN")

    pk = user_pk(user_id)
    sk = item_sk(cart_id, sku)

    try:
        resp = tbl.get_item(Key={"PK": pk, "SK": sk})
        it = resp.get("Item")
        if not it:
            raise HTTPException(status_code=404, detail="Item not found")
        cur_qty = ddb_to_int(it.get("quantity", 0))

        if cur_qty <= quantity:
            tbl.delete_item(Key={"PK": pk, "SK": sk})
            return {"ok": True, "cart_id": cart_id, "sku": sku, "removed": cur_qty, "deleted": True}
        else:
            new_qty = cur_qty - quantity
            ua = now_iso()
            tbl.update_item(
                Key={"PK": pk, "SK": sk},
                UpdateExpression="SET quantity = :nq, updated_at = :ua",
                ExpressionAttributeValues={
                    ":nq": price_to_decimal_cents(new_qty),
                    ":ua": ua,
                },
            )
            return {"ok": True, "cart_id": cart_id, "sku": sku, "removed": quantity, "deleted": False, "remaining": new_qty}
    except HTTPException:
        raise
    except ClientError as e:
        raise HTTPException(status_code=500, detail=f"Failed to remove item: {e.response['Error']['Message']}")


# -----------------------------------------------------------------------------
# API: List items
# -----------------------------------------------------------------------------
@app.get("/carts/{cart_id}/items")
def list_items(cart_id: str, x_user_id: Optional[str] = Header(default=None, convert_underscores=False)):
    user_id = safe_user_id(x_user_id)
    cart = get_cart(user_id, cart_id)
    if not cart:
        raise HTTPException(status_code=404, detail="Cart not found")

    items = list_cart_items_raw(user_id, cart_id)
    views: List[Dict[str, Any]] = []
    for it in items:
        qty = ddb_to_int(it.get("quantity", 0))
        unit = ddb_to_int(it.get("unit_price_cents", 0))
        views.append(
            {
                "sku": it["sku"],
                "name": it.get("name", ""),
                "quantity": qty,
                "unit_price_cents": unit,
                "line_total_cents": qty * unit,
                "updated_at": it.get("updated_at", ""),
            }
        )
    views.sort(key=lambda x: x["sku"])
    return {"cart_id": cart_id, "items": views}


# -----------------------------------------------------------------------------
# API: Get cart total
# -----------------------------------------------------------------------------
@app.get("/carts/{cart_id}/total")
def get_cart_total(cart_id: str, x_user_id: Optional[str] = Header(default=None, convert_underscores=False)):
    user_id = safe_user_id(x_user_id)
    cart = get_cart(user_id, cart_id)
    if not cart:
        raise HTTPException(status_code=404, detail="Cart not found")

    items = list_cart_items_raw(user_id, cart_id)
    total = compute_cart_total_cents_from_items(items)
    return {"cart_id": cart_id, "total_cents": total, "currency": cart.get("currency", "USD")}


# -----------------------------------------------------------------------------
# API: Purchase cart
# -----------------------------------------------------------------------------
@app.post("/carts/{cart_id}/purchase", response_model=PurchaseResponse)
def purchase_cart(cart_id: str, x_user_id: Optional[str] = Header(default=None, convert_underscores=False)):
    user_id = safe_user_id(x_user_id)
    cart = get_cart(user_id, cart_id)
    if not cart:
        raise HTTPException(status_code=404, detail="Cart not found")
    if cart.get("status") == "PURCHASED":
        raise HTTPException(status_code=409, detail="Cart already purchased")
    if not is_open_cart(cart):
        raise HTTPException(status_code=409, detail="Cart is not OPEN")

    items = list_cart_items_raw(user_id, cart_id)
    if not items:
        raise HTTPException(status_code=409, detail="Cannot purchase an empty cart")

    total_cents = compute_cart_total_cents_from_items(items)
    purchased_at = now_iso()
    order_id = gen_id("order")

    pk = user_pk(user_id)
    cart_key = {"PK": pk, "SK": cart_sk(cart_id)}

    try:
        ddb_client.transact_write_items(
            TransactItems=[
                {
                    "Update": {
                        "TableName": DDB_TABLE,
                        "Key": {"PK": {"S": cart_key["PK"]}, "SK": {"S": cart_key["SK"]}},
                        "UpdateExpression": "SET #st = :p, purchased_at = :pa, purchased_total_cents = :tot, order_id = :oid, updated_at = :ua",
                        "ConditionExpression": "#st = :open",
                        "ExpressionAttributeNames": {"#st": "status"},
                        "ExpressionAttributeValues": {
                            ":p": {"S": "PURCHASED"},
                            ":open": {"S": "OPEN"},
                            ":pa": {"S": purchased_at},
                            ":ua": {"S": purchased_at},
                            ":oid": {"S": order_id},
                            ":tot": {"N": str(int(total_cents))},
                        },
                    }
                },
                {
                    "Put": {
                        "TableName": DDB_TABLE,
                        "Item": {
                            "PK": {"S": pk},
                            "SK": {"S": f"ORDER#{order_id}"},
                            "entity_type": {"S": "order"},
                            "order_id": {"S": order_id},
                            "cart_id": {"S": cart_id},
                            "created_at": {"S": purchased_at},
                            "total_cents": {"N": str(int(total_cents))},
                            "currency": {"S": cart.get("currency", "USD")},
                        },
                        "ConditionExpression": "attribute_not_exists(PK) AND attribute_not_exists(SK)",
                    }
                },
            ]
        )
    except ClientError as e:
        code = e.response["Error"].get("Code", "")
        if code == "TransactionCanceledException":
            raise HTTPException(status_code=409, detail="Purchase failed (cart not OPEN anymore)")
        raise HTTPException(status_code=500, detail=f"Failed to purchase cart: {e.response['Error']['Message']}")

    return PurchaseResponse(
        cart_id=cart_id,
        order_id=order_id,
        purchased_at=purchased_at,
        purchased_total_cents=total_cents,
        currency=cart.get("currency", "USD"),
    )


# -----------------------------------------------------------------------------
# SSE endpoint: real-time cart events
# -----------------------------------------------------------------------------
@app.get("/carts/{cart_id}/events")
async def cart_events_sse(
    cart_id: str,
    x_user_id: Optional[str] = Header(default=None, convert_underscores=False),
    last_event_id: Optional[str] = None,  # optional query param
    last_event_id_header: Optional[str] = Header(default=None, alias="Last-Event-ID"),
):
    """
    Server-Sent Events stream.
    - Subscribe and receive real-time cart updates (from DynamoDB Streams fanout).
    - If EVENTS_TABLE is enabled, we can also replay missed events (best-effort).
    """
    user_id = safe_user_id(x_user_id)
    cart = get_cart(user_id, cart_id)
    if not cart:
        raise HTTPException(status_code=404, detail="Cart not found")

    # Prefer Last-Event-ID header over query param
    cursor = last_event_id_header or last_event_id

    q = await hub.subscribe(cart_id)

    async def maybe_replay_from_events_table():
        # Best-effort: if you use EVENTS_TABLE you can pull recent events.
        # We don't do a perfect resume here (that requires tracking and querying by SK),
        # but we *can* quickly dump a small recent window so client catches up.
        if not events_tbl:
            return []
        try:
            # Pull last N events (descending requires a different schema; we'll just pull recent by Query + limit)
            resp = events_tbl.query(
                KeyConditionExpression="PK = :pk",
                ExpressionAttributeValues={":pk": cart_event_pk(cart_id)},
                Limit=50,
            )
            items = resp.get("Items", [])
            # Sort by SK
            items.sort(key=lambda it: it["SK"])
            # If cursor is provided, only send events with id > cursor (cursor is an event_id string)
            if cursor:
                items = [it for it in items if it.get("event_id") and it["event_id"] > cursor]
            out = []
            for it in items:
                out.append({
                    "id": it.get("event_id", ""),
                    "type": it.get("event_type", "replay"),
                    "created_at": it.get("created_at", ""),
                    "payload": it.get("payload", {}),
                })
            return out
        except Exception:
            return []

    replay = await maybe_replay_from_events_table()

    async def event_gen():
        # On connect, send a "hello" plus an optional replay
        hello_id = gen_id("hello")
        yield f"id: {hello_id}\nevent: hello\ndata: {json.dumps({'cart_id': cart_id, 'ts': now_iso()})}\n\n"

        for ev in replay:
            ev_id = ev.get("id") or gen_id("ev")
            yield f"id: {ev_id}\nevent: {ev.get('type','replay')}\ndata: {json.dumps(ev)}\n\n"

        last_hb = time.time()

        try:
            while True:
                # heartbeat so proxies don't kill it
                now = time.time()
                if now - last_hb >= SSE_HEARTBEAT_SECONDS:
                    last_hb = now
                    yield f"event: heartbeat\ndata: {json.dumps({'ts': now_iso()})}\n\n"

                try:
                    ev = await asyncio.wait_for(q.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue

                ev_id = ev.get("event_id") or gen_id("ev")
                ev_type = ev.get("event_type", "update")
                yield f"id: {ev_id}\nevent: {ev_type}\ndata: {json.dumps(ev)}\n\n"
        finally:
            await hub.unsubscribe(cart_id, q)

    return StreamingResponse(event_gen(), media_type="text/event-stream")


# -----------------------------------------------------------------------------
# DynamoDB Streams consumer (reads stream, emits to hub, optionally writes EVENTS_TABLE)
# -----------------------------------------------------------------------------
def _describe_stream_arn_for_table(table_name: str) -> Optional[str]:
    resp = ddb_client.describe_table(TableName=table_name)
    return resp["Table"].get("LatestStreamArn")

def _extract_cart_ids_from_stream_record(r: Dict[str, Any]) -> Set[str]:
    """
    Tries to find cart_id(s) affected by this record.
    We rely on your single-table key patterns:
      - cart item SK: CART#{cart_id}#ITEM#{sku}
      - cart SK: CART#{cart_id}
    """
    cart_ids: Set[str] = set()

    def inspect_keys(img: Dict[str, Any]):
        if not img:
            return
        # Keys may be in Keys or in NewImage/OldImage depending on stream view type.
        pk = img.get("PK", {}).get("S") if isinstance(img.get("PK"), dict) else None
        sk = img.get("SK", {}).get("S") if isinstance(img.get("SK"), dict) else None
        # If it's already plain dict (when we repackage), handle that too:
        if pk is None and isinstance(img.get("PK"), str):
            pk = img.get("PK")
        if sk is None and isinstance(img.get("SK"), str):
            sk = img.get("SK")

        if not sk:
            return
        if sk.startswith("CART#") and "#ITEM#" in sk:
            # CART#{cart_id}#ITEM#{sku}
            mid = sk.split("#ITEM#", 1)[0]  # CART#{cart_id}
            cart_ids.add(mid.split("CART#", 1)[1])
        elif sk.startswith("CART#") and sk.count("#") == 1:
            # CART#{cart_id}
            cart_ids.add(sk.split("CART#", 1)[1])

    ddbrec = r.get("dynamodb", {})
    inspect_keys(ddbrec.get("Keys", {}))
    inspect_keys(ddbrec.get("NewImage", {}))
    inspect_keys(ddbrec.get("OldImage", {}))
    return cart_ids

def _make_event_from_stream_record(r: Dict[str, Any], cart_id: str) -> Dict[str, Any]:
    ev_id = gen_id("ev")
    created_at = now_iso()
    event_type = r.get("eventName", "update")  # INSERT/MODIFY/REMOVE

    # Keep payload light: ship keys + eventName; client can refetch /items and /total
    ddbrec = r.get("dynamodb", {})
    payload = {
        "eventName": r.get("eventName"),
        "approxCreationDateTime": ddbrec.get("ApproximateCreationDateTime"),
        "keys": ddbrec.get("Keys"),
    }

    return {
        "event_id": ev_id,
        "event_type": event_type.lower(),
        "cart_id": cart_id,
        "created_at": created_at,
        "payload": payload,
    }

def _write_event_to_events_table(event: Dict[str, Any]):
    if not events_tbl:
        return
    try:
        # Optional TTL if your EVENTS_TABLE has TTL enabled on 'ttl'
        ttl = int(time.time()) + EVENT_RETENTION_SECONDS
        events_tbl.put_item(
            Item={
                "PK": cart_event_pk(event["cart_id"]),
                "SK": event_sk(event["created_at"], event["event_id"]),
                "event_id": event["event_id"],
                "event_type": event["event_type"],
                "cart_id": event["cart_id"],
                "created_at": event["created_at"],
                "payload": event["payload"],
                "ttl": ttl,
            }
        )
    except Exception:
        # best-effort
        pass

def _stream_consumer_loop(stop_flag: threading.Event):
    try:
        stream_arn = _describe_stream_arn_for_table(DDB_TABLE)
        if not stream_arn:
            print("[streams] Table has no LatestStreamArn. Is DynamoDB Streams enabled?")
            return

        desc = streams_client.describe_stream(StreamArn=stream_arn)
        shards = desc["StreamDescription"].get("Shards", [])
        if not shards:
            print("[streams] No shards found.")
            return

        shard_iters: Dict[str, str] = {}
        for sh in shards:
            shard_id = sh["ShardId"]
            it = streams_client.get_shard_iterator(
                StreamArn=stream_arn,
                ShardId=shard_id,
                ShardIteratorType="LATEST",
            )["ShardIterator"]
            shard_iters[shard_id] = it

        print(f"[streams] consumer started. shards={len(shard_iters)} events_table={'on' if events_tbl else 'off'}")

        # We need an event loop reference to publish into asyncio hub from this thread.
        loop = asyncio.get_event_loop()

        while not stop_flag.is_set():
            for shard_id, it in list(shard_iters.items()):
                if stop_flag.is_set():
                    break
                if not it:
                    continue

                resp = streams_client.get_records(ShardIterator=it, Limit=200)
                shard_iters[shard_id] = resp.get("NextShardIterator")
                recs = resp.get("Records", [])

                for r in recs:
                    cart_ids = _extract_cart_ids_from_stream_record(r)
                    for cid in cart_ids:
                        ev = _make_event_from_stream_record(r, cid)
                        _write_event_to_events_table(ev)
                        # publish to SSE subscribers (async)
                        asyncio.run_coroutine_threadsafe(hub.publish(cid, ev), loop)

            time.sleep(STREAM_POLL_SECONDS)

        print("[streams] consumer stopping")

    except Exception as e:
        print(f"[streams] consumer error: {e}")


_stream_stop = threading.Event()
_stream_thread: Optional[threading.Thread] = None

@app.on_event("startup")
def on_startup():
    global _stream_thread
    if ENABLE_STREAM_CONSUMER:
        # NOTE: uvicorn uses an event loop; stream thread will publish into it via run_coroutine_threadsafe.
        _stream_thread = threading.Thread(target=_stream_consumer_loop, args=(_stream_stop,), daemon=True)
        _stream_thread.start()

@app.on_event("shutdown")
def on_shutdown():
    _stream_stop.set()
    if _stream_thread and _stream_thread.is_alive():
        _stream_thread.join(timeout=2.0)


# -----------------------------------------------------------------------------
# Health
# -----------------------------------------------------------------------------
@app.get("/health")
def health():
    return {
        "ok": True,
        "table": DDB_TABLE,
        "region": AWS_REGION,
        "streams_consumer": ENABLE_STREAM_CONSUMER,
        "events_table": EVENTS_TABLE or None,
    }
