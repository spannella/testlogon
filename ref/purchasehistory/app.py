import os
import time
import json
import uuid
import threading
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Literal

import boto3
from botocore.exceptions import ClientError

from fastapi import FastAPI, HTTPException, Header, Depends, Query
from pydantic import BaseModel, Field, conint, confloat

# =============================================================================
# Config
# =============================================================================

AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

# Main table holds transactions and a couple of GSI-friendly attributes
DDB_TXN_TABLE = os.environ.get("DDB_TXN_TABLE", "purchase_transactions")
# Events table holds audit trail produced by the Streams consumer
DDB_EVENTS_TABLE = os.environ.get("DDB_EVENTS_TABLE", "purchase_transaction_events")

# Set to "1" to auto-create tables on startup (useful for dev)
AUTO_CREATE_TABLES = os.environ.get("AUTO_CREATE_TABLES", "1") == "1"

# Enable the in-process streams consumer (dev / small deployments)
ENABLE_STREAMS_CONSUMER = os.environ.get("ENABLE_STREAMS_CONSUMER", "1") == "1"

# Streams consumer poll seconds
STREAM_POLL_SECONDS = float(os.environ.get("STREAM_POLL_SECONDS", "0.75"))

ddb = boto3.client("dynamodb", region_name=AWS_REGION)
ddb_resource = boto3.resource("dynamodb", region_name=AWS_REGION)

app = FastAPI(title="Purchase Transaction History (DynamoDB + Streams)")


# =============================================================================
# Helpers
# =============================================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def require(cond: bool, status: int, message: str):
    if not cond:
        raise HTTPException(status_code=status, detail=message)

def get_user_id_from_bearer(authorization: Optional[str]) -> str:
    """
    Demo auth:
      Authorization: Bearer <user_id>
    """
    require(bool(authorization), 401, "Missing Authorization header")
    parts = authorization.split()
    require(len(parts) == 2 and parts[0].lower() == "bearer", 401, "Invalid Authorization header")
    user_id = parts[1].strip()
    require(len(user_id) >= 3, 401, "Invalid user id")
    return user_id

def get_table(name: str):
    return ddb_resource.Table(name)

def ddb_str(x: str) -> Dict[str, str]:
    return {"S": x}

def ddb_num(x: float) -> Dict[str, str]:
    # DynamoDB expects numbers as strings
    return {"N": str(x)}

def ddb_int(x: int) -> Dict[str, str]:
    return {"N": str(int(x))}


# =============================================================================
# Data Model
# =============================================================================

TxnStatus = Literal[
    "PENDING",            # created, not completed yet
    "COMPLETED",          # completed successfully
    "REVERTED",           # payment reverted/refunded/reversed
    "CANCEL_REQUESTED",   # cancellation requested by buyer/seller/admin
    "CANCELLED",          # cancellation approved
    "CANCEL_DENIED"       # cancellation denied, transaction continues
]

CancelDecision = Literal["APPROVE", "DENY"]

class Money(BaseModel):
    amount: confloat(gt=0) = Field(..., description="Transaction amount (positive)")
    currency: str = Field(..., min_length=3, max_length=10, description="Currency code, e.g. USD")

class ShippingInfo(BaseModel):
    carrier: Optional[str] = None
    tracking_number: Optional[str] = None
    shipped_at: Optional[str] = None  # ISO-8601
    delivered_at: Optional[str] = None  # ISO-8601
    address: Optional[Dict[str, Any]] = None  # arbitrary structured address

class AddPurchaseTransactionRequest(BaseModel):
    # Buyer is derived from auth; include merchant/seller or external references here:
    merchant_id: Optional[str] = None
    external_ref: Optional[str] = None  # payment processor id, order id, etc.
    money: Money
    description: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class AddPurchaseTransactionResponse(BaseModel):
    txn_id: str
    status: TxnStatus
    created_at: str

class TransactionSummary(BaseModel):
    txn_id: str
    created_at: str
    updated_at: str
    status: TxnStatus
    amount: float
    currency: str
    merchant_id: Optional[str] = None
    external_ref: Optional[str] = None
    description: Optional[str] = None

class TransactionInfo(TransactionSummary):
    buyer_id: str
    shipping: Optional[ShippingInfo] = None
    cancel: Optional[Dict[str, Any]] = None
    completed_at: Optional[str] = None
    reverted_at: Optional[str] = None
    version: int
    metadata: Optional[Dict[str, Any]] = None

class MarkRevertedRequest(BaseModel):
    reason: Optional[str] = None

class UpdateShippingRequest(BaseModel):
    shipping: ShippingInfo

class RequestCancelRequest(BaseModel):
    reason: Optional[str] = None

class RespondCancelRequest(BaseModel):
    decision: CancelDecision
    note: Optional[str] = None

class MarkCompletedRequest(BaseModel):
    # optionally store settlement / processor references, etc.
    processor_ref: Optional[str] = None
    note: Optional[str] = None


# =============================================================================
# Auth Dependency
# =============================================================================

def current_user_id(Authorization: Optional[str] = Header(default=None)) -> str:
    return get_user_id_from_bearer(Authorization)


# =============================================================================
# Table Creation (Dev helper)
# =============================================================================

def create_tables_if_needed():
    existing = set()
    try:
        resp = ddb.list_tables()
        existing = set(resp.get("TableNames", []))
    except Exception:
        pass

    if DDB_TXN_TABLE not in existing:
        print(f"[init] creating table {DDB_TXN_TABLE} ...")
        # PK: pk, SK: sk
        # pk = "USER#<buyer_id>"
        # sk = "TXN#<created_at>#<txn_id>"
        # GSI1 for direct lookup by txn_id:
        #   gsi1pk = "TXN#<txn_id>"
        #   gsi1sk = "TXN"
        ddb.create_table(
            TableName=DDB_TXN_TABLE,
            BillingMode="PAY_PER_REQUEST",
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "gsi1pk", "AttributeType": "S"},
                {"AttributeName": "gsi1sk", "AttributeType": "S"},
            ],
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "gsi1",
                    "KeySchema": [
                        {"AttributeName": "gsi1pk", "KeyType": "HASH"},
                        {"AttributeName": "gsi1sk", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
            StreamSpecification={
                "StreamEnabled": True,
                "StreamViewType": "NEW_AND_OLD_IMAGES",
            },
        )
        ddb.get_waiter("table_exists").wait(TableName=DDB_TXN_TABLE)
        print(f"[init] created {DDB_TXN_TABLE}")

    if DDB_EVENTS_TABLE not in existing:
        print(f"[init] creating table {DDB_EVENTS_TABLE} ...")
        # Events table:
        # pk = "TXN#<txn_id>"
        # sk = "<event_time>#<event_id>"
        ddb.create_table(
            TableName=DDB_EVENTS_TABLE,
            BillingMode="PAY_PER_REQUEST",
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
        )
        ddb.get_waiter("table_exists").wait(TableName=DDB_EVENTS_TABLE)
        print(f"[init] created {DDB_EVENTS_TABLE}")


# =============================================================================
# DynamoDB Streams Consumer (writes audit events)
# =============================================================================

class StreamsConsumer:
    def __init__(self):
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_iterators: Dict[str, str] = {}  # shard_id -> iterator

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, name="ddb-streams-consumer", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2.0)

    def _run(self):
        # Describe stream for the transaction table
        try:
            desc = ddb.describe_table(TableName=DDB_TXN_TABLE)
            stream_arn = desc["Table"].get("LatestStreamArn")
            if not stream_arn:
                print("[streams] No stream ARN (is Streams enabled on the table?)")
                return
        except Exception as e:
            print(f"[streams] Failed to describe table: {e}")
            return

        print(f"[streams] consumer running, stream_arn={stream_arn}")

        events_tbl = get_table(DDB_EVENTS_TABLE)

        while not self._stop.is_set():
            try:
                stream_desc = ddb.describe_stream(StreamArn=stream_arn)
                shards = stream_desc["StreamDescription"].get("Shards", [])

                for shard in shards:
                    shard_id = shard["ShardId"]
                    if shard_id not in self._last_iterators:
                        # Start at TRIM_HORIZON (oldest). For prod you might prefer LATEST.
                        it = ddb.get_shard_iterator(
                            StreamArn=stream_arn,
                            ShardId=shard_id,
                            ShardIteratorType="LATEST",
                        )["ShardIterator"]
                        self._last_iterators[shard_id] = it

                    it = self._last_iterators[shard_id]
                    if not it:
                        continue

                    rec = ddb.get_records(ShardIterator=it, Limit=100)
                    self._last_iterators[shard_id] = rec.get("NextShardIterator")

                    records = rec.get("Records", [])
                    for r in records:
                        # Store a compact audit record
                        event_time = now_iso()
                        event_id = uuid.uuid4().hex

                        ddb_event = {
                            "event_id": event_id,
                            "event_time": event_time,
                            "event_name": r.get("eventName"),
                            "dynamodb": {
                                "Keys": r.get("dynamodb", {}).get("Keys"),
                                "NewImage": r.get("dynamodb", {}).get("NewImage"),
                                "OldImage": r.get("dynamodb", {}).get("OldImage"),
                            },
                        }

                        # Derive txn_id if present
                        txn_id = None
                        new_img = ddb_event["dynamodb"].get("NewImage") or {}
                        old_img = ddb_event["dynamodb"].get("OldImage") or {}
                        # txn_id stored as attribute "txn_id"
                        if "txn_id" in new_img:
                            txn_id = new_img["txn_id"].get("S")
                        elif "txn_id" in old_img:
                            txn_id = old_img["txn_id"].get("S")

                        if not txn_id:
                            continue

                        events_tbl.put_item(
                            Item={
                                "pk": f"TXN#{txn_id}",
                                "sk": f"{event_time}#{event_id}",
                                "txn_id": txn_id,
                                "event_time": event_time,
                                "event_name": ddb_event["event_name"],
                                "payload": ddb_event,  # stored as a map by boto3 resource layer
                            }
                        )

                time.sleep(STREAM_POLL_SECONDS)
            except Exception as e:
                print(f"[streams] error: {e}")
                time.sleep(1.5)


streams_consumer = StreamsConsumer()


# =============================================================================
# DynamoDB Access Patterns
# =============================================================================

def make_user_pk(user_id: str) -> str:
    return f"USER#{user_id}"

def make_txn_sk(created_at: str, txn_id: str) -> str:
    # sort newest last if you want reverse scans; we’ll just use chronological
    return f"TXN#{created_at}#{txn_id}"

def make_gsi1pk(txn_id: str) -> str:
    return f"TXN#{txn_id}"

def txn_item_to_summary(item: Dict[str, Any]) -> TransactionSummary:
    return TransactionSummary(
        txn_id=item["txn_id"],
        created_at=item["created_at"],
        updated_at=item["updated_at"],
        status=item["status"],
        amount=float(item["amount"]),
        currency=item["currency"],
        merchant_id=item.get("merchant_id"),
        external_ref=item.get("external_ref"),
        description=item.get("description"),
    )

def txn_item_to_info(item: Dict[str, Any]) -> TransactionInfo:
    shipping = item.get("shipping")
    cancel = item.get("cancel")
    return TransactionInfo(
        txn_id=item["txn_id"],
        buyer_id=item["buyer_id"],
        created_at=item["created_at"],
        updated_at=item["updated_at"],
        status=item["status"],
        amount=float(item["amount"]),
        currency=item["currency"],
        merchant_id=item.get("merchant_id"),
        external_ref=item.get("external_ref"),
        description=item.get("description"),
        shipping=ShippingInfo(**shipping) if shipping else None,
        cancel=cancel,
        completed_at=item.get("completed_at"),
        reverted_at=item.get("reverted_at"),
        version=int(item.get("version", 0)),
        metadata=item.get("metadata"),
    )

def fetch_txn_by_id(txn_id: str) -> Optional[Dict[str, Any]]:
    tbl = get_table(DDB_TXN_TABLE)
    resp = tbl.query(
        IndexName="gsi1",
        KeyConditionExpression="gsi1pk = :p AND gsi1sk = :s",
        ExpressionAttributeValues={
            ":p": make_gsi1pk(txn_id),
            ":s": "TXN",
        },
        Limit=1,
    )
    items = resp.get("Items", [])
    return items[0] if items else None


# =============================================================================
# API
# =============================================================================

@app.on_event("startup")
def on_startup():
    if AUTO_CREATE_TABLES:
        create_tables_if_needed()
    if ENABLE_STREAMS_CONSUMER:
        streams_consumer.start()

@app.on_event("shutdown")
def on_shutdown():
    streams_consumer.stop()


# -------------------------
# Add purchase transaction
# -------------------------
@app.post("/transactions", response_model=AddPurchaseTransactionResponse)
def add_purchase_transaction(
    req: AddPurchaseTransactionRequest,
    user_id: str = Depends(current_user_id),
):
    tbl = get_table(DDB_TXN_TABLE)

    txn_id = uuid.uuid4().hex
    created_at = now_iso()

    item = {
        "pk": make_user_pk(user_id),
        "sk": make_txn_sk(created_at, txn_id),
        "gsi1pk": make_gsi1pk(txn_id),
        "gsi1sk": "TXN",

        "txn_id": txn_id,
        "buyer_id": user_id,

        "created_at": created_at,
        "updated_at": created_at,
        "status": "PENDING",

        "amount": str(req.money.amount),
        "currency": req.money.currency,

        "merchant_id": req.merchant_id,
        "external_ref": req.external_ref,
        "description": req.description,
        "metadata": req.metadata,

        "version": 1,
    }

    # remove None values to avoid DynamoDB validation issues
    item = {k: v for k, v in item.items() if v is not None}

    try:
        tbl.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
        )
    except ClientError as e:
        raise HTTPException(status_code=500, detail=f"DDB error: {e.response.get('Error', {}).get('Message')}")

    return AddPurchaseTransactionResponse(txn_id=txn_id, status="PENDING", created_at=created_at)


# -------------------------
# List purchase transactions
# -------------------------
@app.get("/transactions", response_model=List[TransactionSummary])
def list_purchase_transactions(
    user_id: str = Depends(current_user_id),
    limit: conint(ge=1, le=100) = Query(25),
    # optionally filter by status
    status: Optional[TxnStatus] = Query(None),
):
    tbl = get_table(DDB_TXN_TABLE)
    pk = make_user_pk(user_id)

    try:
        resp = tbl.query(
            KeyConditionExpression="pk = :p AND begins_with(sk, :prefix)",
            ExpressionAttributeValues={
                ":p": pk,
                ":prefix": "TXN#",
            },
            Limit=int(limit),
        )
    except ClientError as e:
        raise HTTPException(status_code=500, detail=f"DDB error: {e.response.get('Error', {}).get('Message')}")

    items = resp.get("Items", [])
    summaries = [txn_item_to_summary(it) for it in items]
    if status:
        summaries = [s for s in summaries if s.status == status]
    return summaries


# -------------------------
# View purchase transaction info
# -------------------------
@app.get("/transactions/{txn_id}", response_model=TransactionInfo)
def view_purchase_transaction_info(
    txn_id: str,
    user_id: str = Depends(current_user_id),
):
    item = fetch_txn_by_id(txn_id)
    require(item is not None, 404, "Transaction not found")
    require(item.get("buyer_id") == user_id, 403, "Not allowed")
    return txn_item_to_info(item)


# -------------------------
# Mark purchase transaction as reverted
# -------------------------
@app.post("/transactions/{txn_id}/revert", response_model=TransactionInfo)
def mark_purchase_transaction_reverted(
    txn_id: str,
    req: MarkRevertedRequest,
    user_id: str = Depends(current_user_id),
):
    tbl = get_table(DDB_TXN_TABLE)
    item = fetch_txn_by_id(txn_id)
    require(item is not None, 404, "Transaction not found")
    require(item.get("buyer_id") == user_id, 403, "Not allowed")

    # Only allow revert from COMPLETED or PENDING (up to you)
    require(item["status"] in ["COMPLETED", "PENDING"], 409, f"Cannot revert from status {item['status']}")

    updated_at = now_iso()

    try:
        tbl.update_item(
            Key={"pk": item["pk"], "sk": item["sk"]},
            UpdateExpression=(
                "SET #st = :st, updated_at = :u, reverted_at = :u, "
                "revert_reason = :rr, version = version + :one"
            ),
            ConditionExpression="version = :v",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":st": "REVERTED",
                ":u": updated_at,
                ":rr": req.reason or "",
                ":one": 1,
                ":v": int(item.get("version", 0)),
            },
            ReturnValues="ALL_NEW",
        )
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code == "ConditionalCheckFailedException":
            raise HTTPException(status_code=409, detail="Conflict: transaction was updated by someone else")
        raise HTTPException(status_code=500, detail=f"DDB error: {e.response.get('Error', {}).get('Message')}")

    # refetch via GSI to return canonical view
    out = fetch_txn_by_id(txn_id)
    return txn_item_to_info(out)


# -------------------------
# Update purchase transaction with shipping info
# -------------------------
@app.put("/transactions/{txn_id}/shipping", response_model=TransactionInfo)
def update_purchase_transaction_shipping(
    txn_id: str,
    req: UpdateShippingRequest,
    user_id: str = Depends(current_user_id),
):
    tbl = get_table(DDB_TXN_TABLE)
    item = fetch_txn_by_id(txn_id)
    require(item is not None, 404, "Transaction not found")
    require(item.get("buyer_id") == user_id, 403, "Not allowed")

    # Usually you only want shipping updates after completion, but keep flexible:
    require(item["status"] not in ["CANCELLED"], 409, "Cannot update shipping for cancelled transactions")

    updated_at = now_iso()
    shipping_map = req.shipping.model_dump(exclude_none=True)

    try:
        tbl.update_item(
            Key={"pk": item["pk"], "sk": item["sk"]},
            UpdateExpression="SET shipping = :s, updated_at = :u, version = version + :one",
            ConditionExpression="version = :v",
            ExpressionAttributeValues={
                ":s": shipping_map,
                ":u": updated_at,
                ":one": 1,
                ":v": int(item.get("version", 0)),
            },
            ReturnValues="ALL_NEW",
        )
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code == "ConditionalCheckFailedException":
            raise HTTPException(status_code=409, detail="Conflict: transaction was updated by someone else")
        raise HTTPException(status_code=500, detail=f"DDB error: {e.response.get('Error', {}).get('Message')}")

    out = fetch_txn_by_id(txn_id)
    return txn_item_to_info(out)


# -------------------------
# Request purchase be cancelled
# -------------------------
@app.post("/transactions/{txn_id}/cancel/request", response_model=TransactionInfo)
def request_purchase_cancel(
    txn_id: str,
    req: RequestCancelRequest,
    user_id: str = Depends(current_user_id),
):
    tbl = get_table(DDB_TXN_TABLE)
    item = fetch_txn_by_id(txn_id)
    require(item is not None, 404, "Transaction not found")
    require(item.get("buyer_id") == user_id, 403, "Not allowed")

    require(item["status"] in ["PENDING", "COMPLETED"], 409, f"Cannot request cancel from status {item['status']}")

    updated_at = now_iso()
    cancel_obj = {
        "requested_by": user_id,
        "requested_at": updated_at,
        "reason": req.reason or "",
        "status": "OPEN",
    }

    try:
        tbl.update_item(
            Key={"pk": item["pk"], "sk": item["sk"]},
            UpdateExpression="SET #st = :st, cancel = :c, updated_at = :u, version = version + :one",
            ConditionExpression="version = :v AND #st <> :already",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":st": "CANCEL_REQUESTED",
                ":c": cancel_obj,
                ":u": updated_at,
                ":one": 1,
                ":v": int(item.get("version", 0)),
                ":already": "CANCEL_REQUESTED",
            },
            ReturnValues="ALL_NEW",
        )
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code == "ConditionalCheckFailedException":
            raise HTTPException(status_code=409, detail="Conflict or already requested")
        raise HTTPException(status_code=500, detail=f"DDB error: {e.response.get('Error', {}).get('Message')}")

    out = fetch_txn_by_id(txn_id)
    return txn_item_to_info(out)


# -------------------------
# Respond to purchase cancel request
# -------------------------
@app.post("/transactions/{txn_id}/cancel/respond", response_model=TransactionInfo)
def respond_to_purchase_cancel_request(
    txn_id: str,
    req: RespondCancelRequest,
    user_id: str = Depends(current_user_id),
):
    """
    In a real system this is usually merchant/admin-side.
    For this demo, allow the buyer to respond as well (but you can lock it down).
    """
    tbl = get_table(DDB_TXN_TABLE)
    item = fetch_txn_by_id(txn_id)
    require(item is not None, 404, "Transaction not found")
    require(item.get("buyer_id") == user_id, 403, "Not allowed")

    require(item["status"] == "CANCEL_REQUESTED", 409, "No active cancel request to respond to")

    updated_at = now_iso()
    decision = req.decision

    if decision == "APPROVE":
        new_status = "CANCELLED"
        cancel_status = "APPROVED"
    else:
        new_status = "CANCEL_DENIED"
        cancel_status = "DENIED"

    # Merge existing cancel object
    cancel_obj = item.get("cancel") or {}
    cancel_obj.update({
        "responded_by": user_id,
        "responded_at": updated_at,
        "decision": decision,
        "status": cancel_status,
        "note": req.note or "",
    })

    try:
        tbl.update_item(
            Key={"pk": item["pk"], "sk": item["sk"]},
            UpdateExpression="SET #st = :st, cancel = :c, updated_at = :u, version = version + :one",
            ConditionExpression="version = :v AND #st = :expected",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":st": new_status,
                ":c": cancel_obj,
                ":u": updated_at,
                ":one": 1,
                ":v": int(item.get("version", 0)),
                ":expected": "CANCEL_REQUESTED",
            },
            ReturnValues="ALL_NEW",
        )
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code == "ConditionalCheckFailedException":
            raise HTTPException(status_code=409, detail="Conflict: status/version changed")
        raise HTTPException(status_code=500, detail=f"DDB error: {e.response.get('Error', {}).get('Message')}")

    out = fetch_txn_by_id(txn_id)
    return txn_item_to_info(out)


# -------------------------
# Update purchase transaction as completed
# -------------------------
@app.post("/transactions/{txn_id}/complete", response_model=TransactionInfo)
def mark_purchase_transaction_completed(
    txn_id: str,
    req: MarkCompletedRequest,
    user_id: str = Depends(current_user_id),
):
    tbl = get_table(DDB_TXN_TABLE)
    item = fetch_txn_by_id(txn_id)
    require(item is not None, 404, "Transaction not found")
    require(item.get("buyer_id") == user_id, 403, "Not allowed")

    require(item["status"] in ["PENDING", "CANCEL_DENIED"], 409, f"Cannot complete from status {item['status']}")

    updated_at = now_iso()
    processor_ref = req.processor_ref or item.get("external_ref") or ""

    try:
        tbl.update_item(
            Key={"pk": item["pk"], "sk": item["sk"]},
            UpdateExpression=(
                "SET #st = :st, updated_at = :u, completed_at = :u, "
                "processor_ref = :pr, completion_note = :n, version = version + :one"
            ),
            ConditionExpression="version = :v",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":st": "COMPLETED",
                ":u": updated_at,
                ":pr": processor_ref,
                ":n": req.note or "",
                ":one": 1,
                ":v": int(item.get("version", 0)),
            },
            ReturnValues="ALL_NEW",
        )
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code == "ConditionalCheckFailedException":
            raise HTTPException(status_code=409, detail="Conflict: transaction was updated by someone else")
        raise HTTPException(status_code=500, detail=f"DDB error: {e.response.get('Error', {}).get('Message')}")

    out = fetch_txn_by_id(txn_id)
    return txn_item_to_info(out)


# =============================================================================
# (Optional) Read audit events written by Streams consumer
# =============================================================================

@app.get("/transactions/{txn_id}/events")
def get_transaction_events(
    txn_id: str,
    user_id: str = Depends(current_user_id),
    limit: conint(ge=1, le=200) = Query(50),
):
    """
    Reads events from DDB_EVENTS_TABLE that the Streams consumer writes.
    """
    # ensure user can access txn
    item = fetch_txn_by_id(txn_id)
    require(item is not None, 404, "Transaction not found")
    require(item.get("buyer_id") == user_id, 403, "Not allowed")

    tbl = get_table(DDB_EVENTS_TABLE)
    pk = f"TXN#{txn_id}"
    try:
        resp = tbl.query(
            KeyConditionExpression="pk = :p",
            ExpressionAttributeValues={":p": pk},
            Limit=int(limit),
        )
    except ClientError as e:
        raise HTTPException(status_code=500, detail=f"DDB error: {e.response.get('Error', {}).get('Message')}")

    return {
        "txn_id": txn_id,
        "events": resp.get("Items", []),
    }
