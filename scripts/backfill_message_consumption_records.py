#!/usr/bin/env python3
"""Backfill per-recipient once-media consumption records.

Safe to re-run: uses deterministic keys and conditional put.
"""
from __future__ import annotations

import os
from typing import Any, Dict, Iterable

import boto3
from boto3.dynamodb.conditions import Attr, Key


DDB_ENDPOINT_URL = os.getenv("DDB_ENDPOINT_URL") or os.getenv("AWS_ENDPOINT_URL")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

DDB_MESSAGES = os.getenv("DDB_MESSAGES", "Messages")
DDB_PARTICIPANTS = os.getenv("DDB_PARTICIPANTS", "Participants")
DDB_MESSAGE_CONSUMPTION = os.getenv("DDB_MESSAGE_CONSUMPTION", "MessageConsumption")

PENDING = "pending"


def _ddb_resource():
    kwargs: Dict[str, Any] = {"region_name": AWS_REGION}
    if DDB_ENDPOINT_URL:
        kwargs["endpoint_url"] = DDB_ENDPOINT_URL
        kwargs["aws_access_key_id"] = os.getenv("AWS_ACCESS_KEY_ID", "test")
        kwargs["aws_secret_access_key"] = os.getenv("AWS_SECRET_ACCESS_KEY", "test")
        kwargs["aws_session_token"] = os.getenv("AWS_SESSION_TOKEN", "test")
    return boto3.resource("dynamodb", **kwargs)


def _iter_once_messages(tbl_msgs) -> Iterable[dict]:
    scan_kwargs: Dict[str, Any] = {
        "FilterExpression": Attr("consumption_policy").is_in(["view_once", "listen_once"])
    }
    last_key = None
    while True:
        if last_key:
            scan_kwargs["ExclusiveStartKey"] = last_key
        resp = tbl_msgs.scan(**scan_kwargs)
        for item in resp.get("Items", []):
            yield item
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break


def _participants_for_conversation(tbl_parts, conversation_id: str) -> list[dict]:
    try:
        resp = tbl_parts.query(
            IndexName="GSI1",
            KeyConditionExpression=Key("GSI1PK").eq(conversation_id),
        )
    except Exception:
        return []
    return resp.get("Items", [])


def _backfill_record(tbl_consumption, *, msg: dict, participant_id: str) -> bool:
    created_at = int(msg.get("created_at", 0) or 0)
    message_id = str(msg.get("message_id") or "")
    conversation_id = str(msg.get("conversation_id") or "")
    sender_id = str(msg.get("sender_id") or "")
    media_kind = str(msg.get("media_kind") or "")
    policy = str(msg.get("consumption_policy") or "")
    recipient_message = f"{participant_id}#{message_id}"

    item = {
        "conversation_id": conversation_id,
        "recipient_message": recipient_message,
        "recipient_id": participant_id,
        "message_id": message_id,
        "sender_id": sender_id,
        "created_at": created_at,
        "consumption_policy": policy,
        "media_kind": media_kind,
        "consumption_state": PENDING,
        "consumed_at": 0,
        "GSI1PK": f"{conversation_id}#{PENDING}",
        "GSI1SK": f"{created_at:010d}#{message_id}#{participant_id}",
        "GSI2SK": f"{created_at:010d}#{conversation_id}#{message_id}",
    }

    try:
        tbl_consumption.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(conversation_id) AND attribute_not_exists(recipient_message)",
        )
        return True
    except tbl_consumption.meta.client.exceptions.ConditionalCheckFailedException:
        return False


def main() -> None:
    ddb = _ddb_resource()
    tbl_msgs = ddb.Table(DDB_MESSAGES)
    tbl_parts = ddb.Table(DDB_PARTICIPANTS)
    tbl_consumption = ddb.Table(DDB_MESSAGE_CONSUMPTION)

    scanned = 0
    created = 0
    skipped = 0

    for msg in _iter_once_messages(tbl_msgs):
        scanned += 1
        conversation_id = str(msg.get("conversation_id") or "")
        sender_id = str(msg.get("sender_id") or "")
        for participant in _participants_for_conversation(tbl_parts, conversation_id):
            recipient_id = str(participant.get("user_id") or "")
            if not recipient_id or recipient_id == sender_id:
                continue
            if _backfill_record(tbl_consumption, msg=msg, participant_id=recipient_id):
                created += 1
            else:
                skipped += 1

    print(
        f"Backfill complete: scanned_messages={scanned} created_records={created} skipped_existing={skipped}"
    )


if __name__ == "__main__":
    main()
