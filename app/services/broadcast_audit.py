from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Attr, Key
from fastapi import HTTPException

from app.core.tables import T
from app.models_broadcast import BroadcastActionAuditEventModel


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def audit_to_item(event: BroadcastActionAuditEventModel) -> Dict[str, Any]:
    return {
        "audit_id": event.audit_id,
        "action": event.action,
        "actor": event.actor,
        "correlation_id": event.correlation_id,
        "resource_type": event.resource_type,
        "resource_id": event.resource_id,
        "created_at": event.created_at,
        "metadata": event.metadata,
        "scope": "ALL",
    }


def audit_from_item(item: Dict[str, Any]) -> BroadcastActionAuditEventModel:
    return BroadcastActionAuditEventModel(
        audit_id=item["audit_id"],
        action=item["action"],
        actor=item["actor"],
        correlation_id=item["correlation_id"],
        resource_type=item["resource_type"],
        resource_id=item["resource_id"],
        created_at=item["created_at"],
        metadata=item.get("metadata") or {},
    )


def record_broadcast_action(
    *,
    action: str,
    actor: str,
    correlation_id: str,
    resource_type: str,
    resource_id: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> BroadcastActionAuditEventModel:
    event = BroadcastActionAuditEventModel(
        audit_id=str(uuid4()),
        action=action,  # type: ignore[arg-type]
        actor=actor,
        correlation_id=correlation_id,
        resource_type=resource_type,  # type: ignore[arg-type]
        resource_id=resource_id,
        created_at=now_iso(),
        metadata=metadata or {},
    )
    T.broadcast_action_audit.put_item(Item=audit_to_item(event))
    return event


def query_broadcast_actions(
    *,
    actor: Optional[str] = None,
    created_from: Optional[str] = None,
    created_to: Optional[str] = None,
    limit: int = 50,
) -> List[BroadcastActionAuditEventModel]:
    if limit < 1 or limit > 200:
        raise HTTPException(status_code=400, detail="invalid limit")

    if actor:
        key_expr = Key("actor").eq(actor)
        if created_from and created_to:
            key_expr = key_expr & Key("created_at").between(created_from, created_to)
        elif created_from:
            key_expr = key_expr & Key("created_at").gte(created_from)
        elif created_to:
            key_expr = key_expr & Key("created_at").lte(created_to)
        resp = T.broadcast_action_audit.query(
            IndexName="ByActorCreatedAt",
            KeyConditionExpression=key_expr,
            Limit=limit,
            ScanIndexForward=False,
        )
        return [audit_from_item(i) for i in resp.get("Items", [])]

    key_expr = Key("scope").eq("ALL")
    filter_expr = None
    if created_from:
        filter_expr = Attr("created_at").gte(created_from)
    if created_to:
        ce = Attr("created_at").lte(created_to)
        filter_expr = ce if filter_expr is None else filter_expr & ce

    kwargs: Dict[str, Any] = {
        "IndexName": "ByCreatedAt",
        "KeyConditionExpression": key_expr,
        "Limit": limit,
        "ScanIndexForward": False,
    }
    if filter_expr is not None:
        kwargs["FilterExpression"] = filter_expr
    resp = T.broadcast_action_audit.query(**kwargs)
    return [audit_from_item(i) for i in resp.get("Items", [])]
