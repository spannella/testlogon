"""DynamoDB CRUD for broadcast inputs, guest invites, and layout (BCAST-016).

Single-table design in BroadcastInputs:
  PK = SESSION#{session_id}
  SK = INPUT#{input_id} | INVITE#{invite_id} | LAYOUT
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.models_broadcast import (
    BroadcastGuestInvite,
    BroadcastInputModel,
    BroadcastLayoutConfig,
    LayoutPosition,
)

logger = logging.getLogger("broadcast.input_store")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _session_pk(session_id: str) -> str:
    return f"SESSION#{session_id}"


# ── Input operations ──────────────────────────────────────────────


def create_input(
    *,
    session_id: str,
    input_type: str = "primary",
    label: str = "",
    ingest_url: str | None = None,
    stream_key_ref: str | None = None,
    aws_input_arn: str | None = None,
    aws_input_id: str | None = None,
    position: int = 0,
    created_by: str,
    relay_mode: str | None = None,
) -> BroadcastInputModel:
    input_id = f"inp_{uuid4().hex[:12]}"
    ts = _now_iso()
    model = BroadcastInputModel(
        input_id=input_id,
        session_id=session_id,
        input_type=input_type,
        label=label,
        ingest_url=ingest_url,
        stream_key_ref=stream_key_ref,
        aws_input_arn=aws_input_arn,
        aws_input_id=aws_input_id,
        position=position,
        created_by=created_by,
        created_at=ts,
        updated_at=ts,
        relay_mode=relay_mode,
    )
    item: Dict[str, Any] = {
        "pk": _session_pk(session_id),
        "sk": f"INPUT#{input_id}",
        "created_by": created_by,
        "created_at": ts,
        **{k: v for k, v in model.model_dump().items() if v is not None},
    }
    T.broadcast_inputs.put_item(Item=item)
    return model


def get_input(session_id: str, input_id: str) -> BroadcastInputModel:
    resp = T.broadcast_inputs.get_item(
        Key={"pk": _session_pk(session_id), "sk": f"INPUT#{input_id}"}
    )
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Input not found.")
    return _input_from_item(item)


def list_inputs(session_id: str) -> list[BroadcastInputModel]:
    resp = T.broadcast_inputs.query(
        KeyConditionExpression=Key("pk").eq(_session_pk(session_id)) & Key("sk").begins_with("INPUT#"),
    )
    inputs = [_input_from_item(i) for i in resp.get("Items", [])]
    inputs.sort(key=lambda x: x.position)
    return inputs


def update_input(session_id: str, input_id: str, fields: dict) -> BroadcastInputModel:
    current = get_input(session_id, input_id)
    data = current.model_dump()
    data.update(fields)
    data["updated_at"] = _now_iso()
    updated = BroadcastInputModel(**data)
    item: Dict[str, Any] = {
        "pk": _session_pk(session_id),
        "sk": f"INPUT#{input_id}",
        "created_by": updated.created_by,
        "created_at": updated.created_at,
        **{k: v for k, v in updated.model_dump().items() if v is not None},
    }
    T.broadcast_inputs.put_item(Item=item)
    return updated


def delete_input(session_id: str, input_id: str) -> bool:
    try:
        T.broadcast_inputs.delete_item(
            Key={"pk": _session_pk(session_id), "sk": f"INPUT#{input_id}"}
        )
        return True
    except Exception:
        return False


def mark_input_live(session_id: str, input_id: str, *, is_live: bool = True) -> BroadcastInputModel:
    ts = now_ts()
    fields: Dict[str, Any] = {"is_live": is_live}
    if is_live:
        fields["connected_at"] = ts
        fields["disconnected_at"] = None
    else:
        fields["disconnected_at"] = ts
    return update_input(session_id, input_id, fields)


def count_inputs(session_id: str) -> int:
    resp = T.broadcast_inputs.query(
        KeyConditionExpression=Key("pk").eq(_session_pk(session_id)) & Key("sk").begins_with("INPUT#"),
        Select="COUNT",
    )
    return resp.get("Count", 0)


def delete_all_inputs(session_id: str) -> int:
    """Delete all INPUT#, INVITE#, and LAYOUT records for a session."""
    resp = T.broadcast_inputs.query(
        KeyConditionExpression=Key("pk").eq(_session_pk(session_id)),
    )
    items = resp.get("Items", [])
    count = 0
    for item in items:
        T.broadcast_inputs.delete_item(Key={"pk": item["pk"], "sk": item["sk"]})
        count += 1
    return count


def _input_from_item(item: Dict[str, Any]) -> BroadcastInputModel:
    return BroadcastInputModel(
        input_id=item.get("input_id", ""),
        session_id=item.get("session_id", ""),
        input_type=item.get("input_type", "primary"),
        label=item.get("label", ""),
        ingest_url=item.get("ingest_url"),
        stream_key_ref=item.get("stream_key_ref"),
        aws_input_arn=item.get("aws_input_arn"),
        aws_input_id=item.get("aws_input_id"),
        is_live=bool(item.get("is_live", False)),
        connected_at=int(item["connected_at"]) if item.get("connected_at") is not None else None,
        disconnected_at=int(item["disconnected_at"]) if item.get("disconnected_at") is not None else None,
        position=int(item.get("position", 0)),
        created_by=item.get("created_by", ""),
        created_at=item.get("created_at", ""),
        updated_at=item.get("updated_at", ""),
        relay_mode=item.get("relay_mode"),
        relay_process_id=item.get("relay_process_id"),
    )


# ── Guest invite operations ──────────────────────────────────────


def create_guest_invite(
    *,
    session_id: str,
    input_id: str,
    created_by: str,
    join_mode: str = "browser",
    ingest_url: str | None = None,
    stream_key_ref: str | None = None,
    expires_at: int,
) -> BroadcastGuestInvite:
    invite_id = f"inv_{uuid4().hex[:12]}"
    ts = _now_iso()
    model = BroadcastGuestInvite(
        invite_id=invite_id,
        session_id=session_id,
        input_id=input_id,
        created_by=created_by,
        status="pending",
        join_mode=join_mode,
        ingest_url=ingest_url,
        stream_key_ref=stream_key_ref,
        expires_at=expires_at,
        created_at=ts,
        updated_at=ts,
    )
    item: Dict[str, Any] = {
        "pk": _session_pk(session_id),
        "sk": f"INVITE#{invite_id}",
        "created_by": created_by,
        "created_at": ts,
        "invite_status": "pending",
        "expires_at": expires_at,
        **{k: v for k, v in model.model_dump().items() if v is not None},
    }
    T.broadcast_inputs.put_item(Item=item)
    return model


def get_guest_invite(session_id: str, invite_id: str) -> BroadcastGuestInvite:
    resp = T.broadcast_inputs.get_item(
        Key={"pk": _session_pk(session_id), "sk": f"INVITE#{invite_id}"}
    )
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Guest invite not found.")
    return _invite_from_item(item)


def list_guest_invites(session_id: str, *, status_filter: str | None = None) -> list[BroadcastGuestInvite]:
    resp = T.broadcast_inputs.query(
        KeyConditionExpression=Key("pk").eq(_session_pk(session_id)) & Key("sk").begins_with("INVITE#"),
    )
    invites = [_invite_from_item(i) for i in resp.get("Items", [])]
    if status_filter:
        invites = [i for i in invites if i.status == status_filter]
    return invites


def accept_guest_invite(
    session_id: str,
    invite_id: str,
    *,
    guest_user_id: str,
    guest_display_name: str,
) -> BroadcastGuestInvite:
    invite = get_guest_invite(session_id, invite_id)
    if invite.status == "accepted":
        raise HTTPException(status_code=409, detail="Invite already accepted.")
    if invite.status in ("expired", "revoked"):
        raise HTTPException(status_code=410, detail="Invite is no longer valid.")
    ts = now_ts()
    if invite.expires_at and invite.expires_at < ts:
        # Auto-expire
        _update_invite_status(session_id, invite_id, "expired")
        raise HTTPException(status_code=410, detail="Invite has expired.")
    return _update_invite_fields(session_id, invite_id, {
        "status": "accepted",
        "guest_user_id": guest_user_id,
        "guest_display_name": guest_display_name,
        "accepted_at": ts,
    })


def revoke_guest_invite(session_id: str, invite_id: str) -> BroadcastGuestInvite:
    return _update_invite_status(session_id, invite_id, "revoked")


def expire_pending_invites(session_id: str) -> int:
    invites = list_guest_invites(session_id, status_filter="pending")
    ts = now_ts()
    count = 0
    for inv in invites:
        if inv.expires_at and inv.expires_at < ts:
            _update_invite_status(session_id, inv.invite_id, "expired")
            count += 1
    return count


def _update_invite_status(session_id: str, invite_id: str, new_status: str) -> BroadcastGuestInvite:
    return _update_invite_fields(session_id, invite_id, {"status": new_status})


def _update_invite_fields(session_id: str, invite_id: str, fields: dict) -> BroadcastGuestInvite:
    invite = get_guest_invite(session_id, invite_id)
    data = invite.model_dump()
    data.update(fields)
    data["updated_at"] = _now_iso()
    updated = BroadcastGuestInvite(**data)
    item: Dict[str, Any] = {
        "pk": _session_pk(session_id),
        "sk": f"INVITE#{invite_id}",
        "created_by": updated.created_by,
        "created_at": updated.created_at,
        "invite_status": updated.status,
        "expires_at": updated.expires_at,
        **{k: v for k, v in updated.model_dump().items() if v is not None},
    }
    T.broadcast_inputs.put_item(Item=item)
    return updated


def _invite_from_item(item: Dict[str, Any]) -> BroadcastGuestInvite:
    return BroadcastGuestInvite(
        invite_id=item.get("invite_id", ""),
        session_id=item.get("session_id", ""),
        input_id=item.get("input_id", ""),
        created_by=item.get("created_by", ""),
        status=item.get("status", item.get("invite_status", "pending")),
        guest_user_id=item.get("guest_user_id"),
        guest_display_name=item.get("guest_display_name"),
        join_mode=item.get("join_mode", "browser"),
        ingest_url=item.get("ingest_url"),
        stream_key=item.get("stream_key"),
        stream_key_ref=item.get("stream_key_ref"),
        expires_at=int(item.get("expires_at", 0)),
        accepted_at=int(item["accepted_at"]) if item.get("accepted_at") is not None else None,
        created_at=item.get("created_at", ""),
        updated_at=item.get("updated_at", ""),
    )


# ── Layout operations ─────────────────────────────────────────────


def _float_to_decimal(val: Any) -> Any:
    """Recursively convert float values to Decimal for DynamoDB compatibility."""
    if isinstance(val, float):
        return Decimal(str(val))
    if isinstance(val, dict):
        return {k: _float_to_decimal(v) for k, v in val.items()}
    if isinstance(val, list):
        return [_float_to_decimal(v) for v in val]
    return val


def save_layout(session_id: str, layout: BroadcastLayoutConfig) -> None:
    positions_raw = [p.model_dump() for p in layout.positions]
    positions_ddb = _float_to_decimal(positions_raw)
    item: Dict[str, Any] = {
        "pk": _session_pk(session_id),
        "sk": "LAYOUT",
        "mode": layout.mode,
        "positions": positions_ddb,
        "primary_input_id": layout.primary_input_id,
        "input_ids": layout.input_ids,
        "updated_at": layout.updated_at or _now_iso(),
    }
    T.broadcast_inputs.put_item(Item=item)


def get_layout(session_id: str) -> BroadcastLayoutConfig | None:
    resp = T.broadcast_inputs.get_item(
        Key={"pk": _session_pk(session_id), "sk": "LAYOUT"}
    )
    item = resp.get("Item")
    if not item:
        return None
    positions = []
    for p in item.get("positions", []):
        positions.append(LayoutPosition(
            input_id=p["input_id"],
            x=float(p["x"]),
            y=float(p["y"]),
            width=float(p["width"]),
            height=float(p["height"]),
            z_index=int(p.get("z_index", 0)),
        ))
    return BroadcastLayoutConfig(
        mode=item.get("mode", "single"),
        positions=positions,
        primary_input_id=item.get("primary_input_id"),
        input_ids=item.get("input_ids", []),
        updated_at=item.get("updated_at", ""),
    )
