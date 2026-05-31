from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.models_broadcast import (
    BroadcastOutputModel,
    BroadcastProfileModel,
    BroadcastSessionModel,
    BroadcastSessionTransitionAuditModel,
)
from app.services.broadcast_state_machine import build_transition_audit, validate_transition
from app.services.broadcast_secrets import enforce_secret_reference_only


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _profile_pk(profile_id: str) -> str:
    return f"PROFILE#{profile_id}"


def _session_pk(session_id: str) -> str:
    return f"SESSION#{session_id}"


def profile_to_item(profile: BroadcastProfileModel) -> Dict[str, Any]:
    return {
        "profile_id": profile.id,
        "name": profile.name,
        "region": profile.region,
        "rendition_preset": profile.rendition_preset,
        "watermark_asset": profile.watermark_asset,
        "drm_policy_id": profile.drm_policy_id,
        "drm_credentials_ref": profile.drm_credentials_ref,
        "drm_credentials_last_rotated_at": profile.drm_credentials_last_rotated_at,
        "drm_credentials_rotation_interval_seconds": profile.drm_credentials_rotation_interval_seconds,
        "created_by": profile.created_by,
        "created_at": profile.created_at,
        "updated_at": profile.updated_at,
        "pk": _profile_pk(profile.id),
    }


def profile_from_item(item: Dict[str, Any]) -> BroadcastProfileModel:
    return BroadcastProfileModel(
        id=item["profile_id"],
        name=item["name"],
        region=item["region"],
        rendition_preset=item["rendition_preset"],
        watermark_asset=item.get("watermark_asset"),
        drm_policy_id=item.get("drm_policy_id"),
        drm_credentials_ref=item.get("drm_credentials_ref"),
        drm_credentials_last_rotated_at=item.get("drm_credentials_last_rotated_at"),
        drm_credentials_rotation_interval_seconds=int(item.get("drm_credentials_rotation_interval_seconds") or 86400),
        created_by=item["created_by"],
        created_at=item.get("created_at") or "",
        updated_at=item.get("updated_at") or "",
    )


def create_profile(
    *,
    name: str,
    region: str,
    rendition_preset: str,
    created_by: str,
    watermark_asset: str | None = None,
    drm_policy_id: str | None = None,
    drm_credentials_ref: str | None = None,
    drm_credentials_last_rotated_at: str | None = None,
    drm_credentials_rotation_interval_seconds: int = 86400,
) -> BroadcastProfileModel:
    enforce_secret_reference_only("drm_credentials_ref", drm_credentials_ref)
    ts = now_iso()
    profile = BroadcastProfileModel(
        id=str(uuid4()),
        name=name,
        region=region,
        rendition_preset=rendition_preset,
        watermark_asset=watermark_asset,
        drm_policy_id=drm_policy_id,
        drm_credentials_ref=drm_credentials_ref,
        drm_credentials_last_rotated_at=drm_credentials_last_rotated_at,
        drm_credentials_rotation_interval_seconds=drm_credentials_rotation_interval_seconds,
        created_by=created_by,
        created_at=ts,
        updated_at=ts,
    )
    T.broadcast_profiles.put_item(
        Item=profile_to_item(profile),
        ConditionExpression="attribute_not_exists(profile_id)",
    )
    return profile


def get_profile(profile_id: str) -> BroadcastProfileModel:
    resp = T.broadcast_profiles.get_item(Key={"profile_id": profile_id}, ConsistentRead=True)
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="broadcast profile not found")
    return profile_from_item(item)


def session_to_item(session: BroadcastSessionModel) -> Dict[str, Any]:
    item: Dict[str, Any] = {
        "session_id": session.id,
        "profile_id": session.profile_id,
        "status": session.status,
        "ingest_url": session.ingest_url,
        "stream_key_ref": session.stream_key_ref,
        "stream_key_last_rotated_at": session.stream_key_last_rotated_at,
        "stream_key_rotation_interval_seconds": session.stream_key_rotation_interval_seconds,
        "started_at": session.started_at,
        "stopped_at": session.stopped_at,
        "created_by": session.created_by,
        "created_at": session.created_at,
        "updated_at": session.updated_at,
        "pk": _session_pk(session.id),
        # Scheduling (BCAST-009)
        "scheduled_at": session.scheduled_at,
        "schedule_status": session.schedule_status,
        "name": session.name,
        "description": session.description,
        "thumbnail_url": session.thumbnail_url,
        "cancelled_at": session.cancelled_at,
        "announcement_post_id": session.announcement_post_id,
        # Go-Private (BCAST-011)
        "private_session_id": session.private_session_id,
        "private_behavior": session.private_behavior,
        "private_min_rate_cents": session.private_min_rate_cents,
        # Private Chat (BCAST-012)
        "private_chat_enabled": session.private_chat_enabled,
        "private_chat_tiers": session.private_chat_tiers,
        "private_chat_voyeur_enabled": session.private_chat_voyeur_enabled,
        "private_chat_voyeur_price_cents": session.private_chat_voyeur_price_cents,
        # Tipping (BCAST-013)
        "tip_total_cents": session.tip_total_cents,
        "tip_count": session.tip_count,
        "tip_enabled": session.tip_enabled,
        "tip_min_cents": session.tip_min_cents,
        "tip_max_cents": session.tip_max_cents,
        # Live Q&A Mode (ENGAGE-003)
        "qa_mode_enabled": session.qa_mode_enabled,
        "moderators": session.moderators,
        # Multi-input / Co-streaming (BCAST-016)
        "max_inputs": session.max_inputs,
        "active_layout": session.active_layout,
        "active_input_ids": session.active_input_ids,
        "primary_input_id": session.primary_input_id,
        "guest_invite_enabled": session.guest_invite_enabled,
        # Viewer Clip Creation (ENGAGE-005)
        "clips_enabled": session.clips_enabled,
        # Go-Private / Visibility (BCAST-011)
        "broadcast_privacy_visibility": session.broadcast_privacy_visibility,
        "broadcast_privacy_updated_at": session.broadcast_privacy_updated_at,
    }
    # Remove None values to avoid DynamoDB issues with GSI sort keys
    return {k: v for k, v in item.items() if v is not None}


def session_from_item(item: Dict[str, Any]) -> BroadcastSessionModel:
    return BroadcastSessionModel(
        id=item["session_id"],
        profile_id=item["profile_id"],
        status=item.get("status") or "draft",
        ingest_url=item.get("ingest_url"),
        stream_key_ref=item.get("stream_key_ref"),
        stream_key_last_rotated_at=item.get("stream_key_last_rotated_at"),
        stream_key_rotation_interval_seconds=int(item.get("stream_key_rotation_interval_seconds") or 86400),
        started_at=item.get("started_at"),
        stopped_at=item.get("stopped_at"),
        created_by=item["created_by"],
        created_at=item.get("created_at") or "",
        updated_at=item.get("updated_at") or "",
        # Scheduling (BCAST-009)
        scheduled_at=int(item["scheduled_at"]) if item.get("scheduled_at") is not None else None,
        schedule_status=item.get("schedule_status"),
        name=item.get("name"),
        description=item.get("description"),
        thumbnail_url=item.get("thumbnail_url"),
        cancelled_at=item.get("cancelled_at"),
        announcement_post_id=item.get("announcement_post_id"),
        # Go-Private (BCAST-011)
        private_session_id=item.get("private_session_id"),
        private_behavior=item.get("private_behavior"),
        private_min_rate_cents=int(item["private_min_rate_cents"]) if item.get("private_min_rate_cents") is not None else None,
        # Private Chat (BCAST-012)
        private_chat_enabled=bool(item.get("private_chat_enabled", False)),
        private_chat_tiers=item.get("private_chat_tiers"),
        private_chat_voyeur_enabled=bool(item.get("private_chat_voyeur_enabled", False)),
        private_chat_voyeur_price_cents=int(item["private_chat_voyeur_price_cents"]) if item.get("private_chat_voyeur_price_cents") is not None else None,
        # Tipping (BCAST-013)
        tip_total_cents=int(item.get("tip_total_cents", 0) or 0),
        tip_count=int(item.get("tip_count", 0) or 0),
        tip_enabled=bool(item.get("tip_enabled", True)),
        tip_min_cents=int(item.get("tip_min_cents", 100) or 100),
        tip_max_cents=int(item.get("tip_max_cents", 100000) or 100000),
        # Live Q&A Mode (ENGAGE-003)
        qa_mode_enabled=bool(item.get("qa_mode_enabled", False)),
        moderators=item.get("moderators"),
        # Multi-input / Co-streaming (BCAST-016)
        max_inputs=int(item.get("max_inputs", 4) or 4),
        active_layout=item.get("active_layout"),
        active_input_ids=item.get("active_input_ids"),
        primary_input_id=item.get("primary_input_id"),
        guest_invite_enabled=bool(item.get("guest_invite_enabled", False)),
        # Viewer Clip Creation (ENGAGE-005)
        clips_enabled=bool(item.get("clips_enabled", True)),
        # Go-Private / Visibility (BCAST-011)
        broadcast_privacy_visibility=item.get("broadcast_privacy_visibility") or "public",
        broadcast_privacy_updated_at=item.get("broadcast_privacy_updated_at"),
    )


def create_session(
    *,
    profile_id: str,
    created_by: str,
    ingest_url: str | None = None,
    stream_key_ref: str | None = None,
    stream_key_last_rotated_at: str | None = None,
    stream_key_rotation_interval_seconds: int = 86400,
) -> BroadcastSessionModel:
    enforce_secret_reference_only("stream_key_ref", stream_key_ref)
    ts = now_iso()
    session = BroadcastSessionModel(
        id=str(uuid4()),
        profile_id=profile_id,
        status="draft",
        ingest_url=ingest_url,
        stream_key_ref=stream_key_ref,
        stream_key_last_rotated_at=stream_key_last_rotated_at,
        stream_key_rotation_interval_seconds=stream_key_rotation_interval_seconds,
        created_by=created_by,
        created_at=ts,
        updated_at=ts,
    )
    T.broadcast_sessions.put_item(
        Item=session_to_item(session),
        ConditionExpression="attribute_not_exists(session_id)",
    )
    return session


def get_session(session_id: str) -> BroadcastSessionModel:
    resp = T.broadcast_sessions.get_item(Key={"session_id": session_id}, ConsistentRead=True)
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="broadcast session not found")
    return session_from_item(item)


def delete_session(session_id: str) -> Dict[str, bool]:
    existing = get_session(session_id)
    _ = existing
    T.broadcast_sessions.delete_item(Key={"session_id": session_id})
    return {"ok": True}


def output_to_item(output: BroadcastOutputModel) -> Dict[str, Any]:
    return {
        "session_id": output.session_id,
        "mediapackage_endpoint": output.mediapackage_endpoint,
        "cloudfront_playback_url": output.cloudfront_playback_url,
        "s3_archive_prefix": output.s3_archive_prefix,
        "aws_input_arn": output.aws_input_arn,
        "aws_channel_arn": output.aws_channel_arn,
        "provider_state_snapshot": output.provider_state_snapshot,
        "updated_at": output.updated_at,
        "scope": "ALL",
    }


def output_from_item(item: Dict[str, Any]) -> BroadcastOutputModel:
    return BroadcastOutputModel(
        session_id=item["session_id"],
        mediapackage_endpoint=item.get("mediapackage_endpoint"),
        cloudfront_playback_url=item.get("cloudfront_playback_url"),
        s3_archive_prefix=item.get("s3_archive_prefix"),
        aws_input_arn=item.get("aws_input_arn"),
        aws_channel_arn=item.get("aws_channel_arn"),
        provider_state_snapshot=item.get("provider_state_snapshot") or {},
        updated_at=item["updated_at"],
    )


def transition_audit_to_item(audit: BroadcastSessionTransitionAuditModel) -> Dict[str, Any]:
    return {
        "transition_id": audit.transition_id,
        "session_id": audit.session_id,
        "from_status": audit.from_status,
        "to_status": audit.to_status,
        "reason": audit.reason,
        "actor": audit.actor,
        "created_at": audit.created_at,
        "error_code": audit.error_code,
    }


def put_output(
    *,
    session_id: str,
    mediapackage_endpoint: str | None = None,
    cloudfront_playback_url: str | None = None,
    s3_archive_prefix: str | None = None,
    aws_input_arn: str | None = None,
    aws_channel_arn: str | None = None,
    provider_state_snapshot: Dict[str, Any] | None = None,
) -> BroadcastOutputModel:
    output = BroadcastOutputModel(
        session_id=session_id,
        mediapackage_endpoint=mediapackage_endpoint,
        cloudfront_playback_url=cloudfront_playback_url,
        s3_archive_prefix=s3_archive_prefix,
        aws_input_arn=aws_input_arn,
        aws_channel_arn=aws_channel_arn,
        provider_state_snapshot=provider_state_snapshot or {},
        updated_at=now_iso(),
    )
    T.broadcast_outputs.put_item(Item=output_to_item(output))
    return output


def get_output(session_id: str) -> BroadcastOutputModel | None:
    resp = T.broadcast_outputs.get_item(
        Key={"session_id": session_id, "scope": "ALL"},
        ConsistentRead=True,
    )
    item = resp.get("Item")
    if not item:
        return None
    return output_from_item(item)


def transition_session_status(
    *,
    session_id: str,
    to_status: str,
    reason: str,
    actor: str,
    extra_fields: Optional[Dict[str, Any]] = None,
) -> BroadcastSessionModel:
    current = get_session(session_id)
    validation = validate_transition(current.status, to_status)  # type: ignore[arg-type]
    if not validation.legal:
        raise HTTPException(
            status_code=409,
            detail={
                "code": validation.error_code,
                "from_status": current.status,
                "to_status": to_status,
            },
        )

    # Build updated model preserving all existing fields
    update_data = current.model_dump()
    update_data["status"] = to_status
    update_data["updated_at"] = now_iso()
    # Apply any extra scheduling/cancel fields
    if extra_fields:
        update_data.update(extra_fields)
    updated = BroadcastSessionModel(**update_data)
    T.broadcast_sessions.put_item(Item=session_to_item(updated))
    audit = build_transition_audit(
        transition_id=str(uuid4()),
        session_id=session_id,
        from_status=current.status,
        to_status=to_status,  # type: ignore[arg-type]
        reason=reason,
        actor=actor,
    )
    T.broadcast_session_transitions.put_item(Item=transition_audit_to_item(audit))
    return updated


def list_profiles_by_creator(created_by: str, *, limit: int = 200) -> List[BroadcastProfileModel]:
    """Scan broadcast_profiles table filtered by created_by. No GSI — table is small."""
    kwargs: Dict[str, Any] = {"Limit": limit}
    if created_by:
        from boto3.dynamodb.conditions import Attr
        kwargs["FilterExpression"] = Attr("created_by").eq(created_by)

    items: List[BroadcastProfileModel] = []
    while True:
        resp = T.broadcast_profiles.scan(**kwargs)
        items.extend(profile_from_item(i) for i in resp.get("Items", []))
        if not resp.get("LastEvaluatedKey") or len(items) >= limit:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    return items[:limit]


def list_sessions_by_status(status: str, *, limit: int = 50, cursor: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if not status:
        raise HTTPException(status_code=400, detail="status is required")
    if not isinstance(limit, int) or limit < 1 or limit > 200:
        raise HTTPException(status_code=400, detail="invalid limit")

    kwargs: Dict[str, Any] = {
        "IndexName": "ByStatusCreatedAt",
        "KeyConditionExpression": Key("status").eq(status),
        "Limit": limit,
        "ScanIndexForward": False,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = cursor

    resp = T.broadcast_sessions.query(**kwargs)
    items = [session_from_item(i) for i in resp.get("Items", [])]
    return {"items": items, "cursor": resp.get("LastEvaluatedKey")}


def list_sessions_by_creator(created_by: str, *, limit: int = 50, cursor: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if not created_by:
        raise HTTPException(status_code=400, detail="created_by is required")
    if not isinstance(limit, int) or limit < 1 or limit > 200:
        raise HTTPException(status_code=400, detail="invalid limit")

    kwargs: Dict[str, Any] = {
        "IndexName": "ByCreatorCreatedAt",
        "KeyConditionExpression": Key("created_by").eq(created_by),
        "Limit": limit,
        "ScanIndexForward": False,
    }
    if cursor:
        kwargs["ExclusiveStartKey"] = cursor

    resp = T.broadcast_sessions.query(**kwargs)
    items = [session_from_item(i) for i in resp.get("Items", [])]
    return {"items": items, "cursor": resp.get("LastEvaluatedKey")}


# ─── Scheduling queries (BCAST-009) ─────────────────────────────


def list_due_scheduled_sessions(*, now: int, limit: int = 10) -> List[BroadcastSessionModel]:
    """Get scheduled sessions that are past their scheduled_at time.

    Queries ByScheduledAt GSI: schedule_status='scheduled', scheduled_at <= now.
    Returns oldest-first so the most overdue sessions are processed first.
    """
    resp = T.broadcast_sessions.query(
        IndexName="ByScheduledAt",
        KeyConditionExpression=Key("schedule_status").eq("scheduled") & Key("scheduled_at").lte(now),
        ScanIndexForward=True,
        Limit=limit,
    )
    return [session_from_item(i) for i in resp.get("Items", [])]


def list_upcoming_sessions(*, now: int, limit: int = 50) -> List[BroadcastSessionModel]:
    """List all scheduled sessions whose scheduled_at is still in the future.

    Global viewer-discovery query across all creators. Uses the ByScheduledAt GSI
    (schedule_status='scheduled', scheduled_at > now), ordered soonest-first.
    """
    resp = T.broadcast_sessions.query(
        IndexName="ByScheduledAt",
        KeyConditionExpression=Key("schedule_status").eq("scheduled") & Key("scheduled_at").gt(now),
        ScanIndexForward=True,
        Limit=limit,
    )
    return [session_from_item(i) for i in resp.get("Items", [])]


def list_scheduled_sessions_by_creator(created_by: str, *, limit: int = 50) -> List[BroadcastSessionModel]:
    """List sessions with schedule_status='scheduled' for a specific creator.

    Uses ByCreatorCreatedAt GSI filtered by schedule_status.
    """
    from boto3.dynamodb.conditions import Attr
    kwargs: Dict[str, Any] = {
        "IndexName": "ByCreatorCreatedAt",
        "KeyConditionExpression": Key("created_by").eq(created_by),
        "FilterExpression": Attr("schedule_status").eq("scheduled"),
        "Limit": limit,
        "ScanIndexForward": False,
    }
    resp = T.broadcast_sessions.query(**kwargs)
    return [session_from_item(i) for i in resp.get("Items", [])]


def update_session_fields(session_id: str, fields: Dict[str, Any]) -> BroadcastSessionModel:
    """Update arbitrary fields on a session by doing a get-modify-put cycle.

    This preserves all existing fields while applying the updates.
    """
    current = get_session(session_id)
    data = current.model_dump()
    data.update(fields)
    data["updated_at"] = now_iso()
    updated = BroadcastSessionModel(**data)
    T.broadcast_sessions.put_item(Item=session_to_item(updated))
    return updated
