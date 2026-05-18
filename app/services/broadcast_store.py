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
    return {
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
    }


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


def transition_session_status(*, session_id: str, to_status: str, reason: str, actor: str) -> BroadcastSessionModel:
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

    updated = BroadcastSessionModel(
        id=current.id,
        profile_id=current.profile_id,
        status=to_status,  # type: ignore[arg-type]
        ingest_url=current.ingest_url,
        stream_key_ref=current.stream_key_ref,
        stream_key_last_rotated_at=current.stream_key_last_rotated_at,
        stream_key_rotation_interval_seconds=current.stream_key_rotation_interval_seconds,
        started_at=current.started_at,
        stopped_at=current.stopped_at,
        created_by=current.created_by,
        created_at=current.created_at,
        updated_at=now_iso(),
    )
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
