from __future__ import annotations

import time

from app.models_broadcast import BroadcastSessionModel
from app.services.broadcast_cloudfront import cloudfront_security_defaults, mint_cloudfront_signed_playback_url
from app.metrics import (
    record_broadcast_provision_latency,
    record_broadcast_session_action,
)
from app.services.broadcast_playback import mint_local_playback_url
from app.services.broadcast_provider import get_broadcast_provider
from app.services.broadcast_store import delete_session, get_output, get_profile, get_session, put_output, transition_session_status
from app.core.settings import S


def start_session_with_provider(
    *,
    session_id: str,
    actor: str,
    reason: str,
    correlation_id: str = "",
    idempotency_key: str = "",
) -> BroadcastSessionModel:
    provider = get_broadcast_provider()
    current = get_session(session_id)
    profile = get_profile(current.profile_id)

    if current.status == "draft":
        transition_session_status(session_id=session_id, to_status="provisioning", reason="start-requested", actor=actor)
        t0 = time.monotonic()
        try:
            provisioned = provider.provision(
                current,
                profile=profile,
                correlation_id=correlation_id,
                idempotency_key=idempotency_key,
            )
            put_output(
                session_id=current.id,
                mediapackage_endpoint=provisioned.details.get("mediapackage_endpoint_url"),
                s3_archive_prefix=provisioned.details.get("archive_prefix"),
                aws_input_arn=provisioned.details.get("input_arn"),
                aws_channel_arn=provisioned.details.get("channel_arn"),
                provider_state_snapshot={
                    "provider": provisioned.provider,
                    "operation": provisioned.operation,
                    "state": provisioned.state,
                    "details": provisioned.details,
                },
            )
            current = transition_session_status(
                session_id=session_id,
                to_status="ready",
                reason="provider-provisioned",
                actor=actor,
            )
            record_broadcast_provision_latency(provider=provider.name, result="success", elapsed_seconds=time.monotonic() - t0)
        except Exception as exc:
            transition_session_status(
                session_id=session_id,
                to_status="error",
                reason=f"provisioning_failed:{type(exc).__name__}",
                actor=actor,
            )
            record_broadcast_provision_latency(provider=provider.name, result="failure", elapsed_seconds=time.monotonic() - t0)
            raise

    if current.status == "ready":
        try:
            provider.start(current, correlation_id=correlation_id, idempotency_key=idempotency_key)
            record_broadcast_session_action(provider=provider.name, action="start", result="success")
        except Exception as exc:
            record_broadcast_session_action(provider=provider.name, action="start", result="failure")
            transition_session_status(
                session_id=session_id,
                to_status="error",
                reason=f"start_failed:{type(exc).__name__}",
                actor=actor,
            )
            raise
        current = transition_session_status(session_id=session_id, to_status="live", reason=reason, actor=actor)
        existing = get_output(current.id)
        if provider.name == "aws" and existing and existing.mediapackage_endpoint:
            signed = mint_cloudfront_signed_playback_url(origin_url=existing.mediapackage_endpoint)
            playback_url = signed.playback_url
            provider_snapshot = dict(existing.provider_state_snapshot or {})
            provider_snapshot["cloudfront"] = cloudfront_security_defaults()
            provider_snapshot["cloudfront"]["token_expires_at"] = signed.expires_at
        else:
            playback_url = mint_local_playback_url(current.id).url
            provider_snapshot = existing.provider_state_snapshot if existing else {}
        put_output(
            session_id=current.id,
            cloudfront_playback_url=playback_url,
            mediapackage_endpoint=existing.mediapackage_endpoint if existing else None,
            s3_archive_prefix=(existing.s3_archive_prefix if existing and existing.s3_archive_prefix else f"s3://{S.broadcast_local_archive_bucket}/{S.broadcast_local_archive_prefix}/{current.id}/"),
            aws_input_arn=existing.aws_input_arn if existing else None,
            aws_channel_arn=existing.aws_channel_arn if existing else None,
            provider_state_snapshot=provider_snapshot,
        )

    return current if current.status == "live" else get_session(session_id)


def stop_session_with_provider(
    *,
    session_id: str,
    actor: str,
    reason: str,
    correlation_id: str = "",
    idempotency_key: str = "",
) -> BroadcastSessionModel:
    provider = get_broadcast_provider()
    current = get_session(session_id)

    if current.status in {"ready", "live"}:
        transition_session_status(session_id=session_id, to_status="stopping", reason=reason, actor=actor)
        try:
            provider.stop(current, correlation_id=correlation_id, idempotency_key=idempotency_key)
            record_broadcast_session_action(provider=provider.name, action="stop", result="success")
        except Exception as exc:
            record_broadcast_session_action(provider=provider.name, action="stop", result="failure")
            transition_session_status(
                session_id=session_id,
                to_status="error",
                reason=f"stop_failed:{type(exc).__name__}",
                actor=actor,
            )
            raise
        current = transition_session_status(session_id=session_id, to_status="stopped", reason="provider-stopped", actor=actor)
    elif current.status == "stopping":
        current = transition_session_status(session_id=session_id, to_status="stopped", reason=reason, actor=actor)

    return current if current.status == "stopped" else get_session(session_id)


def delete_session_with_provider(*, session_id: str) -> dict[str, bool]:
    provider = get_broadcast_provider()
    current = get_session(session_id)
    try:
        provider.teardown(current)
        record_broadcast_session_action(provider=provider.name, action="delete", result="success")
    except Exception:
        record_broadcast_session_action(provider=provider.name, action="delete", result="failure")
        raise
    return delete_session(session_id)
