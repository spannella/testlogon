from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Protocol

from fastapi import HTTPException

from app.core.settings import S
from app.models_broadcast import BroadcastProfileModel, BroadcastSessionModel
from app.services.broadcast_mediolive import (
    _client as _medialive_client,
    _find_input_by_name,
    _with_retry,
    provision_mediolive_input_and_channel,
)
from app.services.broadcast_mediapackage import provision_mediapackage_channel_and_endpoint

try:
    from botocore.exceptions import ClientError
except Exception:  # pragma: no cover
    class ClientError(Exception):  # type: ignore[no-redef]
        def __init__(self, response: dict | None = None, operation_name: str = "") -> None:
            super().__init__(operation_name or "client_error")
            self.response = response or {}

logger = logging.getLogger("broadcast.provider")


@dataclass(frozen=True)
class ProviderResult:
    operation: str
    provider: str
    state: str
    details: Dict[str, Any] = field(default_factory=dict)


class BroadcastProvider(Protocol):
    name: str

    def provision(
        self,
        session: BroadcastSessionModel,
        *,
        profile: BroadcastProfileModel | None = None,
        correlation_id: str = "",
        idempotency_key: str = "",
    ) -> ProviderResult: ...
    def start(self, session: BroadcastSessionModel, *, correlation_id: str = "", idempotency_key: str = "") -> ProviderResult: ...
    def stop(self, session: BroadcastSessionModel, *, correlation_id: str = "", idempotency_key: str = "") -> ProviderResult: ...
    def status(self, session: BroadcastSessionModel) -> ProviderResult: ...
    def teardown(self, session: BroadcastSessionModel) -> ProviderResult: ...


class LocalBroadcastProvider:
    name = "local"

    def provision(
        self,
        session: BroadcastSessionModel,
        *,
        profile: BroadcastProfileModel | None = None,
        correlation_id: str = "",
        idempotency_key: str = "",
    ) -> ProviderResult:
        _ = profile
        _ = (correlation_id, idempotency_key)
        return ProviderResult("provision", self.name, "ready", {"session_id": session.id})

    def start(self, session: BroadcastSessionModel, *, correlation_id: str = "", idempotency_key: str = "") -> ProviderResult:
        return ProviderResult("start", self.name, "live", {"session_id": session.id, "correlation_id": correlation_id, "idempotency_key": idempotency_key})

    def stop(self, session: BroadcastSessionModel, *, correlation_id: str = "", idempotency_key: str = "") -> ProviderResult:
        return ProviderResult("stop", self.name, "stopped", {"session_id": session.id, "correlation_id": correlation_id, "idempotency_key": idempotency_key})

    def status(self, session: BroadcastSessionModel) -> ProviderResult:
        return ProviderResult("status", self.name, session.status, {"session_id": session.id})

    def teardown(self, session: BroadcastSessionModel) -> ProviderResult:
        return ProviderResult("teardown", self.name, "deleted", {"session_id": session.id})


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mediapackage_client():
    try:
        import boto3 as _boto3
    except Exception:  # pragma: no cover
        raise RuntimeError("boto3 is required for aws broadcast provider")
    return _boto3.client(
        "mediapackage",
        region_name=S.aws_region or "us-east-1",
        endpoint_url=S.aws_endpoint_url or None,
    )


_MEDIALIVE_STATE_MAP: Dict[str, str] = {
    "CREATING": "provisioning",
    "CREATE_FAILED": "error",
    "IDLE": "ready",
    "STARTING": "ready",
    "RUNNING": "live",
    "STOPPING": "stopping",
    "DELETING": "stopping",
    "DELETED": "stopped",
    "RECOVERING": "live",
    "UPDATE_FAILED": "error",
}


def _poll_channel_state(
    client,
    channel_id: str,
    *,
    target_states: set,
    error_states: set,
    timeout_seconds: int = 120,
    poll_interval_seconds: float = 5.0,
) -> str:
    """Poll describe_channel until state is in target_states, error_states, or timeout."""
    deadline = time.monotonic() + timeout_seconds
    last_state = "UNKNOWN"
    while time.monotonic() < deadline:
        desc = _with_retry(lambda: client.describe_channel(ChannelId=channel_id))
        last_state = desc.get("State", "UNKNOWN")
        if last_state in target_states:
            return last_state
        if last_state in error_states:
            return last_state
        time.sleep(poll_interval_seconds)
    return last_state


def _poll_input_state(
    client,
    input_id: str,
    *,
    target_states: set,
    timeout_seconds: int = 60,
    poll_interval_seconds: float = 5.0,
) -> str:
    """Poll describe_input until state is in target_states or timeout."""
    deadline = time.monotonic() + timeout_seconds
    last_state = "UNKNOWN"
    while time.monotonic() < deadline:
        try:
            desc = _with_retry(lambda: client.describe_input(InputId=input_id))
            last_state = desc.get("State", "UNKNOWN")
            if last_state in target_states:
                return last_state
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "NotFoundException":
                return "DELETED"
            raise
        time.sleep(poll_interval_seconds)
    return last_state


def _resolve_channel_id(session: BroadcastSessionModel) -> str:
    """Extract channel_id from the persisted output record."""
    from app.services.broadcast_store import get_output

    output = get_output(session.id)
    if not output:
        raise HTTPException(status_code=409, detail="session has no provisioned output")
    channel_id = output.provider_state_snapshot.get("details", {}).get("channel_id")
    if not channel_id:
        # Fallback: derive from channel ARN (format: arn:aws:medialive:REGION:ACCOUNT:channel:ID)
        arn = output.aws_channel_arn or ""
        parts = arn.split(":")
        channel_id = parts[-1] if len(parts) >= 7 else ""
    if not channel_id:
        raise HTTPException(status_code=409, detail="cannot resolve MediaLive channel ID")
    return channel_id


def _resolve_input_id(session: BroadcastSessionModel) -> str | None:
    """Resolve the MediaLive input ID from the output record or naming convention."""
    from app.services.broadcast_store import get_output

    output = get_output(session.id)
    if output:
        input_id = output.provider_state_snapshot.get("details", {}).get("input_id")
        if input_id:
            return input_id
    # Fallback: look up by naming convention
    client = _medialive_client()
    input_name = f"broadcast-{session.id}-input"
    existing = _find_input_by_name(client, name=input_name)
    if existing:
        return existing.get("Id")
    return None


class AwsBroadcastProvider:
    name = "aws"

    def provision(
        self,
        session: BroadcastSessionModel,
        *,
        profile: BroadcastProfileModel | None = None,
        correlation_id: str = "",
        idempotency_key: str = "",
    ) -> ProviderResult:
        if profile is None:
            raise HTTPException(status_code=400, detail={"code": "BROADCAST_PROFILE_REQUIRED", "detail": "profile is required for aws provisioning"})
        live = provision_mediolive_input_and_channel(
            session_id=session.id,
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
        )
        package = provision_mediapackage_channel_and_endpoint(
            session_id=session.id,
            profile=profile,
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
        )
        return ProviderResult(
            "provision",
            self.name,
            "ready",
            {
                "session_id": session.id,
                "input_arn": live.input_arn,
                "channel_arn": live.channel_arn,
                "channel_id": live.channel_id,
                "channel_state": str(live.state_snapshot.get("channel_state") or ""),
                "archive_prefix": live.archive_prefix,
                "mediapackage_channel_arn": package.channel_arn,
                "mediapackage_endpoint_arn": package.endpoint_arn,
                "mediapackage_endpoint_url": package.endpoint_url,
                "packaging_metadata": package.packaging_metadata,
                "correlation_id": correlation_id,
                "idempotency_key": idempotency_key,
            },
        )

    def start(self, session: BroadcastSessionModel, *, correlation_id: str = "", idempotency_key: str = "") -> ProviderResult:
        client = _medialive_client()
        channel_id = _resolve_channel_id(session)

        # Describe current state -- avoid starting if already RUNNING
        desc = _with_retry(lambda: client.describe_channel(ChannelId=channel_id))
        current_state = desc.get("State", "IDLE")

        if current_state == "RUNNING":
            return ProviderResult("start", self.name, "live", {
                "session_id": session.id,
                "channel_id": channel_id,
                "channel_state": "RUNNING",
                "already_running": True,
                "correlation_id": correlation_id,
            })

        if current_state not in ("IDLE", "CREATE_FAILED"):
            return ProviderResult("start", self.name, "error", {
                "session_id": session.id,
                "channel_id": channel_id,
                "channel_state": current_state,
                "error": f"channel in non-startable state: {current_state}",
                "correlation_id": correlation_id,
            })

        # Issue start command
        _with_retry(lambda: client.start_channel(ChannelId=channel_id))

        # Poll until RUNNING or timeout
        timeout = int(S.broadcast_aws_start_timeout_seconds or 120)
        poll_interval = int(S.broadcast_aws_poll_interval_seconds or 5)
        state = _poll_channel_state(
            client, channel_id,
            target_states={"RUNNING"},
            error_states={"CREATE_FAILED", "IDLE"},
            timeout_seconds=timeout,
            poll_interval_seconds=poll_interval,
        )

        if state == "RUNNING":
            return ProviderResult("start", self.name, "live", {
                "session_id": session.id,
                "channel_id": channel_id,
                "channel_state": "RUNNING",
                "started_at": _now_iso(),
                "correlation_id": correlation_id,
            })
        else:
            return ProviderResult("start", self.name, "error", {
                "session_id": session.id,
                "channel_id": channel_id,
                "channel_state": state,
                "error": f"channel did not reach RUNNING within timeout (last state: {state})",
                "correlation_id": correlation_id,
            })

    def stop(self, session: BroadcastSessionModel, *, correlation_id: str = "", idempotency_key: str = "") -> ProviderResult:
        client = _medialive_client()
        channel_id = _resolve_channel_id(session)

        desc = _with_retry(lambda: client.describe_channel(ChannelId=channel_id))
        current_state = desc.get("State", "IDLE")

        if current_state == "IDLE":
            return ProviderResult("stop", self.name, "stopped", {
                "session_id": session.id,
                "channel_id": channel_id,
                "channel_state": "IDLE",
                "already_stopped": True,
                "correlation_id": correlation_id,
            })

        if current_state not in ("RUNNING", "RECOVERING"):
            return ProviderResult("stop", self.name, "error", {
                "session_id": session.id,
                "channel_id": channel_id,
                "channel_state": current_state,
                "error": f"channel in non-stoppable state: {current_state}",
                "correlation_id": correlation_id,
            })

        _with_retry(lambda: client.stop_channel(ChannelId=channel_id))

        timeout = int(S.broadcast_aws_stop_timeout_seconds or 120)
        poll_interval = int(S.broadcast_aws_poll_interval_seconds or 5)
        state = _poll_channel_state(
            client, channel_id,
            target_states={"IDLE"},
            error_states={"RUNNING"},
            timeout_seconds=timeout,
            poll_interval_seconds=poll_interval,
        )

        if state == "IDLE":
            return ProviderResult("stop", self.name, "stopped", {
                "session_id": session.id,
                "channel_id": channel_id,
                "channel_state": "IDLE",
                "stopped_at": _now_iso(),
                "correlation_id": correlation_id,
            })
        else:
            return ProviderResult("stop", self.name, "error", {
                "session_id": session.id,
                "channel_id": channel_id,
                "channel_state": state,
                "error": f"channel did not reach IDLE within timeout (last state: {state})",
                "correlation_id": correlation_id,
            })

    def status(self, session: BroadcastSessionModel) -> ProviderResult:
        client = _medialive_client()
        channel_id = _resolve_channel_id(session)

        try:
            desc = _with_retry(lambda: client.describe_channel(ChannelId=channel_id))
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "NotFoundException":
                return ProviderResult("status", self.name, "error", {
                    "session_id": session.id,
                    "channel_id": channel_id,
                    "error": "channel_not_found",
                })
            raise

        aws_state = desc.get("State", "IDLE")
        mapped = _MEDIALIVE_STATE_MAP.get(aws_state, "error")

        return ProviderResult("status", self.name, mapped, {
            "session_id": session.id,
            "channel_id": channel_id,
            "channel_state": aws_state,
            "pipelines_running": desc.get("PipelinesRunningCount", 0),
        })

    def teardown(self, session: BroadcastSessionModel) -> ProviderResult:
        ml_client = _medialive_client()
        mp_client = _mediapackage_client()
        channel_id = _resolve_channel_id(session)
        pkg_channel_id = f"broadcast-{session.id}-pkg"
        endpoint_id = f"broadcast-{session.id}-hls"
        errors: list[str] = []

        # 1. Ensure channel is stopped before deletion
        try:
            desc = _with_retry(lambda: ml_client.describe_channel(ChannelId=channel_id))
            if desc.get("State") in ("RUNNING", "RECOVERING"):
                _with_retry(lambda: ml_client.stop_channel(ChannelId=channel_id))
                poll_interval = int(S.broadcast_aws_poll_interval_seconds or 5)
                _poll_channel_state(
                    ml_client, channel_id,
                    target_states={"IDLE"},
                    error_states=set(),
                    timeout_seconds=90,
                    poll_interval_seconds=poll_interval,
                )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "NotFoundException":
                errors.append(f"stop_channel: {exc}")

        # 2. Delete MediaLive channel
        try:
            _with_retry(lambda: ml_client.delete_channel(ChannelId=channel_id))
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "NotFoundException":
                errors.append(f"delete_channel: {exc}")

        # 3. Delete MediaLive input (must wait for channel deletion to release attachment)
        input_name = f"broadcast-{session.id}-input"
        try:
            existing = _find_input_by_name(ml_client, name=input_name)
            if existing:
                input_id = existing.get("Id", "")
                poll_interval = int(S.broadcast_aws_poll_interval_seconds or 5)
                _poll_input_state(
                    ml_client, input_id,
                    target_states={"DETACHED", "IDLE"},
                    timeout_seconds=60,
                    poll_interval_seconds=poll_interval,
                )
                _with_retry(lambda: ml_client.delete_input(InputId=input_id))
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "NotFoundException":
                errors.append(f"delete_input: {exc}")

        # 4. Delete MediaPackage origin endpoint
        try:
            _with_retry(lambda: mp_client.delete_origin_endpoint(Id=endpoint_id))
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "NotFoundException":
                errors.append(f"delete_origin_endpoint: {exc}")

        # 5. Delete MediaPackage channel
        try:
            _with_retry(lambda: mp_client.delete_channel(Id=pkg_channel_id))
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "NotFoundException":
                errors.append(f"delete_mediapackage_channel: {exc}")

        if errors:
            logger.warning("teardown partial errors", extra={
                "session_id": session.id,
                "errors": errors,
            })
            return ProviderResult("teardown", self.name, "error", {
                "session_id": session.id,
                "partial_errors": errors,
                "resources_may_remain": True,
            })

        return ProviderResult("teardown", self.name, "deleted", {
            "session_id": session.id,
            "channel_id": channel_id,
            "deleted_at": _now_iso(),
            "resources_cleaned": True,
        })


def get_broadcast_provider(provider_name: str | None = None) -> BroadcastProvider:
    name = (provider_name or S.broadcast_provider or "local").strip().lower()
    if name == "local":
        return LocalBroadcastProvider()
    if name == "aws":
        return AwsBroadcastProvider()
    raise HTTPException(status_code=500, detail={"code": "BROADCAST_PROVIDER_UNSUPPORTED", "detail": f"unsupported provider: {name}"})
