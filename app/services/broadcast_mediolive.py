from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict

try:
    import boto3
except Exception:  # pragma: no cover - optional dependency in lightweight test envs
    boto3 = None  # type: ignore[assignment]

try:
    from botocore.exceptions import ClientError
except Exception:  # pragma: no cover - optional dependency in lightweight test envs
    class ClientError(Exception):  # type: ignore[no-redef]
        def __init__(self, response: dict | None = None, operation_name: str = "") -> None:
            super().__init__(operation_name or "client_error")
            self.response = response or {}

from app.core.settings import S
from app.services.broadcast_archive import build_archive_output_group

_TRANSIENT_CODES = {
    "Throttling",
    "ThrottlingException",
    "TooManyRequestsException",
    "InternalError",
    "ServiceUnavailableException",
}


@dataclass(frozen=True)
class MediaLiveProvisionResult:
    input_arn: str
    channel_arn: str
    channel_id: str
    state_snapshot: Dict[str, Any]
    archive_prefix: str


def _client():
    if boto3 is None:  # pragma: no cover - exercised when aws deps are absent
        raise RuntimeError("boto3 is required for aws broadcast provider")
    return boto3.client(
        "medialive",
        region_name=S.aws_region or "us-east-1",
        endpoint_url=S.aws_endpoint_url or None,
    )


def _with_retry(fn: Callable[[], Dict[str, Any]], *, max_attempts: int = 4, base_sleep_seconds: float = 0.2) -> Dict[str, Any]:
    for attempt in range(1, max_attempts + 1):
        try:
            return fn()
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code") or "")
            if code in _TRANSIENT_CODES and attempt < max_attempts:
                delay = base_sleep_seconds * (2 ** (attempt - 1)) + random.uniform(0, 0.05)
                time.sleep(delay)
                continue
            raise


def _find_input_by_name(client, *, name: str) -> Dict[str, Any] | None:
    resp = _with_retry(lambda: client.list_inputs(MaxResults=1000))
    for item in resp.get("Inputs", []):
        if item.get("Name") == name:
            return item
    return None


def _find_channel_by_name(client, *, name: str) -> Dict[str, Any] | None:
    resp = _with_retry(lambda: client.list_channels(MaxResults=1000))
    for item in resp.get("Channels", []):
        if item.get("Name") == name:
            return item
    return None


def provision_mediolive_input_and_channel(
    *,
    session_id: str,
    correlation_id: str,
    idempotency_key: str,
) -> MediaLiveProvisionResult:
    client = _client()
    input_name = f"broadcast-{session_id}-input"
    channel_name = f"broadcast-{session_id}-channel"

    existing_input = _find_input_by_name(client, name=input_name)
    if existing_input:
        input_id = str(existing_input.get("Id") or "")
        input_arn = str(existing_input.get("Arn") or "")
    else:
        create_input = _with_retry(
            lambda: client.create_input(
                Name=input_name,
                Type="RTMP_PUSH",
                RequestId=idempotency_key or f"{session_id}:input",
                Tags={
                    "broadcast-session-id": session_id,
                    "correlation-id": correlation_id,
                },
            )
        )
        input_data = create_input.get("Input", {})
        input_id = str(input_data.get("Id") or "")
        input_arn = str(input_data.get("Arn") or "")

    archive_group = build_archive_output_group(
        bucket=S.broadcast_archive_bucket or "broadcast-archive",
        prefix_root=S.broadcast_archive_prefix_root or "sessions",
        session_id=session_id,
    )
    archive_prefix = archive_group["S3Prefix"]

    existing_channel = _find_channel_by_name(client, name=channel_name)
    if existing_channel:
        channel_id = str(existing_channel.get("Id") or "")
        channel_arn = str(existing_channel.get("Arn") or "")
        state = str(existing_channel.get("State") or "UNKNOWN")
    else:
        create_channel = _with_retry(
            lambda: client.create_channel(
                Name=channel_name,
                InputAttachments=[{"InputId": input_id, "InputAttachmentName": f"{session_id}-input-attach"}],
                RoleArn="arn:aws:iam::000000000000:role/MediaLiveAccessRole",
                Destinations=archive_group["Destinations"],
                EncoderSettings={"OutputGroups": [archive_group]},
                RequestId=idempotency_key or f"{session_id}:channel",
                Tags={
                    "broadcast-session-id": session_id,
                    "correlation-id": correlation_id,
                    "retention": "broadcast",
                },
            )
        )
        channel_data = create_channel.get("Channel", {})
        channel_id = str(channel_data.get("Id") or "")
        channel_arn = str(channel_data.get("Arn") or "")
        state = str(channel_data.get("State") or "CREATING")

    snapshot = {
        "provider": "aws",
        "input_name": input_name,
        "channel_name": channel_name,
        "channel_state": state,
        "archive_prefix": archive_prefix,
        "correlation_id": correlation_id,
        "idempotency_key": idempotency_key,
    }
    return MediaLiveProvisionResult(
        input_arn=input_arn,
        channel_arn=channel_arn,
        channel_id=channel_id,
        state_snapshot=snapshot,
        archive_prefix=archive_prefix,
    )
