from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Protocol


class MediaLiveOrchestrationError(RuntimeError):
    pass


class TransientAwsError(MediaLiveOrchestrationError):
    pass


class AlreadyExistsError(MediaLiveOrchestrationError):
    pass


class MediaLiveControlClient(Protocol):
    def create_channel(self, *, name: str, config: dict) -> str: ...

    def start_channel(self, *, channel_id: str) -> None: ...

    def stop_channel(self, *, channel_id: str) -> None: ...

    def resolve_channel_id(self, *, name: str) -> str | None: ...


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 3
    initial_backoff_seconds: float = 0.2
    backoff_multiplier: float = 2.0


@dataclass(frozen=True)
class LifecycleResult:
    request_id: str
    operation: str
    channel_name: str
    channel_id: str
    status: str
    attempts: int


class MediaLiveChannelOrchestrator:
    def __init__(self, *, client: MediaLiveControlClient, retry_policy: RetryPolicy | None = None, sleep_fn=time.sleep):
        self._client = client
        self._retry_policy = retry_policy or RetryPolicy()
        self._sleep = sleep_fn
        self._idempotency: dict[str, LifecycleResult] = {}

    def execute(
        self,
        *,
        operation: str,
        channel_name: str,
        request_id: str,
        channel_config: dict | None = None,
        channel_id: str | None = None,
    ) -> LifecycleResult:
        existing = self._idempotency.get(request_id)
        if existing:
            return existing

        result = self._execute_with_retry(
            operation=operation,
            channel_name=channel_name,
            request_id=request_id,
            channel_config=channel_config or {},
            channel_id=channel_id,
        )
        self._idempotency[request_id] = result
        return result

    def _execute_with_retry(
        self,
        *,
        operation: str,
        channel_name: str,
        request_id: str,
        channel_config: dict,
        channel_id: str | None,
    ) -> LifecycleResult:
        backoff = self._retry_policy.initial_backoff_seconds
        last_error: Exception | None = None
        for attempt in range(1, self._retry_policy.max_attempts + 1):
            try:
                if operation == "create":
                    try:
                        created_id = self._client.create_channel(name=channel_name, config=channel_config)
                    except AlreadyExistsError:
                        created_id = self._client.resolve_channel_id(name=channel_name)
                        if not created_id:
                            raise
                    return LifecycleResult(
                        request_id=request_id,
                        operation=operation,
                        channel_name=channel_name,
                        channel_id=created_id,
                        status="created",
                        attempts=attempt,
                    )

                resolved = channel_id or self._client.resolve_channel_id(name=channel_name)
                if not resolved:
                    raise MediaLiveOrchestrationError(f"channel not found: {channel_name}")

                if operation == "start":
                    self._client.start_channel(channel_id=resolved)
                    return LifecycleResult(
                        request_id=request_id,
                        operation=operation,
                        channel_name=channel_name,
                        channel_id=resolved,
                        status="started",
                        attempts=attempt,
                    )

                if operation == "stop":
                    self._client.stop_channel(channel_id=resolved)
                    return LifecycleResult(
                        request_id=request_id,
                        operation=operation,
                        channel_name=channel_name,
                        channel_id=resolved,
                        status="stopped",
                        attempts=attempt,
                    )

                raise MediaLiveOrchestrationError(f"unsupported operation: {operation}")
            except TransientAwsError as exc:
                last_error = exc
                if attempt == self._retry_policy.max_attempts:
                    break
                self._sleep(backoff)
                backoff *= self._retry_policy.backoff_multiplier

        raise MediaLiveOrchestrationError(
            f"failed to execute {operation} for {channel_name} after {self._retry_policy.max_attempts} attempts"
        ) from last_error
