from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Protocol

from fastapi import HTTPException

from app.core.settings import S
from app.models_broadcast import BroadcastProfileModel, BroadcastSessionModel
from app.services.broadcast_mediolive import provision_mediolive_input_and_channel
from app.services.broadcast_mediapackage import provision_mediapackage_channel_and_endpoint


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
        return ProviderResult("start", self.name, "live", {"session_id": session.id, "mode": "stub", "correlation_id": correlation_id, "idempotency_key": idempotency_key})

    def stop(self, session: BroadcastSessionModel, *, correlation_id: str = "", idempotency_key: str = "") -> ProviderResult:
        return ProviderResult("stop", self.name, "stopped", {"session_id": session.id, "mode": "stub", "correlation_id": correlation_id, "idempotency_key": idempotency_key})

    def status(self, session: BroadcastSessionModel) -> ProviderResult:
        return ProviderResult("status", self.name, session.status, {"session_id": session.id, "mode": "stub"})

    def teardown(self, session: BroadcastSessionModel) -> ProviderResult:
        return ProviderResult("teardown", self.name, "deleted", {"session_id": session.id, "mode": "stub"})


def get_broadcast_provider(provider_name: str | None = None) -> BroadcastProvider:
    name = (provider_name or S.broadcast_provider or "local").strip().lower()
    if name == "local":
        return LocalBroadcastProvider()
    if name == "aws":
        return AwsBroadcastProvider()
    raise HTTPException(status_code=500, detail={"code": "BROADCAST_PROVIDER_UNSUPPORTED", "detail": f"unsupported provider: {name}"})
