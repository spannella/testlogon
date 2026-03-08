from __future__ import annotations

from dataclasses import dataclass

from app.models import ExternalIdentity
from app.services.sessions import SessionStore


@dataclass(frozen=True)
class IdentityLinkResult:
    user_id: str
    external_identity: ExternalIdentity


def _derive_internal_user_id(email: str | None, sub: str, tenant_id: str) -> str:
    if email:
        return email.strip().lower()
    return f'ext:{tenant_id}:{sub}'


def link_external_identity(
    store: SessionStore,
    *,
    provider_id: str,
    sub: str,
    tenant_id: str,
    email: str | None,
) -> IdentityLinkResult:
    user_id = _derive_internal_user_id(email=email, sub=sub, tenant_id=tenant_id)
    external_identity = store.upsert_external_identity(
        user_id=user_id,
        provider_id=provider_id,
        external_subject=sub,
        external_tenant=tenant_id,
    )
    return IdentityLinkResult(user_id=user_id, external_identity=external_identity)
