from __future__ import annotations

from fastapi import HTTPException

from app.models import IdentityProvider
from app.services.secret_store import SqliteSecretStore


ALLOWED_PROTOCOLS = {'oidc', 'saml'}


def validate_provider_protocol_config(provider: IdentityProvider, db_path: str) -> None:
    provider_type = provider.provider_type.lower().strip()
    if provider_type not in ALLOWED_PROTOCOLS:
        raise HTTPException(status_code=400, detail='invalid_provider_protocol')

    if not provider.issuer:
        raise HTTPException(status_code=400, detail='invalid_provider_issuer_required')
    if not provider.secret_ref:
        raise HTTPException(status_code=400, detail='invalid_provider_secret_ref_required')

    if provider_type == 'oidc':
        if not provider.client_id:
            raise HTTPException(status_code=400, detail='invalid_provider_client_id_required')
    if provider_type == 'saml':
        if not provider.metadata_url:
            raise HTTPException(status_code=400, detail='invalid_provider_metadata_url_required')

    secret_store = SqliteSecretStore(db_path=db_path)
    try:
        secret_store.validate_identity_provider_secret_ref(provider.secret_ref, require_exists=True)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
