from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from functools import lru_cache
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import jwt
import requests
from fastapi import HTTPException

from app.services.auth import issue_sso_session_token
from app.services.identity_linking import link_external_identity
from app.services.role_mapping import resolve_admin_role
from app.services.sessions import SessionStore
from app.services.metrics import COLLECTOR
from app.models import AdminSSOCallbackResponse, AdminSSONormalizedIdentity, AdminSSORoleMappingSimulationResponse


@dataclass(frozen=True)
class AdminSSOStartResult:
    authorization_url: str
    state: str
    nonce: str
    expires_at: datetime


def _get_state_signing_key() -> str:
    return os.getenv('ADMIN_SSO_STATE_SIGNING_KEY', 'dev-admin-sso-state-signing-key')


def _default_redirect_uri() -> str:
    return os.getenv('ADMIN_SSO_REDIRECT_URI', 'http://localhost:8000/auth/admin/sso/callback')


def _default_scope() -> str:
    return os.getenv('ADMIN_SSO_SCOPE', 'openid profile email')


def _state_ttl_seconds() -> int:
    return int(os.getenv('ADMIN_SSO_STATE_TTL_SECONDS', '300'))


def _jwks_cache_ttl_seconds() -> int:
    return int(os.getenv('ADMIN_SSO_JWKS_CACHE_TTL_SECONDS', '300'))


def _authorization_endpoint_for_issuer(issuer: str) -> str:
    return f"{issuer.rstrip('/')}/authorize"


def _sign_state_payload(provider_id: str, nonce: str, expires_at: datetime) -> str:
    payload = f'{provider_id}|{nonce}|{expires_at.isoformat()}'
    mac = hmac.new(_get_state_signing_key().encode(), payload.encode(), hashlib.sha256).digest()
    token = base64.urlsafe_b64encode(mac).decode().rstrip('=')
    return f'{token}.{base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")}'


def _b64url_decode(segment: str) -> bytes:
    pad = '=' * ((4 - len(segment) % 4) % 4)
    return base64.urlsafe_b64decode((segment + pad).encode())


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')


@lru_cache(maxsize=64)
def _load_oidc_metadata(metadata_url: str) -> dict[str, object]:
    try:
        response = requests.get(metadata_url, timeout=5)
        response.raise_for_status()
    except requests.RequestException as exc:
        raise HTTPException(status_code=400, detail='sso_callback_metadata_unreachable') from exc
    try:
        return response.json()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail='sso_callback_metadata_invalid') from exc


def _decode_unverified_header(id_token: str) -> dict[str, object]:
    try:
        return jwt.get_unverified_header(id_token)
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=400, detail='sso_callback_malformed_token') from exc


def _decode_hs256_token(id_token: str, *, issuer: str, audience: str, secret: str) -> dict[str, object]:
    try:
        payload = jwt.decode(
            id_token,
            secret,
            algorithms=['HS256'],
            audience=audience,
            issuer=issuer,
            options={'require': ['exp', 'iss', 'aud']},
        )
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=400, detail='sso_callback_token_expired') from exc
    except jwt.InvalidAudienceError as exc:
        raise HTTPException(status_code=400, detail='sso_callback_invalid_audience') from exc
    except jwt.InvalidIssuerError as exc:
        raise HTTPException(status_code=400, detail='sso_callback_invalid_issuer') from exc
    except jwt.InvalidSignatureError as exc:
        raise HTTPException(status_code=400, detail='sso_callback_invalid_signature') from exc
    except jwt.InvalidAlgorithmError as exc:
        raise HTTPException(status_code=400, detail='sso_callback_invalid_algorithm') from exc
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=400, detail='sso_callback_malformed_token') from exc
    return payload




@lru_cache(maxsize=64)
def _jwks_client(jwks_uri: str, cache_ttl_seconds: int) -> jwt.PyJWKClient:
    return jwt.PyJWKClient(jwks_uri, lifespan=cache_ttl_seconds)

def _decode_rs256_token(
    id_token: str,
    *,
    issuer: str,
    audience: str,
    metadata_url: str | None,
) -> dict[str, object]:
    effective_metadata_url = metadata_url or f"{issuer.rstrip('/')}/.well-known/openid-configuration"
    metadata = _load_oidc_metadata(effective_metadata_url)
    jwks_uri = metadata.get('jwks_uri')
    if not isinstance(jwks_uri, str) or not jwks_uri.strip():
        raise HTTPException(status_code=400, detail='sso_callback_metadata_missing_jwks_uri')

    try:
        signing_key = _jwks_client(jwks_uri, _jwks_cache_ttl_seconds()).get_signing_key_from_jwt(id_token)
        payload = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=['RS256'],
            audience=audience,
            issuer=issuer,
            options={'require': ['exp', 'iss', 'aud']},
        )
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=400, detail='sso_callback_token_expired') from exc
    except jwt.InvalidAudienceError as exc:
        raise HTTPException(status_code=400, detail='sso_callback_invalid_audience') from exc
    except jwt.InvalidIssuerError as exc:
        raise HTTPException(status_code=400, detail='sso_callback_invalid_issuer') from exc
    except jwt.InvalidSignatureError as exc:
        raise HTTPException(status_code=400, detail='sso_callback_invalid_signature') from exc
    except jwt.PyJWKClientError as exc:
        raise HTTPException(status_code=400, detail='sso_callback_jwks_unreachable') from exc
    except jwt.InvalidAlgorithmError as exc:
        raise HTTPException(status_code=400, detail='sso_callback_invalid_algorithm') from exc
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=400, detail='sso_callback_malformed_token') from exc
    return payload


def _parse_and_validate_id_token(
    id_token: str,
    *,
    issuer: str,
    audience: str,
    nonce: str,
    secret: str,
    metadata_url: str | None = None,
) -> dict[str, object]:
    header = _decode_unverified_header(id_token)
    alg = header.get('alg')
    if alg == 'HS256':
        payload = _decode_hs256_token(
            id_token,
            issuer=issuer,
            audience=audience,
            secret=secret,
        )
    elif alg == 'RS256':
        payload = _decode_rs256_token(
            id_token,
            issuer=issuer,
            audience=audience,
            metadata_url=metadata_url,
        )
    else:
        raise HTTPException(status_code=400, detail='sso_callback_invalid_algorithm')

    if payload.get('nonce') != nonce:
        raise HTTPException(status_code=400, detail='sso_callback_invalid_nonce')

    return payload


def _audit_callback_failure(
    store: SessionStore,
    *,
    provider_id: str | None,
    actor_email: str | None,
    external_subject: str | None,
    external_tenant: str | None,
    failure_reason: str,
) -> None:
    store.add_admin_sso_auth_audit_event(
        auth_method='ad_sso',
        outcome='failure',
        actor_email=actor_email,
        provider_id=provider_id,
        external_subject=external_subject,
        external_tenant=external_tenant,
        mapped_role=None,
        failure_reason=failure_reason,
    )


def handle_admin_sso_callback(store: SessionStore, state: str, id_token: str) -> AdminSSOCallbackResponse:
    started_at = time.perf_counter()
    provider_id: str | None = None
    actor_email: str | None = None
    external_subject: str | None = None
    external_tenant: str | None = None
    try:
        state_data = store.consume_admin_sso_start_request(state_signature=state)
        provider = store.get_identity_provider(state_data['provider_id'])
        provider_id = provider.provider_id
        secret = store.get_identity_provider_client_secret(provider.provider_id)

        payload = _parse_and_validate_id_token(
            id_token,
            issuer=provider.issuer,
            audience=provider.client_id,
            nonce=state_data['nonce'],
            secret=secret,
            metadata_url=provider.metadata_url,
        )

        sub = payload.get('sub')
        tenant_id = payload.get('tid') or payload.get('tenant_id')
        if not isinstance(sub, str) or not isinstance(tenant_id, str):
            raise HTTPException(status_code=400, detail='sso_callback_missing_required_claims')
        external_subject = sub
        external_tenant = tenant_id

        email_raw = payload.get('email')
        groups_raw = payload.get('groups', [])
        groups: list[str] = []
        if isinstance(groups_raw, list):
            groups = [str(item) for item in groups_raw]

        mapping = resolve_admin_role(
            store,
            provider_id=provider.provider_id,
            groups=groups,
            default_role=None,
        )
        if mapping.resolved_role is None:
            raise HTTPException(status_code=403, detail=mapping.reason_code)

        email = str(email_raw) if email_raw is not None else None
        actor_email = email
        linked = link_external_identity(
            store,
            provider_id=provider.provider_id,
            sub=sub,
            tenant_id=tenant_id,
            email=email,
        )
        session_role = mapping.resolved_role
        session_token = issue_sso_session_token(
            email=linked.user_id,
            role=session_role,
            auth_method='ad_sso',
        )

        store.add_admin_sso_auth_audit_event(
            auth_method='ad_sso',
            outcome='success',
            actor_email=linked.user_id,
            provider_id=provider.provider_id,
            external_subject=sub,
            external_tenant=tenant_id,
            mapped_role=session_role,
            failure_reason=None,
        )
        COLLECTOR.record_admin_sso_callback(
            outcome='success',
            duration_seconds=time.perf_counter() - started_at,
        )

        return AdminSSOCallbackResponse(
            provider_id=provider.provider_id,
            identity=AdminSSONormalizedIdentity(
                sub=sub,
                email=email,
                groups=groups,
                tenant_id=tenant_id,
            ),
            session_token=session_token,
            session_role=session_role,
            linked_user_id=linked.user_id,
            linked_external_identity_id=linked.external_identity.identity_id,
        )
    except HTTPException as exc:
        reason_code = str(exc.detail)
        outcome = 'denied' if exc.status_code == 403 else 'failure'
        _audit_callback_failure(
            store,
            provider_id=provider_id,
            actor_email=actor_email,
            external_subject=external_subject,
            external_tenant=external_tenant,
            failure_reason=reason_code,
        )
        COLLECTOR.record_admin_sso_callback(
            outcome=outcome,
            duration_seconds=time.perf_counter() - started_at,
            failure_reason=reason_code,
        )
        raise


def simulate_admin_role_mapping(
    store: SessionStore,
    *,
    provider_id: str,
    groups: list[str],
    default_role: str | None = None,
) -> AdminSSORoleMappingSimulationResponse:
    result = resolve_admin_role(
        store,
        provider_id=provider_id,
        groups=groups,
        default_role=default_role,
    )
    return AdminSSORoleMappingSimulationResponse(
        provider_id=provider_id,
        groups=groups,
        resolved_role=result.resolved_role,
        mapping_id=result.mapping_id,
        reason_code=result.reason_code,
    )


def create_admin_sso_start(store: SessionStore, provider_id: str) -> AdminSSOStartResult:
    provider = store.get_identity_provider(provider_id)
    if not provider.enabled:
        raise HTTPException(status_code=400, detail='identity_provider_disabled')
    if not provider.client_id or not provider.issuer or not provider.secret_ref:
        raise HTTPException(status_code=400, detail='identity_provider_misconfigured')

    nonce = base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip('=')
    expires_at = datetime.now(tz=timezone.utc) + timedelta(seconds=_state_ttl_seconds())
    state = _sign_state_payload(provider_id=provider.provider_id, nonce=nonce, expires_at=expires_at)
    store.create_admin_sso_start_request(
        provider_id=provider.provider_id,
        state_signature=state,
        nonce=nonce,
        expires_at=expires_at,
    )

    query = urlencode(
        {
            'client_id': provider.client_id,
            'response_type': 'code',
            'redirect_uri': _default_redirect_uri(),
            'scope': _default_scope(),
            'state': state,
            'nonce': nonce,
        }
    )
    authorization_url = f'{_authorization_endpoint_for_issuer(provider.issuer)}?{query}'

    return AdminSSOStartResult(
        authorization_url=authorization_url,
        state=state,
        nonce=nonce,
        expires_at=expires_at,
    )
