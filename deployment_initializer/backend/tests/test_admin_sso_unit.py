from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.services.admin_sso import _parse_and_validate_id_token
from app.services.role_mapping import resolve_admin_role
from app.models import IdentityProviderRoleMapping


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip('=')


def _make_id_token(
    *,
    secret: str,
    issuer: str,
    audience: str | list[str],
    nonce: str,
    exp: int,
    alg: str = 'HS256',
) -> str:
    header = {'alg': alg, 'typ': 'JWT'}
    payload = {
        'iss': issuer,
        'aud': audience,
        'nonce': nonce,
        'exp': exp,
        'sub': 'unit-sub',
        'email': 'unit@example.com',
        'tid': 'tenant-unit',
        'groups': ['group-admins'],
    }
    h = _b64url(json.dumps(header, separators=(',', ':')).encode())
    p = _b64url(json.dumps(payload, separators=(',', ':')).encode())
    sig = _b64url(hmac.new(secret.encode(), f'{h}.{p}'.encode(), hashlib.sha256).digest())
    return f'{h}.{p}.{sig}'


class _FakeStore:
    def __init__(self, mappings: list[IdentityProviderRoleMapping]) -> None:
        self._mappings = mappings

    def list_identity_provider_role_mappings(self, provider_id: str) -> list[IdentityProviderRoleMapping]:
        assert provider_id == 'provider-1'
        return self._mappings


@pytest.mark.parametrize(
    ('token_builder_kwargs', 'issuer', 'audience', 'nonce', 'expected_detail'),
    [
        ({'issuer': 'https://issuer.bad', 'audience': 'client-1', 'nonce': 'nonce-1'}, 'https://issuer.good', 'client-1', 'nonce-1', 'sso_callback_invalid_issuer'),
        ({'issuer': 'https://issuer.good', 'audience': 'client-bad', 'nonce': 'nonce-1'}, 'https://issuer.good', 'client-1', 'nonce-1', 'sso_callback_invalid_audience'),
        ({'issuer': 'https://issuer.good', 'audience': 'client-1', 'nonce': 'nonce-bad'}, 'https://issuer.good', 'client-1', 'nonce-1', 'sso_callback_invalid_nonce'),
        ({'issuer': 'https://issuer.good', 'audience': 'client-1', 'nonce': 'nonce-1', 'alg': 'none'}, 'https://issuer.good', 'client-1', 'nonce-1', 'sso_callback_invalid_algorithm'),
    ],
)
def test_parse_and_validate_id_token_rejects_security_bypass_patterns(
    token_builder_kwargs: dict[str, object],
    issuer: str,
    audience: str,
    nonce: str,
    expected_detail: str,
) -> None:
    token = _make_id_token(
        secret='unit-secret',
        exp=int((datetime.now(tz=timezone.utc) + timedelta(minutes=5)).timestamp()),
        **token_builder_kwargs,
    )

    with pytest.raises(HTTPException) as err:
        _parse_and_validate_id_token(
            token,
            issuer=issuer,
            audience=audience,
            nonce=nonce,
            secret='unit-secret',
        )
    assert err.value.detail == expected_detail


def test_parse_and_validate_id_token_rejects_expired_and_invalid_signature() -> None:
    expired = _make_id_token(
        secret='unit-secret',
        issuer='https://issuer.good',
        audience='client-1',
        nonce='nonce-1',
        exp=int((datetime.now(tz=timezone.utc) - timedelta(minutes=1)).timestamp()),
    )
    with pytest.raises(HTTPException) as exp_err:
        _parse_and_validate_id_token(
            expired,
            issuer='https://issuer.good',
            audience='client-1',
            nonce='nonce-1',
            secret='unit-secret',
        )
    assert exp_err.value.detail == 'sso_callback_token_expired'

    signed_with_wrong_secret = _make_id_token(
        secret='wrong-secret',
        issuer='https://issuer.good',
        audience='client-1',
        nonce='nonce-1',
        exp=int((datetime.now(tz=timezone.utc) + timedelta(minutes=5)).timestamp()),
    )
    with pytest.raises(HTTPException) as sig_err:
        _parse_and_validate_id_token(
            signed_with_wrong_secret,
            issuer='https://issuer.good',
            audience='client-1',
            nonce='nonce-1',
            secret='unit-secret',
        )
    assert sig_err.value.detail == 'sso_callback_invalid_signature'


def test_parse_and_validate_id_token_accepts_audience_array() -> None:
    token = _make_id_token(
        secret='unit-secret',
        issuer='https://issuer.good',
        audience=['client-2', 'client-1'],
        nonce='nonce-1',
        exp=int((datetime.now(tz=timezone.utc) + timedelta(minutes=5)).timestamp()),
    )

    payload = _parse_and_validate_id_token(
        token,
        issuer='https://issuer.good',
        audience='client-1',
        nonce='nonce-1',
        secret='unit-secret',
    )
    assert payload['sub'] == 'unit-sub'


def test_resolve_admin_role_precedence_and_root_forbidden_regressions() -> None:
    mappings = [
        IdentityProviderRoleMapping(
            mapping_id=1,
            provider_id='provider-1',
            external_group_or_claim='group-admins',
            internal_role='admin',
            priority=10,
            created_at=datetime.now(tz=timezone.utc),
        ),
        IdentityProviderRoleMapping(
            mapping_id=2,
            provider_id='provider-1',
            external_group_or_claim='group-root',
            internal_role='root',
            priority=100,
            created_at=datetime.now(tz=timezone.utc),
        ),
    ]
    store = _FakeStore(mappings)

    mapped = resolve_admin_role(store, provider_id='provider-1', groups=['group-admins'])
    assert mapped.resolved_role == 'admin'
    assert mapped.reason_code == 'role_mapped'

    forbidden = resolve_admin_role(store, provider_id='provider-1', groups=['group-root'])
    assert forbidden.resolved_role is None
    assert forbidden.reason_code == 'sso_root_role_forbidden'

    denied = resolve_admin_role(store, provider_id='provider-1', groups=['unmapped'])
    assert denied.resolved_role is None
    assert denied.reason_code == 'sso_role_mapping_denied'

    default_root_forbidden = resolve_admin_role(
        store,
        provider_id='provider-1',
        groups=['unmapped'],
        default_role='root',
    )
    assert default_root_forbidden.resolved_role is None
    assert default_root_forbidden.reason_code == 'sso_root_role_forbidden'
