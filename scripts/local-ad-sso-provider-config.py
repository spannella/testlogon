#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from urllib.error import URLError
from urllib.request import urlopen


KEYCLOAK_BASE_URL = os.getenv('KEYCLOAK_BASE_URL', 'http://localhost:8081').rstrip('/')
KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM', 'local-ad')
KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', 'deployment-initializer-admin-sso')
KEYCLOAK_CLIENT_SECRET_REF = os.getenv('KEYCLOAK_CLIENT_SECRET_REF', 'secret://identity-providers/local-ad/client-secret')


def fetch_json(url: str) -> dict[str, object]:
    with urlopen(url, timeout=10) as response:  # noqa: S310
        body = response.read().decode('utf-8')
        return json.loads(body)


def main() -> int:
    discovery_url = f'{KEYCLOAK_BASE_URL}/realms/{KEYCLOAK_REALM}/.well-known/openid-configuration'

    try:
        metadata = fetch_json(discovery_url)
    except (URLError, TimeoutError, ValueError) as exc:
        print(f'Failed to read discovery document: {exc}', file=sys.stderr)
        print('Hint: start Keycloak first with DEV_ENABLE_KEYCLOAK=1 scripts/local-ad-sso-up.sh', file=sys.stderr)
        return 1

    provider_payload = {
        'name': 'Local Keycloak AD (dev)',
        'protocol': 'oidc',
        'issuer': metadata.get('issuer', f'{KEYCLOAK_BASE_URL}/realms/{KEYCLOAK_REALM}'),
        'authorization_endpoint': metadata.get('authorization_endpoint'),
        'token_endpoint': metadata.get('token_endpoint'),
        'jwks_uri': metadata.get('jwks_uri'),
        'client_id': KEYCLOAK_CLIENT_ID,
        'client_secret_ref': KEYCLOAK_CLIENT_SECRET_REF,
        'scopes': ['openid', 'profile', 'email'],
        'claim_mappings': {
            'email': 'email',
            'groups': 'groups',
            'subject': 'sub',
        },
        'status': 'draft',
    }

    role_mappings_payload = [
        {
            'target_role': 'admin',
            'source_type': 'group',
            'source_value': 'group-admins',
            'priority': 100,
        },
        {
            'target_role': 'ops',
            'source_type': 'group',
            'source_value': 'group-ops',
            'priority': 200,
        },
    ]

    print('# Root API payload for POST /auth/admin/sso/providers')
    print(json.dumps(provider_payload, indent=2))
    print('')
    print('# Suggested role mappings payload for POST /auth/admin/sso/providers/{provider_id}/role-mappings')
    print(json.dumps(role_mappings_payload, indent=2))
    print('')
    print('# Validation flow (example)')
    print('curl -s -X POST http://localhost:8000/auth/admin/sso/providers \\')
    print("  -H 'content-type: application/json' \\")
    print("  -H 'authorization: Bearer root:<token>' \\")
    print('  -d @provider.json')
    print('curl -s -X POST http://localhost:8000/auth/admin/sso/providers/<provider_id>/validate \\')
    print("  -H 'authorization: Bearer root:<token>'")
    print('curl -s -X POST http://localhost:8000/auth/admin/sso/providers/<provider_id>/activate \\')
    print("  -H 'authorization: Bearer root:<token>'")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
