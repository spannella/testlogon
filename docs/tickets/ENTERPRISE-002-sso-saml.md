# ENTERPRISE-002: SSO / SAML Integration for Enterprise Customers

**Ticket**: ENTERPRISE-002
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-28

---

## 1. Overview & Motivation

### 1.1 Problem Statement

Enterprise customers require their employees to authenticate via their corporate Identity Provider (IdP) -- Azure AD, Okta, OneLogin, Google Workspace -- rather than managing separate credentials on our platform. Today the platform supports three auth modes (cookie sessions, Cognito JWT, dev-mode header fallback) as implemented in `app/auth/deps.py`, but none of them support federated SSO via SAML 2.0 or OIDC from an external enterprise IdP.

The local dev stack documentation (`docs/local-dev-stack.md`, line 29) mentions an optional Keycloak mode for AD SSO development:

```
## AD Admin SSO local IdP option (Keycloak)

For AD SSO feature work, we support an optional local Keycloak mode to emulate a real OIDC IdP.
```

And configuration scripts exist (`scripts/local-ad-sso-up.sh`, `scripts/local-keycloak-rotate-keys.py`), confirming that OIDC infrastructure has been prototyped. However, there is no SAML Service Provider (SP) implementation, no IdP metadata import flow, no JIT provisioning, and no enforcement mechanism to require SSO for specific tenants.

### 1.2 How It Works

1. A root or tenant admin configures an SSO provider by uploading the IdP's SAML metadata XML (or providing a metadata URL).
2. The system parses the metadata, extracts the IdP's SSO URL, SLO URL, and X.509 signing certificate.
3. Attribute mappings are configured: which SAML assertion attribute maps to `email`, `display_name`, and which group assertions map to platform roles (`USER`, `ADMIN`).
4. When SSO-only enforcement is enabled for a tenant, the login page shows only a "Sign in with SSO" button.
5. Clicking it triggers a SAML AuthnRequest redirect to the IdP.
6. After IdP authentication, the browser POSTs the SAML Response to our Assertion Consumer Service (ACS) endpoint.
7. The ACS validates the signature, extracts attributes, performs JIT user provisioning (or updates the existing user), creates a platform session, and redirects to the app.

### 1.3 Design Principles

- **Standards compliant**: Full SAML 2.0 SP implementation with SP-initiated SSO and IdP-initiated SSO support.
- **JIT provisioning**: Users are created automatically on their first SSO login. No manual user creation needed.
- **Attribute mapping flexibility**: Each tenant can map arbitrary SAML assertion attributes to platform fields.
- **SSO-only enforcement**: Tenants can disable password-based login entirely, forcing all users through the IdP.
- **Key rotation safe**: The SP supports multiple IdP certificates for seamless key rotation (the IdP publishes a new cert before revoking the old one).

### 1.4 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Tenant admin | As a tenant admin, I want to configure SAML SSO by uploading my IdP's metadata XML. | POST with XML body creates SSO provider; IdP SSO URL, certificates extracted. |
| Tenant admin | As a tenant admin, I want to map IdP attributes to platform fields. | POST attribute mapping; SAML assertions populate user profile fields on login. |
| Tenant admin | As a tenant admin, I want to enforce SSO-only login for my tenant. | PATCH sets sso_only=true; password login returns 403 for tenant users. |
| End user | As an employee at Acme Corp, I want to click "Sign in with SSO" and be redirected to my company's Okta login. | AuthnRequest redirect works; after IdP auth, user lands in the app authenticated. |
| End user | As a first-time SSO user, I want my account created automatically when I log in via SSO. | JIT provisioning creates user record, profile, and session on first SSO login. |
| Root admin | As a root admin, I want to see SSO login events in the audit log. | Audit events with `event="sso_login"` are recorded for each SSO authentication. |
| Tenant admin | As a tenant admin, I want to test SSO configuration before enforcing it. | Test mode allows SSO login alongside password login; admin verifies both paths work. |
| Tenant admin | As a tenant admin, I want to download the SP metadata XML to configure my IdP. | GET /saml/metadata returns XML with SP entity ID, ACS URL, and signing certificate. |

---

## 2. Current State Analysis

### 2.1 Authentication Architecture (`app/auth/deps.py`)

The `get_authenticated_user` function (line 184) follows a priority chain:
<!-- VERIFIED: app/auth/deps.py:184 — get_authenticated_user -->

```python
# app/auth/deps.py, lines 184-270
async def get_authenticated_user(request: Request) -> AuthenticatedUser:
    # 1. API key principal (lines 194-209)
    # 2. Cookie-based path (lines 211-232)
    # 3. Cognito JWT Bearer token (lines 234-248)
    # 4. Dev-mode fallbacks (lines 250-270)
```
<!-- CORRECTED: was "lines 195-209" for API key principal, actually starts at line 194 -->

The cookie path (lines 217-222) decodes an HS256 JWT signed with `ui_access_token_secret`:
<!-- CORRECTED: was "lines 216-222", actually jwt.decode starts at line 218, but access_cookie check is line 216 -->

```python
payload = jwt.decode(
    access_cookie,
    access_secret,
    algorithms=["HS256"],
    options={"verify_exp": False},
)
```

SSO integration hooks into this existing cookie flow: after SAML assertion validation, the ACS endpoint creates a session and sets the same `ui_session`, `ui_csrf`, and `ui_access_token` cookies. The user then enters the normal cookie-based auth path on subsequent requests.

The critical integration point is the session creation. The ACS must call `create_real_session()` from `app/services/sessions.py` (line 403) which writes the session to `T.sessions` and returns a `SessionInfo` dataclass containing `session_id`, `csrf_token`, and `user_sub`. The ACS then mints the `ui_access_token` JWT using `mint_access_token()` (line 168 of sessions.py) and sets all three cookies on the response.
<!-- CORRECTED: was "line 72", actually create_real_session is at line 403 of sessions.py -->
<!-- VERIFIED: app/services/sessions.py:168 — mint_access_token -->

### 2.2 Session Creation (`app/routers/ui_session.py`)

The login flow starts at `POST /ui/session/start` (line 63):
<!-- VERIFIED: app/routers/ui_session.py:63 — @router.post("/session/start") (router prefix is /ui, so full path is /ui/session/start) -->

```python
# app/routers/ui_session.py, lines 63-69
@router.post("/session/start", response_model=UiSessionStartResp)
async def ui_session_start(
    req: Request,
    body: UiSessionStartReq,
    response: Response = None,
    user_sub: str = Depends(resolve_dev_or_authenticated_user_sub),
):
```
<!-- CORRECTED: route path in code is "/session/start" (router prefix="/ui" adds the /ui part) -->

This endpoint depends on `resolve_dev_or_authenticated_user_sub` which verifies credentials. For SSO, we bypass this entirely -- the ACS endpoint validates the SAML assertion and directly calls `create_real_session()` from `app/services/sessions.py`.

The adaptive login policy (line 38) adds MFA requirements based on anomaly detection:
<!-- VERIFIED: app/routers/ui_session.py:38 — _adaptive_login_policy -->

```python
# app/routers/ui_session.py, lines 38-61
def _adaptive_login_policy(user_sub: str, base_required: list[str], anomaly: dict) -> tuple[...]:
    ...
```

SSO logins skip MFA challenges (the IdP handles MFA). The session is created with `pending_auth=False` and `factors_completed=["sso"]`.

The session cookie configuration in `set_session_cookies()` (line 78 of `app/services/sessions.py`):
<!-- CORRECTED: was "_set_session_cookies() (line 145 of ui_session.py)", actually "set_session_cookies()" at line 78 of app/services/sessions.py. The function does NOT exist in ui_session.py. Signature is: set_session_cookies(response: Response, session: SessionInfo, *, refresh_ttl_seconds: Optional[int] = None) — it does NOT take a separate access_token parameter; it calls mint_access_token() internally. -->

```python
# app/services/sessions.py, line 78
def set_session_cookies(response: Response, session: SessionInfo, *, refresh_ttl_seconds: Optional[int] = None) -> None:
    # Sets ui_session, ui_csrf, and ui_access_token cookies
    # Calls mint_access_token() internally to generate the JWT
```

The ACS endpoint calls this function directly after SAML assertion validation to set session cookies.

### 2.3 Keycloak OIDC Prototype (`docs/local-dev-stack.md`)

The local Keycloak setup (line 29 onward) configures:
<!-- VERIFIED: docs/local-dev-stack.md:29 — "## AD Admin SSO local IdP option (Keycloak)" -->

```
- KEYCLOAK_BASE_URL=http://localhost:8081
- KEYCLOAK_REALM=local-ad
- KEYCLOAK_CLIENT_ID=deployment-initializer-admin-sso
```

And mentions role-mapping from Keycloak groups:

```
5. **Create role mappings**
   - group-admins -> admin
   - group-ops -> ops
```

The existing `scripts/local-ad-sso-provider-config.py` generates provider JSON from live Keycloak metadata, and `POST /auth/admin/sso/providers` creates the provider. This confirms that a provider management API already exists for OIDC. The SAML implementation extends this with a SAML-specific provider type, metadata parsing, and the ACS endpoint.

### 2.4 Settings Configuration (`app/core/settings.py`)

Cognito-related settings exist (lines 20-26):
<!-- VERIFIED: app/core/settings.py:20-24 — cognito settings (cognito_jwks_url is on line 24) -->

```python
# app/core/settings.py, lines 20-24
cognito_user_pool_id: str = os.environ.get("COGNITO_USER_POOL_ID", "")
cognito_region: str = os.environ.get("COGNITO_REGION", "")
cognito_app_client_id: str = os.environ.get("COGNITO_APP_CLIENT_ID", "")
cognito_issuer_url: str = os.environ.get("COGNITO_ISSUER_URL", "")
cognito_jwks_url: str = os.environ.get("COGNITO_JWKS_URL", "")
```
<!-- CORRECTED: was "lines 20-26", actually lines 20-24 (line 25 is cognito_expected_token_use, line 26 is cognito_jwks_ttl_seconds) -->

The `_cognito_enabled()` check (line 25 of deps.py):
<!-- VERIFIED: app/auth/deps.py:25 — _cognito_enabled (actually named _cognito_enabled, checks cognito_user_pool_id and cognito_app_client_id) -->

```python
def _cognito_enabled() -> bool:
    return bool(S.cognito_user_pool_id and S.cognito_app_client_id)
```

When Cognito is enabled, the dev header fallback is disabled. SAML SSO adds a new auth path that operates independently of Cognito -- it produces the same session cookies that the cookie-based path already handles.

### 2.5 User Creation Pattern

New users are created during registration at `POST /ui/register` (in `app/routers/register.py`). The registration flow creates a user record in `T.users` with password hash. JIT provisioning must replicate this record creation without a password hash, setting `auth_method: "sso"` and `sso_provider_id` on the user record.

The user record schema in `T.users`:

```python
{
    "user_sub": "alice@acme.com",
    "email": "alice@acme.com",
    "password_hash": "...",           # empty for SSO users
    "auth_method": "password",         # "password" | "sso" | "both"
    "sso_provider_id": null,           # set for SSO users
    "created_at": 1716883200,
    "last_login_at": 1716883200,
    "status": "active",
}
```

For JIT-provisioned users, the record is:

```python
{
    "user_sub": "alice@acme.com",
    "email": "alice@acme.com",
    "password_hash": "",               # no password
    "auth_method": "sso",
    "sso_provider_id": "sso_abc123",
    "sso_idp_user_id": "alice@acme.com",  # IdP NameID
    "tenant_id": "acme-corp",
    "created_at": 1716883200,
    "last_login_at": 1716883200,
    "status": "active",
    "jit_provisioned": true,
}
```

A profile record is also created in `T.profile`:

```python
{
    "user_sub": "alice@acme.com",
    "display_name": "Alice Smith",      # from SAML assertion
    "email": "alice@acme.com",          # from SAML assertion
    "avatar_url": "",
    "created_at": 1716883200,
}
```

### 2.6 Role System (`app/auth/roles.py`)

The role enum (lines 8-11) has three values:
<!-- VERIFIED: app/auth/roles.py:8-11 — Role enum with ROOT, ADMIN, USER -->

```python
class Role(str, Enum):
    ROOT = "root"
    ADMIN = "admin"
    USER = "user"
```

SAML group-to-role mapping allows IdP groups to grant `ADMIN` role. The `ROOT` role is never assignable via SSO (enforced by `enforce_root_role_invariant` at line 22 in `app/auth/root_invariant.py`).
<!-- VERIFIED: app/auth/root_invariant.py:22 — enforce_root_role_invariant -->

The `AdminScope` enum supports scoped admin profiles. SSO group mappings can also assign admin scopes:

```python
# Role mapping example
{
    "idp_group": "Platform-Admins",
    "platform_role": "admin",
    "admin_profile": {
        "type": "general"
    }
}
{
    "idp_group": "Support-Team",
    "platform_role": "admin",
    "admin_profile": {
        "type": "scoped",
        "scopes": ["auth_support", "billing_support"]
    }
}
```

### 2.7 Ban Check Integration

The `is_user_currently_banned()` function from `app/services/moderation_policy_engine.py` is called during session creation. SSO logins must also check bans:

```python
# In ACS endpoint, before creating session
if is_user_currently_banned(user_sub):
    return RedirectResponse(url="/login?error=account_banned", status_code=303)
```

---

## 3. Technical Design

### 3.1 SAML SP Implementation

The SAML SP is implemented using the `python3-saml` (onelogin) library or the `pysaml2` library. Both handle SAML request/response encoding, XML signature validation, and assertion parsing.

We recommend `python3-saml` for its simpler API and better documentation. The library requires:

1. **SP settings** (entity ID, ACS URL, SLS URL, NameID format, certificate, private key)
2. **IdP settings** (entity ID, SSO URL, SLO URL, certificates)

These are constructed per-request from the provider record in DynamoDB.

```python
# app/services/sso_saml_sp.py (new)
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings

def build_saml_settings(provider: dict, request_data: dict) -> dict:
    """Build python3-saml settings dict from our provider record."""
    sp_entity_id = provider["sp_entity_id"]
    sp_acs_url = provider["sp_acs_url"]

    # Load SP private key and cert from secrets
    sp_private_key = _load_sp_private_key()
    sp_cert = _load_sp_certificate()

    # Build IdP cert list (support multiple for rotation)
    idp_certs = [c["x509_cert"] for c in provider.get("idp_certificates", [])]

    return {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": sp_entity_id,
            "assertionConsumerService": {
                "url": sp_acs_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "singleLogoutService": {
                "url": provider.get("sp_slo_url", ""),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "x509cert": sp_cert,
            "privateKey": sp_private_key,
        },
        "idp": {
            "entityId": provider["idp_entity_id"],
            "singleSignOnService": {
                "url": provider["idp_sso_url"],
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "singleLogoutService": {
                "url": provider.get("idp_slo_url", ""),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509certMulti": {
                "signing": idp_certs,
            },
        },
        "security": {
            "authnRequestsSigned": True,
            "wantAssertionsSigned": True,
            "wantNameId": True,
            "wantNameIdEncrypted": False,
            "wantAssertionsEncrypted": False,
            "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
        },
    }


def prepare_request_data(request) -> dict:
    """Convert a Starlette/FastAPI request to the format python3-saml expects."""
    scheme = request.url.scheme
    host = request.headers.get("host", "localhost")
    return {
        "https": "on" if scheme == "https" else "off",
        "http_host": host,
        "server_port": request.url.port or (443 if scheme == "https" else 80),
        "script_name": request.url.path,
        "get_data": dict(request.query_params),
        "post_data": {},  # populated in ACS from form data
    }
```

### 3.2 Data Model

#### 3.2.1 SSO Provider Table

**Table**: `sso_providers` (new)
**PK**: `tenant_id`
**SK**: `PROVIDER#{provider_id}`

```python
{
    "tenant_id": "acme-corp",
    "sk": "PROVIDER#sso_abc123",
    "provider_id": "sso_abc123",
    "protocol": "saml",              # saml | oidc
    "display_name": "Acme Corp Okta",
    "status": "active",              # active | inactive | testing
    "sso_only": false,               # if true, password login disabled for this tenant
    "idp_entity_id": "https://acme.okta.com/...",
    "idp_sso_url": "https://acme.okta.com/app/.../sso/saml",
    "idp_slo_url": "https://acme.okta.com/app/.../slo/saml",
    "idp_certificates": [            # list supports key rotation
        {
            "x509_cert": "MIIC...",
            "fingerprint_sha256": "AA:BB:CC:...",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_to": "2027-01-01T00:00:00Z",
        }
    ],
    "sp_entity_id": "https://app.acme.com/saml/metadata",
    "sp_acs_url": "https://app.acme.com/saml/acs",
    "sp_slo_url": "https://app.acme.com/saml/slo",
    "attribute_mappings": {
        "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        "display_name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
        "first_name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
        "last_name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
        "groups": "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
        "phone": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/mobilephone",
    },
    "role_mappings": [
        {"idp_group": "Platform-Admins", "platform_role": "admin", "admin_profile": {"type": "general"}},
        {"idp_group": "Platform-Users", "platform_role": "user"},
        {"idp_group": "Support-Team", "platform_role": "admin", "admin_profile": {"type": "scoped", "scopes": ["auth_support"]}},
    ],
    "default_role": "user",
    "jit_provisioning_enabled": true,
    "auto_update_profile": true,     # update display_name/email on each SSO login
    "auto_update_role": false,       # update role from groups on each login (dangerous)
    "allowed_email_domains": ["acme.com", "acme.co.uk"],  # restrict JIT to these domains
    "created_at": 1716883200,
    "updated_at": 1716883200,
    "created_by": "root.admin@testdev.local",
    "metadata_xml_s3_key": "sso-metadata/acme-corp/sso_abc123.xml",
    "last_login_at": null,
    "login_count": 0,
}
```

**Full DDB schema:**

| Attribute | Type | Key | Description |
|-----------|------|-----|-------------|
| `tenant_id` | S | PK | Tenant this provider belongs to |
| `sk` | S | SK | `PROVIDER#{provider_id}` |
| `provider_id` | S | GSI PK | Unique provider identifier |
| `protocol` | S | | `saml` or `oidc` |
| `display_name` | S | | Human-readable name |
| `status` | S | | `active`, `inactive`, `testing` |
| `sso_only` | BOOL | | Whether password login is disabled |
| `idp_entity_id` | S | | IdP entity ID from metadata |
| `idp_sso_url` | S | | IdP SSO endpoint URL |
| `idp_slo_url` | S | | IdP SLO endpoint URL (optional) |
| `idp_certificates` | L | | List of X.509 cert maps |
| `sp_entity_id` | S | | SP entity ID |
| `sp_acs_url` | S | | SP ACS endpoint URL |
| `attribute_mappings` | M | | SAML attribute -> platform field map |
| `role_mappings` | L | | IdP group -> platform role mappings |
| `default_role` | S | | Default role for unmapped users |
| `jit_provisioning_enabled` | BOOL | | Whether to auto-create users |
| `auto_update_profile` | BOOL | | Update profile on each login |
| `auto_update_role` | BOOL | | Update role from groups on login |
| `allowed_email_domains` | SS | | Restrict JIT to these email domains |
| `created_at` | N | | Unix timestamp |
| `updated_at` | N | | Unix timestamp |
| `created_by` | S | | Creator user_sub |
| `metadata_xml_s3_key` | S | | S3 key for stored metadata XML |
| `last_login_at` | N | | Last SSO login timestamp |
| `login_count` | N | | Total SSO login count |

#### 3.2.2 SSO Session Link Table

**Table**: `sso_sessions` (new)
**PK**: `session_id`
**SK**: `SSO_LINK`

```python
{
    "session_id": "sess_xyz789",
    "sk": "SSO_LINK",
    "provider_id": "sso_abc123",
    "tenant_id": "acme-corp",
    "saml_session_index": "...",
    "saml_name_id": "user@acme.com",
    "saml_name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    "authenticated_at": 1716883200,
    "assertion_id": "...",           # for replay detection
    "attributes_raw": { ... },       # full SAML assertion attributes for audit
    "ttl": 1716969600,               # DDB TTL for auto-cleanup
}
```

#### 3.2.3 SAML Assertion Replay Cache

**Table**: `sso_assertion_cache` (new)
**PK**: `assertion_id`
**TTL**: `expires_at`

```python
{
    "assertion_id": "_abc123def456",  # SAML assertion ID
    "consumed_at": 1716883200,
    "tenant_id": "acme-corp",
    "user_sub": "alice@acme.com",
    "expires_at": 1716883500,         # assertion max age + clock skew
}
```

### 3.3 SAML Flow

#### 3.3.1 SP-Initiated SSO (Normal Flow)

```
Browser                  Platform (SP)              IdP (Okta/Azure)
   |                          |                          |
   |  GET /saml/login?tenant=acme-corp                   |
   |  ─────────────────────> |                           |
   |                          | Build AuthnRequest        |
   |                          | Sign with SP private key  |
   |  302 Redirect to IdP SSO URL with SAMLRequest       |
   |  <─────────────────────  |                           |
   |                          |                           |
   |  ──────────────────────────────────────────────────> |
   |                          |      IdP authenticates    |
   |  <────────────────────────────────────────────────── |
   |  POST /saml/acs (SAMLResponse)                      |
   |  ─────────────────────> |                           |
   |                          | Validate signature        |
   |                          | Check assertion replay    |
   |                          | Extract attributes        |
   |                          | Validate email domain     |
   |                          | JIT provision user        |
   |                          | Check ban status          |
   |                          | Map groups to role        |
   |                          | Create session            |
   |                          | Set cookies               |
   |                          | Record SSO session link   |
   |                          | Audit log                 |
   |  302 Redirect to /       |                           |
   |  <─────────────────────  |                           |
```

#### 3.3.2 IdP-Initiated SSO (Unsolicited Flow)

The IdP sends an unsolicited SAMLResponse to the ACS URL. The SP validates it identically but does not have a `RelayState` for redirect. Default redirect is `/`.

The key difference: there is no `InResponseTo` field in the assertion (since no AuthnRequest was sent). The SP must handle this case by skipping the `InResponseTo` validation.

#### 3.3.3 Single Logout (SLO) Flow

```
Browser                  Platform (SP)              IdP (Okta/Azure)
   |                          |                          |
   |  User clicks "Logout"    |                          |
   |  ─────────────────────> |                           |
   |                          | Revoke session            |
   |                          | Build LogoutRequest       |
   |  302 Redirect to IdP SLO URL with SAMLRequest       |
   |  <─────────────────────  |                           |
   |                          |                           |
   |  ──────────────────────────────────────────────────> |
   |                          |   IdP processes logout    |
   |  <────────────────────────────────────────────────── |
   |  GET /saml/slo (LogoutResponse)                     |
   |  ─────────────────────> |                           |
   |                          | Validate response         |
   |  302 Redirect to /login  |                           |
   |  <─────────────────────  |                           |
```

### 3.4 ACS Endpoint Logic

```python
# app/routers/sso_saml.py (new)
from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse

from app.core.normalize import client_ip_from_request, normalize_email
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import audit_event
from app.services.moderation_policy_engine import is_user_currently_banned
from app.services.sessions import create_real_session, mint_access_token
from app.services.sso_saml_provider import (
    get_active_provider_for_tenant,
    increment_login_count,
)
from app.services.sso_saml_sp import build_saml_settings, prepare_request_data
from app.services.sso_saml_jit import ensure_user_exists, update_user_profile
from app.services.sso_saml_roles import map_groups_to_role

logger = logging.getLogger(__name__)

router = APIRouter(tags=["sso-saml"])


@router.get("/saml/login")
async def saml_login(request: Request):
    """SP-initiated SSO: build AuthnRequest and redirect to IdP."""
    tenant_id = getattr(request.state, "tenant_id", "default")
    provider = get_active_provider_for_tenant(tenant_id)
    if not provider:
        raise HTTPException(400, "No active SSO provider for this tenant")

    settings_dict = build_saml_settings(provider, prepare_request_data(request))

    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    auth = OneLogin_Saml2_Auth(prepare_request_data(request), settings_dict)
    redirect_url = auth.login(return_to="/")

    audit_event("sso_login_initiated", "", request,
                tenant_id=tenant_id,
                provider_id=provider["provider_id"],
                idp_sso_url=provider["idp_sso_url"])

    return RedirectResponse(url=redirect_url, status_code=302)


@router.post("/saml/acs")
async def saml_acs(request: Request, response: Response):
    """Assertion Consumer Service: process SAMLResponse from IdP."""
    form = await request.form()
    saml_response_b64 = form.get("SAMLResponse")
    relay_state = form.get("RelayState", "/")

    if not saml_response_b64:
        raise HTTPException(400, "Missing SAMLResponse")

    # 1. Determine tenant from relay_state or request.state.tenant_id
    tenant_id = getattr(request.state, "tenant_id", "default")

    # 2. Load SSO provider for this tenant
    provider = get_active_provider_for_tenant(tenant_id)
    if not provider:
        raise HTTPException(400, "No active SSO provider for this tenant")

    # 3. Build SAML settings and process response
    req_data = prepare_request_data(request)
    req_data["post_data"] = {"SAMLResponse": saml_response_b64}
    if relay_state:
        req_data["post_data"]["RelayState"] = relay_state

    settings_dict = build_saml_settings(provider, req_data)

    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    auth = OneLogin_Saml2_Auth(req_data, settings_dict)
    auth.process_response()

    errors = auth.get_errors()
    if errors:
        error_reason = auth.get_last_error_reason()
        logger.warning("SAML validation failed: %s (reason: %s)", errors, error_reason)
        audit_event("sso_login_failed", "", request,
                    tenant_id=tenant_id,
                    provider_id=provider["provider_id"],
                    errors=str(errors),
                    error_reason=str(error_reason))
        return RedirectResponse(url=f"/login?error=sso_validation_failed", status_code=303)

    if not auth.is_authenticated():
        return RedirectResponse(url="/login?error=sso_not_authenticated", status_code=303)

    # 4. Check assertion replay
    assertion_id = auth.get_last_assertion_id()
    if assertion_id and _is_assertion_replayed(assertion_id):
        audit_event("sso_replay_detected", "", request,
                    tenant_id=tenant_id, assertion_id=assertion_id)
        return RedirectResponse(url="/login?error=sso_replay_detected", status_code=303)
    if assertion_id:
        _record_assertion_consumed(assertion_id, tenant_id)

    # 5. Extract attributes using tenant's attribute mappings
    attributes = auth.get_attributes()
    name_id = auth.get_nameid()
    session_index = auth.get_session_index()

    attr_map = provider.get("attribute_mappings", {})
    email = _extract_attr(attributes, attr_map.get("email"), fallback=name_id)
    display_name = _extract_attr(attributes, attr_map.get("display_name"))
    first_name = _extract_attr(attributes, attr_map.get("first_name"))
    last_name = _extract_attr(attributes, attr_map.get("last_name"))
    groups = _extract_attr_list(attributes, attr_map.get("groups"))
    phone = _extract_attr(attributes, attr_map.get("phone"))

    if not email:
        return RedirectResponse(url="/login?error=sso_no_email", status_code=303)

    email = normalize_email(email)

    # 5a. Validate email domain
    allowed_domains = provider.get("allowed_email_domains", [])
    if allowed_domains:
        email_domain = email.split("@")[1] if "@" in email else ""
        if email_domain not in allowed_domains:
            audit_event("sso_domain_rejected", email, request,
                        tenant_id=tenant_id, email_domain=email_domain)
            return RedirectResponse(url="/login?error=sso_domain_not_allowed", status_code=303)

    # Build display_name from first/last if not directly available
    if not display_name and (first_name or last_name):
        display_name = f"{first_name or ''} {last_name or ''}".strip()

    # 6. Map groups to platform role
    role = map_groups_to_role(
        groups=groups,
        role_mappings=provider.get("role_mappings", []),
        default_role=provider.get("default_role", "user"),
    )

    # 7. JIT user provisioning or update
    user_sub = email
    if provider.get("jit_provisioning_enabled", True):
        user = ensure_user_exists(
            user_sub=user_sub,
            display_name=display_name or email.split("@")[0],
            tenant_id=tenant_id,
            role=role,
            provider_id=provider["provider_id"],
            phone=phone,
        )
    else:
        # Check user exists
        from app.core.tables import T as tables
        existing = tables.users.get_item(Key={"user_sub": user_sub}).get("Item")
        if not existing:
            return RedirectResponse(url="/login?error=sso_user_not_found", status_code=303)

    # Update profile on each login if configured
    if provider.get("auto_update_profile", True):
        update_user_profile(user_sub, display_name=display_name, phone=phone)

    # Update role from groups if configured
    if provider.get("auto_update_role", False):
        _update_user_role(user_sub, role, provider["provider_id"])

    # 8. Check ban status
    if is_user_currently_banned(user_sub):
        audit_event("sso_login_banned", user_sub, request,
                    tenant_id=tenant_id, provider_id=provider["provider_id"])
        return RedirectResponse(url="/login?error=account_banned", status_code=303)

    # 9. Create session (bypass MFA -- IdP handles it)
    # NOTE: current create_real_session signature is (req: Request, user_sub: str, *, ...)
    # at line 403 of sessions.py — it takes the Request object, not a separate ip parameter.
    session = create_real_session(request, user_sub)
    <!-- CORRECTED: create_real_session(user_sub, ip=ip) is wrong; actual signature is create_real_session(req: Request, user_sub: str) at line 403 -->

    # 10. Record SSO session link
    _record_sso_session_link(
        session_id=session.session_id,
        provider_id=provider["provider_id"],
        tenant_id=tenant_id,
        session_index=session_index,
        name_id=name_id,
        attributes_raw=attributes,
    )

    # 11. Mint access token and set cookies
    # NOTE: current mint_access_token signature is (user_sub: str, session_id: str) at
    # line 168 of sessions.py — no role or tenant_id params. Must be extended for SSO/multi-tenancy.
    access_token = mint_access_token(
        user_sub=user_sub,
        session_id=session.session_id,
        # role and tenant_id require extending mint_access_token signature
    )
    <!-- CORRECTED: mint_access_token currently takes only (user_sub, session_id); role and tenant_id params do not exist yet -->

    redirect = RedirectResponse(url=relay_state or "/", status_code=303)
    _set_sso_cookies(redirect, session, access_token)

    # 12. Update login stats
    increment_login_count(tenant_id, provider["provider_id"])

    # 13. Audit log
    audit_event("sso_login", user_sub, request,
        provider_id=provider["provider_id"],
        protocol="saml",
        tenant_id=tenant_id,
        idp_entity_id=provider["idp_entity_id"],
        name_id=name_id,
        groups=groups,
        role_assigned=role,
        jit_provisioned=bool(provider.get("jit_provisioning_enabled")),
    )

    return redirect


@router.get("/saml/metadata")
async def saml_metadata(request: Request):
    """Serve SP metadata XML for the current tenant's SSO configuration."""
    tenant_id = getattr(request.state, "tenant_id", "default")
    provider = get_active_provider_for_tenant(tenant_id)
    if not provider:
        raise HTTPException(404, "No SSO provider configured for this tenant")

    settings_dict = build_saml_settings(provider, prepare_request_data(request))

    from onelogin.saml2.settings import OneLogin_Saml2_Settings
    saml_settings = OneLogin_Saml2_Settings(settings_dict, sp_validation_only=True)
    metadata = saml_settings.get_sp_metadata()
    errors = saml_settings.validate_metadata(metadata)
    if errors:
        raise HTTPException(500, f"SP metadata validation errors: {errors}")

    return Response(content=metadata, media_type="application/xml")


@router.get("/saml/slo")
async def saml_slo(request: Request):
    """Process Single Logout response from IdP."""
    tenant_id = getattr(request.state, "tenant_id", "default")
    provider = get_active_provider_for_tenant(tenant_id)
    if not provider:
        return RedirectResponse(url="/login", status_code=303)

    req_data = prepare_request_data(request)
    req_data["get_data"] = dict(request.query_params)
    settings_dict = build_saml_settings(provider, req_data)

    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    auth = OneLogin_Saml2_Auth(req_data, settings_dict)
    auth.process_slo()

    errors = auth.get_errors()
    if errors:
        logger.warning("SLO validation failed: %s", errors)

    # Revoke the session associated with this SLO
    session_id = request.cookies.get("ui_session")
    if session_id:
        _revoke_session(session_id)

    audit_event("sso_slo", "", request, tenant_id=tenant_id,
                provider_id=provider["provider_id"])

    return RedirectResponse(url="/login", status_code=303)


def _extract_attr(attributes: dict, attr_name: str | None, fallback: str = "") -> str:
    if not attr_name or attr_name not in attributes:
        return fallback
    values = attributes[attr_name]
    return values[0] if isinstance(values, list) and values else str(values)


def _extract_attr_list(attributes: dict, attr_name: str | None) -> list[str]:
    if not attr_name or attr_name not in attributes:
        return []
    values = attributes[attr_name]
    return values if isinstance(values, list) else [str(values)]


def _is_assertion_replayed(assertion_id: str) -> bool:
    resp = T.sso_assertion_cache.get_item(Key={"assertion_id": assertion_id})
    return resp.get("Item") is not None


def _record_assertion_consumed(assertion_id: str, tenant_id: str) -> None:
    max_age = S.sso_assertion_max_age_seconds + S.sso_assertion_max_clock_skew_seconds
    T.sso_assertion_cache.put_item(Item={
        "assertion_id": assertion_id,
        "consumed_at": now_ts(),
        "tenant_id": tenant_id,
        "expires_at": now_ts() + max_age,
    })


def _record_sso_session_link(
    session_id: str,
    provider_id: str,
    tenant_id: str,
    session_index: str | None,
    name_id: str,
    attributes_raw: dict,
) -> None:
    T.sso_sessions.put_item(Item={
        "session_id": session_id,
        "sk": "SSO_LINK",
        "provider_id": provider_id,
        "tenant_id": tenant_id,
        "saml_session_index": session_index or "",
        "saml_name_id": name_id,
        "authenticated_at": now_ts(),
        "attributes_raw": attributes_raw,
        "ttl": now_ts() + 86400,  # 24h TTL
    })


def _set_sso_cookies(response, session, access_token: str) -> None:
    cookie_kwargs = {
        "httponly": True,
        "secure": S.ui_cookie_secure,
        "samesite": "lax",
        "path": "/",
    }
    response.set_cookie("ui_session", session.session_id, **cookie_kwargs)
    response.set_cookie("ui_csrf", session.csrf_token, **cookie_kwargs, httponly=False)
    response.set_cookie("ui_access_token", access_token, **cookie_kwargs)


def _revoke_session(session_id: str) -> None:
    # Mark session as revoked in DDB
    try:
        T.sessions.update_item(
            Key={"session_id": session_id},
            UpdateExpression="SET #s = :s",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": "revoked"},
        )
    except Exception:
        logger.exception("Failed to revoke session %s during SLO", session_id)


def _update_user_role(user_sub: str, role: str, provider_id: str) -> None:
    from app.auth.root_invariant import enforce_root_role_invariant
    enforce_root_role_invariant(user_sub, role)
    T.users.update_item(
        Key={"user_sub": user_sub},
        UpdateExpression="SET #role = :role, sso_role_updated_at = :now",
        ExpressionAttributeNames={"#role": "role"},
        ExpressionAttributeValues={":role": role, ":now": now_ts()},
    )
```

### 3.5 SSO-Only Enforcement

When `sso_only=true` on the SSO provider, the `POST /ui/session/start` endpoint in `app/routers/ui_session.py` must check:

```python
# app/routers/ui_session.py -- add to ui_session_start
from app.services.sso_saml_provider import is_sso_only_tenant

# At the top of ui_session_start, before credential verification
if S.sso_saml_enabled and is_sso_only_tenant(getattr(request.state, "tenant_id", "default")):
    raise HTTPException(403, "Password login is disabled for this tenant. Use SSO to sign in.")
```

The `is_sso_only_tenant` function:

```python
# app/services/sso_saml_provider.py
def is_sso_only_tenant(tenant_id: str) -> bool:
    """Check if the tenant requires SSO-only login."""
    provider = get_active_provider_for_tenant(tenant_id)
    if not provider:
        return False
    return bool(provider.get("sso_only", False))
```

The login page frontend checks the branding endpoint for `sso_only: true` and hides the password form, showing only the SSO button.

### 3.6 Metadata Parsing

```python
# app/services/sso_saml_metadata.py (new)
from __future__ import annotations

import hashlib
from typing import Any, Dict, List
from xml.etree import ElementTree as ET

import defusedxml.ElementTree as SafeET

SAML_MD_NS = "urn:oasis:names:tc:SAML:2.0:metadata"
SAML_DS_NS = "http://www.w3.org/2000/09/xmldsig#"

_NAMESPACES = {
    "md": SAML_MD_NS,
    "ds": SAML_DS_NS,
}


def parse_idp_metadata(xml_bytes: bytes) -> Dict[str, Any]:
    """Parse SAML IdP metadata XML and extract:
    - idp_entity_id
    - idp_sso_url (HTTP-Redirect or HTTP-POST binding)
    - idp_slo_url (optional)
    - idp_certificates (list of X.509 certs with fingerprints)

    Uses defusedxml to prevent XXE attacks.
    """
    root = SafeET.fromstring(xml_bytes)

    # Entity ID
    entity_id = root.get("entityID")
    if not entity_id:
        raise ValueError("Missing entityID attribute in metadata")

    # Find IDPSSODescriptor
    idp_desc = root.find("md:IDPSSODescriptor", _NAMESPACES)
    if idp_desc is None:
        raise ValueError("Missing IDPSSODescriptor element")

    # SSO URL (prefer HTTP-Redirect binding)
    sso_url = None
    for sso_svc in idp_desc.findall("md:SingleSignOnService", _NAMESPACES):
        binding = sso_svc.get("Binding", "")
        location = sso_svc.get("Location", "")
        if "HTTP-Redirect" in binding:
            sso_url = location
            break
        if "HTTP-POST" in binding and not sso_url:
            sso_url = location

    if not sso_url:
        raise ValueError("No SingleSignOnService endpoint found in metadata")

    # SLO URL (optional)
    slo_url = None
    for slo_svc in idp_desc.findall("md:SingleLogoutService", _NAMESPACES):
        binding = slo_svc.get("Binding", "")
        location = slo_svc.get("Location", "")
        if "HTTP-Redirect" in binding:
            slo_url = location
            break
        if "HTTP-POST" in binding and not slo_url:
            slo_url = location

    # Certificates
    certs: List[Dict[str, str]] = []
    for key_desc in idp_desc.findall("md:KeyDescriptor", _NAMESPACES):
        use = key_desc.get("use", "signing")
        if use not in ("signing", ""):
            continue
        x509_data = key_desc.find("ds:KeyInfo/ds:X509Data/ds:X509Certificate", _NAMESPACES)
        if x509_data is not None and x509_data.text:
            cert_text = x509_data.text.strip()
            fingerprint = _compute_cert_fingerprint(cert_text)
            certs.append({
                "x509_cert": cert_text,
                "fingerprint_sha256": fingerprint,
            })

    if not certs:
        raise ValueError("No signing certificates found in metadata")

    return {
        "idp_entity_id": entity_id,
        "idp_sso_url": sso_url,
        "idp_slo_url": slo_url,
        "idp_certificates": certs,
    }


def _compute_cert_fingerprint(cert_b64: str) -> str:
    """Compute SHA-256 fingerprint of a base64-encoded X.509 certificate."""
    import base64
    cert_der = base64.b64decode(cert_b64)
    digest = hashlib.sha256(cert_der).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))
```

### 3.7 JIT Provisioning Service

```python
# app/services/sso_saml_jit.py (new)
from __future__ import annotations

from typing import Any, Dict, Optional

from app.core.tables import T
from app.core.time import now_ts


def ensure_user_exists(
    user_sub: str,
    display_name: str,
    tenant_id: str,
    role: str,
    provider_id: str,
    phone: Optional[str] = None,
) -> Dict[str, Any]:
    """Create user if not exists (JIT provisioning). If user exists, return existing record."""
    existing = T.users.get_item(Key={"user_sub": user_sub}).get("Item")

    if existing:
        # Link SSO provider if not already linked
        if not existing.get("sso_provider_id"):
            T.users.update_item(
                Key={"user_sub": user_sub},
                UpdateExpression="SET sso_provider_id = :pid, auth_method = :am",
                ExpressionAttributeValues={
                    ":pid": provider_id,
                    ":am": "both" if existing.get("password_hash") else "sso",
                },
            )
        return existing

    # Create new user
    now = now_ts()
    user_item = {
        "user_sub": user_sub,
        "email": user_sub,
        "password_hash": "",
        "auth_method": "sso",
        "sso_provider_id": provider_id,
        "sso_idp_user_id": user_sub,
        "tenant_id": tenant_id,
        "role": role,
        "status": "active",
        "jit_provisioned": True,
        "created_at": now,
        "last_login_at": now,
    }
    T.users.put_item(Item=user_item)

    # Create profile
    profile_item = {
        "user_sub": user_sub,
        "display_name": display_name,
        "email": user_sub,
        "phone": phone or "",
        "created_at": now,
    }
    T.profile.put_item(Item=profile_item)

    # Add to tenant members (ENTERPRISE-001)
    T.tenant_members.put_item(Item={
        "tenant_id": tenant_id,
        "user_sub": user_sub,
        "role": "member",
        "status": "active",
        "joined_at": now,
        "invited_by": "sso_jit",
    })

    return user_item


def update_user_profile(
    user_sub: str,
    display_name: Optional[str] = None,
    phone: Optional[str] = None,
) -> None:
    """Update user profile from SSO attributes (on each login if auto_update_profile=true)."""
    update_parts = ["updated_at = :now"]
    attr_values: Dict[str, Any] = {":now": now_ts()}

    if display_name:
        update_parts.append("display_name = :dn")
        attr_values[":dn"] = display_name
    if phone:
        update_parts.append("phone = :phone")
        attr_values[":phone"] = phone

    if len(update_parts) > 1:
        T.profile.update_item(
            Key={"user_sub": user_sub},
            UpdateExpression="SET " + ", ".join(update_parts),
            ExpressionAttributeValues=attr_values,
        )
```

---

## 4. API Endpoints

### 4.1 Provider Management (Tenant Admin or Root)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/v1/admin/sso/providers` | `require_root_session` or `require_tenant_admin` | Create SSO provider from metadata XML |
| GET | `/v1/admin/sso/providers` | `require_root_session` or `require_tenant_admin` | List SSO providers for tenant |
| GET | `/v1/admin/sso/providers/{provider_id}` | `require_root_session` or `require_tenant_admin` | Get provider details |
| PATCH | `/v1/admin/sso/providers/{provider_id}` | `require_root_session` or `require_tenant_admin` | Update provider (toggle status, sso_only, mappings) |
| DELETE | `/v1/admin/sso/providers/{provider_id}` | `require_root_session` or `require_tenant_admin` | Delete SSO provider |
| POST | `/v1/admin/sso/providers/{provider_id}/metadata` | `require_root_session` or `require_tenant_admin` | Upload/update IdP metadata XML |
| POST | `/v1/admin/sso/providers/{provider_id}/role-mappings` | `require_root_session` or `require_tenant_admin` | Configure group-to-role mappings |
| GET | `/v1/admin/sso/providers/{provider_id}/test` | `require_root_session` or `require_tenant_admin` | Generate a test AuthnRequest URL |
| GET | `/v1/admin/sso/providers/{provider_id}/stats` | `require_root_session` or `require_tenant_admin` | Login count, last login, active users |

### 4.2 SAML Flow Endpoints (Public)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/saml/login` | None | SP-initiated SSO: redirect to IdP |
| POST | `/saml/acs` | None | Assertion Consumer Service: process SAMLResponse |
| GET | `/saml/metadata` | None | SP metadata XML (for IdP configuration) |
| GET | `/saml/slo` | None | Single Logout (optional) |

### 4.3 SSO Info Endpoint (Frontend)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/sso/info` | None | Returns whether SSO is available/enforced for current tenant |

### 4.4 Request / Response Models

```python
# app/models.py -- new models

class SsoProviderCreateReq(BaseModel):
    display_name: str = Field(min_length=1, max_length=256)
    protocol: str = Field(default="saml", pattern=r"^(saml|oidc)$")
    metadata_xml: Optional[str] = None  # base64-encoded IdP metadata XML
    metadata_url: Optional[str] = None  # URL to fetch metadata (alternative)
    sso_only: bool = False
    jit_provisioning_enabled: bool = True
    auto_update_profile: bool = True
    auto_update_role: bool = False
    default_role: str = Field(default="user", pattern=r"^(user|admin)$")
    allowed_email_domains: Optional[list[str]] = None

class SsoAttributeMappingReq(BaseModel):
    email: str = Field(description="SAML attribute name for email")
    display_name: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    groups: Optional[str] = None
    phone: Optional[str] = None

class SsoRoleMappingReq(BaseModel):
    idp_group: str = Field(min_length=1, max_length=256)
    platform_role: str = Field(pattern=r"^(user|admin)$")
    admin_profile: Optional[dict] = None  # {"type": "general"} or {"type": "scoped", "scopes": [...]}

class SsoProviderOut(BaseModel):
    provider_id: str
    tenant_id: str
    protocol: str
    display_name: str
    status: str
    sso_only: bool
    idp_entity_id: Optional[str]
    idp_sso_url: Optional[str]
    sp_entity_id: str
    sp_acs_url: str
    attribute_mappings: dict
    role_mappings: list[dict]
    jit_provisioning_enabled: bool
    auto_update_profile: bool
    auto_update_role: bool
    default_role: str
    allowed_email_domains: Optional[list[str]]
    login_count: int
    last_login_at: Optional[int]
    created_at: int
    updated_at: int

class SsoInfoOut(BaseModel):
    sso_available: bool
    sso_only: bool
    sso_login_url: Optional[str]
    provider_display_name: Optional[str]
    provider_protocol: Optional[str]

class SsoProviderStatsOut(BaseModel):
    provider_id: str
    login_count: int
    last_login_at: Optional[int]
    active_sso_users: int
    jit_provisioned_users: int
```

---

## 5. Frontend Components

### 5.1 Login Page SSO Button

**File**: `frontend/src/pages/Login.tsx` (modified)

- On mount, call `GET /ui/sso/info` to check if SSO is available for this tenant
- If `sso_available=true`, render "Sign in with SSO" button that navigates to `/saml/login`
- If `sso_only=true`, hide the password form entirely and show only the SSO button
- SSO button uses tenant branding colors

```tsx
// Login.tsx integration
const { data: ssoInfo } = useQuery({
  queryKey: ["sso-info"],
  queryFn: () => client.get<SsoInfoOut>("/ui/sso/info").then(r => r.data),
  staleTime: 60_000,
});

// In the JSX:
{ssoInfo?.sso_available && (
  <div className="mt-4">
    <div className="relative">
      <div className="absolute inset-0 flex items-center">
        <span className="w-full border-t" />
      </div>
      {!ssoInfo.sso_only && (
        <div className="relative flex justify-center text-xs uppercase">
          <span className="bg-background px-2 text-muted-foreground">Or</span>
        </div>
      )}
    </div>
    <Button
      variant="outline"
      className="w-full mt-4"
      onClick={() => window.location.href = ssoInfo.sso_login_url || "/saml/login"}
    >
      <Shield className="mr-2 h-4 w-4" />
      Sign in with {ssoInfo.provider_display_name || "SSO"}
    </Button>
  </div>
)}
{ssoInfo?.sso_only && (
  <p className="text-sm text-muted-foreground text-center mt-2">
    Your organization requires SSO login. Contact your IT admin for access.
  </p>
)}
```

### 5.2 SSO Provider Admin Page

**File**: `frontend/src/pages/admin/SsoProviders.tsx` (new)

- Table of configured SSO providers with status badge (active/inactive/testing)
- "Add Provider" dialog with metadata XML upload (drag-and-drop) or URL input
- Provider detail view with tabs: Configuration, Attribute Mappings, Role Mappings, Test, Stats
- "Test SSO" button opens IdP login in a popup and reports success/failure
- Download SP metadata button

### 5.3 Attribute Mapping Editor

**File**: `frontend/src/pages/admin/SsoAttributeMapping.tsx` (new)

- Table with Platform Field (email, display_name, groups) and SAML Attribute (editable text input)
- Pre-filled with common attribute URIs for Azure AD, Okta, Google Workspace:

```typescript
const COMMON_ATTRIBUTE_PRESETS = {
  "Azure AD": {
    email: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    display_name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
    first_name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
    last_name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
    groups: "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
  },
  "Okta": {
    email: "email",
    display_name: "displayName",
    first_name: "firstName",
    last_name: "lastName",
    groups: "groups",
  },
  "Google Workspace": {
    email: "email",
    display_name: "name",
    first_name: "given_name",
    last_name: "family_name",
    groups: "groups",
  },
};
```

- "Load from metadata" button parses uploaded metadata for attribute suggestions

### 5.4 SSO Callback Handler

**File**: `frontend/src/pages/SsoCallback.tsx` (new)

- Handles the redirect from `POST /saml/acs` (the ACS sets cookies and redirects to `/`)
- If the redirect includes an error parameter, display error message
- On success, extract user info from cookies and update `authStore`

---

## 6. DynamoDB Table Definitions

### 6.1 New Tables for `scripts/local-ddb-init.py`

```python
TableDef("sso_providers", pk="tenant_id", sk="sk",
    gsis=[
        GSIDef("provider-id-index", pk="provider_id", sk="tenant_id"),
    ]),
TableDef("sso_sessions", pk="session_id", sk="sk"),
TableDef("sso_assertion_cache", pk="assertion_id"),
TableDef("sso_audit", pk="tenant_id", sk="event_id",
    gsis=[
        GSIDef("user-events-index", pk="user_sub", sk="event_id"),
    ],
    attr_types={"event_id": "S"}),
```

### 6.2 Settings Additions for `app/core/settings.py`

```python
# SSO / SAML (ENTERPRISE-002)
sso_saml_enabled: bool = os.environ.get("SSO_SAML_ENABLED", "0") not in ("0", "false", "False")
sso_providers_table_name: str = os.environ.get("SSO_PROVIDERS_TABLE_NAME", "sso_providers")
sso_sessions_table_name: str = os.environ.get("SSO_SESSIONS_TABLE_NAME", "sso_sessions")
sso_assertion_cache_table_name: str = os.environ.get("SSO_ASSERTION_CACHE_TABLE_NAME", "sso_assertion_cache")
sso_sp_private_key_secret_name: str = os.environ.get("SSO_SP_PRIVATE_KEY_SECRET_NAME", "sso-sp-private-key")
sso_sp_certificate_secret_name: str = os.environ.get("SSO_SP_CERTIFICATE_SECRET_NAME", "sso-sp-certificate")
sso_assertion_max_age_seconds: int = int(os.environ.get("SSO_ASSERTION_MAX_AGE_SECONDS", "300"))
sso_assertion_max_clock_skew_seconds: int = int(os.environ.get("SSO_ASSERTION_MAX_CLOCK_SKEW_SECONDS", "180"))
sso_jit_default_plan: str = os.environ.get("SSO_JIT_DEFAULT_PLAN", "user")
sso_metadata_max_size_bytes: int = int(os.environ.get("SSO_METADATA_MAX_SIZE_BYTES", "1048576"))
sso_session_link_ttl_seconds: int = int(os.environ.get("SSO_SESSION_LINK_TTL_SECONDS", "86400"))
```

---

## 7. E2E Test Plan

### 7.1 Test File

**File**: `frontend/e2e/sso-saml.spec.ts` (new)

### 7.2 Test Sections

| Section | Tests | Description |
|---------|-------|-------------|
| 86 | 5 | SSO provider CRUD API (create with metadata, list, get, update status, delete) |
| 87 | 4 | Attribute and role mapping API (set email mapping, set group mapping, invalid mapping, update) |
| 88 | 3 | SSO info endpoint (no SSO configured, SSO available, SSO only) |
| 89 | 4 | SAML flow (AuthnRequest generation, ACS mock validation, JIT provisioning, session creation) |
| 90 | 3 | SSO-only enforcement (password login blocked, SSO login works, toggle off re-enables password) |
| 91 | 3 | SSO login UI (SSO button visible, password form hidden when sso_only, error display) |

### 7.3 Mock IdP Strategy

Tests use a mock SAML IdP that:
1. Generates a pre-signed SAMLResponse with test assertions
2. Posts directly to `/saml/acs` without a real IdP redirect
3. The signed response uses a test X.509 certificate registered as the IdP certificate in the provider record

```typescript
import * as crypto from "crypto";

// Generate a self-signed test certificate pair
function generateTestCertificateAndKey(): { cert: string; key: string } {
    // Use a pre-generated test cert for deterministic tests
    return {
        cert: TEST_IDP_CERT_B64,  // pre-baked in test constants
        key: TEST_IDP_KEY_PEM,
    };
}

// Generate a valid SAMLResponse for testing
function generateTestSamlResponse(params: {
    email: string;
    displayName: string;
    groups: string[];
    recipientAcsUrl: string;
    issuer: string;
    certPem: string;
    keyPem: string;
}): string {
    // Build XML assertion with attributes
    // Sign with the test private key
    // Base64-encode
    // Return as SAMLResponse field
    return base64EncodedSamlResponse;
}

test.beforeAll(async ({ request }) => {
    // Create SSO provider with test certificate
    const testCert = generateTestCertificateAndKey();
    const metadata = generateTestIdpMetadata(testCert.cert, "https://test-idp.local/sso");

    await request.post("/v1/admin/sso/providers", {
        headers: { Authorization: `Bearer ${rootToken}` },
        data: {
            display_name: "Test IdP",
            protocol: "saml",
            metadata_xml: btoa(metadata),
            jit_provisioning_enabled: true,
        },
    });
});
```

### 7.4 ACS Flow Test

```typescript
test("ACS processes valid SAMLResponse and creates session", async ({ request }) => {
    const samlResponse = generateTestSamlResponse({
        email: "sso-test-user@test.local",
        displayName: "SSO Test User",
        groups: ["Platform-Users"],
        recipientAcsUrl: "http://localhost:3000/saml/acs",
        issuer: "https://test-idp.local",
        certPem: TEST_IDP_CERT_PEM,
        keyPem: TEST_IDP_KEY_PEM,
    });

    const resp = await request.post("/saml/acs", {
        form: {
            SAMLResponse: samlResponse,
            RelayState: "/",
        },
    });

    // ACS returns 303 redirect to RelayState
    expect(resp.status()).toBe(303);

    // Verify session cookies were set
    const cookies = resp.headers()["set-cookie"];
    expect(cookies).toContain("ui_session");
    expect(cookies).toContain("ui_access_token");

    // Verify user was JIT-provisioned
    const userResp = await request.get("/ui/profile", {
        headers: { Cookie: extractCookies(cookies) },
    });
    expect(userResp.status()).toBe(200);
    const profile = await userResp.json();
    expect(profile.email).toBe("sso-test-user@test.local");
});
```

---

## 8. Edge Cases & Error Handling

### 8.1 Expired SAML Assertions

SAML assertions include `NotBefore` and `NotOnOrAfter` timestamps. The ACS endpoint rejects assertions outside this window (with a configurable clock skew tolerance of `sso_assertion_max_clock_skew_seconds`, default 180 seconds).

### 8.2 Replay Attacks

Each SAML assertion has a unique `ID`. The ACS stores consumed assertion IDs in the `sso_assertion_cache` table (with DDB TTL = assertion max age + clock skew). Replayed assertions are rejected with a redirect to `/login?error=sso_replay_detected`.

### 8.3 Signature Validation Failures

If the IdP's signing certificate does not match any certificate in the provider's `idp_certificates` list, the ACS redirects to `/login?error=sso_validation_failed`. The admin receives an alert suggesting the IdP may have rotated its key. The UI shows guidance on re-uploading metadata.

### 8.4 JIT Provisioning Conflicts

If a user already exists with the same email but was created via password registration (not SSO), JIT provisioning links the SSO identity to the existing account rather than creating a duplicate. The user retains both login methods unless `sso_only` is enforced. The `auth_method` field is updated to `"both"`.

### 8.5 Group Mapping Ambiguity

If a user belongs to multiple IdP groups that map to different roles, the highest-privilege role wins (`ADMIN` > `USER`). `ROOT` is never assignable via SSO mapping.

```python
def map_groups_to_role(groups: list[str], role_mappings: list[dict], default_role: str) -> str:
    """Map IdP groups to the highest applicable platform role."""
    ROLE_PRIORITY = {"root": 3, "admin": 2, "user": 1}
    best_role = default_role
    best_priority = ROLE_PRIORITY.get(default_role, 0)

    for mapping in role_mappings:
        if mapping["idp_group"] in groups:
            role = mapping["platform_role"]
            # Never assign root via SSO
            if role == "root":
                continue
            priority = ROLE_PRIORITY.get(role, 0)
            if priority > best_priority:
                best_role = role
                best_priority = priority

    return best_role
```

### 8.6 IdP-Initiated SSO Without Tenant Context

When the IdP sends an unsolicited SAMLResponse, there is no `RelayState` to determine the tenant. The ACS uses the IdP entity ID from the assertion to look up the provider record (via the `provider-id-index` GSI), which contains the `tenant_id`.

### 8.7 SP Metadata Generation

The `/saml/metadata` endpoint generates the SP metadata XML dynamically based on the current tenant's configuration. This includes the SP entity ID, ACS URL, and the SP's X.509 certificate for request signing. The IdP administrator imports this metadata to configure the integration from their side.

### 8.8 Metadata URL Auto-Refresh

When a provider is configured with `metadata_url` (instead of uploaded XML), a background job can periodically fetch the metadata to detect certificate rotations. This is opt-in and runs weekly via the unified scheduler.

---

## 9. Security Considerations

### 9.1 XML Signature Validation

SAML responses use XML Digital Signatures (XMLDSig). The `python3-saml` library validates the signature against the IdP's X.509 certificate. The system rejects:
- Unsigned responses (unless explicitly configured for testing)
- Responses signed with an unknown certificate
- Wrapping attacks (XSW) via strict schema validation
- XML external entity (XXE) attacks via `defusedxml` parser

### 9.2 SP Signing Key Storage

The SP's private key (used to sign AuthnRequests and decrypt encrypted assertions) is stored in AWS Secrets Manager or the mock KMS (`scripts/mock_kms_server.py`). It is never exposed via API or stored in DynamoDB. The environment variable `SSO_SP_PRIVATE_KEY_SECRET_NAME` references the secret.

### 9.3 SSO Session Binding

The SSO session link (`sso_sessions` table) associates the platform session with the SAML `SessionIndex`. This enables Single Logout (SLO): when the IdP sends a LogoutRequest, the platform can identify and revoke the corresponding session.

### 9.4 Audit Trail

All SSO events are logged:
- `sso_login` -- successful SSO authentication
- `sso_login_failed` -- assertion validation failure
- `sso_login_initiated` -- SP-initiated AuthnRequest sent
- `sso_jit_provision` -- new user created via JIT
- `sso_replay_detected` -- assertion replay attempt blocked
- `sso_domain_rejected` -- email domain not in allowed list
- `sso_login_banned` -- SSO login attempt by banned user
- `sso_provider_created` / `sso_provider_updated` / `sso_provider_deleted`
- `sso_slo` -- Single Logout processed

These are recorded via `audit_event()` from `app/services/alerts.py` (line 570).

### 9.5 Certificate Rotation

The provider record supports multiple certificates in `idp_certificates`. During key rotation, the IdP publishes a new certificate alongside the old one. The SP accepts assertions signed with either certificate. After the old certificate expires, the admin removes it from the provider record.

### 9.6 Root Role Protection

The `enforce_root_role_invariant()` function in `app/auth/root_invariant.py` prevents non-root users from gaining root access. SSO role mappings cannot map any group to `ROOT`. If attempted, the mapping is rejected with 400.

### 9.7 Email Domain Restriction

The `allowed_email_domains` field on the provider restricts JIT provisioning to specific email domains. This prevents attackers who gain access to the IdP from creating accounts with arbitrary email addresses.

---

## 10. Local Development

### 10.1 Mock SAML IdP

A mock SAML IdP is included for local development:

```bash
# Start mock IdP alongside Keycloak
python3 scripts/mock_saml_idp.py --port 8082
```

The mock IdP:
- Serves a login form at `http://localhost:8082/login`
- Generates valid SAMLResponses signed with a self-signed certificate
- The certificate is pre-registered in the dev tenant's SSO provider
- Supports configurable user attributes (email, groups)

### 10.2 Dev Mode Bypass

When `S.dev_mode` is `True` and `SSO_SAML_ENABLED` is set, a dev shortcut allows testing the ACS without a real IdP:

```
POST /saml/acs?dev_bypass=1
X-User-Sub: test-sso-user@example.com
```

This creates a session as if a valid SAML assertion was received. Only available in dev mode.

### 10.3 Local Keycloak Integration

The existing Keycloak setup can be extended to test SAML (not just OIDC):

```bash
# Configure Keycloak as a SAML IdP
python3 scripts/local-keycloak-saml-config.py
# This creates a SAML client in Keycloak and registers the SP metadata
```

---

## 11. Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| `python3-saml` | `>=1.16.0` | SAML SP implementation |
| `defusedxml` | `>=0.7.1` | XXE-safe XML parsing |
| `xmlsec` | `>=1.3.13` | XML signature validation (C extension) |
| `cryptography` | `>=41.0.0` | X.509 certificate handling (already in requirements) |

---

## 12. Migration Plan

### 12.1 Phase 1: Infrastructure (Week 1)

1. Add `python3-saml`, `defusedxml`, `xmlsec` to requirements
2. Create `sso_providers`, `sso_sessions`, `sso_assertion_cache` tables
3. Implement metadata parsing service
4. Generate SP certificate and private key for dev environment

### 12.2 Phase 2: Core SAML (Week 2)

1. Implement SAML SP settings builder
2. Implement ACS endpoint with assertion validation
3. Implement JIT provisioning service
4. Implement role mapping logic
5. Add SSO session link recording

### 12.3 Phase 3: Provider Management (Week 3)

1. Provider CRUD endpoints
2. Attribute mapping and role mapping APIs
3. SSO info endpoint
4. SP metadata generation endpoint
5. SSO-only enforcement in login flow

### 12.4 Phase 4: Frontend & E2E (Week 4)

1. Login page SSO button
2. SSO provider admin page
3. Attribute mapping editor
4. Mock SAML IdP for testing
5. E2E test suite

---

## Codebase References

| Ref | File | Line(s) | Status |
|-----|------|---------|--------|
| `get_authenticated_user` | `app/auth/deps.py` | 184 | VERIFIED |
| `create_real_session` | `app/services/sessions.py` | 403 | VERIFIED |
| `mint_access_token` | `app/services/sessions.py` | 168 | VERIFIED |
| `set_session_cookies` | `app/services/sessions.py` | 78 | VERIFIED |
| `require_ui_session` | `app/services/sessions.py` | 283 | VERIFIED |
| `_adaptive_login_policy` | `app/routers/ui_session.py` | 38 | VERIFIED |
| Session start endpoint | `app/routers/ui_session.py` | 63 | VERIFIED |
| Cognito settings | `app/core/settings.py` | 20-24 | VERIFIED |
| `_cognito_enabled` | `app/auth/deps.py` | 25 | VERIFIED |
| `Role` enum | `app/auth/roles.py` | 8 | VERIFIED |
| `enforce_root_role_invariant` | `app/auth/root_invariant.py` | 22 | VERIFIED |
| SSO SAML router | `app/routers/sso_saml.py` | exists, registered at `app/main.py:173` | VERIFIED |
| SAML metadata service | `app/services/sso_saml_metadata.py` | exists | VERIFIED |
| SAML provider service | `app/services/sso_saml_provider.py` | exists | VERIFIED |
| SAML roles service | `app/services/sso_saml_roles.py` | exists | VERIFIED |
| SAML SP service | `app/services/sso_saml_sp.py` | exists | VERIFIED |
| SAML JIT provisioning | `app/services/sso_saml_jit.py` | exists | VERIFIED |
