"""SSO / SAML router (ENTERPRISE-002).

Provides:
- SAML flow endpoints (login, ACS, metadata, SLO)
- SSO info endpoint for frontend
- Provider management (admin CRUD)
"""
from __future__ import annotations

import base64
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse

from app.auth.deps import require_root_session
from app.core.normalize import normalize_email
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.alerts import audit_event
from app.services.moderation_policy_engine import is_user_currently_banned
from app.services.sessions import SessionInfo, create_real_session, set_session_cookies
from app.services.sso_saml_jit import ensure_user_exists, update_user_profile
from app.services.sso_saml_metadata import parse_idp_metadata
from app.services.sso_saml_provider import (
    create_provider,
    delete_provider,
    get_active_provider_for_tenant,
    get_provider,
    increment_login_count,
    is_sso_only_tenant,
    list_providers,
    update_provider,
)
from app.services.sso_saml_roles import map_groups_to_role
from app.services.sso_saml_sp import (
    MockSamlAuth,  # retained for the admin-only test_provider endpoint
    build_saml_settings,
    get_saml_auth,  # GAP-0174: picks real OneLogin_Saml2_Auth in prod, mock in dev
    prepare_request_data,
)

logger = logging.getLogger(__name__)

# Maximum accepted RelayState length; longer values are treated as hostile/oversized.
_MAX_RELAY_STATE_LEN = 2048


def _safe_relay_state(value: str | None) -> str:
    """Return ``value`` only if it is a safe same-origin redirect target (CWE-601).

    Permits:
      - Empty / ``None`` -> ``"/"``
      - Relative paths starting with a single ``"/"`` (but not ``"//"``)
      - Absolute http(s) URLs whose host matches ``S.public_base_url``

    Rejects (falls back to ``"/"``):
      - Protocol-relative URLs (``"//evil.example/..."``)
      - Absolute URLs on a foreign host
      - Non-http(s) schemes (``javascript:``, ``data:``, ``file:``, etc.)
      - Oversized input or input containing non-printable / control characters
      - Anything that raises during parsing
    """
    if not value:
        return "/"
    try:
        rs = str(value).strip()
    except Exception:
        return "/"
    if not rs:
        return "/"
    # Oversized or non-printable (control chars, newlines used for header injection).
    if len(rs) > _MAX_RELAY_STATE_LEN or not rs.isprintable():
        return "/"
    # Protocol-relative URL ("//host/...") -> always external.
    if rs.startswith("//"):
        return "/"
    # Safe relative path.
    if rs.startswith("/"):
        return rs
    # Absolute URL: only same-origin http(s) targets are allowed.
    try:
        parsed = urlparse(rs)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return "/"
        allowed = urlparse(S.public_base_url)
        if parsed.netloc != allowed.netloc:
            return "/"
    except Exception:
        return "/"
    return rs

router = APIRouter(tags=["sso-saml"])


# ── SAML Flow Endpoints (Public) ──────────────────────────────────


@router.get("/saml/login")
async def saml_login(request: Request, tenant: str = "default"):
    """SP-initiated SSO: build AuthnRequest and redirect to IdP."""
    if not S.sso_saml_enabled:
        raise HTTPException(404, "SSO is not enabled")

    tenant_id = tenant
    provider = get_active_provider_for_tenant(tenant_id)
    if not provider:
        raise HTTPException(400, "No active SSO provider for this tenant")

    settings_dict = build_saml_settings(provider, prepare_request_data(request))
    auth = get_saml_auth(prepare_request_data(request), settings_dict)
    redirect_url = auth.login(return_to="/")

    audit_event(
        "sso_login_initiated", "", request,
        tenant_id=tenant_id,
        provider_id=provider["provider_id"],
        idp_sso_url=provider.get("idp_sso_url", ""),
    )

    return RedirectResponse(url=redirect_url, status_code=302)


@router.post("/saml/acs")
async def saml_acs(request: Request):
    """Assertion Consumer Service: process SAMLResponse from IdP."""
    form = await request.form()
    saml_response_b64 = form.get("SAMLResponse")
    relay_state = form.get("RelayState", "/")
    tenant_id = str(form.get("tenant_id", "default"))

    if not saml_response_b64:
        raise HTTPException(400, "Missing SAMLResponse")

    if not S.sso_saml_enabled:
        raise HTTPException(404, "SSO is not enabled")

    # Dev bypass mode
    if S.dev_mode and request.query_params.get("dev_bypass") == "1":
        user_sub = request.headers.get("x-user-sub", "")
        if not user_sub:
            raise HTTPException(400, "X-User-Sub header required for dev bypass")
        return await _dev_bypass_acs(request, user_sub, tenant_id, relay_state)

    # Load SSO provider for this tenant
    provider = get_active_provider_for_tenant(tenant_id)
    if not provider:
        raise HTTPException(400, "No active SSO provider for this tenant")

    # Build SAML settings and process response
    req_data = prepare_request_data(request)
    req_data["post_data"] = {"SAMLResponse": saml_response_b64}
    if relay_state:
        req_data["post_data"]["RelayState"] = relay_state

    settings_dict = build_saml_settings(provider, req_data)
    auth = get_saml_auth(req_data, settings_dict)
    auth.process_response()

    errors = auth.get_errors()
    if errors:
        error_reason = auth.get_last_error_reason()
        logger.warning("SAML validation failed: %s (reason: %s)", errors, error_reason)
        audit_event(
            "sso_login_failed", "", request,
            tenant_id=tenant_id,
            provider_id=provider["provider_id"],
            errors=str(errors),
            error_reason=str(error_reason),
        )
        return RedirectResponse(url="/login?error=sso_validation_failed", status_code=303)

    if not auth.is_authenticated():
        return RedirectResponse(url="/login?error=sso_not_authenticated", status_code=303)

    # Check assertion replay
    assertion_id = auth.get_last_assertion_id()
    if assertion_id and _is_assertion_replayed(assertion_id):
        audit_event("sso_replay_detected", "", request,
                    tenant_id=tenant_id, assertion_id=assertion_id)
        return RedirectResponse(url="/login?error=sso_replay_detected", status_code=303)
    if assertion_id:
        _record_assertion_consumed(assertion_id, tenant_id)

    # Extract attributes using tenant's attribute mappings
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

    # Validate email domain
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

    # Map groups to platform role
    role = map_groups_to_role(
        groups=groups,
        role_mappings=provider.get("role_mappings", []),
        default_role=provider.get("default_role", "user"),
    )

    # JIT user provisioning or update
    user_sub = email
    if provider.get("jit_provisioning_enabled", True):
        ensure_user_exists(
            user_sub=user_sub,
            display_name=display_name or email.split("@")[0],
            tenant_id=tenant_id,
            role=role,
            provider_id=provider["provider_id"],
            phone=phone,
        )
    else:
        existing = T.users.get_item(Key={"user_sub": user_sub}).get("Item")
        if not existing:
            return RedirectResponse(url="/login?error=sso_user_not_found", status_code=303)

    # Update profile on each login if configured
    if provider.get("auto_update_profile", True):
        update_user_profile(user_sub, display_name=display_name, phone=phone)

    # Check ban status
    if is_user_currently_banned(user_sub):
        audit_event("sso_login_banned", user_sub, request,
                    tenant_id=tenant_id, provider_id=provider["provider_id"])
        return RedirectResponse(url="/login?error=account_banned", status_code=303)

    # Create session (bypass MFA -- IdP handles it)
    session = create_real_session(request, user_sub)

    # Record SSO session link
    _record_sso_session_link(
        session_id=session.session_id,
        provider_id=provider["provider_id"],
        tenant_id=tenant_id,
        session_index=session_index,
        name_id=name_id,
        attributes_raw=attributes,
    )

    # Set session cookies on the redirect response
    redirect = RedirectResponse(url=_safe_relay_state(relay_state), status_code=303)
    set_session_cookies(redirect, session)

    # Update login stats
    increment_login_count(tenant_id, provider["provider_id"])

    # Audit log
    audit_event(
        "sso_login", user_sub, request,
        provider_id=provider["provider_id"],
        protocol="saml",
        tenant_id=tenant_id,
        idp_entity_id=provider.get("idp_entity_id", ""),
        name_id=name_id,
        groups=groups,
        role_assigned=role,
        jit_provisioned=bool(provider.get("jit_provisioning_enabled")),
    )

    return redirect


@router.get("/saml/metadata")
async def saml_metadata(request: Request, tenant: str = "default"):
    """Serve SP metadata XML for the current tenant's SSO configuration."""
    if not S.sso_saml_enabled:
        raise HTTPException(404, "SSO is not enabled")

    tenant_id = tenant
    provider = get_active_provider_for_tenant(tenant_id)
    if not provider:
        raise HTTPException(404, "No SSO provider configured for this tenant")

    sp_entity_id = provider.get("sp_entity_id", "")
    sp_acs_url = provider.get("sp_acs_url", "")

    metadata_xml = f"""<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="{sp_entity_id}">
  <md:SPSSODescriptor AuthnRequestsSigned="false"
                       WantAssertionsSigned="true"
                       protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                 Location="{sp_acs_url}"
                                 index="0"
                                 isDefault="true"/>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
  </md:SPSSODescriptor>
</md:EntityDescriptor>"""
    return Response(content=metadata_xml, media_type="application/xml")


@router.get("/saml/slo")
async def saml_slo(request: Request):
    """Process Single Logout response from IdP."""
    session_id = request.cookies.get("ui_session")
    if session_id:
        _revoke_session(session_id)

    audit_event("sso_slo", "", request)
    return RedirectResponse(url="/login", status_code=303)


# ── SSO Info Endpoint (Frontend) ──────────────────────────────────


@router.get("/ui/sso/info")
async def sso_info(request: Request, tenant: str = "default"):
    """Returns whether SSO is available/enforced for current tenant."""
    if not S.sso_saml_enabled:
        return {
            "sso_available": False,
            "sso_only": False,
            "sso_login_url": None,
            "provider_display_name": None,
            "provider_protocol": None,
        }

    tenant_id = tenant
    provider = get_active_provider_for_tenant(tenant_id)
    if not provider:
        return {
            "sso_available": False,
            "sso_only": False,
            "sso_login_url": None,
            "provider_display_name": None,
            "provider_protocol": None,
        }

    return {
        "sso_available": True,
        "sso_only": bool(provider.get("sso_only", False)),
        "sso_login_url": f"/saml/login?tenant={tenant_id}",
        "provider_display_name": provider.get("display_name", "SSO"),
        "provider_protocol": provider.get("protocol", "saml"),
    }


# ── Provider Management (Admin) ──────────────────────────────────


@router.post("/v1/admin/sso/providers")
async def create_sso_provider(
    request: Request,
    ctx: dict = Depends(require_root_session),
):
    """Create SSO provider from metadata XML."""
    body = await request.json()
    display_name = body.get("display_name", "")
    if not display_name:
        raise HTTPException(400, "display_name is required")

    protocol = body.get("protocol", "saml")
    tenant_id = body.get("tenant_id", "default")

    # Parse metadata if provided
    idp_entity_id = ""
    idp_sso_url = ""
    idp_slo_url = ""
    idp_certificates: List[Dict[str, str]] = []

    metadata_xml_b64 = body.get("metadata_xml")
    if metadata_xml_b64:
        try:
            xml_bytes = base64.b64decode(metadata_xml_b64)
            parsed = parse_idp_metadata(xml_bytes)
            idp_entity_id = parsed["idp_entity_id"]
            idp_sso_url = parsed["idp_sso_url"]
            idp_slo_url = parsed.get("idp_slo_url", "")
            idp_certificates = parsed["idp_certificates"]
        except Exception as exc:
            raise HTTPException(400, f"Failed to parse metadata XML: {exc}")

    provider = create_provider(
        tenant_id=tenant_id,
        display_name=display_name,
        protocol=protocol,
        sso_only=body.get("sso_only", False),
        jit_provisioning_enabled=body.get("jit_provisioning_enabled", True),
        auto_update_profile=body.get("auto_update_profile", True),
        auto_update_role=body.get("auto_update_role", False),
        default_role=body.get("default_role", "user"),
        allowed_email_domains=body.get("allowed_email_domains"),
        created_by=ctx.sub,
        idp_entity_id=idp_entity_id,
        idp_sso_url=idp_sso_url,
        idp_slo_url=idp_slo_url,
        idp_certificates=idp_certificates,
    )

    audit_event(
        "sso_provider_created", ctx.sub, request,
        provider_id=provider["provider_id"],
        tenant_id=tenant_id,
    )

    return provider


@router.get("/v1/admin/sso/providers")
async def list_sso_providers(
    request: Request,
    tenant_id: str = "default",
    ctx: dict = Depends(require_root_session),
):
    """List SSO providers for tenant."""
    providers = list_providers(tenant_id)
    return {"providers": providers}


@router.get("/v1/admin/sso/providers/{provider_id}")
async def get_sso_provider(
    provider_id: str,
    tenant_id: str = "default",
    ctx: dict = Depends(require_root_session),
):
    """Get provider details."""
    provider = get_provider(tenant_id, provider_id)
    if not provider:
        raise HTTPException(404, "SSO provider not found")
    return provider


@router.patch("/v1/admin/sso/providers/{provider_id}")
async def update_sso_provider(
    provider_id: str,
    request: Request,
    ctx: dict = Depends(require_root_session),
):
    """Update provider settings."""
    body = await request.json()
    tenant_id = body.pop("tenant_id", "default")
    provider = update_provider(tenant_id, provider_id, body)
    if not provider:
        raise HTTPException(404, "SSO provider not found")

    audit_event(
        "sso_provider_updated", ctx.sub, request,
        provider_id=provider_id,
        tenant_id=tenant_id,
    )

    return provider


@router.delete("/v1/admin/sso/providers/{provider_id}")
async def delete_sso_provider(
    provider_id: str,
    request: Request,
    tenant_id: str = "default",
    ctx: dict = Depends(require_root_session),
):
    """Delete SSO provider."""
    delete_provider(tenant_id, provider_id)

    audit_event(
        "sso_provider_deleted", ctx.sub, request,
        provider_id=provider_id,
        tenant_id=tenant_id,
    )

    return {"ok": True}


@router.post("/v1/admin/sso/providers/{provider_id}/metadata")
async def upload_metadata(
    provider_id: str,
    request: Request,
    ctx: dict = Depends(require_root_session),
):
    """Upload/update IdP metadata XML."""
    body = await request.json()
    tenant_id = body.get("tenant_id", "default")
    metadata_xml_b64 = body.get("metadata_xml")
    if not metadata_xml_b64:
        raise HTTPException(400, "metadata_xml is required")

    try:
        xml_bytes = base64.b64decode(metadata_xml_b64)
        parsed = parse_idp_metadata(xml_bytes)
    except Exception as exc:
        raise HTTPException(400, f"Failed to parse metadata XML: {exc}")

    updates = {
        "idp_entity_id": parsed["idp_entity_id"],
        "idp_sso_url": parsed["idp_sso_url"],
        "idp_slo_url": parsed.get("idp_slo_url", ""),
        "idp_certificates": parsed["idp_certificates"],
    }

    provider = update_provider(tenant_id, provider_id, updates)
    return provider or {"ok": True}


@router.post("/v1/admin/sso/providers/{provider_id}/role-mappings")
async def set_role_mappings(
    provider_id: str,
    request: Request,
    ctx: dict = Depends(require_root_session),
):
    """Configure group-to-role mappings."""
    body = await request.json()
    tenant_id = body.get("tenant_id", "default")
    role_mappings = body.get("role_mappings", [])

    # Validate no root mappings
    for mapping in role_mappings:
        if mapping.get("platform_role") == "root":
            raise HTTPException(400, "Cannot map a group to the root role via SSO")

    provider = update_provider(tenant_id, provider_id, {"role_mappings": role_mappings})
    return provider or {"ok": True}


@router.post("/v1/admin/sso/providers/{provider_id}/attribute-mappings")
async def set_attribute_mappings(
    provider_id: str,
    request: Request,
    ctx: dict = Depends(require_root_session),
):
    """Configure SAML attribute mappings."""
    body = await request.json()
    tenant_id = body.get("tenant_id", "default")
    attribute_mappings = body.get("attribute_mappings", {})

    provider = update_provider(tenant_id, provider_id, {"attribute_mappings": attribute_mappings})
    return provider or {"ok": True}


@router.get("/v1/admin/sso/providers/{provider_id}/stats")
async def get_provider_stats(
    provider_id: str,
    tenant_id: str = "default",
    ctx: dict = Depends(require_root_session),
):
    """Get SSO provider login stats."""
    provider = get_provider(tenant_id, provider_id)
    if not provider:
        raise HTTPException(404, "SSO provider not found")

    return {
        "provider_id": provider_id,
        "login_count": int(provider.get("login_count", 0)),
        "last_login_at": provider.get("last_login_at"),
        "status": provider.get("status", "unknown"),
    }


@router.get("/v1/admin/sso/providers/{provider_id}/test")
async def test_provider(
    provider_id: str,
    request: Request,
    tenant_id: str = "default",
    ctx: dict = Depends(require_root_session),
):
    """Generate a test AuthnRequest URL."""
    provider = get_provider(tenant_id, provider_id)
    if not provider:
        raise HTTPException(404, "SSO provider not found")

    settings_dict = build_saml_settings(provider, prepare_request_data(request))
    # Admin-only (require_root_session) connection-test endpoint that only builds a
    # redirect URL and never issues a real session; MockSamlAuth is intentional here
    # and is not part of the authentication path fixed in GAP-0174.
    auth = MockSamlAuth(prepare_request_data(request), settings_dict)
    redirect_url = auth.login(return_to="/")

    return {
        "test_url": redirect_url,
        "idp_sso_url": provider.get("idp_sso_url", ""),
        "sp_entity_id": provider.get("sp_entity_id", ""),
    }


# ── Private helpers ──────────────────────────────────────────────


async def _dev_bypass_acs(
    request: Request,
    user_sub: str,
    tenant_id: str,
    relay_state: str,
) -> RedirectResponse:
    """Dev-mode ACS bypass -- creates a session without SAML validation."""
    provider = get_active_provider_for_tenant(tenant_id)
    provider_id = provider["provider_id"] if provider else "dev_provider"

    # JIT provision if needed
    if provider and provider.get("jit_provisioning_enabled", True):
        ensure_user_exists(
            user_sub=user_sub,
            display_name=user_sub.split("@")[0],
            tenant_id=tenant_id,
            role=provider.get("default_role", "user"),
            provider_id=provider_id,
        )

    # Create session
    session = create_real_session(request, user_sub)
    redirect = RedirectResponse(url=_safe_relay_state(relay_state), status_code=303)
    set_session_cookies(redirect, session)

    audit_event(
        "sso_login", user_sub, request,
        provider_id=provider_id,
        protocol="saml",
        tenant_id=tenant_id,
        dev_bypass=True,
    )

    return redirect


def _extract_attr(attributes: Dict, attr_name: Optional[str], fallback: str = "") -> str:
    if not attr_name or attr_name not in attributes:
        return fallback
    values = attributes[attr_name]
    return values[0] if isinstance(values, list) and values else str(values)


def _extract_attr_list(attributes: Dict, attr_name: Optional[str]) -> List[str]:
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
    session_index: Optional[str],
    name_id: str,
    attributes_raw: Dict,
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
        "ttl": now_ts() + S.sso_session_link_ttl_seconds,
    })


def _revoke_session(session_id: str) -> None:
    """Mark session as revoked in DDB."""
    try:
        # Sessions table uses (user_sub, session_id) as key, but we don't know user_sub here.
        # In a real implementation, we'd look up the SSO session link first.
        # For now, just delete the SSO session link.
        T.sso_sessions.delete_item(Key={"session_id": session_id, "sk": "SSO_LINK"})
    except Exception:
        logger.exception("Failed to revoke SSO session link %s during SLO", session_id)
