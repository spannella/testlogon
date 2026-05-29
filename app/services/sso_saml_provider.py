"""SSO SAML Provider management service (ENTERPRISE-002)."""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts


def create_provider(
    tenant_id: str,
    display_name: str,
    protocol: str = "saml",
    *,
    sso_only: bool = False,
    jit_provisioning_enabled: bool = True,
    auto_update_profile: bool = True,
    auto_update_role: bool = False,
    default_role: str = "user",
    allowed_email_domains: Optional[List[str]] = None,
    created_by: str = "",
    idp_entity_id: str = "",
    idp_sso_url: str = "",
    idp_slo_url: str = "",
    idp_certificates: Optional[List[Dict[str, str]]] = None,
    sp_entity_id: str = "",
    sp_acs_url: str = "",
) -> Dict[str, Any]:
    """Create a new SSO provider for a tenant."""
    provider_id = f"sso_{uuid.uuid4().hex[:12]}"
    now = now_ts()

    item: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "sk": f"PROVIDER#{provider_id}",
        "provider_id": provider_id,
        "protocol": protocol,
        "display_name": display_name,
        "status": "active",
        "sso_only": sso_only,
        "idp_entity_id": idp_entity_id,
        "idp_sso_url": idp_sso_url,
        "idp_slo_url": idp_slo_url or "",
        "idp_certificates": idp_certificates or [],
        "sp_entity_id": sp_entity_id or f"https://localhost:3000/saml/metadata",
        "sp_acs_url": sp_acs_url or f"https://localhost:3000/saml/acs",
        "attribute_mappings": {},
        "role_mappings": [],
        "default_role": default_role,
        "jit_provisioning_enabled": jit_provisioning_enabled,
        "auto_update_profile": auto_update_profile,
        "auto_update_role": auto_update_role,
        "allowed_email_domains": allowed_email_domains or [],
        "created_at": now,
        "updated_at": now,
        "created_by": created_by,
        "login_count": 0,
        "last_login_at": 0,
    }
    T.sso_providers.put_item(Item=item)
    return item


def get_provider(tenant_id: str, provider_id: str) -> Optional[Dict[str, Any]]:
    """Get a specific SSO provider."""
    resp = T.sso_providers.get_item(
        Key={"tenant_id": tenant_id, "sk": f"PROVIDER#{provider_id}"}
    )
    return resp.get("Item")


def get_provider_by_id(provider_id: str) -> Optional[Dict[str, Any]]:
    """Look up provider by provider_id via GSI."""
    resp = T.sso_providers.query(
        IndexName="provider-id-index",
        KeyConditionExpression=Key("provider_id").eq(provider_id),
        Limit=1,
    )
    items = resp.get("Items", [])
    return items[0] if items else None


def list_providers(tenant_id: str) -> List[Dict[str, Any]]:
    """List all SSO providers for a tenant."""
    resp = T.sso_providers.query(
        KeyConditionExpression=Key("tenant_id").eq(tenant_id)
        & Key("sk").begins_with("PROVIDER#"),
    )
    return resp.get("Items", [])


def update_provider(
    tenant_id: str,
    provider_id: str,
    updates: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Update an SSO provider."""
    allowed_fields = {
        "display_name", "status", "sso_only", "default_role",
        "jit_provisioning_enabled", "auto_update_profile", "auto_update_role",
        "allowed_email_domains", "attribute_mappings", "role_mappings",
        "idp_entity_id", "idp_sso_url", "idp_slo_url", "idp_certificates",
        "sp_entity_id", "sp_acs_url",
    }
    filtered = {k: v for k, v in updates.items() if k in allowed_fields}
    if not filtered:
        return get_provider(tenant_id, provider_id)

    filtered["updated_at"] = now_ts()

    update_parts = []
    attr_values: Dict[str, Any] = {}
    attr_names: Dict[str, str] = {}

    for idx, (field, value) in enumerate(filtered.items()):
        placeholder = f":v{idx}"
        name_placeholder = f"#f{idx}"
        update_parts.append(f"{name_placeholder} = {placeholder}")
        attr_values[placeholder] = value
        attr_names[name_placeholder] = field

    T.sso_providers.update_item(
        Key={"tenant_id": tenant_id, "sk": f"PROVIDER#{provider_id}"},
        UpdateExpression="SET " + ", ".join(update_parts),
        ExpressionAttributeValues=attr_values,
        ExpressionAttributeNames=attr_names,
    )
    return get_provider(tenant_id, provider_id)


def delete_provider(tenant_id: str, provider_id: str) -> bool:
    """Delete an SSO provider."""
    T.sso_providers.delete_item(
        Key={"tenant_id": tenant_id, "sk": f"PROVIDER#{provider_id}"}
    )
    return True


def get_active_provider_for_tenant(tenant_id: str) -> Optional[Dict[str, Any]]:
    """Get the first active SSO provider for a tenant."""
    providers = list_providers(tenant_id)
    for p in providers:
        if p.get("status") in ("active", "testing"):
            return p
    return None


def is_sso_only_tenant(tenant_id: str) -> bool:
    """Check if the tenant requires SSO-only login."""
    provider = get_active_provider_for_tenant(tenant_id)
    if not provider:
        return False
    return bool(provider.get("sso_only", False))


def increment_login_count(tenant_id: str, provider_id: str) -> None:
    """Increment login count and update last_login_at."""
    try:
        T.sso_providers.update_item(
            Key={"tenant_id": tenant_id, "sk": f"PROVIDER#{provider_id}"},
            UpdateExpression="SET login_count = if_not_exists(login_count, :zero) + :one, last_login_at = :now",
            ExpressionAttributeValues={
                ":zero": 0,
                ":one": 1,
                ":now": now_ts(),
            },
        )
    except Exception:
        pass
