"""SSO SAML JIT (Just-in-Time) provisioning service (ENTERPRISE-002)."""
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
    user_item: Dict[str, Any] = {
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
    profile_item: Dict[str, Any] = {
        "user_sub": user_sub,
        "display_name": display_name,
        "email": user_sub,
        "phone": phone or "",
        "created_at": now,
    }
    T.profile.put_item(Item=profile_item)

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
        try:
            T.profile.update_item(
                Key={"user_sub": user_sub},
                UpdateExpression="SET " + ", ".join(update_parts),
                ExpressionAttributeValues=attr_values,
            )
        except Exception:
            pass
