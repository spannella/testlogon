"""
Tenant CRUD service (ENTERPRISE-001).

Manages tenant lifecycle: creation, updates, domain management, and plan limits.
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError

from app.core.tables import T
from app.core.time import now_ts


# ── Plan limits ──────────────────────────────────────────────────────────────

def _plan_limits(plan: str) -> Dict[str, Any]:
    limits = {
        "free": {"max_members": 5, "max_storage_bytes": 1 * 1024 ** 3},
        "starter": {"max_members": 50, "max_storage_bytes": 10 * 1024 ** 3},
        "enterprise": {"max_members": 10_000, "max_storage_bytes": 1024 ** 4},
    }
    return limits.get(plan, limits["starter"])


# ── CRUD ─────────────────────────────────────────────────────────────────────

def create_tenant(
    slug: str,
    display_name: str,
    plan: str = "starter",
    primary_domain: Optional[str] = None,
    created_by: str = "",
) -> Dict[str, Any]:
    """Create a new tenant.  Raises ValueError on duplicate slug."""
    tenant_id = f"t_{uuid.uuid4().hex[:16]}"
    ts = now_ts()

    # Check slug uniqueness via a full scan (small table — no Limit so filter sees all items)
    scan_resp = T.tenants.scan(
        FilterExpression=Attr("slug").eq(slug),
    )
    if scan_resp.get("Items"):
        raise ValueError(f"Slug '{slug}' is already in use")

    item: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "slug": slug,
        "display_name": display_name,
        "status": "active",
        "plan": plan,
        "custom_domains": [],
        "primary_domain": primary_domain or "",
        "branding": {},
        "settings_overrides": {},
        "limits": _plan_limits(plan),
        "member_count": 0,
        "storage_used_bytes": 0,
        "created_by": created_by,
        "created_at": ts,
        "updated_at": ts,
    }

    T.tenants.put_item(Item=item)

    # Add primary domain mapping if provided
    if primary_domain:
        try:
            _add_domain_record(tenant_id, primary_domain)
        except ValueError:
            pass  # domain already claimed — tenant still created

    return item


def get_tenant(tenant_id: str) -> Optional[Dict[str, Any]]:
    resp = T.tenants.get_item(Key={"tenant_id": tenant_id})
    return resp.get("Item")


def list_tenants(
    limit: int = 50,
    cursor: Optional[str] = None,
    status_filter: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Scan tenants table with optional status filter.  Returns (items, next_cursor)."""
    kwargs: Dict[str, Any] = {"Limit": limit}

    if status_filter:
        kwargs["FilterExpression"] = Attr("status").eq(status_filter)

    if cursor:
        kwargs["ExclusiveStartKey"] = {"tenant_id": cursor}

    resp = T.tenants.scan(**kwargs)
    items = resp.get("Items", [])
    last_key = resp.get("LastEvaluatedKey")
    next_cursor = last_key["tenant_id"] if last_key else None
    return items, next_cursor


def update_tenant(
    tenant_id: str,
    *,
    display_name: Optional[str] = None,
    plan: Optional[str] = None,
    status: Optional[str] = None,
    branding: Optional[Dict[str, Any]] = None,
    settings_overrides: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Partial update of a tenant record.  Returns the updated item or None if not found."""
    update_parts: List[str] = []
    attr_names: Dict[str, str] = {}
    attr_values: Dict[str, Any] = {}

    if display_name is not None:
        update_parts.append("#dn = :dn")
        attr_names["#dn"] = "display_name"
        attr_values[":dn"] = display_name

    if plan is not None:
        update_parts.append("#pl = :pl")
        attr_names["#pl"] = "plan"
        attr_values[":pl"] = plan
        # Also update limits when plan changes
        update_parts.append("#lm = :lm")
        attr_names["#lm"] = "limits"
        attr_values[":lm"] = _plan_limits(plan)

    if status is not None:
        update_parts.append("#st = :st")
        attr_names["#st"] = "status"
        attr_values[":st"] = status

    if branding is not None:
        update_parts.append("#br = :br")
        attr_names["#br"] = "branding"
        attr_values[":br"] = branding

    if settings_overrides is not None:
        update_parts.append("#so = :so")
        attr_names["#so"] = "settings_overrides"
        attr_values[":so"] = settings_overrides

    if not update_parts:
        return get_tenant(tenant_id)

    update_parts.append("#ua = :ua")
    attr_names["#ua"] = "updated_at"
    attr_values[":ua"] = now_ts()

    try:
        resp = T.tenants.update_item(
            Key={"tenant_id": tenant_id},
            UpdateExpression="SET " + ", ".join(update_parts),
            ExpressionAttributeNames=attr_names,
            ExpressionAttributeValues=attr_values,
            ConditionExpression=Attr("tenant_id").exists(),
            ReturnValues="ALL_NEW",
        )
        return resp.get("Attributes")
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return None
        raise


def soft_delete_tenant(tenant_id: str) -> Optional[Dict[str, Any]]:
    """Mark a tenant as deleted."""
    return update_tenant(tenant_id, status="deleted")


# ── Domain management ────────────────────────────────────────────────────────

def _add_domain_record(tenant_id: str, domain: str) -> None:
    """Write a domain → tenant mapping.  Raises ValueError if domain is already claimed."""
    try:
        T.tenant_domains.put_item(
            Item={
                "domain": domain.lower().strip(),
                "sk": "DOMAIN",
                "tenant_id": tenant_id,
                "created_at": now_ts(),
            },
            ConditionExpression=Attr("domain").not_exists(),
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise ValueError(f"Domain '{domain}' is already claimed")
        raise


def add_domain(tenant_id: str, domain: str) -> Dict[str, Any]:
    """Add a custom domain to a tenant.  Returns the tenant record."""
    tenant = get_tenant(tenant_id)
    if not tenant:
        raise ValueError("Tenant not found")

    _add_domain_record(tenant_id, domain)

    # Append to custom_domains list on the tenant record
    custom_domains = list(tenant.get("custom_domains") or [])
    d_lower = domain.lower().strip()
    if d_lower not in custom_domains:
        custom_domains.append(d_lower)
    T.tenants.update_item(
        Key={"tenant_id": tenant_id},
        UpdateExpression="SET custom_domains = :cd, updated_at = :ua",
        ExpressionAttributeValues={":cd": custom_domains, ":ua": now_ts()},
    )

    # Invalidate cache
    from app.middleware.tenant import invalidate_tenant_cache
    invalidate_tenant_cache(tenant_id)

    return {**tenant, "custom_domains": custom_domains}


def remove_domain(tenant_id: str, domain: str) -> None:
    """Remove a domain mapping."""
    d_lower = domain.lower().strip()

    # Delete the domain record
    T.tenant_domains.delete_item(Key={"domain": d_lower, "sk": "DOMAIN"})

    # Remove from custom_domains list
    tenant = get_tenant(tenant_id)
    if tenant:
        custom_domains = [d for d in (tenant.get("custom_domains") or []) if d != d_lower]
        T.tenants.update_item(
            Key={"tenant_id": tenant_id},
            UpdateExpression="SET custom_domains = :cd, updated_at = :ua",
            ExpressionAttributeValues={":cd": custom_domains, ":ua": now_ts()},
        )

    # Invalidate caches
    from app.middleware.tenant import invalidate_domain_cache, invalidate_tenant_cache
    invalidate_domain_cache(d_lower)
    invalidate_tenant_cache(tenant_id)


def get_tenant_branding(tenant_id: str) -> Dict[str, Any]:
    """Return branding info for a tenant.  Falls back to defaults."""
    tenant = get_tenant(tenant_id) if tenant_id != "default" else None
    if tenant:
        branding = tenant.get("branding") or {}
        return {
            "tenant_id": tenant["tenant_id"],
            "display_name": tenant.get("display_name", ""),
            "logo_url": branding.get("logo_url"),
            "favicon_url": branding.get("favicon_url"),
            "primary_color": branding.get("primary_color", "#2563EB"),
            "accent_color": branding.get("accent_color", "#7C3AED"),
        }
    return {
        "tenant_id": "default",
        "display_name": "Default",
        "logo_url": None,
        "favicon_url": None,
        "primary_color": "#2563EB",
        "accent_color": "#7C3AED",
    }


def get_tenant_info(tenant_id: str) -> Optional[Dict[str, Any]]:
    """Return public-safe tenant info."""
    if tenant_id == "default":
        return {
            "tenant_id": "default",
            "slug": "default",
            "display_name": "Default",
            "status": "active",
            "plan": "starter",
        }
    tenant = get_tenant(tenant_id)
    if not tenant:
        return None
    return {
        "tenant_id": tenant["tenant_id"],
        "slug": tenant.get("slug", ""),
        "display_name": tenant.get("display_name", ""),
        "status": tenant.get("status", "active"),
        "plan": tenant.get("plan", "starter"),
    }
