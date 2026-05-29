"""SSO SAML role mapping service (ENTERPRISE-002)."""
from __future__ import annotations

from typing import Dict, List


ROLE_PRIORITY: Dict[str, int] = {"root": 3, "admin": 2, "user": 1}


def map_groups_to_role(
    groups: List[str],
    role_mappings: List[Dict],
    default_role: str = "user",
) -> str:
    """Map IdP groups to the highest applicable platform role.

    ROOT is never assignable via SSO mapping.
    """
    best_role = default_role
    best_priority = ROLE_PRIORITY.get(default_role, 0)

    for mapping in role_mappings:
        idp_group = mapping.get("idp_group", "")
        if idp_group in groups:
            role = mapping.get("platform_role", "user")
            # Never assign root via SSO
            if role == "root":
                continue
            priority = ROLE_PRIORITY.get(role, 0)
            if priority > best_priority:
                best_role = role
                best_priority = priority

    return best_role
