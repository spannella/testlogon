from __future__ import annotations

from dataclasses import dataclass

from app.services.sessions import SessionStore


@dataclass(frozen=True)
class RoleMappingResult:
    resolved_role: str | None
    mapping_id: int | None
    reason_code: str


def resolve_admin_role(
    store: SessionStore,
    *,
    provider_id: str,
    groups: list[str],
    default_role: str | None = None,
) -> RoleMappingResult:
    normalized_groups = [g.strip() for g in groups if g and g.strip()]
    mappings = store.list_identity_provider_role_mappings(provider_id)

    for mapping in mappings:
        if mapping.external_group_or_claim in normalized_groups:
            if mapping.internal_role == 'root':
                return RoleMappingResult(
                    resolved_role=None,
                    mapping_id=mapping.mapping_id,
                    reason_code='sso_root_role_forbidden',
                )
            return RoleMappingResult(
                resolved_role=mapping.internal_role,
                mapping_id=mapping.mapping_id,
                reason_code='role_mapped',
            )

    if default_role:
        if default_role == 'root':
            return RoleMappingResult(
                resolved_role=None,
                mapping_id=None,
                reason_code='sso_root_role_forbidden',
            )
        return RoleMappingResult(
            resolved_role=default_role,
            mapping_id=None,
            reason_code='role_default_applied',
        )

    return RoleMappingResult(
        resolved_role=None,
        mapping_id=None,
        reason_code='sso_role_mapping_denied',
    )
