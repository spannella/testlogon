from __future__ import annotations

from typing import Callable, Optional

from app.core.settings import S


def _csv_set(raw: str) -> set[str]:
    return {part.strip() for part in str(raw or "").split(",") if part.strip()}


def resolve_user_tenant_id(user_id: str) -> str:
    uid = str(user_id or "").strip()
    if not uid:
        return ""
    try:
        from app.core.tables import T
        row = T.users.get_item(Key={"user_id": uid}).get("Item") or {}
    except Exception:
        return ""
    return str(row.get("tenant_id") or row.get("tenant") or "").strip()


def is_webrtc_direct_call_enabled_for(
    *,
    user_id: str,
    tenant_id: Optional[str] = None,
    cohort: Optional[str] = None,
    tenant_resolver: Callable[[str], str] = resolve_user_tenant_id,
) -> bool:
    """Return whether direct calling is enabled for a given user/context.

    Mode behavior:
    - disabled/off/false/0: globally disabled
    - enabled/on/true/1: globally enabled (subject to kill switch)
    - internal/pilot_internal: enabled only for internal tenant IDs
    - selective/tenant/cohort: enabled for allowlisted tenants and/or cohorts
    """

    if S.messaging_webrtc_direct_call_kill_switch:
        return False
    if not S.messaging_webrtc_direct_call_enabled:
        return False

    mode = str(S.messaging_webrtc_direct_call_mode or "enabled").strip().lower()
    if mode in {"enabled", "on", "true", "1"}:
        return True
    if mode in {"disabled", "off", "false", "0", ""}:
        return False

    effective_tenant = str(tenant_id or "").strip() or tenant_resolver(user_id)
    effective_cohort = str(cohort or "").strip().lower()

    if mode in {"internal", "pilot_internal"}:
        internal_tenants = _csv_set(S.messaging_webrtc_direct_call_internal_tenant_ids)
        return bool(effective_tenant and effective_tenant in internal_tenants)

    if mode in {"selective", "tenant", "cohort"}:
        enabled_tenants = _csv_set(S.messaging_webrtc_direct_call_enabled_tenant_ids)
        enabled_cohorts = {c.lower() for c in _csv_set(S.messaging_webrtc_direct_call_enabled_cohorts)}
        tenant_allowed = bool(effective_tenant and effective_tenant in enabled_tenants)
        cohort_allowed = bool(effective_cohort and effective_cohort in enabled_cohorts)
        if enabled_tenants and enabled_cohorts:
            return tenant_allowed or cohort_allowed
        if enabled_tenants:
            return tenant_allowed
        if enabled_cohorts:
            return cohort_allowed
        return False

    return False


def get_webrtc_direct_call_flag_snapshot() -> dict[str, object]:
    return {
        "enabled": bool(S.messaging_webrtc_direct_call_enabled),
        "kill_switch": bool(S.messaging_webrtc_direct_call_kill_switch),
        "mode": str(S.messaging_webrtc_direct_call_mode),
        "enabled_tenant_ids": sorted(_csv_set(S.messaging_webrtc_direct_call_enabled_tenant_ids)),
        "internal_tenant_ids": sorted(_csv_set(S.messaging_webrtc_direct_call_internal_tenant_ids)),
        "enabled_cohorts": sorted({c.lower() for c in _csv_set(S.messaging_webrtc_direct_call_enabled_cohorts)}),
    }


__all__ = [
    "is_webrtc_direct_call_enabled_for",
    "get_webrtc_direct_call_flag_snapshot",
    "resolve_user_tenant_id",
]
