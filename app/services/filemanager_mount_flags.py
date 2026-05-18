from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from fastapi import HTTPException

from app.core.settings import S
from app.metrics import record_filemgr_mount_rollout_decision


@dataclass(frozen=True)
class ICloudMountAccessDecision:
    enabled: bool
    cohort: str
    reason: str


def _csv_set(raw: str) -> set[str]:
    return {part.strip() for part in str(raw or "").split(",") if part.strip()}


def _env_flag_bool(name: str) -> Optional[bool]:
    raw = os.environ.get(name)
    if raw is None:
        return None
    val = str(raw).strip().lower()
    if val in {"1", "true", "yes", "on"}:
        return True
    if val in {"0", "false", "no", "off"}:
        return False
    return None


def _parse_rollout_mode_overrides(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for chunk in str(raw or "").split(","):
        part = chunk.strip()
        if not part or ":" not in part:
            continue
        env_name, mode = part.split(":", 1)
        env_key = env_name.strip().lower()
        mode_val = mode.strip().lower()
        if env_key and mode_val:
            out[env_key] = mode_val
    return out


def evaluate_icloud_mount_access(*, user_sub: str, tenant_id: Optional[str] = None) -> ICloudMountAccessDecision:
    env_name = str(getattr(S, "filemgr_icloud_mount_environment", "dev") or "dev").strip().lower()
    configured_mode = str(getattr(S, "filemgr_icloud_mount_rollout_mode", "internal") or "internal").strip().lower()

    def _decision(*, enabled: bool, cohort: str, reason: str, mode: str | None = None) -> ICloudMountAccessDecision:
        record_filemgr_mount_rollout_decision(
            provider="icloud",
            environment=env_name,
            mode=(mode or configured_mode),
            cohort=cohort,
            reason=reason,
        )
        return ICloudMountAccessDecision(enabled=enabled, cohort=cohort, reason=reason)

    enabled_override = _env_flag_bool("FILEMGR_ICLOUD_MOUNT_ENABLED_OVERRIDE")
    globally_enabled = bool(getattr(S, "filemgr_icloud_mount_enabled", False)) if enabled_override is None else enabled_override
    if not globally_enabled:
        return _decision(enabled=False, cohort="disabled", reason="global_flag_off")

    kill_switch_override = _env_flag_bool("FILEMGR_ICLOUD_MOUNT_KILL_SWITCH_OVERRIDE")
    kill_switch = bool(getattr(S, "filemgr_icloud_mount_kill_switch", False)) if kill_switch_override is None else kill_switch_override
    if kill_switch:
        return _decision(enabled=False, cohort="disabled", reason="kill_switch")

    mode = configured_mode
    env_mode_overrides = _parse_rollout_mode_overrides(getattr(S, "filemgr_icloud_mount_rollout_mode_by_env", ""))
    mode = env_mode_overrides.get(env_name, mode)
    uid = str(user_sub or "").strip()
    tid = str(tenant_id or "").strip()

    enabled_tenants = _csv_set(getattr(S, "filemgr_icloud_mount_enabled_tenant_ids", ""))
    disabled_tenants = _csv_set(getattr(S, "filemgr_icloud_mount_disabled_tenant_ids", ""))
    if tid and tid in disabled_tenants:
        return _decision(enabled=False, cohort="disabled", reason="tenant_denylist", mode=mode)

    if tid and tid in enabled_tenants:
        return _decision(enabled=True, cohort="tenant_override", reason="tenant_allowlist", mode=mode)

    internal_users = _csv_set(getattr(S, "filemgr_icloud_mount_internal_user_subs", ""))
    internal_tenants = _csv_set(getattr(S, "filemgr_icloud_mount_internal_tenant_ids", ""))
    beta_users = _csv_set(getattr(S, "filemgr_icloud_mount_beta_user_subs", ""))
    beta_tenants = _csv_set(getattr(S, "filemgr_icloud_mount_beta_tenant_ids", ""))

    is_internal = (uid and uid in internal_users) or (tid and tid in internal_tenants)
    is_beta = is_internal or (uid and uid in beta_users) or (tid and tid in beta_tenants)

    if mode in {"ga", "general", "all", "enabled", "on", "true", "1"}:
        return _decision(enabled=True, cohort="ga", reason="mode_ga", mode=mode)
    if mode in {"beta", "pilot", "selective"}:
        if is_beta:
            return _decision(enabled=True, cohort="beta", reason="beta_allowlist", mode=mode)
        return _decision(enabled=False, cohort="disabled", reason="beta_allowlist_miss", mode=mode)
    if mode in {"internal", "dogfood"}:
        if is_internal:
            return _decision(enabled=True, cohort="internal", reason="internal_allowlist", mode=mode)
        return _decision(enabled=False, cohort="disabled", reason="internal_allowlist_miss", mode=mode)

    return _decision(enabled=False, cohort="disabled", reason=f"unknown_mode:{mode or 'unset'}", mode=mode)


def enforce_icloud_mount_enabled(*, user_sub: str, tenant_id: Optional[str] = None) -> ICloudMountAccessDecision:
    decision = evaluate_icloud_mount_access(user_sub=user_sub, tenant_id=tenant_id)
    if not decision.enabled:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "feature_disabled",
                "provider": "icloud",
                "reason": decision.reason,
                "cohort": decision.cohort,
            },
        )
    return decision
