from __future__ import annotations

import hashlib
from typing import Any, Dict

from app.core.settings import S

ROLLOUT_PRODUCTS = ("filemanager", "newsfeed", "tickets", "shopping", "messager")
ROLLOUT_PHASES = {"off", "disabled", "shadow", "observe", "canary", "enforce", "ga", "general_availability"}
DUAL_CREDENTIAL_MODES = {"prefer_api_key", "prefer_session", "reject"}


def _as_int(value: Any, default: int) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return default


def _stable_bucket(subject: str) -> int:
    digest = hashlib.sha256(subject.encode("utf-8")).hexdigest()
    return int(digest[:8], 16) % 100


def _product_flag_enabled(product: str) -> bool:
    return bool(getattr(S, f"api_key_{product}", True))


def _product_phase(product: str) -> str:
    raw = str(getattr(S, f"api_key_{product}_phase", "ga") or "ga").strip().lower()
    if raw in {"off", "disabled"}:
        return "off"
    if raw in {"shadow", "observe"}:
        return "shadow"
    if raw in {"canary"}:
        return "canary"
    if raw in {"enforce", "ga", "general_availability"}:
        return "ga"
    return "ga"


def _canary_allowlist(product: str) -> set[str]:
    raw = str(getattr(S, f"api_key_{product}_canary_subjects", "") or "")
    return {item.strip() for item in raw.split(",") if item.strip()}


def evaluate_api_key_rollout(product: str, principal: Dict[str, Any]) -> Dict[str, Any]:
    enabled = _product_flag_enabled(product)
    phase = _product_phase(product)
    subject = str(principal.get("api_key_id") or principal.get("user_sub") or "anonymous")
    percent = max(0, min(100, _as_int(getattr(S, f"api_key_{product}_canary_percent", 0), 0)))
    bucket = _stable_bucket(subject)
    allowlisted = subject in _canary_allowlist(product)
    within_percent = bucket < percent

    if not enabled:
        return {"product": product, "phase": "off", "enforce": False, "shadow": False, "reason": "flag_disabled"}
    if phase == "off":
        return {"product": product, "phase": "off", "enforce": False, "shadow": False, "reason": "phase_off"}
    if phase == "shadow":
        return {"product": product, "phase": "shadow", "enforce": False, "shadow": True, "reason": "shadow_only"}
    if phase == "canary":
        return {
            "product": product,
            "phase": "canary",
            "enforce": bool(allowlisted or within_percent),
            "shadow": True,
            "reason": "canary_match" if (allowlisted or within_percent) else "canary_shadow_only",
            "subject_bucket": bucket,
            "canary_percent": percent,
        }
    return {"product": product, "phase": "ga", "enforce": True, "shadow": False, "reason": "ga"}


def validate_api_key_rollout_settings() -> None:
    errors: list[str] = []
    for product in ROLLOUT_PRODUCTS:
        enabled_attr = f"api_key_{product}"
        phase_attr = f"api_key_{product}_phase"
        percent_attr = f"api_key_{product}_canary_percent"

        if not hasattr(S, enabled_attr):
            errors.append(f"missing {enabled_attr}")
        if not hasattr(S, phase_attr):
            errors.append(f"missing {phase_attr}")
        if not hasattr(S, percent_attr):
            errors.append(f"missing {percent_attr}")

        phase_raw = str(getattr(S, phase_attr, "") or "").strip().lower()
        if phase_raw not in ROLLOUT_PHASES:
            errors.append(f"{phase_attr} has invalid value '{phase_raw}'")

        percent = _as_int(getattr(S, percent_attr, 0), -1)
        if percent < 0 or percent > 100:
            errors.append(f"{percent_attr} must be between 0 and 100 (got {percent})")

    dual_mode = str(getattr(S, "api_key_dual_credential_mode", "prefer_api_key") or "prefer_api_key").strip().lower()
    if dual_mode not in DUAL_CREDENTIAL_MODES:
        errors.append(
            "api_key_dual_credential_mode has invalid value "
            f"'{dual_mode}' (expected one of {sorted(DUAL_CREDENTIAL_MODES)})"
        )
    drift_threshold = _as_int(getattr(S, "api_key_registry_drift_warn_threshold", 0), -1)
    if drift_threshold < 0:
        errors.append(
            f"api_key_registry_drift_warn_threshold must be >= 0 (got {drift_threshold})"
        )

    if errors:
        raise ValueError("Invalid API-key rollout settings: " + "; ".join(errors))


def get_api_key_rollout_state(*, include_subjects: bool = False) -> Dict[str, Any]:
    products: Dict[str, Dict[str, Any]] = {}
    for product in ROLLOUT_PRODUCTS:
        phase_attr = f"api_key_{product}_phase"
        percent_attr = f"api_key_{product}_canary_percent"
        subjects_attr = f"api_key_{product}_canary_subjects"
        raw_phase = str(getattr(S, phase_attr, "ga") or "ga").strip()
        row: Dict[str, Any] = {
            "enabled": _product_flag_enabled(product),
            "phase_raw": raw_phase,
            "phase_effective": _product_phase(product),
            "canary_percent": max(0, min(100, _as_int(getattr(S, percent_attr, 0), 0))),
            "canary_subject_count": len(_canary_allowlist(product)),
        }
        if include_subjects:
            row["canary_subjects_raw"] = str(getattr(S, subjects_attr, "") or "")
        products[product] = row

    return {
        "dual_credential_mode": str(getattr(S, "api_key_dual_credential_mode", "prefer_api_key") or "prefer_api_key").strip().lower(),
        "products": products,
    }
