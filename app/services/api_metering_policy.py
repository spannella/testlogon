from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Iterable, Set

from fastapi import HTTPException

from app.core.settings import S

_ALLOWED_STATUS_CLASSES: Set[str] = {"1xx", "2xx", "3xx", "4xx", "5xx"}


@dataclass(frozen=True)
class ApiUsagePolicy:
    billable_status_classes: Set[str]
    quota_status_classes: Set[str]
    rate_limit_billable: bool
    rate_limit_counts_toward_quota: bool
    auth_failed_billable: bool
    auth_failed_counts_toward_quota: bool


@dataclass(frozen=True)
class ApiUsageDecision:
    status_class: str
    billable: bool
    counts_toward_quota: bool
    reason: str


def _parse_status_classes(raw_value: str, *, default: Iterable[str]) -> Set[str]:
    raw = (raw_value or "").strip()
    if not raw:
        return set(default)
    items = {token.strip().lower() for token in raw.split(",") if token.strip()}
    invalid = sorted(items - _ALLOWED_STATUS_CLASSES)
    if invalid:
        raise ValueError(f"invalid status classes: {', '.join(invalid)}")
    return items


def load_api_usage_policy() -> ApiUsagePolicy:
    return ApiUsagePolicy(
        billable_status_classes=_parse_status_classes(S.api_usage_billable_status_classes, default={"2xx"}),
        quota_status_classes=_parse_status_classes(S.api_usage_quota_status_classes, default={"2xx", "4xx", "5xx"}),
        rate_limit_billable=bool(S.api_usage_rate_limit_billable),
        rate_limit_counts_toward_quota=bool(S.api_usage_rate_limit_counts_toward_quota),
        auth_failed_billable=bool(S.api_usage_auth_failed_billable),
        auth_failed_counts_toward_quota=bool(S.api_usage_auth_failed_counts_toward_quota),
    )


def status_class_for_code(status_code: int) -> str:
    code = max(100, min(int(status_code), 599))
    return f"{code // 100}xx"


def classify_api_call(
    status_code: int,
    *,
    is_rate_limited: bool = False,
    is_auth_failed: bool = False,
    policy: ApiUsagePolicy | None = None,
) -> ApiUsageDecision:
    active = policy or load_api_usage_policy()
    status_class = status_class_for_code(status_code)

    if is_rate_limited:
        return ApiUsageDecision(
            status_class=status_class,
            billable=active.rate_limit_billable,
            counts_toward_quota=active.rate_limit_counts_toward_quota,
            reason="rate_limited",
        )

    if is_auth_failed:
        return ApiUsageDecision(
            status_class=status_class,
            billable=active.auth_failed_billable,
            counts_toward_quota=active.auth_failed_counts_toward_quota,
            reason="auth_failed",
        )

    return ApiUsageDecision(
        status_class=status_class,
        billable=status_class in active.billable_status_classes,
        counts_toward_quota=status_class in active.quota_status_classes,
        reason="status_class_policy",
    )


def build_limit_denial_detail(
    *,
    limit_type: str,
    scope: str,
    current: int,
    limit: int,
    reset_at: int,
    route_id: str | None = None,
    api_key_id: str | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "code": "api_limit_exceeded",
        "limit_type": limit_type,
        "scope": scope,
        "current": int(current),
        "limit": int(limit),
        "reset_at": int(reset_at),
    }
    if route_id:
        payload["route_id"] = route_id
    if api_key_id:
        payload["api_key_id"] = api_key_id
    return payload


def build_limit_denial_headers(detail: dict[str, object]) -> dict[str, str]:
    reset_at = int(detail.get("reset_at") or 0)
    now = int(time.time())
    retry_after = max(0, reset_at - now) if reset_at else 0

    headers = {
        "x-api-limit-code": str(detail.get("code") or "api_limit_exceeded"),
        "x-api-limit-scope": str(detail.get("scope") or "account"),
        "x-api-limit-type": str(detail.get("limit_type") or "unknown"),
        "x-api-limit-current": str(int(detail.get("current") or 0)),
        "x-api-limit-limit": str(int(detail.get("limit") or 0)),
    }
    if reset_at:
        headers["x-api-limit-reset-at"] = str(reset_at)
        headers["retry-after"] = str(retry_after)
    return headers


def raise_limit_denied(
    *,
    limit_type: str,
    scope: str,
    current: int,
    limit: int,
    reset_at: int,
    route_id: str | None = None,
    api_key_id: str | None = None,
) -> None:
    raise HTTPException(
        status_code=429,
        detail=build_limit_denial_detail(
            limit_type=limit_type,
            scope=scope,
            current=current,
            limit=limit,
            reset_at=reset_at,
            route_id=route_id,
            api_key_id=api_key_id,
        ),
    )
