"""Geo-access enforcement utility (GEO-001).

Called by content routers to check if a viewer's country is allowed
to access content with the given geo-restriction settings.

Not a global middleware -- called explicitly by video/broadcast/catalog
endpoints after loading content metadata.
"""

from __future__ import annotations

import logging
import time
from threading import Lock
from typing import List, Optional

from fastapi import HTTPException, Request

from app.core.settings import S
from app.services.geoip import lookup_country, get_mock_country

logger = logging.getLogger(__name__)

# GAP-0217 (GEO-001): the platform-level block list is DDB-backed and
# hot-reloadable. The env-var ``geo_platform_block_countries`` stays as a
# bootstrap override and is unioned with the DDB record. An in-process TTL cache
# bounds DDB reads so ``check_geo_access`` stays fast on the hot path.
_PLATFORM_BLOCK_PK = "PLATFORM"
_PLATFORM_BLOCK_SK = "GEO_BLOCK"
_platform_block_cache: set = set()
_platform_block_cache_ts: float = 0.0
_platform_block_lock = Lock()


def _platform_block_ttl() -> int:
    return int(getattr(S, "geo_platform_block_cache_ttl_seconds", 60) or 0)


def reset_platform_block_cache() -> None:
    """Invalidate the in-process platform-block cache (called after a write)."""
    global _platform_block_cache_ts
    with _platform_block_lock:
        _platform_block_cache_ts = 0.0


def _load_platform_block_from_ddb() -> set:
    """Read the platform block list from DynamoDB. Fail-safe: returns empty set on error."""
    try:
        from app.core.tables import T

        item = T.geo_rules.get_item(
            Key={"pk": _PLATFORM_BLOCK_PK, "sk": _PLATFORM_BLOCK_SK}
        ).get("Item") or {}
        return {str(c).strip().upper() for c in (item.get("countries") or []) if str(c).strip()}
    except Exception:  # pragma: no cover - defensive; DDB transient failure
        logger.warning("geo platform-block DDB read failed; falling back to env-var only", exc_info=True)
        return set()


def get_platform_blocked_countries() -> set:
    """Union of the env-var and DDB-backed platform block lists, cached for the TTL.

    On a DDB read error the cache timestamp is left unchanged so the next call
    retries immediately; the env-var value still applies (fail-safe).
    """
    global _platform_block_cache, _platform_block_cache_ts
    env_countries = _parse_csv(getattr(S, "geo_platform_block_countries", ""))
    ttl = _platform_block_ttl()
    now = time.monotonic()
    with _platform_block_lock:
        if ttl > 0 and (now - _platform_block_cache_ts) < ttl and _platform_block_cache_ts > 0:
            return _platform_block_cache | env_countries
        ddb_countries = _load_platform_block_from_ddb()
        _platform_block_cache = ddb_countries
        _platform_block_cache_ts = now
        return ddb_countries | env_countries


def set_platform_blocked_countries(countries: List[str], updated_by: str) -> List[str]:
    """Persist the platform block list to DynamoDB (ROOT-only callers).

    Validates/normalises ISO-3166 alpha-2 codes, writes the single
    pk=PLATFORM/sk=GEO_BLOCK record, and invalidates the in-process cache so the
    change is visible without a restart.
    """
    from app.core.tables import T
    from app.core.time import now_ts

    validated = _validate_country_codes(countries)
    T.geo_rules.put_item(
        Item={
            "pk": _PLATFORM_BLOCK_PK,
            "sk": _PLATFORM_BLOCK_SK,
            "countries": validated,
            "updated_at": now_ts(),
            "updated_by": updated_by,
        }
    )
    reset_platform_block_cache()
    return validated


def _validate_country_codes(countries: Optional[List[str]]) -> List[str]:
    """Normalise to sorted, de-duplicated upper-case ISO alpha-2 codes."""
    out: set = set()
    for raw in countries or []:
        code = str(raw).strip().upper()
        if len(code) != 2 or not code.isalpha():
            raise HTTPException(
                status_code=400,
                detail={"code": "invalid_country_code", "message": f"Invalid ISO country code: {raw!r}"},
            )
        out.add(code)
    return sorted(out)


def check_geo_access(
    request: Request,
    geo_mode: Optional[str],
    geo_countries: Optional[List[str]],
) -> Optional[str]:
    """Check if the request IP is allowed to access content with the given geo settings.

    Returns the viewer's country code, or raises HTTPException(403) if blocked.
    Returns None when geo-blocking is disabled, no restrictions exist, or country
    cannot be determined (fail-open in dev mode).
    """
    if not getattr(S, "geo_blocking_enabled", True):
        return None  # Feature disabled

    ip = _get_client_ip(request)

    # Dev mode: check X-Geo-Country header override first
    country: Optional[str] = None
    if S.dev_mode:
        header_country = request.headers.get("x-geo-country")
        if header_country:
            country = header_country.strip().upper()

    # Check mock overrides (from E2E test hooks)
    if country is None:
        mock_country = get_mock_country(ip)
        if mock_country:
            country = mock_country

    # Platform-level block (always applied first, regardless of per-content settings).
    # GAP-0217: DDB-backed + env-var union, hot-reloadable (no restart required).
    platform_blocked = get_platform_blocked_countries()
    if platform_blocked:
        if country is None:
            country = lookup_country(ip)
        if country and country in platform_blocked:
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "geo_blocked",
                    "message": "This content is not available in your region.",
                    "country": country,
                },
            )

    if not geo_mode or not geo_countries:
        return country  # No per-content restrictions

    # Resolve country if not yet resolved
    if country is None:
        country = lookup_country(ip)

    if country is None:
        # Cannot determine country; fail-open in dev, fail-closed in prod
        if S.dev_mode:
            return None
        raise HTTPException(
            status_code=403,
            detail={
                "code": "geo_unknown",
                "message": "Unable to determine your region. Access denied.",
            },
        )

    if geo_mode == "allow" and country not in geo_countries:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "geo_blocked",
                "message": "This content is not available in your region.",
                "country": country,
            },
        )

    if geo_mode == "block" and country in geo_countries:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "geo_blocked",
                "message": "This content is not available in your region.",
                "country": country,
            },
        )

    return country


def _get_client_ip(request: Request) -> str:
    """Extract client IP from the request."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""


def _parse_csv(value: str) -> set:
    """Parse a comma-separated string into a set of uppercase values."""
    return {v.strip().upper() for v in (value or "").split(",") if v.strip()}
