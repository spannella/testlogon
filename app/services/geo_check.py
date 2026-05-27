"""Geo-access enforcement utility (GEO-001).

Called by content routers to check if a viewer's country is allowed
to access content with the given geo-restriction settings.

Not a global middleware -- called explicitly by video/broadcast/catalog
endpoints after loading content metadata.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import HTTPException, Request

from app.core.settings import S
from app.services.geoip import lookup_country, get_mock_country

logger = logging.getLogger(__name__)


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

    # Platform-level block (always applied first, regardless of per-content settings)
    platform_blocked = _parse_csv(getattr(S, "geo_platform_block_countries", ""))
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
