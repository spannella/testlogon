"""GeoIP lookup service (GEO-001).

Resolves IP addresses to ISO 3166-1 alpha-2 country codes.
In dev mode, accepts the ``X-Geo-Country`` header override for testing.
Uses MaxMind GeoLite2 in production; falls back to returning None in dev
for localhost/private IPs (fail-open).
"""

from __future__ import annotations

import logging
import time
from typing import Dict, Optional, Tuple

from app.core.settings import S

logger = logging.getLogger(__name__)

# ─── In-memory cache ────────────────────────────────────────────────────────

_geo_cache: Dict[str, Tuple[str, float]] = {}


def lookup_country(ip: str) -> Optional[str]:
    """Resolve an IP address to an ISO 3166-1 alpha-2 country code.

    Returns None if the IP cannot be resolved (private, localhost, error).
    """
    if not ip or ip in ("127.0.0.1", "::1", "localhost", "testclient"):
        return None  # Fail-open for local development

    # Private IP ranges -> None
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return None
    except ValueError:
        return None

    cache_ttl = getattr(S, "geo_cache_ttl_seconds", 3600) or 3600
    cache_max = getattr(S, "geo_cache_max_size", 50000) or 50000

    # Check cache
    now = time.time()
    cached = _geo_cache.get(ip)
    if cached and (now - cached[1]) < cache_ttl:
        return cached[0]

    country = _lookup_country_uncached(ip)
    if country:
        # Evict oldest entries if cache is full
        if len(_geo_cache) >= cache_max:
            oldest_key = min(_geo_cache, key=lambda k: _geo_cache[k][1])
            del _geo_cache[oldest_key]
        _geo_cache[ip] = (country, now)
    return country


def _lookup_country_uncached(ip: str) -> Optional[str]:
    """Perform the actual GeoIP lookup."""
    # Option 1: MaxMind GeoLite2 database (production)
    maxmind_db_path = getattr(S, "geo_maxmind_db_path", "") or ""
    if maxmind_db_path:
        return _lookup_maxmind(ip, maxmind_db_path)

    # In dev mode with no MaxMind DB, return None (fail-open)
    return None


def _lookup_maxmind(ip: str, db_path: str) -> Optional[str]:
    try:
        import geoip2.database
        with geoip2.database.Reader(db_path) as reader:
            response = reader.country(ip)
            return response.country.iso_code
    except Exception:
        logger.warning("MaxMind GeoIP lookup failed for %s", ip, exc_info=True)
        return None


def clear_cache() -> int:
    """Clear the GeoIP cache. Returns the number of evicted entries."""
    count = len(_geo_cache)
    _geo_cache.clear()
    return count


# ─── Dev/test mock override ────────────────────────────────────────────────

# Mapping of IP -> country code set by E2E test hooks
_mock_country_overrides: Dict[str, str] = {}


def set_mock_country(ip: str, country_code: str) -> None:
    """Set a mock country override for an IP (dev/test only)."""
    _mock_country_overrides[ip] = country_code.upper()


def clear_mock_countries() -> int:
    """Clear all mock country overrides."""
    count = len(_mock_country_overrides)
    _mock_country_overrides.clear()
    return count


def get_mock_country(ip: str) -> Optional[str]:
    """Get mock country for an IP, if set."""
    return _mock_country_overrides.get(ip)
