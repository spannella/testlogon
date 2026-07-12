"""EVT-005 + EVT-006: CRM Geocoding service.

Provides address-to-lat/lng geocoding (EVT-005) and Haversine-based
proximity search (EVT-006) for platform address book entries.

RULE-1: This module owns crm_geocoding.  It does NOT re-create the KYC
address-verification service; it duplicates only the 10-line deterministic
fingerprint/mock-geocoder logic to avoid a KYC→CRM import dependency.
"""

from __future__ import annotations

import hashlib
import logging
import math
from decimal import Decimal
from typing import Any, Optional

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Address fingerprint (duplicated from kyc_address_verification — intentional,
# per EVT-005 §10 open question #2: avoid KYC→CRM import coupling).
# ---------------------------------------------------------------------------

def _normalize_line(v: Any) -> str:
    return (str(v).strip().upper() if v else "")

def _normalize_city(v: Any) -> str:
    return (str(v).strip().upper() if v else "")

def _normalize_state(v: Any) -> str:
    return (str(v).strip().upper() if v else "")

def _normalize_postal(v: Any) -> str:
    return (str(v).strip().upper() if v else "")

def _normalize_country(v: Any) -> str:
    return (str(v).strip().upper() if v else "")


def _address_fingerprint_crm(address: dict) -> str:
    """Stable, normalised string fingerprint of an address.

    Accepts both ``line1``/``line2`` and ``line_1``/``line_2`` variants.
    Pipe-delimited, same normalisation as KYC fingerprint.
    """
    parts = [
        _normalize_line(address.get("line_1") or address.get("line1")),
        _normalize_line(address.get("line_2") or address.get("line2")),
        _normalize_city(address.get("city")),
        _normalize_state(address.get("state")),
        _normalize_postal(address.get("postal_code")),
        _normalize_country(address.get("country")),
    ]
    return "|".join(parts)


# ---------------------------------------------------------------------------
# EVT-005: geocode_address
# ---------------------------------------------------------------------------

def geocode_address(address: dict) -> Optional[dict]:
    """Return ``{"lat": float, "lng": float}`` or ``None``.

    When ``S.crm_geocoding_provider_url`` is empty (the default) the result
    is a deterministic SHA-256 mock — same byte-for-byte logic as
    ``kyc_address_verification._geocode`` (lines 218–224).  When a provider
    URL is configured the function issues a synchronous HTTP GET to that URL
    (Nominatim JSON shape: ``[{"lat": "...", "lon": "..."}]``).

    Returns ``None`` immediately when ``S.crm_geocoding_enabled`` is ``False``
    or when the fingerprint is entirely blank (empty address).
    """
    if not S.crm_geocoding_enabled:
        return None

    fp = _address_fingerprint_crm(address)
    if not any(fp.split("|")):
        # All six parts are empty strings — nothing to geocode.
        return None

    if not S.crm_geocoding_provider_url:
        # --- deterministic SHA-256 mock (SECOPS-007: no dev_mode branch) ---
        digest = hashlib.sha256(fp.encode("utf-8")).digest()
        lat_raw = int.from_bytes(digest[0:4], "big")
        lng_raw = int.from_bytes(digest[4:8], "big")
        lat = round((lat_raw % 180_000_000) / 1_000_000.0 - 90.0, 6)
        lng = round((lng_raw % 360_000_000) / 1_000_000.0 - 180.0, 6)
        return {"lat": lat, "lng": lng}

    # --- real provider path (Nominatim JSON) ---------------------------------
    try:
        import requests  # lazy import — only needed on the prod path

        params: dict[str, str] = {}
        if address.get("line1") or address.get("line_1"):
            params["street"] = str(address.get("line1") or address.get("line_1"))
        if address.get("city"):
            params["city"] = str(address["city"])
        if address.get("state"):
            params["state"] = str(address["state"])
        if address.get("postal_code"):
            params["postalcode"] = str(address["postal_code"])
        if address.get("country"):
            params["country"] = str(address["country"])
        params["format"] = "json"

        resp = requests.get(S.crm_geocoding_provider_url, params=params, timeout=5)
        if resp.status_code != 200:
            return None
        data = resp.json()
        if not data or not isinstance(data, list):
            return None
        first = data[0]
        return {"lat": float(first["lat"]), "lng": float(first["lon"])}
    except Exception as exc:
        logger.warning("crm_geocoding: provider request failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# EVT-005: apply_geocode_to_address
# ---------------------------------------------------------------------------

def apply_geocode_to_address(user_sub: str, address_id: str) -> Optional[dict]:
    """Read address from DDB, geocode it, write lat/lng/geocoded_at back.

    Returns the updated item dict or ``None`` if geocoding produced no result.
    Never raises — all DDB and network errors are caught and logged.
    """
    try:
        item = T.addresses.get_item(
            Key={"user_sub": user_sub, "address_id": address_id}
        ).get("Item")
        if not item:
            return None

        result = geocode_address(item)
        if result is None:
            return None

        ts = now_ts()
        # DynamoDB requires Decimal for numeric attributes, not float.
        T.addresses.update_item(
            Key={"user_sub": user_sub, "address_id": address_id},
            UpdateExpression="SET lat = :lat, lng = :lng, geocoded_at = :ts",
            ExpressionAttributeValues={
                ":lat": Decimal(str(result["lat"])),
                ":lng": Decimal(str(result["lng"])),
                ":ts": ts,
            },
        )

        # Best-effort audit
        try:
            from app.services.alerts import audit_event  # lazy import
            audit_event(
                "crm_address_geocoded",
                user_sub,
                address_id=address_id,
                lat=result["lat"],
                lng=result["lng"],
            )
        except Exception:
            pass

        # Return the updated item
        updated = dict(item)
        updated.update({"lat": result["lat"], "lng": result["lng"], "geocoded_at": ts})
        return updated

    except Exception as exc:
        logger.warning(
            "apply_geocode_to_address failed for %s/%s: %s", user_sub, address_id, exc
        )
        return None


# ---------------------------------------------------------------------------
# EVT-005: geocode_party_address (soft dependency on PTY-001)
# ---------------------------------------------------------------------------

def geocode_party_address(party_id: str, address: dict) -> None:
    """Write lat/lng/geocoded_at onto a party record if T.party is available.

    Skips entirely (no exception) when:
    - S.crm_geocoding_enabled is False
    - T.party handle is absent or None (PTY-001 not yet merged)
    - geocode_address returns None
    - any DDB error occurs
    """
    if not S.crm_geocoding_enabled:
        return
    if not getattr(S, "party_crm_enabled", False):
        return
    party_table = getattr(T, "party", None)
    if party_table is None:
        return
    try:
        result = geocode_address(address)
        if result is None:
            return
        ts = now_ts()
        party_table.update_item(
            Key={"party_id": party_id},
            UpdateExpression="SET lat = :lat, lng = :lng, geocoded_at = :ts",
            ExpressionAttributeValues={
                ":lat": Decimal(str(result["lat"])),
                ":lng": Decimal(str(result["lng"])),
                ":ts": ts,
            },
        )
    except Exception as exc:
        logger.warning("geocode_party_address: failed for %s: %s", party_id, exc)


# ---------------------------------------------------------------------------
# EVT-005: list_geocoded_addresses
# ---------------------------------------------------------------------------

def list_geocoded_addresses(user_sub: str) -> list[dict]:
    """Return all of user_sub's address items that carry both lat and lng.

    Implements a full LastEvaluatedKey pagination loop (list_addresses in
    addresses.py is a single query call with no loop; we cannot reuse it).
    """
    items: list[dict] = []
    kwargs: dict[str, Any] = {
        "KeyConditionExpression": Key("user_sub").eq(user_sub),
    }
    while True:
        resp = T.addresses.query(**kwargs)
        items.extend(resp.get("Items", []))
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        kwargs["ExclusiveStartKey"] = lek

    return [item for item in items if "lat" in item and "lng" in item]


# ---------------------------------------------------------------------------
# EVT-006: haversine_km
# ---------------------------------------------------------------------------

def haversine_km(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    """Great-circle distance in kilometres using the Haversine formula.

    R = 6371.0 km (IUGG mean Earth radius).
    Pure Python, no third-party dependencies.
    Numerically stable at antipodal points (atan2(1, 0) = π/2).
    """
    R = 6371.0
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lng2 - lng1)
    a = (
        math.sin(dphi / 2) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    )
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(max(0.0, 1 - a)))


# ---------------------------------------------------------------------------
# EVT-006: rate_limit_proximity_search
# ---------------------------------------------------------------------------

def rate_limit_proximity_search(user_sub: str) -> None:
    """Raise HTTPException(429) when rate limit is exceeded.

    Uses _bucket_limit from app.services.rate_limit (lazy import).
    Window/caps are env-configurable via Settings.
    """
    from app.services.rate_limit import _bucket_limit  # lazy import (Rule-1)
    from fastapi import HTTPException

    ok = _bucket_limit(
        user_sub,
        f"prox_search:{user_sub}",
        S.crm_proximity_search_rate_limit_n,
        S.crm_proximity_search_rate_limit_win,
    )
    if not ok:
        raise HTTPException(
            429, "Proximity search rate limit exceeded; try again shortly"
        )


# ---------------------------------------------------------------------------
# EVT-006: proximity_search
# ---------------------------------------------------------------------------

def proximity_search(
    user_sub: str,
    center_lat: float,
    center_lng: float,
    radius_km: float,
    limit: int = 50,
    entity_type: str = "address",
) -> list[dict]:
    """Return items within radius_km of (center_lat, center_lng), sorted ascending.

    entity_type="address" (always available):
        Queries T.addresses for user_sub, keeps only geocoded items, applies
        Haversine filter, sorts, slices to limit.

    entity_type="party" (post-PTY-001):
        Returns [] when T.party is absent (hasattr guard).

    Raises ValueError for unknown entity_type or radius out of range.
    Returns [] immediately when flags are off.
    """
    if not S.crm_proximity_search_enabled or not S.crm_geocoding_enabled:
        return []

    if not (0 <= radius_km <= S.crm_proximity_search_max_radius_km):
        raise ValueError(
            f"radius_km must be between 0 and {S.crm_proximity_search_max_radius_km}"
        )

    if entity_type == "address":
        return _proximity_search_addresses(
            user_sub, center_lat, center_lng, radius_km, limit
        )
    elif entity_type == "party":
        return _proximity_search_party(
            user_sub, center_lat, center_lng, radius_km, limit
        )
    else:
        raise ValueError(f"Unknown entity_type: {entity_type}")


def _proximity_search_addresses(
    user_sub: str,
    center_lat: float,
    center_lng: float,
    radius_km: float,
    limit: int,
) -> list[dict]:
    # Fetch all geocoded addresses for the user (paginated loop).
    geocoded = list_geocoded_addresses(user_sub)

    results: list[dict] = []
    for item in geocoded:
        try:
            lat = float(item["lat"])
            lng = float(item["lng"])
        except (KeyError, TypeError, ValueError):
            continue
        dist = haversine_km(center_lat, center_lng, lat, lng)
        if dist <= radius_km:
            results.append({
                "entity_type": "address",
                "entity_id": item.get("address_id", ""),
                "name": item.get("line1") or item.get("address_id", ""),
                "lat": lat,
                "lng": lng,
                "distance_km": round(dist, 3),
                "address_id": item.get("address_id"),
                "city": item.get("city"),
                "country": item.get("country"),
            })

    results.sort(key=lambda r: r["distance_km"])
    return results[:limit]


def _proximity_search_party(
    user_sub: str,
    center_lat: float,
    center_lng: float,
    radius_km: float,
    limit: int,
) -> list[dict]:
    """Party proximity search — requires PTY-001 to be merged (T.party present)."""
    if not getattr(S, "party_crm_enabled", False):
        return []
    party_table = getattr(T, "party", None)
    if party_table is None:
        return []

    try:
        items: list[dict] = []
        kwargs: dict[str, Any] = {
            "KeyConditionExpression": Key("user_sub").eq(user_sub),
        }
        while True:
            resp = party_table.query(**kwargs)
            items.extend(resp.get("Items", []))
            lek = resp.get("LastEvaluatedKey")
            if not lek:
                break
            kwargs["ExclusiveStartKey"] = lek

        results: list[dict] = []
        for item in items:
            if "lat" not in item or "lng" not in item:
                continue
            try:
                lat = float(item["lat"])
                lng = float(item["lng"])
            except (TypeError, ValueError):
                continue
            dist = haversine_km(center_lat, center_lng, lat, lng)
            if dist <= radius_km:
                results.append({
                    "entity_type": "party",
                    "entity_id": item.get("party_id", ""),
                    "name": item.get("display_name") or item.get("party_id", ""),
                    "lat": lat,
                    "lng": lng,
                    "distance_km": round(dist, 3),
                    "address_id": None,
                    "city": item.get("city"),
                    "country": item.get("country"),
                })

        results.sort(key=lambda r: r["distance_km"])
        return results[:limit]
    except Exception as exc:
        logger.warning("proximity_search_party failed: %s", exc)
        return []
