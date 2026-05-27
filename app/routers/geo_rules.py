"""Geo-blocking endpoints (GEO-001).

CRUD for per-content geo-restrictions and utility endpoints for
country listing, my-country lookup, and geo-check dry-run.
Also includes a dev-only mock endpoint for E2E tests.
"""

from __future__ import annotations

import logging
import re
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.models import (
    GeoCheckResult,
    GeoCountriesListOut,
    GeoCountryOut,
    GeoRestrictionOut,
    GeoRestrictionRequest,
    MyCountryOut,
)
from app.services.geoip import clear_cache, lookup_country, get_mock_country
from app.services.geo_check import check_geo_access
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/geo", tags=["geo-blocking"])


# ─── ISO 3166-1 Countries ──────────────────────────────────────────────────

ISO_COUNTRIES: List[dict] = [
    {"code": "AD", "name": "Andorra"},
    {"code": "AE", "name": "United Arab Emirates"},
    {"code": "AF", "name": "Afghanistan"},
    {"code": "AG", "name": "Antigua and Barbuda"},
    {"code": "AI", "name": "Anguilla"},
    {"code": "AL", "name": "Albania"},
    {"code": "AM", "name": "Armenia"},
    {"code": "AO", "name": "Angola"},
    {"code": "AQ", "name": "Antarctica"},
    {"code": "AR", "name": "Argentina"},
    {"code": "AS", "name": "American Samoa"},
    {"code": "AT", "name": "Austria"},
    {"code": "AU", "name": "Australia"},
    {"code": "AW", "name": "Aruba"},
    {"code": "AX", "name": "Aland Islands"},
    {"code": "AZ", "name": "Azerbaijan"},
    {"code": "BA", "name": "Bosnia and Herzegovina"},
    {"code": "BB", "name": "Barbados"},
    {"code": "BD", "name": "Bangladesh"},
    {"code": "BE", "name": "Belgium"},
    {"code": "BF", "name": "Burkina Faso"},
    {"code": "BG", "name": "Bulgaria"},
    {"code": "BH", "name": "Bahrain"},
    {"code": "BI", "name": "Burundi"},
    {"code": "BJ", "name": "Benin"},
    {"code": "BL", "name": "Saint Barthelemy"},
    {"code": "BM", "name": "Bermuda"},
    {"code": "BN", "name": "Brunei Darussalam"},
    {"code": "BO", "name": "Bolivia"},
    {"code": "BQ", "name": "Bonaire, Sint Eustatius and Saba"},
    {"code": "BR", "name": "Brazil"},
    {"code": "BS", "name": "Bahamas"},
    {"code": "BT", "name": "Bhutan"},
    {"code": "BV", "name": "Bouvet Island"},
    {"code": "BW", "name": "Botswana"},
    {"code": "BY", "name": "Belarus"},
    {"code": "BZ", "name": "Belize"},
    {"code": "CA", "name": "Canada"},
    {"code": "CC", "name": "Cocos (Keeling) Islands"},
    {"code": "CD", "name": "Congo, Democratic Republic"},
    {"code": "CF", "name": "Central African Republic"},
    {"code": "CG", "name": "Congo"},
    {"code": "CH", "name": "Switzerland"},
    {"code": "CI", "name": "Cote d'Ivoire"},
    {"code": "CK", "name": "Cook Islands"},
    {"code": "CL", "name": "Chile"},
    {"code": "CM", "name": "Cameroon"},
    {"code": "CN", "name": "China"},
    {"code": "CO", "name": "Colombia"},
    {"code": "CR", "name": "Costa Rica"},
    {"code": "CU", "name": "Cuba"},
    {"code": "CV", "name": "Cabo Verde"},
    {"code": "CW", "name": "Curacao"},
    {"code": "CX", "name": "Christmas Island"},
    {"code": "CY", "name": "Cyprus"},
    {"code": "CZ", "name": "Czechia"},
    {"code": "DE", "name": "Germany"},
    {"code": "DJ", "name": "Djibouti"},
    {"code": "DK", "name": "Denmark"},
    {"code": "DM", "name": "Dominica"},
    {"code": "DO", "name": "Dominican Republic"},
    {"code": "DZ", "name": "Algeria"},
    {"code": "EC", "name": "Ecuador"},
    {"code": "EE", "name": "Estonia"},
    {"code": "EG", "name": "Egypt"},
    {"code": "EH", "name": "Western Sahara"},
    {"code": "ER", "name": "Eritrea"},
    {"code": "ES", "name": "Spain"},
    {"code": "ET", "name": "Ethiopia"},
    {"code": "FI", "name": "Finland"},
    {"code": "FJ", "name": "Fiji"},
    {"code": "FK", "name": "Falkland Islands"},
    {"code": "FM", "name": "Micronesia"},
    {"code": "FO", "name": "Faroe Islands"},
    {"code": "FR", "name": "France"},
    {"code": "GA", "name": "Gabon"},
    {"code": "GB", "name": "United Kingdom"},
    {"code": "GD", "name": "Grenada"},
    {"code": "GE", "name": "Georgia"},
    {"code": "GF", "name": "French Guiana"},
    {"code": "GG", "name": "Guernsey"},
    {"code": "GH", "name": "Ghana"},
    {"code": "GI", "name": "Gibraltar"},
    {"code": "GL", "name": "Greenland"},
    {"code": "GM", "name": "Gambia"},
    {"code": "GN", "name": "Guinea"},
    {"code": "GP", "name": "Guadeloupe"},
    {"code": "GQ", "name": "Equatorial Guinea"},
    {"code": "GR", "name": "Greece"},
    {"code": "GS", "name": "South Georgia"},
    {"code": "GT", "name": "Guatemala"},
    {"code": "GU", "name": "Guam"},
    {"code": "GW", "name": "Guinea-Bissau"},
    {"code": "GY", "name": "Guyana"},
    {"code": "HK", "name": "Hong Kong"},
    {"code": "HM", "name": "Heard Island and McDonald Islands"},
    {"code": "HN", "name": "Honduras"},
    {"code": "HR", "name": "Croatia"},
    {"code": "HT", "name": "Haiti"},
    {"code": "HU", "name": "Hungary"},
    {"code": "ID", "name": "Indonesia"},
    {"code": "IE", "name": "Ireland"},
    {"code": "IL", "name": "Israel"},
    {"code": "IM", "name": "Isle of Man"},
    {"code": "IN", "name": "India"},
    {"code": "IO", "name": "British Indian Ocean Territory"},
    {"code": "IQ", "name": "Iraq"},
    {"code": "IR", "name": "Iran"},
    {"code": "IS", "name": "Iceland"},
    {"code": "IT", "name": "Italy"},
    {"code": "JE", "name": "Jersey"},
    {"code": "JM", "name": "Jamaica"},
    {"code": "JO", "name": "Jordan"},
    {"code": "JP", "name": "Japan"},
    {"code": "KE", "name": "Kenya"},
    {"code": "KG", "name": "Kyrgyzstan"},
    {"code": "KH", "name": "Cambodia"},
    {"code": "KI", "name": "Kiribati"},
    {"code": "KM", "name": "Comoros"},
    {"code": "KN", "name": "Saint Kitts and Nevis"},
    {"code": "KP", "name": "North Korea"},
    {"code": "KR", "name": "South Korea"},
    {"code": "KW", "name": "Kuwait"},
    {"code": "KY", "name": "Cayman Islands"},
    {"code": "KZ", "name": "Kazakhstan"},
    {"code": "LA", "name": "Lao People's Democratic Republic"},
    {"code": "LB", "name": "Lebanon"},
    {"code": "LC", "name": "Saint Lucia"},
    {"code": "LI", "name": "Liechtenstein"},
    {"code": "LK", "name": "Sri Lanka"},
    {"code": "LR", "name": "Liberia"},
    {"code": "LS", "name": "Lesotho"},
    {"code": "LT", "name": "Lithuania"},
    {"code": "LU", "name": "Luxembourg"},
    {"code": "LV", "name": "Latvia"},
    {"code": "LY", "name": "Libya"},
    {"code": "MA", "name": "Morocco"},
    {"code": "MC", "name": "Monaco"},
    {"code": "MD", "name": "Moldova"},
    {"code": "ME", "name": "Montenegro"},
    {"code": "MF", "name": "Saint Martin (French part)"},
    {"code": "MG", "name": "Madagascar"},
    {"code": "MH", "name": "Marshall Islands"},
    {"code": "MK", "name": "North Macedonia"},
    {"code": "ML", "name": "Mali"},
    {"code": "MM", "name": "Myanmar"},
    {"code": "MN", "name": "Mongolia"},
    {"code": "MO", "name": "Macao"},
    {"code": "MP", "name": "Northern Mariana Islands"},
    {"code": "MQ", "name": "Martinique"},
    {"code": "MR", "name": "Mauritania"},
    {"code": "MS", "name": "Montserrat"},
    {"code": "MT", "name": "Malta"},
    {"code": "MU", "name": "Mauritius"},
    {"code": "MV", "name": "Maldives"},
    {"code": "MW", "name": "Malawi"},
    {"code": "MX", "name": "Mexico"},
    {"code": "MY", "name": "Malaysia"},
    {"code": "MZ", "name": "Mozambique"},
    {"code": "NA", "name": "Namibia"},
    {"code": "NC", "name": "New Caledonia"},
    {"code": "NE", "name": "Niger"},
    {"code": "NF", "name": "Norfolk Island"},
    {"code": "NG", "name": "Nigeria"},
    {"code": "NI", "name": "Nicaragua"},
    {"code": "NL", "name": "Netherlands"},
    {"code": "NO", "name": "Norway"},
    {"code": "NP", "name": "Nepal"},
    {"code": "NR", "name": "Nauru"},
    {"code": "NU", "name": "Niue"},
    {"code": "NZ", "name": "New Zealand"},
    {"code": "OM", "name": "Oman"},
    {"code": "PA", "name": "Panama"},
    {"code": "PE", "name": "Peru"},
    {"code": "PF", "name": "French Polynesia"},
    {"code": "PG", "name": "Papua New Guinea"},
    {"code": "PH", "name": "Philippines"},
    {"code": "PK", "name": "Pakistan"},
    {"code": "PL", "name": "Poland"},
    {"code": "PM", "name": "Saint Pierre and Miquelon"},
    {"code": "PN", "name": "Pitcairn"},
    {"code": "PR", "name": "Puerto Rico"},
    {"code": "PS", "name": "Palestine"},
    {"code": "PT", "name": "Portugal"},
    {"code": "PW", "name": "Palau"},
    {"code": "PY", "name": "Paraguay"},
    {"code": "QA", "name": "Qatar"},
    {"code": "RE", "name": "Reunion"},
    {"code": "RO", "name": "Romania"},
    {"code": "RS", "name": "Serbia"},
    {"code": "RU", "name": "Russian Federation"},
    {"code": "RW", "name": "Rwanda"},
    {"code": "SA", "name": "Saudi Arabia"},
    {"code": "SB", "name": "Solomon Islands"},
    {"code": "SC", "name": "Seychelles"},
    {"code": "SD", "name": "Sudan"},
    {"code": "SE", "name": "Sweden"},
    {"code": "SG", "name": "Singapore"},
    {"code": "SH", "name": "Saint Helena"},
    {"code": "SI", "name": "Slovenia"},
    {"code": "SJ", "name": "Svalbard and Jan Mayen"},
    {"code": "SK", "name": "Slovakia"},
    {"code": "SL", "name": "Sierra Leone"},
    {"code": "SM", "name": "San Marino"},
    {"code": "SN", "name": "Senegal"},
    {"code": "SO", "name": "Somalia"},
    {"code": "SR", "name": "Suriname"},
    {"code": "SS", "name": "South Sudan"},
    {"code": "ST", "name": "Sao Tome and Principe"},
    {"code": "SV", "name": "El Salvador"},
    {"code": "SX", "name": "Sint Maarten (Dutch part)"},
    {"code": "SY", "name": "Syrian Arab Republic"},
    {"code": "SZ", "name": "Eswatini"},
    {"code": "TC", "name": "Turks and Caicos Islands"},
    {"code": "TD", "name": "Chad"},
    {"code": "TF", "name": "French Southern Territories"},
    {"code": "TG", "name": "Togo"},
    {"code": "TH", "name": "Thailand"},
    {"code": "TJ", "name": "Tajikistan"},
    {"code": "TK", "name": "Tokelau"},
    {"code": "TL", "name": "Timor-Leste"},
    {"code": "TM", "name": "Turkmenistan"},
    {"code": "TN", "name": "Tunisia"},
    {"code": "TO", "name": "Tonga"},
    {"code": "TR", "name": "Turkey"},
    {"code": "TT", "name": "Trinidad and Tobago"},
    {"code": "TV", "name": "Tuvalu"},
    {"code": "TW", "name": "Taiwan"},
    {"code": "TZ", "name": "Tanzania"},
    {"code": "UA", "name": "Ukraine"},
    {"code": "UG", "name": "Uganda"},
    {"code": "UM", "name": "United States Minor Outlying Islands"},
    {"code": "US", "name": "United States"},
    {"code": "UY", "name": "Uruguay"},
    {"code": "UZ", "name": "Uzbekistan"},
    {"code": "VA", "name": "Holy See"},
    {"code": "VC", "name": "Saint Vincent and the Grenadines"},
    {"code": "VE", "name": "Venezuela"},
    {"code": "VG", "name": "Virgin Islands (British)"},
    {"code": "VI", "name": "Virgin Islands (U.S.)"},
    {"code": "VN", "name": "Viet Nam"},
    {"code": "VU", "name": "Vanuatu"},
    {"code": "WF", "name": "Wallis and Futuna"},
    {"code": "WS", "name": "Samoa"},
    {"code": "YE", "name": "Yemen"},
    {"code": "YT", "name": "Mayotte"},
    {"code": "ZA", "name": "South Africa"},
    {"code": "ZM", "name": "Zambia"},
    {"code": "ZW", "name": "Zimbabwe"},
]

_COUNTRY_CODE_SET = {c["code"] for c in ISO_COUNTRIES}


# ─── Utility endpoints ─────────────────────────────────────────────────────


@router.get("/countries", response_model=GeoCountriesListOut)
def list_countries(user=Depends(require_ui_session)):
    """List all ISO 3166-1 countries for the picker UI."""
    return GeoCountriesListOut(
        countries=[GeoCountryOut(**c) for c in ISO_COUNTRIES]
    )


@router.get("/my-country", response_model=MyCountryOut)
def get_my_country(request: Request, user=Depends(require_ui_session)):
    """Return the viewer's detected country (debugging)."""
    from app.services.geo_check import _get_client_ip

    ip = _get_client_ip(request)

    # Check X-Geo-Country header in dev mode
    if S.dev_mode:
        header_country = request.headers.get("x-geo-country")
        if header_country:
            return MyCountryOut(
                country=header_country.strip().upper(),
                ip=ip,
                source="header_override",
            )

    # Check mock overrides
    mock = get_mock_country(ip)
    if mock:
        return MyCountryOut(country=mock, ip=ip, source="mock_override")

    if not ip or ip in ("127.0.0.1", "::1", "localhost", "testclient"):
        return MyCountryOut(country=None, ip=ip, source="localhost")

    country = lookup_country(ip)
    source = "maxmind" if getattr(S, "geo_maxmind_db_path", "") else "none"
    return MyCountryOut(country=country, ip=ip, source=source)


@router.get("/check")
def check_geo_dry_run(
    request: Request,
    geo_mode: Optional[str] = Query(default=None),
    geo_countries: Optional[str] = Query(default=None, description="Comma-separated country codes"),
    user=Depends(require_ui_session),
):
    """Dry-run a geo-check against the current viewer's IP.

    Allows testing geo rules without applying them to actual content.
    """
    countries_list = None
    if geo_countries:
        countries_list = [c.strip().upper() for c in geo_countries.split(",") if c.strip()]

    try:
        resolved_country = check_geo_access(request, geo_mode, countries_list)
        return GeoCheckResult(
            allowed=True,
            country=resolved_country,
            geo_mode=geo_mode,
        )
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, dict) else {}
        return GeoCheckResult(
            allowed=False,
            country=detail.get("country"),
            geo_mode=geo_mode,
            matched_rule=detail.get("code"),
        )


# ─── Per-video geo CRUD ───────────────────────────────────────────────────


@router.patch("/videos/{video_id}", response_model=GeoRestrictionOut)
def set_video_geo(
    video_id: str,
    body: GeoRestrictionRequest,
    user=Depends(require_ui_session),
):
    """Set geo-restriction on a video."""
    user_sub = user["user_sub"]

    from app.services.video_metadata_store import get_video
    video = get_video(video_id)

    if video.owner_user_id != user_sub:
        raise HTTPException(status_code=403, detail="forbidden")

    update_parts = ["updated_at = :ua"]
    expr_values: dict = {":ua": now_ts()}

    if body.geo_mode is None:
        update_parts.append("geo_mode = :gm")
        expr_values[":gm"] = None
        # Remove geo_countries when mode is cleared
        T.video_metadata.update_item(
            Key={"video_id": video_id},
            UpdateExpression="SET updated_at = :ua REMOVE geo_mode, geo_countries",
            ExpressionAttributeValues={":ua": now_ts()},
        )
        return GeoRestrictionOut(ok=True, geo_mode=None, geo_countries=None)

    update_parts.append("geo_mode = :gm")
    expr_values[":gm"] = body.geo_mode
    update_parts.append("geo_countries = :gc")
    expr_values[":gc"] = body.geo_countries

    T.video_metadata.update_item(
        Key={"video_id": video_id},
        UpdateExpression="SET " + ", ".join(update_parts),
        ExpressionAttributeValues=expr_values,
    )
    return GeoRestrictionOut(
        ok=True, geo_mode=body.geo_mode, geo_countries=body.geo_countries
    )


@router.get("/videos/{video_id}")
def get_video_geo(
    video_id: str,
    user=Depends(require_ui_session),
):
    """Get current geo-restriction settings for a video."""
    from app.services.video_metadata_store import get_video
    video = get_video(video_id)

    # Read raw DDB item to get geo fields
    resp = T.video_metadata.get_item(Key={"video_id": video_id})
    item = resp.get("Item", {})

    return {
        "geo_mode": item.get("geo_mode"),
        "geo_countries": item.get("geo_countries"),
    }


# ─── Per-broadcast geo CRUD ────────────────────────────────────────────────


@router.patch("/broadcasts/{session_id}", response_model=GeoRestrictionOut)
def set_broadcast_geo(
    session_id: str,
    body: GeoRestrictionRequest,
    user=Depends(require_ui_session),
):
    """Set geo-restriction on a broadcast session."""
    user_sub = user["user_sub"]

    resp = T.broadcast_sessions.get_item(Key={"session_id": session_id})
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Broadcast session not found")
    if item.get("created_by") != user_sub:
        raise HTTPException(status_code=403, detail="forbidden")

    if body.geo_mode is None:
        T.broadcast_sessions.update_item(
            Key={"session_id": session_id},
            UpdateExpression="SET updated_at = :ua REMOVE geo_mode, geo_countries",
            ExpressionAttributeValues={":ua": now_ts()},
        )
        return GeoRestrictionOut(ok=True, geo_mode=None, geo_countries=None)

    T.broadcast_sessions.update_item(
        Key={"session_id": session_id},
        UpdateExpression="SET geo_mode = :gm, geo_countries = :gc, updated_at = :ua",
        ExpressionAttributeValues={
            ":gm": body.geo_mode,
            ":gc": body.geo_countries,
            ":ua": now_ts(),
        },
    )
    return GeoRestrictionOut(
        ok=True, geo_mode=body.geo_mode, geo_countries=body.geo_countries
    )


# ─── Per-catalog-item geo CRUD ─────────────────────────────────────────────


@router.patch("/catalog/{item_id}", response_model=GeoRestrictionOut)
def set_catalog_geo(
    item_id: str,
    body: GeoRestrictionRequest,
    user=Depends(require_ui_session),
):
    """Set geo-restriction on a catalog item."""
    user_sub = user["user_sub"]

    pk = f"ITEM#{item_id}"
    resp = T.catalog.get_item(Key={"PK": pk, "SK": pk})
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Catalog item not found")
    if item.get("created_by") != user_sub and item.get("owner_user_id") != user_sub:
        raise HTTPException(status_code=403, detail="forbidden")

    if body.geo_mode is None:
        T.catalog.update_item(
            Key={"PK": pk, "SK": pk},
            UpdateExpression="SET updated_at = :ua REMOVE geo_mode, geo_countries",
            ExpressionAttributeValues={":ua": now_ts()},
        )
        return GeoRestrictionOut(ok=True, geo_mode=None, geo_countries=None)

    T.catalog.update_item(
        Key={"PK": pk, "SK": pk},
        UpdateExpression="SET geo_mode = :gm, geo_countries = :gc, updated_at = :ua",
        ExpressionAttributeValues={
            ":gm": body.geo_mode,
            ":gc": body.geo_countries,
            ":ua": now_ts(),
        },
    )
    return GeoRestrictionOut(
        ok=True, geo_mode=body.geo_mode, geo_countries=body.geo_countries
    )


# ─── Dev/test mock endpoints ───────────────────────────────────────────────


@router.post("/mock-country")
def set_mock_geo_country(
    request: Request,
    user=Depends(require_ui_session),
):
    """Set a mock country for an IP (dev mode E2E testing only).

    Body: { "ip": "1.2.3.4", "country_code": "US" }
    """
    if not S.dev_mode:
        raise HTTPException(status_code=404, detail="Not found")

    import json
    body = json.loads(request._body.decode() if hasattr(request, "_body") else "{}")

    # Accept body from request
    return {"detail": "Use X-Geo-Country header for per-request overrides in dev mode"}


@router.post("/clear-cache")
def clear_geo_cache(user=Depends(require_ui_session)):
    """Clear the GeoIP cache (dev/admin utility)."""
    count = clear_cache()
    return {"ok": True, "evicted": count}
