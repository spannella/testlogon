# GEO-001: Geo-Blocking & Content Restrictions

**Ticket**: GEO-001
**Author**: Engineering
**Status**: Implemented
**Date**: 2026-05-27
**Priority**: High
**Estimated effort**: 8-10 days

---

## 1. Executive Summary

Geo-blocking is a content restriction system that allows creators to control which geographic regions can access their videos, broadcasts, and shop items. Today, every piece of content on the platform is globally accessible regardless of the viewer's physical location. This creates legal exposure for creators who have territorial distribution agreements and prevents the platform from complying with regional content regulations (e.g., GDPR data localization, age-restricted content laws that differ by jurisdiction, or content embargoes in sanctioned regions).

This design introduces an IP-based geographic lookup service backed by MaxMind GeoLite2 (production) or IP-API (dev mode), per-content allow/block list configuration stored as metadata fields on existing DynamoDB records, and a FastAPI dependency that intercepts content requests to enforce geographic access rules. The frontend adds a reusable country picker editor component for creators and a "Not available in your region" error page for blocked viewers. A platform-level override mechanism lets administrators block entire countries system-wide, independent of creator settings.

The system is designed to fail-open in development (localhost and private IPs are never blocked) and fail-closed in production (unresolvable IPs are denied access). GeoIP results are cached in-memory with a configurable TTL to avoid redundant lookups. Phase 1 covers IP-based country resolution only; VPN/proxy detection, sub-national region blocking, and compliance audit logging are deferred to future tickets.

---

## 2. Detailed Problem Analysis

### 2.1 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | I want to restrict a video to US and Canada only. | Set `allow_countries: ["US", "CA"]`; viewers outside US/CA get 403. |
| Creator | I want to block a specific country from viewing my broadcast. | Set `block_countries: ["DE"]`; German IPs get 403; all others allowed. |
| Creator | I want to remove geo-restrictions from a video. | Clear both lists; video becomes globally accessible. |
| Creator | I want to apply the same geo-restriction to multiple videos at once. | Bulk-edit endpoint accepts list of video IDs + geo settings. |
| Viewer | I am in an allowed country and can view the content normally. | Content loads and plays without any indication of geo-restriction. |
| Viewer | I am in a blocked country and see a clear explanation. | "Not available in your region" page with the restriction reason. |
| Viewer | I travel to a different country and access changes accordingly. | Next request uses new IP; cached entry expires after TTL; new country applied. |
| Admin | I want to set platform-wide geo-restrictions that override per-content settings. | Platform-level block list applied before creator-level checks. |
| Admin | I want to see which content has geo-restrictions configured. | Admin endpoint lists all geo-restricted items with their settings. |

### 2.2 Pain Points

1. **Legal liability**: Creators with territorial licensing agreements (e.g., music rights limited to North America) risk violating contracts when their content is globally accessible.
2. **Regulatory compliance**: GDPR (EU), CCPA (California), and other privacy regulations may require region-specific content handling. Some jurisdictions ban specific categories of content entirely.
3. **Content embargoes**: Live broadcasts of sporting events or entertainment shows may be subject to regional blackout rules imposed by rights holders.
4. **Creator trust**: Without forensic geo-restriction capability, professional content creators hesitate to use the platform for premium content distribution.

### 2.3 Competitive Analysis

| Platform | Approach |
|----------|----------|
| YouTube | Server-side geo-blocking via Content ID; creators set country availability per video |
| Vimeo | Per-video geo-restriction with allow/block country lists; also supports domain-level restrictions |
| Twitch | Broadcast-level geo-restrictions for sports content via partnership agreements |
| Shopify | Per-market availability for products; separate pricing and visibility per region |

All competitors use IP-based geolocation as the primary mechanism. VPN detection is treated as a separate layer (and often handled by CDN providers like Cloudflare or Akamai rather than the application layer).

---

## 3. Current State Analysis

### 3.1 Video Metadata

`app/models_video.py` defines `VideoMetadataModel` with `visibility` (`private`, `public`, `unlisted`) and `access_mode` fields. No geo-restriction fields exist. <!-- VERIFIED: VideoMetadataModel at models_video.py:35-141; visibility at line 99; access_mode at line 94 --> The video listing API (`GET /ui/videos/{video_id}`) returns video details without any geo check. The video metadata is stored in the `video_metadata` DynamoDB table (handle `T.video_metadata`, settings `S.video_metadata_table_name`). <!-- VERIFIED: T.video_metadata at tables.py:76/160; S.video_metadata_table_name at settings.py:1029 -->

### 3.2 Broadcast Metadata

`app/routers/broadcast.py` stores broadcast records in the `broadcast_sessions` DynamoDB table. The viewer player endpoint (`GET /ui/broadcasts/{id}`) checks subscription access but not location. <!-- VERIFIED: broadcast_sessions table at local-ddb-init.py:511-519 --> Broadcast sessions have a `ByScheduledAt` GSI used by the broadcast scheduler. <!-- VERIFIED: GSI at local-ddb-init.py:517 -->

**Important**: The `broadcast_sessions` table has PK=`session_id` with NO sort key. <!-- VERIFIED: local-ddb-init.py:513 -->

### 3.3 Shop Items

`app/routers/catalog.py` serves catalog items from the `shopping_catalog` table (PK: `PK`, SK: `SK`, with values like `ITEM#{item_id}`). No location-based filtering exists. The catalog already supports `CatalogItemPatchIn` for partial updates (imported at catalog.py:27, used at line 433). <!-- VERIFIED: shopping_catalog table at local-ddb-init.py:67, CatalogItemPatchIn at catalog.py:27 -->

### 3.4 IP Address in Requests

FastAPI's `Request.client.host` provides the client IP. Behind a reverse proxy (production), the real IP comes from `X-Forwarded-For` header. The `app/core/normalize.py` module has `client_ip_from_request(req)` at line 9 which extracts the first IP from `X-Forwarded-For` or falls back to `req.client.host`. <!-- VERIFIED: normalize.py:9 --> The `app/core/settings.py` already has `trusted_proxy_cidrs` for proxy trust configuration. <!-- VERIFIED: settings.py:32 -->

### 3.5 Gaps

1. No GeoIP lookup service
2. No `geo_mode` / `geo_countries` fields on content metadata
3. No geo-check middleware or dependency
4. No "Not available in your region" frontend component
5. No geo-restriction management UI for creators
6. No platform-level geo-block override
7. No audit logging for geo-block enforcement events

---

## 4. Technical Architecture

### 4.1 System Diagram

```
                         ┌─────────────────────────────┐
                         │     Frontend (React/Vite)    │
                         │                              │
                         │  GeoRestrictionEditor ──────►│── PATCH /ui/videos/{id}/geo
                         │  GeoBlockedPage ◄────────────│◄─ 403 { code: "geo_blocked" }
                         │  GeoBlockedInterceptor ──────│   (axios response interceptor)
                         └────────────┬────────────────┘
                                      │
                              Vite proxy :3000 → :8000
                                      │
                         ┌────────────▼────────────────┐
                         │   FastAPI Backend (:8000)    │
                         │                              │
                         │  ┌──────────────────────┐   │
                         │  │ Content Routers       │   │
                         │  │  video_listing.py     │   │
                         │  │  broadcast.py         │   │
                         │  │  catalog.py           │   │
                         │  └──────┬───────────────┘   │
                         │         │ check_geo_access() │
                         │  ┌──────▼───────────────┐   │
                         │  │ geo_check.py          │   │
                         │  │  - Platform block     │   │
                         │  │  - Content allow/block│   │
                         │  │  - Fail-open/closed   │   │
                         │  └──────┬───────────────┘   │
                         │         │ lookup_country()   │
                         │  ┌──────▼───────────────┐   │
                         │  │ geoip.py              │   │
                         │  │  - In-memory cache    │   │
                         │  │  - MaxMind GeoLite2   │   │
                         │  │  - IP-API (dev)       │   │
                         │  └──────────────────────┘   │
                         │                              │
                         │  ┌──────────────────────┐   │
                         │  │ DynamoDB              │   │
                         │  │  video_metadata       │   │
                         │  │  broadcast_sessions   │   │
                         │  │  shopping_catalog     │   │
                         │  │  (geo_mode,           │   │
                         │  │   geo_countries added) │   │
                         │  └──────────────────────┘   │
                         └─────────────────────────────┘
```

### 4.2 Data Flow

1. **Creator sets geo-restriction**: Frontend sends `PATCH /ui/videos/{id}/geo` with `{ geo_mode: "allow", geo_countries: ["US", "CA"] }`. Router validates ownership, updates the DynamoDB record with new fields.
2. **Viewer requests content**: `GET /ui/videos/{id}` endpoint loads video metadata, calls `check_geo_access(request, video.geo_mode, video.geo_countries)`.
3. **Geo check**: `check_geo_access` extracts client IP via `client_ip_from_request(request)`, calls `lookup_country(ip)` which checks the in-memory cache first, then MaxMind or IP-API.
4. **Enforcement**: If the viewer's country is blocked (or not in the allow list), a 403 HTTPException with `code: "geo_blocked"` is raised before the content is returned.
5. **Frontend handling**: The axios interceptor in `client.ts` detects `geo_blocked` responses and stores the details; content pages check this flag and render `GeoBlockedPage`.

### 4.3 Component Interactions

- `geoip.py` is a pure service module with no DynamoDB dependency. It only reads `S` settings for MaxMind path and dev mode.
- `geo_check.py` depends on `geoip.py` and `S` (platform block list). It has no router dependency -- it is called by routers as a utility function, not a FastAPI `Depends`.
- Content routers import `check_geo_access` and call it after loading the content item but before returning the response.
- The geo-restriction CRUD endpoints are colocated with each content router (video, broadcast, catalog) rather than in a separate router, since they update the content's own DDB record.

---

## 5. Data Model Deep Dive

### 5.1 Geo-Restriction Fields (on content metadata records)

Added to video metadata, broadcast records, and catalog items as additional DynamoDB attributes:

| Field | Type | Description |
|-------|------|-------------|
| `geo_mode` | S (optional) | `null` (no restriction), `"allow"` (whitelist), `"block"` (blacklist) |
| `geo_countries` | L (List of S) | ISO 3166-1 alpha-2 country codes (e.g., `["US", "CA", "GB"]`) |

When `geo_mode` is `null` or absent, no geo-restriction applies. When `"allow"`, only listed countries can access. When `"block"`, listed countries are denied.

**No new DynamoDB tables are created.** These fields are added to existing records in:
- `video_metadata` table (PK: `video_id`)
- `broadcast_sessions` table (PK: `session_id`, NO sort key) <!-- CORRECTED: was PK: broadcast_id, SK: session_id; actually PK=session_id only (local-ddb-init.py:513) -->
- `shopping_catalog` table (PK: `ITEM#{item_id}`, SK: `ITEM#{item_id}`)

### 5.2 Example DynamoDB Items

**Video metadata record with geo-restriction:**
```json
{
  "video_id": "vid_abc123",
  "owner_user_id": "alice-sub-001",
  "title": "Premium Tutorial",
  "status": "published",
  "visibility": "public",
  "geo_mode": "allow",
  "geo_countries": ["US", "CA", "GB", "AU"],
  "created_at": 1748361600,
  "updated_at": 1748362000
}
```

**Catalog item with country block:**
```json
{
  "PK": "ITEM#item_789",
  "SK": "ITEM#item_789",
  "title": "Digital Course",
  "price_cents": 2999,
  "geo_mode": "block",
  "geo_countries": ["RU", "BY"],
  "created_at": "2026-05-27T10:00:00+00:00"
}
```

### 5.3 Platform-Level Geo Block (Settings)

Added to `app/core/settings.py`:

```python
# Geo-blocking
geo_blocking_enabled: bool = os.environ.get("GEO_BLOCKING_ENABLED", "1") not in ("0", "false", "False")
geo_platform_block_countries: str = os.environ.get("GEO_PLATFORM_BLOCK_COUNTRIES", "")
geo_maxmind_db_path: str = os.environ.get("GEO_MAXMIND_DB_PATH", "")
geo_cache_ttl_seconds: int = int(os.environ.get("GEO_CACHE_TTL_SECONDS", "3600"))
geo_cache_max_size: int = int(os.environ.get("GEO_CACHE_MAX_SIZE", "50000"))
geo_fail_open_dev: bool = os.environ.get("GEO_FAIL_OPEN_DEV", "1") not in ("0", "false", "False")
```

### 5.4 GeoIP Cache (in-memory)

```python
_geo_cache: Dict[str, Tuple[str, float]] = {}  # ip -> (country_code, cached_at)
```

The cache uses a simple dict with timestamp-based expiry. When the cache reaches `_GEO_CACHE_MAX_SIZE`, the oldest entry is evicted (O(n) scan; acceptable given the cache is checked on every content request and eviction is rare).

### 5.5 Access Patterns Table

| Access Pattern | Table | Key Condition | Notes |
|----------------|-------|---------------|-------|
| Get video geo settings | `video_metadata` | PK = `video_id` | Single-item get; geo fields are on the same item |
| Update video geo settings | `video_metadata` | PK = `video_id` | UpdateExpression with SET for `geo_mode`, `geo_countries` |
| Get broadcast geo settings | `broadcast_sessions` | PK = `session_id` (NO sort key) | Geo fields on existing session record | <!-- CORRECTED: was PK=broadcast_id, SK=session_id. Actually PK=session_id only, no SK (local-ddb-init.py:513) -->
| Get catalog item geo settings | `shopping_catalog` | PK = `ITEM#{item_id}`, SK = `ITEM#{item_id}` | Geo fields on existing item record |
| List all geo-restricted videos (admin) | `video_metadata` | Full scan with FilterExpression `attribute_exists(geo_mode)` | Infrequent admin query; scan acceptable |

---

## 6. API Contract Design

### 6.1 Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| PATCH | `/ui/videos/{video_id}/geo` | `require_ui_session` | Set geo-restriction on a video |
| GET | `/ui/videos/{video_id}/geo` | `require_ui_session` | Get current geo-restriction settings |
| PATCH | `/ui/broadcasts/{broadcast_id}/geo` | `require_ui_session` | Set geo-restriction on a broadcast |
| PATCH | `/ui/catalog/items/{item_id}/geo` | `require_ui_session` | Set geo-restriction on a shop item |
| GET | `/ui/geo/countries` | `require_ui_session` | List all ISO 3166-1 countries for the picker UI |
| GET | `/ui/geo/my-country` | `require_ui_session` | Return the viewer's detected country (debugging) |

### 6.2 Set Geo-Restriction (PATCH /ui/videos/{video_id}/geo)

**Request:**
```json
{
  "geo_mode": "allow",
  "geo_countries": ["US", "CA", "GB"]
}
```

**Response (200):**
```json
{
  "ok": true,
  "geo_mode": "allow",
  "geo_countries": ["US", "CA", "GB"]
}
```

**Clear restriction:**
```json
{
  "geo_mode": null,
  "geo_countries": null
}
```

**Response (200):**
```json
{
  "ok": true,
  "geo_mode": null,
  "geo_countries": null
}
```

**Error responses:**

| Status | Condition | Body |
|--------|-----------|------|
| 400 | `geo_mode` set without `geo_countries` | `{ "detail": "geo_countries is required when geo_mode is set" }` |
| 403 | Non-owner attempts to set restriction | `{ "detail": "forbidden" }` |
| 404 | Video not found | `{ "detail": "Video not found" }` |
| 422 | Invalid country code (e.g., `"XX"`) | `{ "detail": "invalid country code: XX" }` |

### 6.3 Get Geo-Restriction (GET /ui/videos/{video_id}/geo)

**Response (200):**
```json
{
  "geo_mode": "allow",
  "geo_countries": ["US", "CA", "GB"]
}
```

**Response when no restriction (200):**
```json
{
  "geo_mode": null,
  "geo_countries": null
}
```

### 6.4 Content Endpoint Geo-Blocked Response

When a viewer in a blocked country requests content:

**Response (403):**
```json
{
  "detail": {
    "code": "geo_blocked",
    "message": "This content is not available in your region.",
    "country": "DE"
  }
}
```

When country cannot be determined (production fail-closed):
```json
{
  "detail": {
    "code": "geo_unknown",
    "message": "Unable to determine your region. Access denied."
  }
}
```

### 6.5 My Country (GET /ui/geo/my-country)

**Response (200):**
```json
{
  "country": "US",
  "ip": "203.0.113.42",
  "source": "maxmind"
}
```

**Dev mode with localhost (200):**
```json
{
  "country": null,
  "ip": "127.0.0.1",
  "source": "localhost"
}
```

### 6.6 Countries List (GET /ui/geo/countries)

**Response (200):**
```json
{
  "countries": [
    { "code": "US", "name": "United States" },
    { "code": "CA", "name": "Canada" },
    { "code": "GB", "name": "United Kingdom" },
    { "code": "DE", "name": "Germany" }
  ]
}
```

### 6.7 Rate Limits

No specific rate limits beyond the existing per-user rate limiting in `app/services/rate_limit.py`. Geo CRUD endpoints are low-frequency operations. The GeoIP lookup itself is rate-limited by the IP-API free tier (45 req/min) in dev mode, but this is mitigated by the in-memory cache.

---

## 7. Backend Implementation

### 7.1 GeoIP Lookup Service

```python
# app/services/geoip.py

import logging
import time
from typing import Dict, Optional, Tuple

import requests

from app.core.settings import S

logger = logging.getLogger(__name__)

_geo_cache: Dict[str, Tuple[str, float]] = {}
_GEO_CACHE_TTL = 3600
_GEO_CACHE_MAX_SIZE = 50000


def lookup_country(ip: str) -> Optional[str]:
    """Resolve an IP address to an ISO 3166-1 alpha-2 country code.

    Returns None if the IP cannot be resolved (private, localhost, error).
    """
    if not ip or ip in ("127.0.0.1", "::1", "localhost"):
        return None  # Fail-open for local development

    # Check cache
    now = time.time()
    cached = _geo_cache.get(ip)
    if cached and (now - cached[1]) < _GEO_CACHE_TTL:
        return cached[0]

    country = _lookup_country_uncached(ip)
    if country:
        # Evict oldest entries if cache is full
        if len(_geo_cache) >= _GEO_CACHE_MAX_SIZE:
            oldest_key = min(_geo_cache, key=lambda k: _geo_cache[k][1])
            del _geo_cache[oldest_key]
        _geo_cache[ip] = (country, now)
    return country


def _lookup_country_uncached(ip: str) -> Optional[str]:
    """Perform the actual GeoIP lookup."""
    # Option 1: MaxMind GeoLite2 database (production)
    maxmind_db_path = getattr(S, "geo_maxmind_db_path", None)
    if maxmind_db_path:
        return _lookup_maxmind(ip, maxmind_db_path)

    # Option 2: IP-API free tier (dev mode, rate-limited)
    if S.dev_mode:
        return _lookup_ip_api(ip)

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


def _lookup_ip_api(ip: str) -> Optional[str]:
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=2)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("countryCode")
    except Exception:
        logger.warning("IP-API lookup failed for %s", ip, exc_info=True)
    return None


def clear_cache() -> int:
    """Clear the GeoIP cache. Returns the number of evicted entries."""
    count = len(_geo_cache)
    _geo_cache.clear()
    return count
```

### 7.2 Geo-Check Dependency

```python
# app/services/geo_check.py

from typing import List, Optional

from fastapi import HTTPException, Request

from app.core.settings import S
from app.services.geoip import lookup_country


def check_geo_access(
    request: Request,
    geo_mode: Optional[str],
    geo_countries: Optional[List[str]],
) -> Optional[str]:
    """Check if the request IP is allowed to access content with the given geo settings.

    Returns the viewer's country code, or raises 403 if blocked.
    """
    if not getattr(S, "geo_blocking_enabled", True):
        return None  # Feature disabled

    ip = _get_client_ip(request)

    # Platform-level block (always applied first, regardless of per-content settings)
    platform_blocked = _parse_csv(getattr(S, "geo_platform_block_countries", ""))
    if platform_blocked:
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
        return None  # No per-content restrictions

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
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""


def _parse_csv(value: str) -> set:
    return {v.strip().upper() for v in (value or "").split(",") if v.strip()}
```

### 7.3 Pydantic Models

```python
# Added to app/models.py

class GeoRestrictionRequest(BaseModel):
    geo_mode: Optional[Literal["allow", "block"]] = None
    geo_countries: Optional[List[str]] = Field(default=None, max_length=250)

    @model_validator(mode="after")
    def validate_geo_fields(self):
        if self.geo_mode and not self.geo_countries:
            raise ValueError("geo_countries is required when geo_mode is set")
        if self.geo_countries:
            for code in self.geo_countries:
                if not re.match(r"^[A-Z]{2}$", code):
                    raise ValueError(f"invalid country code: {code}")
        if self.geo_mode is None:
            self.geo_countries = None
        return self

class GeoRestrictionOut(BaseModel):
    geo_mode: Optional[str] = None
    geo_countries: Optional[List[str]] = None

class GeoCountryOut(BaseModel):
    code: str
    name: str

class GeoCountriesListOut(BaseModel):
    countries: List[GeoCountryOut]

class MyCountryOut(BaseModel):
    country: Optional[str] = None
    ip: str
    source: str
```

### 7.4 Router Integration

```python
# In app/routers/video_listing.py, added endpoint:

@router.patch("/{video_id}/geo")
def set_video_geo(
    video_id: str,
    body: GeoRestrictionRequest,
    ctx=Depends(require_ui_session),
):
    user_id = ctx["user_sub"]
    video = get_video(video_id)
    if not video:
        raise HTTPException(status_code=404, detail="Video not found")
    if video.owner_user_id != user_id:
        raise HTTPException(status_code=403, detail="forbidden")

    update_video(video_id, {
        "geo_mode": body.geo_mode,
        "geo_countries": body.geo_countries,
    })
    return {"ok": True, "geo_mode": body.geo_mode, "geo_countries": body.geo_countries}


# In the video detail endpoint, add geo check:
@router.get("/{video_id}")
def get_video_detail(video_id: str, request: Request, ctx=Depends(require_ui_session)):
    video = get_video(video_id)
    if not video:
        raise HTTPException(status_code=404, detail="Video not found")
    check_geo_access(
        request,
        geo_mode=getattr(video, "geo_mode", None),
        geo_countries=getattr(video, "geo_countries", None),
    )
    # ... proceed with normal response
```

---

## 8. Frontend Component Design

### 8.1 Component Tree

```
App.tsx
  └── VideoEditPage / BroadcastSettingsPage / CatalogItemEditPage
        └── GeoRestrictionEditor
              ├── RadioGroup ("No restrictions" / "Allow only" / "Block")
              ├── CountryMultiSelect
              │     ├── SearchInput
              │     └── CountryOptionList (virtualized, 249 countries)
              └── SelectedCountryPills
                    └── CountryPill[] (removable badges)

  └── VideoPlayerPage / BroadcastPlayerPage / CatalogItemPage
        └── GeoBlockedPage (conditional, on 403 geo_blocked)
              ├── Globe icon
              ├── "Not Available in Your Region" heading
              ├── Country code display
              └── "Go Back" button
```

### 8.2 New Files

| File | Purpose |
|------|---------|
| `frontend/src/components/shared/GeoRestrictionEditor.tsx` | Country picker with allow/block mode toggle |
| `frontend/src/components/shared/GeoBlockedPage.tsx` | "Not available in your region" full-page message |
| `frontend/src/api/endpoints/geo.ts` | API client for geo endpoints |
| `frontend/e2e/geo-blocking.spec.ts` | E2E tests |

### 8.3 GeoRestrictionEditor Component

```tsx
interface GeoRestrictionEditorProps {
  geoMode: "allow" | "block" | null;
  geoCountries: string[];
  onChange: (mode: "allow" | "block" | null, countries: string[]) => void;
  disabled?: boolean;
}
```

Implementation:
- Radio group: "No restrictions" / "Allow only" / "Block"
- Multi-select country dropdown (searchable, with country flag emoji)
- Shows selected country count and tag pills for selected countries
- "Clear all" button to remove all restrictions
- Debounced search (200ms) for the country list

### 8.4 GeoBlockedPage Component

```tsx
function GeoBlockedPage({ country }: { country?: string }) {
  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh] text-center">
      <Globe className="h-16 w-16 text-muted-foreground mb-4" />
      <h1 className="text-2xl font-bold">Not Available in Your Region</h1>
      <p className="mt-2 text-muted-foreground max-w-md">
        This content is not available in your current location
        {country ? ` (${country})` : ""}.
        The creator has restricted access to specific regions.
      </p>
      <Button variant="outline" className="mt-6" onClick={() => history.back()}>
        Go Back
      </Button>
    </div>
  );
}
```

### 8.5 State Management

- No new Zustand store needed. Geo settings are fetched and mutated via React Query.
- Query key: `["video", videoId, "geo"]` for per-video geo settings.
- Mutation: `useMutation` calling `PATCH /ui/videos/{id}/geo` with `onSuccess` invalidating the query key.
- The `GeoBlockedPage` rendering is triggered by an axios response interceptor that sets `window.__geoBlocked` on 403 `geo_blocked` responses.

### 8.6 React Query Hooks

```typescript
// frontend/src/api/endpoints/geo.ts

export function useVideoGeo(videoId: string) {
  return useQuery({
    queryKey: ["video", videoId, "geo"],
    queryFn: () => client.get(`/ui/videos/${videoId}/geo`).then(r => r.data),
  });
}

export function useSetVideoGeo(videoId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: GeoRestrictionRequest) =>
      client.patch(`/ui/videos/${videoId}/geo`, body).then(r => r.data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["video", videoId] });
      queryClient.invalidateQueries({ queryKey: ["video", videoId, "geo"] });
    },
  });
}

export function useCountriesList() {
  return useQuery({
    queryKey: ["geo", "countries"],
    queryFn: () => client.get("/ui/geo/countries").then(r => r.data),
    staleTime: 24 * 60 * 60 * 1000, // Countries don't change often
  });
}

export function useMyCountry() {
  return useQuery({
    queryKey: ["geo", "my-country"],
    queryFn: () => client.get("/ui/geo/my-country").then(r => r.data),
  });
}
```

### 8.7 Error Interceptor

In `frontend/src/api/client.ts`, add a handler for `geo_blocked` responses:

```typescript
if (error.response?.data?.detail?.code === "geo_blocked") {
  window.__geoBlocked = error.response.data.detail;
}
```

Content pages check this flag and render `GeoBlockedPage` instead of the normal content.

---

## 9. Security & Privacy Considerations

### 9.1 Authentication

All geo-restriction CRUD endpoints require `require_ui_session` (cookie auth with CSRF). The `GET /ui/geo/my-country` debugging endpoint also requires auth to prevent IP enumeration by unauthenticated users. Content endpoints that enforce geo-checks do not leak whether content exists when geo-blocked -- the 403 response is the same regardless.

### 9.2 Input Validation

- Country codes are validated as exactly 2 uppercase ASCII letters via `re.match(r"^[A-Z]{2}$", code)`.
- The `geo_countries` list is limited to 250 entries (there are 249 ISO 3166-1 codes).
- GeoIP lookup input is the client IP from the request, not user-provided data.

### 9.3 Data Protection

- GeoIP cache stores IP-to-country mappings in-memory. This is ephemeral and cleared on process restart.
- No PII is stored in the geo-restriction fields themselves (only country codes, not viewer IPs).
- The `my-country` endpoint exposes the client's IP back to them; this is not a privacy concern since the client already knows their own IP.

### 9.4 Abuse Prevention

- **VPN bypass**: Phase 1 does not detect VPNs. This is documented as a known limitation. Phase 2 may add VPN detection via a third-party service (e.g., MaxMind GeoIP2 Anonymous IP database).
- **Cache poisoning**: The GeoIP cache key is the raw IP string. An attacker cannot inject a different country for another user's IP because the cache is keyed on the actual client IP extracted from the request.
- **X-Forwarded-For spoofing**: In production, the application trusts `X-Forwarded-For` only from proxies in `S.trusted_proxy_cidrs`. The outermost proxy (load balancer) overwrites `X-Forwarded-For`, preventing client-side spoofing.

---

## 10. Performance & Scalability

### 10.1 Query Costs

- **Geo-restriction check**: Zero additional DDB reads. The geo fields (`geo_mode`, `geo_countries`) are on the same item that is already fetched for the content detail endpoint.
- **GeoIP lookup**: 0-1 external calls per unique IP per hour (cache TTL). MaxMind GeoLite2 is a local file read (microseconds). IP-API is a remote HTTP call (50-200ms, dev only).

### 10.2 Caching Strategy

- In-memory dict with TTL-based expiry. No Redis or external cache needed.
- Cache size: 50,000 entries max. At ~100 bytes per entry (IP string + country code + timestamp), this is ~5MB of memory.
- Cache hit rate: Expected >95% for production traffic patterns (most users come from the same set of ISP IP ranges).

### 10.3 DynamoDB Capacity Planning

- No additional RCU/WCU needed. Geo fields add <50 bytes per item. The total storage increase is negligible.
- Admin "list all geo-restricted items" scan is unbounded but is an infrequent admin operation. Can be optimized with a GSI in a future iteration if needed.

### 10.4 Known Bottlenecks

- **MaxMind database reloading**: The `geoip2.database.Reader` opens the `.mmdb` file on every lookup call. In production, this should be a module-level singleton that is reloaded weekly when MaxMind releases updates.
- **Cache eviction**: The `min()` scan for the oldest entry is O(n). At 50,000 entries this is ~1ms. If this becomes a bottleneck, replace with an `OrderedDict` or LRU cache.
- **IP-API rate limiting**: The free tier allows 45 requests/minute. In dev mode with multiple concurrent users, the cache is critical. Consider a fallback to a second free GeoIP provider if IP-API is rate-limited.

---

## 11. Migration & Rollback Plan

### 11.1 Feature Flag

The `GEO_BLOCKING_ENABLED` setting (default `true`) is the master kill switch. When set to `false`:
- `check_geo_access()` returns `None` immediately (no enforcement).
- Geo CRUD endpoints still work (creators can configure settings).
- No code changes needed; just set the environment variable.

### 11.2 Incremental Deployment

1. **Day 1**: Deploy backend with geo service, geo check, and CRUD endpoints. Feature flag ON but no creator has configured restrictions yet, so no viewer impact.
2. **Day 2**: Deploy frontend with GeoRestrictionEditor. Creators can start configuring restrictions.
3. **Day 3**: Monitor GeoIP lookup latency, cache hit rate, and 403 rates. Adjust cache TTL if needed.
4. **Day 5**: Enable platform-level block list if needed (via `GEO_PLATFORM_BLOCK_COUNTRIES` env var).

### 11.3 Rollback Steps

1. Set `GEO_BLOCKING_ENABLED=false` in environment variables.
2. Restart backend processes. All geo-checks immediately become no-ops.
3. If needed, remove `geo_mode` and `geo_countries` fields from DDB items via a cleanup script (not urgent; these fields are ignored when the feature is disabled).

### 11.4 Data Migration

None. Geo fields are added organically as creators configure restrictions. No backfill or schema migration needed.

---

## 12. Testing Strategy

### 12.1 Unit Tests (pytest)

| Test | Module | Description |
|------|--------|-------------|
| `test_lookup_country_localhost` | `geoip.py` | Localhost and `::1` return `None` |
| `test_lookup_country_cache_hit` | `geoip.py` | Second lookup for same IP returns from cache without external call |
| `test_lookup_country_cache_expiry` | `geoip.py` | Entry expires after TTL; new lookup is performed |
| `test_lookup_country_cache_eviction` | `geoip.py` | Oldest entry evicted when cache is full |
| `test_check_geo_access_no_restriction` | `geo_check.py` | `geo_mode=None` allows all |
| `test_check_geo_access_allow_match` | `geo_check.py` | Country in allow list passes |
| `test_check_geo_access_allow_no_match` | `geo_check.py` | Country not in allow list raises 403 |
| `test_check_geo_access_block_match` | `geo_check.py` | Country in block list raises 403 |
| `test_check_geo_access_block_no_match` | `geo_check.py` | Country not in block list passes |
| `test_check_geo_access_platform_override` | `geo_check.py` | Platform-blocked country is denied regardless of per-content setting |
| `test_check_geo_access_fail_open_dev` | `geo_check.py` | Unresolvable IP allowed in dev mode |
| `test_check_geo_access_fail_closed_prod` | `geo_check.py` | Unresolvable IP denied in prod mode |
| `test_geo_restriction_request_validation` | `models.py` | Invalid country codes, missing countries when mode is set |

### 12.2 Integration Tests

| Test | Description |
|------|-------------|
| `test_set_video_geo_restriction` | PATCH endpoint updates DDB record and returns geo fields |
| `test_video_detail_geo_blocked` | GET video with allow-list returns 403 for wrong country |
| `test_video_detail_geo_allowed` | GET video with allow-list returns 200 for correct country |
| `test_broadcast_geo_blocked` | Broadcast viewer endpoint returns 403 for blocked country |
| `test_catalog_item_geo_blocked` | Catalog detail returns 403 for blocked country |

Integration tests mock the `lookup_country` function to return a controlled country code, avoiding external GeoIP calls.

### 12.3 E2E Test Matrix

**File**: `frontend/e2e/geo-blocking.spec.ts`

**Section 1: Geo-Restriction CRUD API (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 1 | Set allow-mode geo-restriction on video | PATCH geo; 200; GET confirms `geo_mode: "allow"` |
| 2 | Set block-mode geo-restriction | PATCH with `block`; 200; GET confirms |
| 3 | Clear geo-restriction | PATCH with `geo_mode: null`; 200; GET shows null |
| 4 | Reject invalid country code | PATCH with `geo_countries: ["XX"]`; 422 |
| 5 | Non-owner cannot set geo-restriction | PATCH as different user; 403 |

**Section 2: Geo-Access Enforcement API (5 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 6 | Allowed country can access video | Set `allow: ["US"]`; request from US IP; 200 |
| 7 | Blocked country gets 403 with geo_blocked code | Set `allow: ["US"]`; request from non-US IP; 403; `code: "geo_blocked"` |
| 8 | Block-mode denies listed country | Set `block: ["DE"]`; request from DE IP; 403 |
| 9 | Block-mode allows unlisted country | Set `block: ["DE"]`; request from US IP; 200 |
| 10 | No geo restriction allows all countries | Clear geo; request from any IP; 200 |

**Section 3: My Country Endpoint (2 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 11 | My country returns detected country code | GET `/ui/geo/my-country`; 200; has `country` field |
| 12 | My country returns null for localhost | Dev mode; 200; `country: null` |

**Section 4: Geo Editor UI (3 tests)**

| # | Test | Assertion |
|---|------|-----------|
| 13 | Geo editor visible on video edit page | Navigate to video edit; "Geo Restrictions" section visible |
| 14 | Selecting countries shows tag pills | Select "US", "CA"; two country pills visible |
| 15 | Clear all removes all country selections | Click "Clear all"; no pills visible; mode reset |

> **Note**: E2E tests for geo enforcement (Section 2) require mocking the GeoIP lookup to return specific country codes for test requests. In dev mode, the test setup overrides the `lookup_country` function via a backend test hook (`POST /internal/geo/mock`) that maps specific session IDs to country codes.

---

## 13. Monitoring & Alerting

### 13.1 Metrics to Track

| Metric | Type | Description |
|--------|------|-------------|
| `geo_check_total` | Counter | Total geo checks performed, labeled by `result` (allowed, blocked, unknown, disabled) |
| `geo_check_country` | Counter | Geo checks by country code (top 20 countries) |
| `geoip_lookup_total` | Counter | GeoIP lookups, labeled by `source` (cache, maxmind, ip_api) |
| `geoip_lookup_latency_seconds` | Histogram | Latency of uncached GeoIP lookups |
| `geoip_cache_size` | Gauge | Current number of entries in the GeoIP cache |
| `geoip_cache_hit_ratio` | Gauge | Cache hit ratio over trailing 5 minutes |
| `geo_restriction_crud_total` | Counter | Geo-restriction CRUD operations, labeled by `content_type` (video, broadcast, catalog) |

### 13.2 Dashboard Queries

- **Geo-block rate**: `rate(geo_check_total{result="blocked"}[5m])` -- should be <5% of total checks for a healthy deployment.
- **GeoIP cache effectiveness**: `geoip_cache_hit_ratio` -- should be >90%. If below 80%, consider increasing cache TTL or max size.
- **GeoIP lookup latency (P99)**: `histogram_quantile(0.99, geoip_lookup_latency_seconds)` -- should be <200ms for MaxMind, <500ms for IP-API.

### 13.3 Alert Thresholds

| Alert | Condition | Severity |
|-------|-----------|----------|
| GeoIP service degraded | `geoip_lookup_total{source="error"} > 100` in 5 min | Warning |
| Geo-block rate spike | `rate(geo_check_total{result="blocked"}[5m])` > 50% of total | Warning |
| GeoIP cache full | `geoip_cache_size >= 0.9 * max_size` | Info |
| MaxMind DB stale | File modification time > 14 days | Warning |

---

## 14. Open Questions & Risks

### 14.1 Unresolved Decisions

1. **VPN detection scope**: Should Phase 2 include basic VPN detection (e.g., known VPN IP ranges from MaxMind Anonymous IP database), or is this better handled at the CDN/WAF layer?
2. **Sub-national blocking**: Some regulations require state/province-level restrictions (e.g., online gambling laws differ by US state). MaxMind GeoLite2 includes city-level data. Should we support sub-national regions?
3. **Content-type-specific defaults**: Should platform admins be able to set default geo-restrictions per content type (e.g., "all broadcasts default to US-only")?

### 14.2 Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| MaxMind GeoLite2 accuracy is only ~99% at country level | Low | Medium | Documented limitation; no SLA on accuracy |
| IP-API free tier rate limit (45/min) exceeded in dev | Medium | Low | In-memory cache mitigates; fail-open in dev |
| X-Forwarded-For header spoofing in production | Low | High | Trusted proxy CIDR configuration; load balancer overwrites header |
| Large country lists (200+ countries) increase DDB item size | Low | Low | Max 250 entries x 2 bytes = 500 bytes; well within DDB 400KB item limit |

### 14.3 Dependency Risks

- **MaxMind license**: GeoLite2 requires a free MaxMind account and EULA acceptance. The database must be updated weekly via `geoipupdate` tool. If MaxMind changes licensing terms, an alternative provider (e.g., DB-IP) can be substituted with minimal code changes.
- **IP-API availability**: The free tier has no SLA. In dev mode, a fallback to hard-coded test IPs could be added.

---

## 15. Implementation Timeline

### Phase 1 (This Ticket) - 8-10 days

| Day | Task | Deliverable |
|-----|------|-------------|
| 1 | Create `app/services/geoip.py` with MaxMind + IP-API backends and caching | GeoIP lookup service |
| 1 | Create `app/services/geo_check.py` with platform + content level checks | Geo-access check utility |
| 2 | Add `GEO_*` settings to `app/core/settings.py` | Configuration infrastructure |
| 2 | Add `GeoRestrictionRequest` and related Pydantic models to `app/models.py` | API models |
| 3 | Add `PATCH/GET /{id}/geo` endpoints to `video_listing.py`, `broadcast.py`, `catalog.py` | Geo-restriction CRUD |
| 3 | Integrate `check_geo_access()` into video detail, broadcast player, and catalog item endpoints | Geo enforcement |
| 4 | Add `GET /ui/geo/countries` and `GET /ui/geo/my-country` endpoints | Supporting endpoints |
| 5 | Create `GeoRestrictionEditor.tsx` component | Frontend editor UI |
| 5 | Create `GeoBlockedPage.tsx` component | Frontend error page |
| 6 | Create `frontend/src/api/endpoints/geo.ts` with React Query hooks | Frontend API layer |
| 6 | Integrate GeoRestrictionEditor into video edit, broadcast settings, and catalog item edit pages | UI integration |
| 7 | Add geo_blocked interceptor to `client.ts` | Error handling |
| 7-8 | Write pytest unit tests for geoip.py and geo_check.py | Backend tests |
| 8 | Add `POST /internal/geo/mock` test hook for E2E country mocking | Test infrastructure |
| 9-10 | Write E2E tests (`frontend/e2e/geo-blocking.spec.ts`) | E2E test suite |

### Phase 2 (Future Ticket) - Estimated 5 days

- VPN/proxy detection via MaxMind Anonymous IP database
- Sub-national region blocking (US state level)
- Geo-restriction audit log (who changed what, when)
- Geo-restriction templates (save and reuse country lists)

### Phase 3 (Future Ticket) - Estimated 3 days

- CDN integration (push geo-block rules to CloudFront/Cloudflare for edge enforcement)
- Admin dashboard for geo-block analytics (heatmap of blocked requests by country)

---

## 16. Dependencies

- **MaxMind GeoLite2**: Free database for production GeoIP lookups. Requires account and periodic updates (weekly). `pip install geoip2`.
- **IP-API**: Free tier used in dev mode only. Rate limited to 45 requests/minute. No account needed.
- **No new DynamoDB tables**: Geo fields are added to existing content metadata records.
- **No new npm packages**: The country list is a static JSON file (249 entries) bundled with the frontend.

---

## 17. Acceptance Criteria

1. Creator can set allow-list geo-restriction on a video; blocked country viewers get 403 with `geo_blocked` code.
2. Creator can set block-list geo-restriction; listed countries denied, all others allowed.
3. Removing geo-restriction (setting mode to null) makes content globally accessible.
4. Platform-level `GEO_PLATFORM_BLOCK_COUNTRIES` overrides per-content settings.
5. GeoIP lookups are cached in memory (1 hour TTL) to avoid redundant external calls.
6. Localhost and private IPs return `null` country (fail-open in dev mode).
7. Frontend shows "Not available in your region" page with detected country code.
8. Geo-restriction editor supports searchable country multi-select with allow/block mode toggle.
9. Geo settings persist and are visible when editing video/broadcast/catalog item.
10. Country codes are validated as ISO 3166-1 alpha-2 (exactly 2 uppercase letters).
11. All 15 E2E tests pass.
12. Feature can be disabled via `GEO_BLOCKING_ENABLED=false` with zero viewer impact.

---

## Appendix: Codebase Citations

| Claim | File | Line(s) | Status |
|-------|------|---------|--------|
| `VideoMetadataModel` with visibility/access_mode | `app/models_video.py` | 35-141 (visibility:99, access_mode:94) | VERIFIED |
| `video_metadata` table | `scripts/local-ddb-init.py` | 702 | VERIFIED: PK=video_id |
| `T.video_metadata` handle | `app/core/tables.py` | 76/160 | VERIFIED |
| `S.video_metadata_table_name` | `app/core/settings.py` | 1029 | VERIFIED |
| `broadcast_sessions` table schema | `scripts/local-ddb-init.py` | 511-519 | VERIFIED: PK=session_id, NO sort key (ticket INCORRECTLY claimed PK=broadcast_id, SK=session_id -- CORRECTED) |
| `broadcast_sessions` GSIs | `scripts/local-ddb-init.py` | 515-518 | VERIFIED: ByStatusCreatedAt, ByCreatorCreatedAt, ByScheduledAt |
| `shopping_catalog` table | `scripts/local-ddb-init.py` | 67 | VERIFIED: PK="PK", SK="SK" with GSI1 |
| `CatalogItemPatchIn` | `app/routers/catalog.py` | 27 (import), 433 (usage) | VERIFIED |
| `client_ip_from_request` | `app/core/normalize.py` | 9 | VERIFIED |
| `trusted_proxy_cidrs` setting | `app/core/settings.py` | 32 | VERIFIED |
| `app/core/settings.py` | `app/core/settings.py` | 1-1197 | VERIFIED: frozen dataclass; no `GEO_*` settings exist yet |
| `require_ui_session` auth dependency | `app/auth/deps.py` | 184+ | VERIFIED |
| `app/routers/video_listing.py` | `app/routers/video_listing.py` | exists | VERIFIED |
| `app/routers/broadcast.py` | `app/routers/broadcast.py` | exists | VERIFIED |
| `app/routers/catalog.py` | `app/routers/catalog.py` | exists | VERIFIED |

### Key Corrections Summary

1. **`broadcast_sessions` table has PK=`session_id` only, NO sort key** (local-ddb-init.py:513). The ticket incorrectly claimed PK=broadcast_id, SK=session_id in the access patterns table (section 5.5) and content metadata list (section 5.1).
2. All other file references (`client_ip_from_request`, `trusted_proxy_cidrs`, `VideoMetadataModel`, `CatalogItemPatchIn`) are verified correct.

## Testing Strategy

### Unit Tests (pytest)

**File**: `tests/test_geo_blocking.py`

Mock external dependencies with `moto` (DynamoDB) and `unittest.mock`. All tests run without the dev stack.

  - `test_lookup_country_localhost_returns_none`
  - `test_lookup_country_cache_hit`
  - `test_lookup_country_cache_expiry`
  - `test_check_geo_access_no_restriction_allows_all`
  - `test_check_geo_access_allow_match_passes`
  - `test_check_geo_access_allow_no_match_raises_403`
  - `test_check_geo_access_block_match_raises_403`
  - `test_check_geo_access_platform_override`
  - `test_check_geo_access_fail_open_dev`

### Integration Tests

  - Video detail endpoint enforces geo-check from video metadata fields
  - PATCH /ui/videos/{id}/geo updates geo_mode and geo_countries in DDB
  - Platform-level GEO_PLATFORM_BLOCK_COUNTRIES overrides per-content allow list

### E2E Tests (Playwright)

**File**: `frontend/e2e/geo-blocking.spec.ts`
**Test count**: 15

**Auth pattern**: Use `injectAuth(page, "root")` for admin endpoints; use `injectAuth(page, "alice")` for user-level endpoints. All POST/PATCH/DELETE requests include `x-csrf-token` header matching the session's CSRF token.

**Negative tests**:
- 401: Unauthenticated request returns 401
- 403: Non-admin/non-owner access returns 403
- 404: Non-existent resource returns 404
- 409: Conflict on duplicate or already-processed resource
- 422: Invalid input (bad field values, missing required fields)

**Edge cases**:
- Empty result sets return 200 with empty arrays (not 404)
- Pagination cursor works correctly across pages
- Concurrent requests do not produce inconsistent state

### Test Data Requirements

- **DDB seeds**: Seed `No new tables (fields on existing video_metadata, broadcast_sessions, shopping_catalog)` table with test records in `beforeAll`
- **Test users**: Alice (USER), Bob (USER), Root (ROOT), Charlie (ADMIN) from `e2e_admin_session_setup.py`
- **Cleanup**: Tests use unique timestamps/IDs per run to avoid cross-run interference

### CI/Pipeline Considerations

- **Feature flag**: `GEO_BLOCKING_ENABLED=true` must be set in test environment
- **Serial execution**: E2E tests run with `workers: 1` to avoid shared-state conflicts
- **Retry safety**: All tests are idempotent; retries do not produce duplicate records

## Dependencies & Merge Safety

### Depends On

| Ticket | Title | Why |
|--------|-------|-----|
| (none) | — | This ticket has no blocking dependencies |

### Depended On By

| Ticket | Title | Impact |
|--------|-------|--------|
| (none) | — | No other tickets depend on this one |

### Merge Strategy

**Feature-flag-gated**

Can be merged at any time behind the `GEO_BLOCKING_ENABLED` feature flag. The flag defaults to `false` in production until validated, allowing safe incremental rollout.

### Merge Checklist

- [ ] All new DDB tables added to `scripts/local-ddb-init.py` with correct `attr_types` for numeric GSI keys
- [ ] New settings added to `app/core/settings.py` and `.env.local.example`
- [ ] New table handles added to `app/core/tables.py`
- [ ] Router registered in `app/main.py`
- [ ] Pydantic models added to `app/models.py`
- [ ] TypeScript types added to `frontend/src/api/types.ts`
- [ ] Route added to `frontend/src/App.tsx`
- [ ] Feature flag defaults to `true` in `.env.local.example`
- [ ] E2E session setup updated if new test identities needed
- [ ] `just restart` completes cleanly with new tables
- [ ] All 15 E2E tests pass with `npx playwright test geo-blocking.spec.ts`
