# BCAST-002: Build Viewer Playback Page with HLS Player

## 1. Overview & Motivation

### Problem Statement

The broadcast backend infrastructure is fully operational: sessions can be created,
started, and stopped; signed playback URLs are minted via `POST /broadcast/sessions/{id}/playback-url`;
CloudFront token validation guards access; and a separate playback entitlement system
issues short-lived JWTs for per-device, per-session authorization. However, there is
currently **no frontend video player component anywhere in the codebase**. Viewers have
no way to consume a live or archived broadcast stream in the browser.

The platform needs a dedicated public-facing playback page that:

1. Accepts a broadcast session identifier (or pre-signed URL) as a route parameter.
2. Acquires a playback entitlement token via the existing `/v1/playback/entitlements/issue` API.
3. Initializes an HLS.js-based adaptive bitrate player to consume the `.m3u8` manifest.
4. Optionally handles DRM-protected streams using EME (Encrypted Media Extensions) with
   the local DRM key delivery endpoint.
5. Provides quality-level selection, play/pause/seek controls, fullscreen, and responsive
   layout suitable for mobile and desktop.
6. Handles error states gracefully: expired tokens, revoked entitlements, network failures,
   unsupported browsers, and codec incompatibilities.

### User Stories

1. **As a viewer**, I want to open a link to a live broadcast and immediately see the
   stream playing at the best quality my connection supports.
2. **As a viewer**, I want to manually switch between quality levels (e.g., 1080p, 720p,
   480p, Auto) without interrupting playback.
3. **As a viewer on mobile**, I want the player to fill the viewport responsively and
   support native fullscreen gestures.
4. **As a viewer**, I want clear feedback when the stream is buffering, when my
   entitlement expires, or when an error occurs.
5. **As the platform**, I want playback protected by short-lived entitlement tokens so
   that unauthorized sharing of URLs does not grant indefinite access.
6. **As the platform**, I want DRM-protected streams to work transparently on supported
   browsers (Chrome/Edge via Widevine, Firefox via Widevine, Safari via FairPlay) with
   fallback messaging on unsupported configurations.

### Success Criteria

- Viewer can watch a live HLS stream end-to-end in Chromium, Firefox, and Safari.
- Playback entitlement token is acquired before stream load and refreshed before expiry.
- Quality selector shows all available renditions from the master playlist.
- Player handles token expiry mid-stream by re-issuing and re-attaching without visible
  interruption (seamless token rotation).
- DRM-protected streams play on Widevine-capable browsers; a clear error banner is shown
  on non-DRM-capable browsers.
- E2E tests cover the critical path using a stubbed HLS manifest.

---

## 2. Current State Analysis

### 2.1 Backend: Playback URL Minting

**File**: `app/routers/broadcast.py` (line 313)
**Endpoint**: `POST /broadcast/sessions/{session_id}/playback-url`
**Auth**: `require_ui_session` (cookie auth or Bearer token)

The endpoint:
1. Loads the session via `get_session(session_id)`.
2. Loads existing output via `get_output(session_id)` to check for a CloudFront URL.
3. Calls `mint_local_playback_url(session.id)` which generates a signed URL of the form:
   ```
   http://localhost:8090/hls/{stream_key}/master.m3u8?md5={token}&expires={unix_ts}
   ```
4. Prefers `output.cloudfront_playback_url` if the session has been provisioned through
   AWS MediaPackage/CloudFront.
5. Returns `BroadcastPlaybackUrlOut`:
   ```json
   { "session_id": "...", "playback_url": "https://...", "expires_at": 1717171717 }
   ```

**File**: `app/services/broadcast_playback.py`

The `mint_local_playback_url` function:
- Validates the stream key against `/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/`.
- Computes `expires_at = now + ttl` (default TTL: 600s from `S.broadcast_local_cache_token_ttl_seconds`).
- Signs the path using MD5 (nginx `secure_link` compatible): `md5("{expires}{path} {secret}")`.
- Returns `LocalPlaybackUrl(url=..., expires_at=...)`.

### 2.2 Backend: Playback Entitlement System

**File**: `app/routers/playback_entitlements.py`
**Prefix**: `/v1/playback`
**Auth**: `get_authenticated_user` (Bearer token)

Three endpoints:
| Method | Path | Purpose |
|--------|------|---------|
| POST | `/entitlements/issue` | Mint a short-lived HMAC-signed JWT (HS256, typ=PLAYBACKJWT) |
| POST | `/entitlements/revoke` | Revoke by JTI or session_id+tenant_id |
| GET | `/protected/ping` | Validate a Bearer playback token (middleware or inline) |

**File**: `app/services/playback_entitlements.py`

The issued token contains claims: `tenant_id`, `asset_id`, `session_id`, `device_id`,
`profile`, `aud`, `iat`, `exp`, `jti`. Max TTL is 300s (configurable via
`PLAYBACK_ENTITLEMENT_MAX_TTL_SECONDS`). Validation enforces:
- Signature verification (HMAC-SHA256)
- Expiry check with clock skew tolerance (30s default)
- Audience match
- Revocation check (per-JTI and per-session caches)
- Replay protection (optional, `PLAYBACK_ENTITLEMENT_REPLAY_PROTECTION_ENABLED`)

**Middleware** (`app/main.py` line 137): All requests to `/v1/playback/protected/*` are
intercepted by `_playback_entitlement_middleware()` which extracts and validates the
Bearer token, attaching `request.state.playback_claims`.

### 2.3 Backend: DRM Key Delivery

**File**: `app/services/broadcast_local_drm.py`

For DRM-protected streams:
- `mint_local_drm_token(stream_key, ttl)` generates an HMAC-SHA256-signed token
  (`{b64url(payload)}.{b64url(sig)}` where payload = `{stream_key}:{expires}`).
- `validate_local_drm_token(token, stream_key)` verifies signature + expiry. Also
  accepts a static dev token (`BROADCAST_LOCAL_DRM_STATIC_TOKEN=dev-token`).
- `load_local_drm_key(stream_key, token)` returns 16-byte AES-128 key from filesystem
  (`tmp/broadcast-hls/keys/{stream_key}.key`).
- Key URI in HLS manifests uses `#EXT-X-KEY:METHOD=AES-128,URI="..."` pointing to the
  key delivery endpoint.

### 2.4 Backend: CloudFront Token Verification

**File**: `app/services/broadcast_cloudfront.py`

- `validate_cloudfront_token(path, token, expires_at)` verifies HMAC-SHA256 signature
  over `{normalized_path}:{expires_at}`.
- Exposed at `GET /broadcast/playback/verify?path=...&cf_token=...&cf_expires=...`.
- Used by CDN edge (Lambda@Edge or CloudFront Functions) to validate viewer access before
  serving segments.

### 2.5 Frontend: No Player Component Exists

**`frontend/package.json`**: Contains zero video player dependencies. No `hls.js`,
`video.js`, `plyr`, `shaka-player`, or `dash.js` in either `dependencies` or
`devDependencies`.

**`frontend/src/`**: The only `<video>` element is in `MediaPreviewThumb.tsx` -- a tiny
hover-preview thumbnail for the file manager. It uses native `<video>` with a direct
`.mp4` source and has no HLS, MSE, or EME integration.

**`frontend/src/api/endpoints/`**: No broadcast or playback endpoint wrapper file exists.

**`frontend/src/App.tsx`**: No `/watch`, `/play`, `/broadcast`, or `/live` route is
defined. Public routes (no auth shell) currently include `/login`, `/register`,
`/password-recovery`, `/magic-link-verify`, `/event/:calendarId/:eventId`, and
`/questionnaires/published/:publishedSlug/respond`.

### 2.6 Settings & Configuration

Relevant backend settings (from `app/core/settings.py`):

| Setting | Default | Purpose |
|---------|---------|---------|
| `broadcast_local_cache_public_base_url` | `http://localhost:8090` | HLS manifest/segment base URL |
| `broadcast_local_cache_token_secret` | `local-cache-secret` | Secret for manifest URL signing |
| `broadcast_local_cache_token_ttl_seconds` | `600` | Playback URL validity window |
| `broadcast_local_drm_token_secret` | `local-drm-secret` | Secret for DRM key token |
| `broadcast_local_drm_static_token` | `dev-token` | Bypass token for dev DRM keys |
| `broadcast_local_drm_key_root` | `tmp/broadcast-hls/keys` | Filesystem path for AES-128 keys |
| `playback_entitlement_secret` | (empty) | HMAC secret for entitlement JWTs |
| `playback_entitlement_max_ttl_seconds` | `300` | Maximum token lifetime |
| `playback_entitlement_expected_audience` | `playback` | Required `aud` claim |
| `broadcast_cloudfront_domain` | (empty) | Production CDN domain |
| `broadcast_cloudfront_token_ttl_seconds` | `600` | CloudFront signed URL TTL |

---

## 3. Technical Design

### 3.1 HLS.js Integration

**Library**: `hls.js` (MIT license, ~75KB gzipped). The industry-standard JavaScript
library for HLS playback via Media Source Extensions (MSE). It handles:
- Master playlist parsing (multi-bitrate `#EXT-X-STREAM-INF`)
- Level switching (ABR engine or manual quality selection)
- Segment fetch, demux, and remux into fMP4 for MSE
- Live edge tracking, DVR buffer management
- AES-128 key fetch + segment decryption (standard HLS DRM)
- Error recovery (network retries, media errors, level fallback)

**Native fallback**: Safari supports HLS natively via `<video src="...m3u8">`. On Safari,
we skip HLS.js initialization and attach the manifest URL directly. Feature detection:
```ts
const nativeHls = videoElement.canPlayType("application/vnd.apple.mpegURL") !== "";
```

### 3.2 Player Component Architecture

```
ViewerPlayerPage (route component)
  |
  +-- usePlaybackSession(sessionId)       // React Query: mint playback URL
  |     returns { playbackUrl, expiresAt, isLoading, error }
  |
  +-- usePlaybackEntitlement(sessionId)   // Issue + auto-refresh entitlement JWT
  |     returns { token, claims, refresh() }
  |
  +-- HlsPlayer                            // Core player wrapper
  |     |
  |     +-- <video ref={videoRef} />       // Native HTML5 video element
  |     +-- PlayerOverlay                  // Custom controls layer
  |     |     +-- PlayPauseButton
  |     |     +-- SeekBar (live: disabled, VOD: enabled)
  |     |     +-- VolumeControl
  |     |     +-- QualitySelector          // Dropdown from hls.levels
  |     |     +-- FullscreenButton
  |     |     +-- LiveIndicator            // Red dot + "LIVE" badge
  |     |     +-- BufferIndicator          // Buffering spinner overlay
  |     |
  |     +-- PlayerErrorBoundary            // Error state display
  |
  +-- EntitlementExpiryBanner              // Warning when token nears expiry
```

### 3.3 Player States

```
IDLE ──> LOADING ──> READY ──> PLAYING ──> PAUSED
  |         |           |          |           |
  v         v           v          v           v
ERROR    ERROR       ERROR      ERROR      ENDED (VOD only)
                                   |
                                   v
                               BUFFERING ──> PLAYING (recovery)
```

State transitions and UI:
| State | UI | Actions |
|-------|-----|---------|
| `IDLE` | Poster image or session title card | Waiting for playback URL mint |
| `LOADING` | Skeleton + spinner | HLS.js loading manifest |
| `READY` | First frame rendered, controls visible | Autoplay attempted |
| `PLAYING` | Video playing, controls auto-hide after 3s | User can pause/seek |
| `PAUSED` | Video frozen, controls always visible | User can resume |
| `BUFFERING` | Spinner overlay on video | HLS.js rebuffering |
| `ENDED` | Replay button overlay | VOD reached end |
| `ERROR` | Error card with message + retry button | Categorized error |

### 3.4 EME / DRM Integration

For streams with `#EXT-X-KEY:METHOD=AES-128`, HLS.js handles key fetch automatically.
The key URI in the manifest points to the backend DRM key endpoint:
```
#EXT-X-KEY:METHOD=AES-128,URI="/broadcast/drm/keys/{stream_key}?token={drm_token}",IV=0x...
```

For Widevine/FairPlay DRM (future, when MediaPackage is used):
- Configure `hls.js` with `emeEnabled: true` and `drmSystems` config.
- Provide `licenseUrl` and optional `serverCertificateUrl` per key system.
- Player detects `EXT-X-SESSION-KEY` or `EXT-X-KEY:METHOD=SAMPLE-AES` and requests
  license through EME `MediaKeySession`.

**Implementation phases**:
1. **Phase 1 (this ticket)**: AES-128 key delivery via HLS.js built-in `loader` config.
   Set `xhrSetup` on `Hls.config` to inject the DRM token as a query parameter or header
   on key requests.
2. **Phase 2 (future)**: Full Widevine/FairPlay via `hls.js` EME support (requires
   DRM-specific packaging from MediaPackage v2).

### 3.5 Quality Selector

HLS.js exposes levels after `MANIFEST_PARSED` event:
```ts
hls.on(Hls.Events.MANIFEST_PARSED, (event, data) => {
  const levels = data.levels.map((level, index) => ({
    index,
    height: level.height,     // e.g. 1080, 720, 480
    width: level.width,
    bitrate: level.bitrate,   // bps
    label: `${level.height}p`,
  }));
  setAvailableLevels([{ index: -1, label: "Auto" }, ...levels]);
});
```

Quality switch:
```ts
function setQuality(levelIndex: number) {
  hls.currentLevel = levelIndex; // -1 = ABR auto
  hls.loadLevel = levelIndex;
}
```

### 3.6 Token Refresh Strategy

Playback entitlement tokens have a max TTL of 300 seconds. The player must refresh
before expiry to avoid mid-stream interruption.

Strategy:
1. Issue initial token when player mounts.
2. Set a refresh timer at `(ttl_seconds * 0.75)` -- e.g., refresh at 225s for a 300s token.
3. On refresh success, store new token for subsequent key/segment requests.
4. On refresh failure, show `EntitlementExpiryBanner` with countdown + retry button.
5. If token expires without refresh, HLS.js key fetch will fail with 401, triggering
   `ERROR` state with "Session expired -- please reload" message.

### 3.7 Error Handling

| Error Category | HLS.js Event / Source | User-Facing Message |
|---------------|----------------------|---------------------|
| Manifest load failed | `MANIFEST_LOADING_ERROR` | "Stream unavailable. It may have ended or the URL has expired." |
| Media error (decode) | `ERROR` with `type=mediaError` | "Playback error. Attempting recovery..." (auto-recover via `recoverMediaError()`) |
| Network error (segments) | `FRAG_LOAD_ERROR` | "Network interruption. Retrying..." (auto-retry 3x) |
| Fatal error | `ERROR` with `fatal=true` | "Playback failed. Please try again." + Retry button |
| Entitlement expired | Key load returns 401 | "Your viewing session has expired. Click to refresh." |
| DRM unsupported | `requestMediaKeySystemAccess` rejects | "DRM playback is not supported on this browser/device." |
| Autoplay blocked | `video.play()` rejects with `NotAllowedError` | Show unmute/play button overlay (muted autoplay fallback) |

Recovery actions:
- **Media errors**: Call `hls.recoverMediaError()` up to 2 times, then `hls.swapAudioCodec()` + recover once more.
- **Network errors**: HLS.js internal retry (configurable `fragLoadingMaxRetry: 6`, `manifestLoadingMaxRetry: 4`).
- **Fatal errors**: Destroy HLS instance, re-create with fresh token and URL.

### 3.8 Responsive Layout

The player page uses a 16:9 aspect ratio container that fills available width:
```tsx
<div className="relative w-full max-w-5xl mx-auto aspect-video bg-black rounded-lg overflow-hidden">
  <video ref={videoRef} className="absolute inset-0 w-full h-full object-contain" />
  <PlayerOverlay />
</div>
```

Mobile considerations:
- Controls use `touch-action: manipulation` to prevent double-tap zoom.
- Fullscreen uses `Fullscreen API` on the container div (not just `<video>`) to include
  custom controls in fullscreen mode.
- iOS Safari: use `video.webkitEnterFullscreen()` for native fullscreen (custom controls
  are hidden -- acceptable trade-off).
- Volume control hidden on mobile (hardware volume only).
- Tap-to-toggle play/pause on video surface.

---

## 4. Implementation Plan

### 4.1 Package Dependencies

Add to `frontend/package.json`:
```json
{
  "dependencies": {
    "hls.js": "^1.5.0"
  }
}
```

No other packages needed. HLS.js is the only runtime dependency. The player UI uses
existing shadcn/ui primitives (`Button`, `Slider`, `Select`, `Badge`) and Tailwind CSS.

### 4.2 File Structure

```
frontend/src/
  api/endpoints/
    broadcast.ts                 # NEW: API wrappers for broadcast + playback endpoints
  pages/
    watch/
      ViewerPlayerPage.tsx       # NEW: Route component (public, no auth shell)
      HlsPlayer.tsx             # NEW: HLS.js wrapper with MSE/native fallback
      PlayerOverlay.tsx          # NEW: Custom control bar + overlays
      QualitySelector.tsx        # NEW: Level picker dropdown
      usePlaybackSession.ts     # NEW: Hook to mint playback URL
      usePlaybackEntitlement.ts # NEW: Hook to issue/refresh entitlement
      usePlayerState.ts         # NEW: State machine for player lifecycle
      playerTypes.ts            # NEW: TypeScript interfaces
```

### 4.3 Route Setup

**`frontend/src/App.tsx`** -- add a public route (no `ProtectedRoute` wrapper):
```tsx
const ViewerPlayerPage = lazy(() => import("@/pages/watch/ViewerPlayerPage"));

// Inside <Routes>, alongside other public routes:
<Route path="/watch/:sessionId" element={<ViewerPlayerPage />} />
```

This follows the same pattern as `/event/:calendarId/:eventId` (public route, lazy-loaded,
no `AppShell` layout). The watch page has its own minimal chrome (back button, title).

**`frontend/vite.config.ts`** -- add proxy for `/broadcast` path:
```ts
"/broadcast": "http://localhost:8000",
```

The `/v1` prefix is already proxied, covering `/v1/playback/entitlements/*`.

### 4.4 API Endpoint Wrappers

**`frontend/src/api/endpoints/broadcast.ts`**:
```ts
import api from "../client";

export interface PlaybackUrlResponse {
  session_id: string;
  playback_url: string;
  expires_at: number;
}

export interface PlaybackEntitlementResponse {
  entitlement: {
    token: string;
    expires_at_epoch: number;
    audience: string;
    ttl_seconds: number;
    jti: string;
  };
  issued_for: string;
}

export interface BroadcastSessionResponse {
  id: string;
  profile_id: string;
  status: string;
  ingest_url?: string;
  cloudfront_playback_url?: string;
  started_at?: string;
  stopped_at?: string;
}

export const mintPlaybackUrl = (sessionId: string) =>
  api.post<PlaybackUrlResponse>(`/broadcast/sessions/${sessionId}/playback-url`);

export const getSession = (sessionId: string) =>
  api.get<BroadcastSessionResponse>(`/broadcast/sessions/${sessionId}`);

export const issuePlaybackEntitlement = (body: {
  tenant_id: string;
  asset_id: string;
  session_id: string;
  device_id: string;
  profile: string;
  audience?: string;
  ttl_seconds?: number;
}) => api.post<PlaybackEntitlementResponse>("/v1/playback/entitlements/issue", body);
```

### 4.5 Core HLS Player Component

**`frontend/src/pages/watch/HlsPlayer.tsx`** (key implementation details):

```tsx
import { useEffect, useRef, useCallback } from "react";
import Hls, { Events, ErrorTypes, ErrorDetails } from "hls.js";

interface HlsPlayerProps {
  src: string;
  drmToken?: string;
  entitlementToken?: string;
  autoPlay?: boolean;
  onLevelsLoaded?: (levels: QualityLevel[]) => void;
  onStateChange?: (state: PlayerState) => void;
  onError?: (error: PlayerError) => void;
}

export function HlsPlayer({ src, drmToken, entitlementToken, autoPlay = true, ...props }: HlsPlayerProps) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const hlsRef = useRef<Hls | null>(null);

  useEffect(() => {
    const video = videoRef.current;
    if (!video || !src) return;

    // Safari native HLS
    if (video.canPlayType("application/vnd.apple.mpegURL") && !Hls.isSupported()) {
      video.src = src;
      if (autoPlay) video.play().catch(() => { /* autoplay blocked */ });
      return;
    }

    if (!Hls.isSupported()) {
      props.onError?.({ type: "fatal", message: "HLS playback is not supported in this browser." });
      return;
    }

    const hls = new Hls({
      enableWorker: true,
      lowLatencyMode: true,
      backBufferLength: 30,
      maxBufferLength: 30,
      maxMaxBufferLength: 60,
      fragLoadingMaxRetry: 6,
      manifestLoadingMaxRetry: 4,
      levelLoadingMaxRetry: 4,
      xhrSetup: (xhr, url) => {
        // Inject DRM token on key requests
        if (url.includes("/drm/keys/") && drmToken) {
          const separator = url.includes("?") ? "&" : "?";
          xhr.open("GET", `${url}${separator}token=${drmToken}`, true);
        }
        // Inject entitlement token as Bearer on segment requests (if CDN requires it)
        if (entitlementToken && url.includes("/hls/")) {
          xhr.setRequestHeader("Authorization", `Bearer ${entitlementToken}`);
        }
      },
    });

    hls.loadSource(src);
    hls.attachMedia(video);

    hls.on(Events.MANIFEST_PARSED, (_, data) => {
      props.onLevelsLoaded?.(data.levels.map((l, i) => ({
        index: i,
        height: l.height,
        width: l.width,
        bitrate: l.bitrate,
        label: l.height ? `${l.height}p` : `${Math.round(l.bitrate / 1000)}kbps`,
      })));
      if (autoPlay) video.play().catch(() => { /* autoplay policy */ });
    });

    hls.on(Events.ERROR, (_, data) => {
      if (!data.fatal) return;
      switch (data.type) {
        case ErrorTypes.MEDIA_ERROR:
          hls.recoverMediaError();
          break;
        case ErrorTypes.NETWORK_ERROR:
          props.onError?.({ type: "network", message: "Network error. Retrying..." });
          hls.startLoad();
          break;
        default:
          props.onError?.({ type: "fatal", message: "Playback failed." });
          hls.destroy();
      }
    });

    hlsRef.current = hls;
    return () => { hls.destroy(); hlsRef.current = null; };
  }, [src, drmToken]);

  return <video ref={videoRef} className="absolute inset-0 w-full h-full object-contain" playsInline />;
}
```

### 4.6 Playback Entitlement Hook

**`frontend/src/pages/watch/usePlaybackEntitlement.ts`**:

```ts
import { useCallback, useEffect, useRef, useState } from "react";
import { issuePlaybackEntitlement } from "@/api/endpoints/broadcast";

export function usePlaybackEntitlement(sessionId: string, deviceId: string) {
  const [token, setToken] = useState<string | null>(null);
  const [expiresAt, setExpiresAt] = useState<number>(0);
  const [error, setError] = useState<string | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout>>();

  const issue = useCallback(async () => {
    try {
      const { data } = await issuePlaybackEntitlement({
        tenant_id: "default",
        asset_id: sessionId,
        session_id: sessionId,
        device_id: deviceId,
        profile: "adaptive",
        audience: "playback",
        ttl_seconds: 120,
      });
      setToken(data.entitlement.token);
      setExpiresAt(data.entitlement.expires_at_epoch);
      setError(null);

      // Schedule refresh at 75% of TTL
      const refreshMs = data.entitlement.ttl_seconds * 750; // 75% in ms
      timerRef.current = setTimeout(() => { void issue(); }, refreshMs);
    } catch (err) {
      setError("Failed to acquire playback entitlement");
    }
  }, [sessionId, deviceId]);

  useEffect(() => {
    void issue();
    return () => { if (timerRef.current) clearTimeout(timerRef.current); };
  }, [issue]);

  return { token, expiresAt, error, refresh: issue };
}
```

### 4.7 ViewerPlayerPage Route Component

**`frontend/src/pages/watch/ViewerPlayerPage.tsx`**:

```tsx
import { useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Loader2, ArrowLeft, AlertCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { mintPlaybackUrl, getSession } from "@/api/endpoints/broadcast";
import { HlsPlayer } from "./HlsPlayer";
import { PlayerOverlay } from "./PlayerOverlay";
import { usePlaybackEntitlement } from "./usePlaybackEntitlement";
import { useState } from "react";

export default function ViewerPlayerPage() {
  const { sessionId } = useParams<{ sessionId: string }>();
  const deviceId = useState(() => crypto.randomUUID())[0];

  const sessionQuery = useQuery({
    queryKey: ["broadcast-session", sessionId],
    queryFn: () => getSession(sessionId!),
    enabled: !!sessionId,
  });

  const playbackQuery = useQuery({
    queryKey: ["broadcast-playback-url", sessionId],
    queryFn: () => mintPlaybackUrl(sessionId!),
    enabled: !!sessionId && sessionQuery.data?.status === "live",
  });

  const { token: entitlementToken, error: entitlementError } =
    usePlaybackEntitlement(sessionId!, deviceId);

  // ... render loading, error, and player states
}
```

### 4.8 Integration with Existing Patterns

The implementation follows established frontend patterns:
- **React Query** for server state (`useQuery` for session/playback URL, no `useMutation`
  since the mint endpoint is idempotent and can be treated as a query).
- **Lazy loading** via `React.lazy()` in `App.tsx` (code-split the player page).
- **shadcn/ui primitives** for controls (`Button`, `Slider` for seek bar, `Select` for
  quality, `Badge` for live indicator).
- **Tailwind CSS** for responsive layout (no custom CSS files).
- **Error boundaries** following the `ErrorPage` component pattern.
- **Public route** pattern matching `PublicEventPage` -- minimal chrome, no `AppShell`,
  uses `useParams` for route params.

---

## 5. Testing Strategy

### 5.1 E2E Test File Structure

**`frontend/e2e/broadcast-player.spec.ts`**

The test file follows established E2E patterns (serial describe blocks, section numbering,
cookie-based auth injection, `apiPost` helpers with CSRF).

### 5.2 HLS Stub Server

Since E2E tests cannot rely on a real RTMP ingest + transcoder, we use a **static HLS
fixture** served by the Vite dev server:

1. Place a minimal valid HLS manifest + segment at:
   ```
   frontend/public/test-fixtures/hls/
     master.m3u8          # Master playlist with 1 rendition
     stream_0/
       playlist.m3u8      # Media playlist with 3 segments
       segment_000.ts     # ~1s MPEG-TS segment (can be a synthetic 1-frame video)
       segment_001.ts
       segment_002.ts
   ```

2. In E2E tests, intercept the playback URL response to point at the fixture:
   ```ts
   await page.route("**/broadcast/sessions/*/playback-url", async (route) => {
     await route.fulfill({
       status: 200,
       contentType: "application/json",
       body: JSON.stringify({
         session_id: testSessionId,
         playback_url: "http://localhost:3000/test-fixtures/hls/master.m3u8",
         expires_at: Math.floor(Date.now() / 1000) + 600,
       }),
     });
   });
   ```

3. For segment requests, intercept and serve a minimal valid TS:
   ```ts
   // Alternatively, let Vite serve static files from public/
   // No route interception needed if fixtures are in public/
   ```

### 5.3 Test Sections

| Section | Name | Tests |
|---------|------|-------|
| 110.1 | Player loads and renders video element | Verify `<video>` is attached, controls visible |
| 110.2 | Quality selector shows available levels | Mock manifest with multiple renditions, verify dropdown |
| 110.3 | Play/pause toggle works | Click play, verify playing state; click pause, verify paused |
| 110.4 | Fullscreen button triggers fullscreen API | Click fullscreen, verify `document.fullscreenElement` |
| 110.5 | Live indicator shown for live sessions | Mock session status=live, verify "LIVE" badge |
| 110.6 | Error state on manifest load failure | Intercept manifest 404, verify error UI |
| 110.7 | Error state on expired playback URL | Intercept manifest 403, verify "expired" message |
| 110.8 | Entitlement token refresh | Set short TTL, verify re-issue call before expiry |
| 110.9 | Autoplay blocked fallback | Mock `video.play()` rejection, verify play button overlay |
| 110.10 | Page renders 404 for invalid session ID | Navigate to `/watch/nonexistent`, verify error state |

### 5.4 Testing Error States

```ts
test("110.6 Error state when manifest fails to load", async ({ page }) => {
  // Intercept to return 404 for manifest
  await page.route("**/hls/**/*.m3u8", (route) =>
    route.fulfill({ status: 404, body: "Not Found" })
  );

  await page.goto(`/watch/${testSessionId}`);
  await expect(page.getByText(/stream unavailable/i)).toBeVisible({ timeout: 10_000 });
  await expect(page.getByRole("button", { name: /retry/i })).toBeVisible();
});

test("110.7 Error state when playback URL is expired", async ({ page }) => {
  await page.route("**/broadcast/sessions/*/playback-url", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        session_id: testSessionId,
        playback_url: "http://localhost:3000/test-fixtures/hls/master.m3u8",
        expires_at: Math.floor(Date.now() / 1000) - 10, // already expired
      }),
    });
  });

  // Also make manifest return 403 (simulating cache proxy rejection)
  await page.route("**/test-fixtures/hls/master.m3u8", (route) =>
    route.fulfill({ status: 403, body: "Forbidden" })
  );

  await page.goto(`/watch/${testSessionId}`);
  await expect(page.getByText(/expired/i)).toBeVisible({ timeout: 10_000 });
});
```

### 5.5 Testing DRM Flow

Since DRM key delivery in dev mode accepts a static token (`dev-token`), E2E tests can:

1. Create an HLS fixture with `#EXT-X-KEY:METHOD=AES-128,URI="/broadcast/drm/keys/test-stream?token=dev-token"`.
2. Place a 16-byte key file at `tmp/broadcast-hls/keys/test-stream.key`.
3. Encrypt fixture segments with that key using `openssl enc -aes-128-cbc`.
4. Verify the player loads and plays without showing DRM error UI.

```ts
test("110.11 DRM-protected stream plays with valid token", async ({ page }) => {
  // Stub session with DRM profile
  await page.route("**/broadcast/sessions/*", async (route) => {
    if (route.request().method() === "GET") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          id: testSessionId,
          status: "live",
          profile_id: "drm-profile",
        }),
      });
    } else {
      await route.continue();
    }
  });

  await page.goto(`/watch/${testSessionId}`);
  // Should NOT show DRM error
  await expect(page.getByText(/drm.*not supported/i)).not.toBeVisible({ timeout: 5_000 });
  // Should show the video element with a non-zero currentTime after playback starts
  await page.waitForFunction(() => {
    const v = document.querySelector("video");
    return v && v.readyState >= 2; // HAVE_CURRENT_DATA
  }, { timeout: 15_000 });
});
```

### 5.6 Unit Tests (Vitest)

The player hooks can be tested independently:

- **`usePlaybackEntitlement.test.ts`**: Mock `issuePlaybackEntitlement` API call, verify
  token state updates, verify refresh timer fires at 75% TTL.
- **`usePlayerState.test.ts`**: Drive state machine transitions, verify valid transitions
  only (e.g., cannot go from IDLE to PAUSED directly).
- **`QualitySelector.test.tsx`**: Render with mock levels, verify dropdown items, verify
  `onQualityChange` callback.

### 5.7 Test Data Cleanup

The player page is **read-only** from a data perspective (no DynamoDB writes except
entitlement issuance which uses an in-memory cache). No cleanup is needed between test
runs. Entitlement tokens expire naturally. The broadcast session used in tests can be
created once in `beforeAll` and left in place.

### 5.8 Browser Compatibility Matrix

| Browser | HLS Method | DRM Support | Notes |
|---------|-----------|-------------|-------|
| Chrome/Edge | HLS.js (MSE) | Widevine + AES-128 | Full support |
| Firefox | HLS.js (MSE) | Widevine + AES-128 | Full support |
| Safari | Native `<video>` | FairPlay + AES-128 | HLS.js not needed; native handles ABR |
| Safari (iOS) | Native `<video>` | FairPlay + AES-128 | Fullscreen via `webkitEnterFullscreen` |
| Mobile Chrome | HLS.js (MSE) | Widevine + AES-128 | Touch controls |

E2E tests run in Chromium only (per `playwright.config.ts`), but the component includes
Safari-specific code paths that should be manually verified.
