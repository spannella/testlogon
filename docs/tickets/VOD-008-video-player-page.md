# VOD-008: Video Player Page with DRM Support

**Ticket**: VOD-008
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-24

---

## 1. Overview & Motivation

The platform's video pipeline (VOD-001 through VOD-006) handles ingestion, transcoding, and storage of video assets as multi-bitrate HLS streams. The broadcast system (BCAST-002) already provisions playback URLs for live streams. However, there is no dedicated frontend page for on-demand video playback that:

1. Loads an HLS master manifest and presents adaptive bitrate streaming to the viewer.
2. Integrates with the playback entitlement token system to authorize and decrypt DRM-protected content.
3. Provides manual quality selection alongside automatic ABR switching.
4. Renders forensic watermark overlays (dynamic text or static image) as a visible deterrent.
5. Displays video metadata (title, description, upload date, duration) alongside the player.
6. Handles error states gracefully: expired tokens, video still processing, video not found, unsupported browser.

**User stories:**

- *As a subscriber*, I want to navigate to `/videos/:videoId`, see the video auto-play in the best quality my connection supports, and manually switch quality if needed.
- *As a content creator*, I want to share a time-limited link to my video that expires after the entitlement TTL.
- *As an operator*, I want DRM-protected content to be unplayable without a valid entitlement token, and I want visible watermarks rendered over the playback surface.
- *As a viewer on a slow connection*, I want the player to automatically downshift to a lower rendition without buffering stalls.

**Dependencies:**
- VOD-006 (HLS packaging and S3 storage of manifests/segments)
- BCAST-002 (reusable player component patterns from broadcast playback)

---

## 2. Current State Analysis

### 2.1 HLS Output Format (ABR Ladder)

The transcoding pipeline produces a master playlist and per-rendition variant playlists. The canonical ABR ladder is defined in `app/contracts/video_rendition_profiles.py`:

| Rendition | Resolution | Video Bitrate | Audio Bitrate | FPS | GOP |
|-----------|-----------|---------------|---------------|-----|-----|
| 1080p | 1920x1080 | 6000 kbps | 192 kbps | 30 | 2s |
| 720p | 1280x720 | 3500 kbps | 128 kbps | 30 | 2s |
| 540p | 960x540 | 2200 kbps | 128 kbps | 30 | 2s |
| 360p | 640x360 | 1200 kbps | 96 kbps | 30 | 2s |

The `write_master_playlist()` function in `app/services/ffmpeg_abr_pipeline.py` (line 131) generates a `master.m3u8` with `#EXT-X-STREAM-INF` entries pointing to `{rendition_name}/index.m3u8`:

```
#EXTM3U
#EXT-X-VERSION:3
#EXT-X-STREAM-INF:BANDWIDTH=6000000,RESOLUTION=1920x1080
1080p/index.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=3500000,RESOLUTION=1280x720
720p/index.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=2200000,RESOLUTION=960x540
540p/index.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=1200000,RESOLUTION=640x360
360p/index.m3u8
```

Each rendition directory contains `index.m3u8` (media playlist) and `seg_XXXXX.ts` segments (2-second HLS segments with H.264 video + AAC audio).

The S3 path convention for VOD assets (from `app/contracts/video_rendition_profiles.py` line 61):
```
tenants/{tenant_id}/assets/{asset_id}/hls/{rendition_name}/index.m3u8
```

### 2.2 Playback Entitlement Token System

The entitlement system (`app/services/playback_entitlements.py`) issues short-lived HS256-signed JWTs with type `PLAYBACKJWT`. The flow:

1. **Issue**: `POST /v1/playback/entitlements/issue` -- authenticated user requests a token for a specific `asset_id` + `tenant_id` with a TTL (max 300s configurable via `S.playback_entitlement_max_ttl_seconds`).
2. **Validate**: `GET /v1/playback/protected/ping` -- validates a Bearer token, checking signature, expiry, audience, replay protection, and revocation.
3. **Revoke**: `POST /v1/playback/entitlements/revoke` -- invalidate by JTI or session_id.

Token payload claims:
```json
{
  "tenant_id": "...",
  "asset_id": "...",
  "session_id": "...",
  "device_id": "...",
  "profile": "hd_1080p",
  "aud": "playback",
  "iat": 1716566400,
  "exp": 1716566520,
  "jti": "unique_token_id"
}
```

The router (`app/routers/playback_entitlements.py`) uses `get_authenticated_user` (Bearer auth via Cognito or session) to gate token issuance.

### 2.3 Broadcast Playback URL Pattern

The broadcast router (`app/routers/broadcast.py` line 313) demonstrates the playback URL minting pattern:

```python
@router.post("/sessions/{session_id}/playback-url", response_model=BroadcastPlaybackUrlOut)
def mint_playback_url_route(session_id: str, ctx: dict = Depends(_ctx)):
    minted = mint_local_playback_url(session.id)
    playback_url = existing.cloudfront_playback_url or minted.url
    return BroadcastPlaybackUrlOut(session_id=session.id, playback_url=playback_url, expires_at=minted.expires_at)
```

The local playback URL (`app/services/broadcast_playback.py`) appends `?md5=<token>&expires=<epoch>` query parameters for nginx `secure_link`-style validation. The CloudFront variant (`app/services/broadcast_cloudfront.py`) uses `?cf_token=<hmac>&cf_expires=<epoch>`.

### 2.4 DRM Policy Configuration

The video pipeline contract (`app/contracts/video_pipeline_contract.py` line 23) defines DRM profiles:

```python
class DrmPolicy(BaseModel):
    profile: Literal["none", "widevine", "fairplay", "playready", "multi_drm"] = "none"
    key_rotation_seconds: int | None = Field(default=300, ge=60)
    per_content_key: bool = True
    offline_allowed: bool = False
```

For DRM-protected assets, the player must inject the entitlement token into the EME license request as a Bearer token header.

### 2.5 Watermark Overlay System

The watermark policy (`app/contracts/watermark_policy.py`) supports three modes:
- `none` -- no watermark
- `static_image` -- overlay a tenant branding image (stored in `app/static/uploads/watermarks/`)
- `dynamic_text` -- render interpolated text with template variables (`{{tenant_id}}`, `{{session_id}}`, `{{timestamp}}`)

For VOD playback, watermarks are burned into the transcoded segments at encoding time (server-side). However, an additional client-side forensic overlay (semi-transparent, positioned text showing the viewer's session ID) is required as a secondary deterrent against screen recording.

### 2.6 Existing Frontend Patterns

The frontend follows a consistent page structure:
- Pages live under `frontend/src/pages/<feature>/` with a top-level `<Feature>Page.tsx`
- Routes are registered in `frontend/src/App.tsx` with lazy loading
- API calls via `frontend/src/api/endpoints/<feature>.ts` using the shared axios instance
- React Query for server state management
- shadcn/ui primitives for UI components

No HLS.js dependency currently exists in `frontend/package.json`. The frontend does reference video files in messaging (video thumbnails, file uploads), but no dedicated player component exists.

---

## 3. Technical Design

### 3.1 Player Library Selection: HLS.js

**Choice**: [HLS.js](https://github.com/video-dev/hls.js) (MIT license, ~200KB gzipped)

**Rationale**:
1. HLS.js is the de-facto standard for HLS playback in browsers without native HLS support (Chrome, Firefox, Edge). Safari uses native `<video>` HLS support.
2. It provides programmatic quality selection via `hls.levels` and `hls.currentLevel`.
3. It exposes `xhr-setup` hooks for injecting authorization headers on manifest/segment requests.
4. EME (Encrypted Media Extensions) support is available via the `eme` controller for Widevine/PlayReady.
5. ABR controller is built-in with configurable bandwidth estimation.

**Alternative considered**: Video.js -- heavier (400KB+), provides UI chrome we don't need (we build custom controls with shadcn/ui).

**Safari handling**: Detect `canPlayType('application/vnd.apple.mpegURL')` -- if native HLS is supported, use the native `<video src="...m3u8">` path with FairPlay EME via `WebKitMediaKeys`. HLS.js is not loaded on Safari.

### 3.2 Component Architecture

```
frontend/src/pages/videos/
├── VideoPlayerPage.tsx          # Route component — fetches metadata, orchestrates layout
├── HlsPlayer.tsx                # Core HLS.js video element + controls
├── QualitySelector.tsx          # Dropdown for manual rendition selection
├── PlayerControls.tsx           # Play/pause, seek, volume, fullscreen, PiP
├── VideoMetadataPanel.tsx       # Title, description, date, owner, share button
├── WatermarkOverlay.tsx         # Semi-transparent forensic text overlay
├── PlayerErrorBoundary.tsx      # Error states: expired, not found, processing
└── usePlaybackEntitlement.ts    # React Query hook for token issuance + refresh
```

#### `VideoPlayerPage.tsx` (route-level orchestrator)

```tsx
export default function VideoPlayerPage() {
  const { videoId } = useParams<{ videoId: string }>();
  const { data: video, isLoading, error } = useQuery({
    queryKey: ["video", videoId],
    queryFn: () => getVideo(videoId!),
    enabled: !!videoId,
  });
  const { token, isTokenLoading, tokenError } = usePlaybackEntitlement(video);

  if (isLoading || isTokenLoading) return <PlayerSkeleton />;
  if (error?.status === 404) return <PlayerErrorBoundary type="not_found" />;
  if (video?.status !== "published") return <PlayerErrorBoundary type="processing" video={video} />;
  if (tokenError) return <PlayerErrorBoundary type="access_expired" />;

  return (
    <div className="mx-auto max-w-5xl space-y-4 p-4">
      <div className="relative aspect-video overflow-hidden rounded-lg bg-black">
        <HlsPlayer
          manifestUrl={video.hls_manifest_url}
          entitlementToken={token}
          drmPolicy={video.drm_policy_id}
          renditions={video.renditions}
        />
        <WatermarkOverlay sessionId={token?.jti} tenantId={video.owner_user_id} />
      </div>
      <VideoMetadataPanel video={video} />
    </div>
  );
}
```

#### `HlsPlayer.tsx` (core player with HLS.js integration)

Key responsibilities:
1. Initialize HLS.js instance on mount (or native `<video>` on Safari).
2. Configure `xhrSetup` to inject `Authorization: Bearer <token>` on manifest and segment requests.
3. Listen to `Hls.Events.MANIFEST_PARSED` to populate available quality levels.
4. Expose `currentLevel` / `setCurrentLevel` for quality switching.
5. Handle `Hls.Events.ERROR` to detect fatal errors and trigger token refresh or error state.
6. Destroy HLS.js instance on unmount to prevent memory leaks.

```tsx
interface HlsPlayerProps {
  manifestUrl: string;
  entitlementToken: string;
  drmPolicy?: string | null;
  renditions: VideoRendition[];
  onLevelsLoaded?: (levels: QualityLevel[]) => void;
}
```

#### `usePlaybackEntitlement.ts` (token lifecycle hook)

```tsx
export function usePlaybackEntitlement(video: VideoOut | undefined) {
  const queryClient = useQueryClient();

  return useQuery({
    queryKey: ["playback-entitlement", video?.video_id],
    queryFn: async () => {
      const resp = await apiClient.post("/v1/playback/entitlements/issue", {
        tenant_id: video!.owner_user_id,
        asset_id: video!.video_id,
        session_id: crypto.randomUUID(),
        device_id: getDeviceId(),
        profile: "hd_1080p",
        audience: "playback",
        ttl_seconds: 120,
      });
      return resp.data.entitlement;
    },
    enabled: !!video && video.status === "published",
    refetchInterval: 90_000, // refresh token 30s before expiry (120s TTL)
    staleTime: 80_000,
  });
}
```

The hook auto-refreshes the entitlement token before expiry using React Query's `refetchInterval`. The 90-second interval ensures a new token is obtained well before the 120-second TTL expires.

### 3.3 HLS.js Integration Details

#### Initialization

```typescript
import Hls from "hls.js";

const hls = new Hls({
  xhrSetup: (xhr: XMLHttpRequest, url: string) => {
    xhr.setRequestHeader("Authorization", `Bearer ${entitlementToken}`);
  },
  startLevel: -1, // auto-select initial quality
  capLevelToPlayerSize: true, // don't load 1080p on a 360p viewport
  maxBufferLength: 30,
  maxMaxBufferLength: 60,
});

hls.loadSource(manifestUrl);
hls.attachMedia(videoElement);
```

#### Quality Switching

HLS.js exposes `hls.levels` (array of `Level` objects with `width`, `height`, `bitrate`) after `MANIFEST_PARSED`. Setting `hls.currentLevel = index` forces a specific quality; setting to `-1` re-enables ABR auto-switching.

The `QualitySelector` component maps `hls.levels` to the canonical rendition labels:

```tsx
const qualityLabels = levels.map((level) => ({
  index: level.id,
  label: `${level.height}p`,
  bitrate: level.bitrate,
  active: level.id === currentLevel,
}));
```

#### Token Refresh Without Interruption

When `usePlaybackEntitlement` returns a new token (via `refetchInterval`), the `HlsPlayer` must update the `xhrSetup` closure without destroying and re-creating the HLS.js instance. This is achieved by storing the token in a `useRef`:

```tsx
const tokenRef = useRef(entitlementToken);
useEffect(() => { tokenRef.current = entitlementToken; }, [entitlementToken]);

// In HLS config:
xhrSetup: (xhr) => {
  xhr.setRequestHeader("Authorization", `Bearer ${tokenRef.current}`);
}
```

### 3.4 DRM Token Flow (EME Integration)

For videos with `drm_policy_id !== null`, the player must configure EME key systems:

1. **Widevine** (Chrome/Firefox/Edge): Configure HLS.js `emeEnabled: true` with a `widevineLicenseUrl` pointing to the backend license proxy. The entitlement token is sent as a Bearer header on the license request.

2. **FairPlay** (Safari): Use `WebKitMediaKeys` API with the entitlement token embedded in the SPC (Server Playback Context) certificate request.

3. **PlayReady** (Edge legacy): Supported via the same EME path as Widevine with a different key system string.

For the dev/mock environment (where `S.dev_mode=True`), DRM is bypassed -- content is served unencrypted. The player detects `drm_policy_id === "none"` or `null` and skips EME configuration entirely.

**License proxy endpoint** (to be added by VOD-010):
```
POST /v1/playback/license
Authorization: Bearer <entitlement_token>
Body: <license_challenge_bytes>
Response: <license_response_bytes>
```

Until VOD-010 is implemented, the player checks `drmPolicy` and if it is anything other than `"none"` or `null` while in dev mode, it logs a warning and plays without DRM.

### 3.5 Watermark Overlay (Client-Side Forensic Layer)

The `WatermarkOverlay` component renders a semi-transparent, non-interactive `<div>` positioned absolutely over the video surface:

```tsx
export function WatermarkOverlay({ sessionId, tenantId }: { sessionId?: string; tenantId?: string }) {
  if (!sessionId) return null;
  return (
    <div
      className="pointer-events-none absolute inset-0 flex items-end justify-end p-4 select-none"
      aria-hidden="true"
    >
      <span className="text-xs text-white/20 font-mono">
        {tenantId?.slice(0, 8)}:{sessionId.slice(0, 12)}
      </span>
    </div>
  );
}
```

This overlay is positioned at `bottom_right` with 20% opacity (matching the server-side watermark policy default of `opacity: 0.7` for dynamic text, but lighter for client-side as it supplements the burned-in watermark). The text shows a truncated tenant ID and session JTI for forensic identification of screen recordings.

The overlay uses `pointer-events-none` and `select-none` CSS to prevent user interaction or text selection. `aria-hidden="true"` excludes it from screen readers.

### 3.6 Share Button (Time-Limited Signed URL)

The `VideoMetadataPanel` includes a "Share" button that generates a time-limited playback URL:

1. User clicks "Share" button.
2. Frontend calls `POST /v1/playback/entitlements/issue` with a longer TTL (e.g., 300s) and a unique `session_id`.
3. The generated token is appended to the URL as a query parameter: `/videos/{videoId}?token={entitlement_token}`.
4. The URL is copied to clipboard with a toast notification.

When a viewer opens a shared URL with a `?token=` parameter, `VideoPlayerPage` uses that token directly instead of issuing a new one, skipping the auth-gated issue flow.

### 3.7 Error State Handling

| State | Detection | UI |
|-------|-----------|-----|
| Video not found | `GET /ui/videos/{id}` returns 404 | "Video not found" card with back navigation |
| Still processing | `video.status` not in `["published", "approved"]` | "Video is being processed" with spinner + status text |
| Token expired | `validate` returns `token_expired` or `refetchInterval` fails | "Access expired. Please refresh." with retry button |
| Token revoked | `token_revoked` error from validation | "Access has been revoked" message |
| Network error | HLS.js `ERROR` event with `type: NETWORK_ERROR` | "Playback error. Check your connection." with retry |
| Unsupported browser | `!Hls.isSupported()` and no native HLS | "Your browser does not support video playback" |

---

## 4. Implementation Plan

### 4.1 New npm Dependency

Add to `frontend/package.json` dependencies:

```json
"hls.js": "^1.5.0"
```

HLS.js v1.5+ includes EME support in the main bundle (no separate plugin needed).

### 4.2 New Files to Create

| File | Description |
|------|-------------|
| `frontend/src/pages/videos/VideoPlayerPage.tsx` | Route-level page component |
| `frontend/src/pages/videos/HlsPlayer.tsx` | Core HLS.js player wrapper |
| `frontend/src/pages/videos/QualitySelector.tsx` | Rendition quality dropdown |
| `frontend/src/pages/videos/PlayerControls.tsx` | Transport controls (play, seek, volume, fullscreen) |
| `frontend/src/pages/videos/VideoMetadataPanel.tsx` | Title, description, metadata display + share button |
| `frontend/src/pages/videos/WatermarkOverlay.tsx` | Forensic watermark overlay |
| `frontend/src/pages/videos/PlayerErrorBoundary.tsx` | Error state cards |
| `frontend/src/pages/videos/usePlaybackEntitlement.ts` | React Query hook for token management |
| `frontend/src/pages/videos/useHlsPlayer.ts` | Custom hook encapsulating HLS.js lifecycle |
| `frontend/src/api/endpoints/videos.ts` | API endpoint wrappers for video metadata + entitlements |

### 4.3 Files to Modify

| File | Change |
|------|--------|
| `frontend/package.json` | Add `hls.js` dependency |
| `frontend/src/App.tsx` | Add lazy import for `VideoPlayerPage` + route `<Route path="videos/:videoId" element={<VideoPlayerPage />} />` |
| `frontend/src/components/layout/Sidebar.tsx` | Add "Videos" nav item with `Film` icon to Main or Productivity group |
| `frontend/src/components/layout/AppShell.tsx` | Add "Videos" to MobileSidebar if applicable |
| `frontend/src/api/types.ts` | Add `VideoOut`, `VideoRendition`, `PlaybackEntitlement` TypeScript interfaces |
| `vite.config.ts` (proxy) | Add `/v1/playback` to the proxy list if not already covered |

### 4.4 Step-by-Step Implementation Order

**Phase 1: API Layer + Types** (no UI yet)
1. Add TypeScript interfaces to `frontend/src/api/types.ts`:
   - `VideoRendition` (label, width, height, bitrate_kbps)
   - `VideoOut` (video_id, owner_user_id, title, description, status, hls_manifest_url, renditions, thumbnail_url, etc.)
   - `PlaybackEntitlementOut` (token, expires_at_epoch, audience, ttl_seconds, jti)
2. Create `frontend/src/api/endpoints/videos.ts` with:
   - `getVideo(videoId: string): Promise<VideoOut>`
   - `listMyVideos(cursor?: string): Promise<{ items: VideoOut[]; cursor?: string }>`
   - `issuePlaybackEntitlement(params): Promise<{ entitlement: PlaybackEntitlementOut }>`

**Phase 2: Core Player Component**
3. Install `hls.js` dependency.
4. Implement `useHlsPlayer.ts` -- encapsulates HLS.js instance creation, source loading, event handling, cleanup.
5. Implement `HlsPlayer.tsx` -- renders `<video>` element, uses `useHlsPlayer`, exposes quality levels.
6. Implement `QualitySelector.tsx` -- shadcn/ui `Select` component bound to HLS.js levels.
7. Implement `PlayerControls.tsx` -- play/pause, seek bar, volume slider, fullscreen toggle, PiP button.

**Phase 3: Token Management + DRM**
8. Implement `usePlaybackEntitlement.ts` -- handles token issuance, auto-refresh, shared URL token fallback.
9. Add EME configuration to `useHlsPlayer.ts` for Widevine/FairPlay when `drmPolicy` is set.
10. Implement `WatermarkOverlay.tsx`.

**Phase 4: Page Assembly**
11. Implement `VideoMetadataPanel.tsx` -- title, description, date formatting, share button with clipboard copy.
12. Implement `PlayerErrorBoundary.tsx` -- error state cards for all scenarios.
13. Implement `VideoPlayerPage.tsx` -- combines all sub-components.
14. Register route in `App.tsx`, add sidebar entry.

**Phase 5: Polish**
15. Add keyboard shortcuts (Space = play/pause, F = fullscreen, M = mute, arrow keys = seek).
16. Add Picture-in-Picture support detection + toggle.
17. Add loading skeleton for player area.
18. Test Safari native HLS fallback path.

### 4.5 API Endpoint Wrappers

`frontend/src/api/endpoints/videos.ts`:

```typescript
import { apiClient } from "../client";
import type { VideoOut, PlaybackEntitlementOut } from "../types";

export async function getVideo(videoId: string): Promise<VideoOut> {
  const { data } = await apiClient.get(`/ui/videos/${videoId}`);
  return data;
}

export async function listMyVideos(cursor?: string): Promise<{ items: VideoOut[]; cursor?: string }> {
  const { data } = await apiClient.get("/ui/videos", { params: { cursor } });
  return data;
}

export async function issuePlaybackEntitlement(params: {
  tenantId: string;
  assetId: string;
  sessionId: string;
  deviceId: string;
  profile?: string;
  ttlSeconds?: number;
}): Promise<{ entitlement: PlaybackEntitlementOut; issued_for: string }> {
  const { data } = await apiClient.post("/v1/playback/entitlements/issue", {
    tenant_id: params.tenantId,
    asset_id: params.assetId,
    session_id: params.sessionId,
    device_id: params.deviceId,
    profile: params.profile ?? "hd_1080p",
    audience: "playback",
    ttl_seconds: params.ttlSeconds ?? 120,
  });
  return data;
}
```

### 4.6 Vite Proxy Configuration

The Vite dev server must proxy `/v1/playback` to the backend. Check `frontend/vite.config.ts` -- the existing proxy likely covers `/v1` already (it proxies all `/api`, `/ui`, `/v1`, `/mock`, `/internal` paths). If not, add:

```typescript
"/v1": { target: "http://localhost:8000", changeOrigin: true },
```

---

## 5. Testing Strategy

### 5.1 Unit Tests (Vitest)

Location: `frontend/src/pages/videos/__tests__/`

#### `usePlaybackEntitlement.test.ts`

| Test | What it validates |
|------|-------------------|
| `issues token on mount when video is published` | Hook calls `/v1/playback/entitlements/issue` and returns token data |
| `does not issue token when video is processing` | Hook is disabled (no network call) when `video.status !== "published"` |
| `uses URL token param when present` | When `?token=` is in URL, hook returns it directly without API call |
| `refreshes token before expiry` | After 90s, a new token is fetched (mock timer advancement) |
| `returns tokenError on issue failure` | When API returns 400/401, hook exposes error state |

#### `useHlsPlayer.test.ts`

| Test | What it validates |
|------|-------------------|
| `creates HLS instance when supported` | Mocked `Hls.isSupported()` returns true, instance is created |
| `falls back to native on Safari` | `Hls.isSupported()` returns false but `canPlayType` returns `"maybe"` |
| `destroys instance on unmount` | `hls.destroy()` called in cleanup |
| `updates token ref without re-init` | Changing `entitlementToken` prop updates ref but does not destroy/recreate HLS |
| `emits levels on MANIFEST_PARSED` | `onLevelsLoaded` callback fires with parsed levels array |
| `handles fatal error gracefully` | `ERROR` event with `fatal=true` triggers error callback |

#### `QualitySelector.test.tsx`

| Test | What it validates |
|------|-------------------|
| `renders all quality levels` | Dropdown shows 1080p, 720p, 540p, 360p options |
| `shows "Auto" as default` | Initial selection is "Auto (ABR)" |
| `calls onQualityChange on selection` | Clicking "720p" calls handler with level index |
| `highlights active level` | Currently playing level shows checkmark |

#### `WatermarkOverlay.test.tsx`

| Test | What it validates |
|------|-------------------|
| `renders truncated session info` | Shows `{tenantId}:{sessionId}` text |
| `hidden when no sessionId` | Returns null when sessionId is undefined |
| `has pointer-events-none` | The overlay div has non-interactive styling |

### 5.2 E2E Tests (Playwright)

Location: `frontend/e2e/video-player.spec.ts`

Since Playwright runs in a real browser, HLS.js can be loaded and configured. However, serving actual HLS manifests from the mock backend requires mocking the manifest/segment responses. The strategy is:

1. **Mock the video metadata API** to return a `published` video with `hls_manifest_url` pointing to a test manifest.
2. **Mock the entitlement API** to return a valid token.
3. **Serve a minimal HLS manifest** via Playwright route interception (no actual media decoding needed for most tests).
4. **Test player UI** (controls, quality selector, error states) without relying on actual video playback.

#### Test Sections

**Section 110: Video Player — API Integration**

| Test | What it validates |
|------|-------------------|
| `110.1 Fetches video metadata on page load` | Navigating to `/videos/{id}` triggers `GET /ui/videos/{id}` |
| `110.2 Issues entitlement token for published video` | `POST /v1/playback/entitlements/issue` called with correct params |
| `110.3 Displays 404 error for missing video` | Navigate to non-existent ID, see "Video not found" |
| `110.4 Displays processing state for non-published video` | Mock video with `status=encoding`, see processing indicator |
| `110.5 Displays access expired on token failure` | Mock issue endpoint to return 401, see error card |

**Section 111: Video Player — HLS Playback**

| Test | What it validates |
|------|-------------------|
| `111.1 Loads HLS manifest and attaches to video element` | Video element exists with `src` or HLS.js attached |
| `111.2 Quality selector shows rendition levels` | After manifest loads, dropdown contains 1080p/720p/540p/360p + Auto |
| `111.3 Switching quality changes HLS.js level` | Select 720p, verify HLS.js level update |
| `111.4 Auto quality re-enables ABR` | Select Auto after manual 720p, verify level reset to -1 |

**Section 112: Video Player — UI Controls**

| Test | What it validates |
|------|-------------------|
| `112.1 Play/pause button toggles playback` | Click play, video plays; click pause, video pauses |
| `112.2 Volume slider adjusts video volume` | Drag slider, verify `video.volume` changes |
| `112.3 Mute button toggles mute state` | Click mute, `video.muted = true` |
| `112.4 Fullscreen button enters fullscreen` | Click fullscreen, verify `document.fullscreenElement` |
| `112.5 Seek bar updates on timeupdate` | Verify progress bar width increases over time |

**Section 113: Video Player — Metadata and Share**

| Test | What it validates |
|------|-------------------|
| `113.1 Displays video title and description` | Title and description text visible |
| `113.2 Displays formatted upload date` | Date formatted (e.g., "May 24, 2026") |
| `113.3 Share button copies URL to clipboard` | Click share, verify clipboard contains URL with token |

**Section 114: Video Player — Watermark Overlay**

| Test | What it validates |
|------|-------------------|
| `114.1 Watermark overlay visible during playback` | Text overlay element exists with session info |
| `114.2 Watermark is non-interactive` | Element has `pointer-events: none` computed style |

**Section 115: Video Player — Token Refresh**

| Test | What it validates |
|------|-------------------|
| `115.1 Token refresh occurs before expiry` | After advancing clock, second issue call is made |
| `115.2 Playback continues through token refresh` | Video remains playing during token rotation |

#### E2E Helper Pattern

```typescript
// Mock HLS manifest served via page.route()
const MOCK_MASTER_MANIFEST = `#EXTM3U
#EXT-X-VERSION:3
#EXT-X-STREAM-INF:BANDWIDTH=6000000,RESOLUTION=1920x1080
1080p/index.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=3500000,RESOLUTION=1280x720
720p/index.m3u8`;

const MOCK_VARIANT_PLAYLIST = `#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:2
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:2.000,
segment_000.ts
#EXT-X-ENDLIST`;

// In beforeAll:
await page.route("**/hls/**/master.m3u8", (route) => {
  route.fulfill({ body: MOCK_MASTER_MANIFEST, contentType: "application/vnd.apple.mpegURL" });
});
await page.route("**/hls/**/index.m3u8", (route) => {
  route.fulfill({ body: MOCK_VARIANT_PLAYLIST, contentType: "application/vnd.apple.mpegURL" });
});
await page.route("**/*.ts", (route) => {
  // Serve minimal valid MPEG-TS segment (188 bytes of zeros with sync byte)
  const minimalTs = Buffer.alloc(188, 0);
  minimalTs[0] = 0x47; // sync byte
  route.fulfill({ body: minimalTs, contentType: "video/mp2t" });
});
```

This approach allows testing the player UI, quality selection, and error handling without requiring a real video transcoding pipeline to produce actual playable segments.

### 5.3 Mocking Strategy for HLS in Playwright

The key challenge is that HLS.js will try to parse manifest files and decode segments. For E2E tests focused on UI behavior:

1. **Manifest parsing tests**: Serve syntactically valid m3u8 manifests via `page.route()`. HLS.js will parse these and populate `hls.levels` correctly, enabling quality selector tests.

2. **Segment playback tests**: For tests that need `timeupdate` events, serve minimal TS segments. Chromium's media pipeline may not decode them, but HLS.js will buffer them. Use `page.evaluate(() => video.currentTime = 5)` to simulate playback progression for seek bar tests.

3. **Error state tests**: Mock the video metadata API to return specific error codes or non-published statuses. These tests don't involve HLS.js at all.

4. **Token injection tests**: Intercept the manifest fetch via `page.route()` and verify the `Authorization` header contains the expected Bearer token:

```typescript
let capturedAuthHeader: string | null = null;
await page.route("**/master.m3u8", (route, request) => {
  capturedAuthHeader = request.headers()["authorization"] ?? null;
  route.fulfill({ body: MOCK_MASTER_MANIFEST, contentType: "application/vnd.apple.mpegURL" });
});
// ... navigate to player page ...
expect(capturedAuthHeader).toMatch(/^Bearer .+/);
```

### 5.4 Backend Unit Tests (Pytest)

No new backend code is required for VOD-008 specifically (the endpoints already exist). However, add integration tests verifying the full flow:

**`tests/test_video_playback_flow.py`**:

| Test | What it validates |
|------|-------------------|
| `test_issue_entitlement_for_video` | Issue token with video's asset_id, validate it succeeds |
| `test_expired_token_rejected` | Issue with TTL=1, sleep 2s, validate returns expired |
| `test_token_audience_mismatch_rejected` | Issue with audience "playback", validate with "other" audience fails |

### 5.5 Accessibility Testing

The video player must meet WCAG 2.1 AA:
- All controls keyboard-accessible (Tab order: play, seek, volume, quality, fullscreen)
- `aria-label` on all icon-only buttons
- `role="slider"` on seek bar and volume with `aria-valuemin`, `aria-valuemax`, `aria-valuenow`
- Focus-visible rings on all interactive elements
- Watermark overlay excluded from tab order and screen readers (`aria-hidden="true"`, `tabIndex={-1}`)

---

## Appendix: File Change Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `frontend/package.json` | Modify | Add `hls.js` dependency |
| `frontend/src/api/types.ts` | Modify | Add `VideoOut`, `VideoRendition`, `PlaybackEntitlementOut` interfaces |
| `frontend/src/api/endpoints/videos.ts` | New | API wrappers: `getVideo`, `listMyVideos`, `issuePlaybackEntitlement` |
| `frontend/src/pages/videos/VideoPlayerPage.tsx` | New | Route-level page orchestrator |
| `frontend/src/pages/videos/HlsPlayer.tsx` | New | HLS.js player wrapper component |
| `frontend/src/pages/videos/useHlsPlayer.ts` | New | HLS.js lifecycle hook |
| `frontend/src/pages/videos/usePlaybackEntitlement.ts` | New | Token issuance + refresh hook |
| `frontend/src/pages/videos/QualitySelector.tsx` | New | Rendition quality dropdown (shadcn/ui Select) |
| `frontend/src/pages/videos/PlayerControls.tsx` | New | Transport controls component |
| `frontend/src/pages/videos/VideoMetadataPanel.tsx` | New | Metadata display + share button |
| `frontend/src/pages/videos/WatermarkOverlay.tsx` | New | Forensic overlay component |
| `frontend/src/pages/videos/PlayerErrorBoundary.tsx` | New | Error state card component |
| `frontend/src/pages/videos/__tests__/usePlaybackEntitlement.test.ts` | New | Token hook unit tests |
| `frontend/src/pages/videos/__tests__/useHlsPlayer.test.ts` | New | HLS lifecycle unit tests |
| `frontend/src/pages/videos/__tests__/QualitySelector.test.tsx` | New | Quality selector unit tests |
| `frontend/src/pages/videos/__tests__/WatermarkOverlay.test.tsx` | New | Watermark overlay unit tests |
| `frontend/src/App.tsx` | Modify | Add lazy import + `<Route path="videos/:videoId">` |
| `frontend/src/components/layout/Sidebar.tsx` | Modify | Add "Videos" nav item with `Film` icon |
| `frontend/e2e/video-player.spec.ts` | New | E2E tests: sections 110-115 (~20 tests) |
