---
id: AND-170
title: Watermark/overlay hooks
milestone: M4
epic: E23
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-168]
blocks: []
---

# AND-170 — Watermark/overlay hooks

## 1. Overview & Goal

This ticket adds a dynamic, per-user watermark/overlay system that renders on top of
the reusable Media3/ExoPlayer surface delivered by AND-168 whenever protected content
is played back. The goal is to deter casual screen-recording and re-distribution of
protected video by burning a forensically traceable, moving overlay (username/email,
account id, and a coarse timestamp) into the rendered frame region for the *duration of
playback*, in both inline and fullscreen modes, and to keep the overlay legible but
non-destructive to the viewing experience.

The deliverable is a **composable overlay hook layer** plus the policy plumbing that
decides *whether* an overlay is required for a given playable item, *what text* it
displays, and *how* it animates. The overlay is a presentation-layer concern: it is a
client-side deterrent, not a DRM mechanism (see §8). The acceptance bar is narrow and
testable: **the overlay renders over playback when, and only when, the content is marked
as requiring it**, survives orientation changes and the fullscreen/PiP transitions owned
by AND-168, and carries the correct identity string for the signed-in user.

Non-goals: hardware DRM / Widevine provisioning, secure-flag screenshot blocking
policy (tracked separately — see §13), server-side burned-in watermarking, and any
new playback transport. This ticket consumes the existing player; it does not modify
its transport or controls beyond adding an overlay slot.

## 2. Context & References

- Player host: AND-168 *Reusable player UI* (Media3/ExoPlayer 1.4, HLS, controls,
  buffering/error states, fullscreen, PiP). This ticket plugs into that player's
  composable surface and must coexist with its control chrome and PiP transitions.
- Auth/identity: session via `POST /ui/session/start` → MFA → `POST /ui/session/finalize`
  → `GET /ui/me`. **Corrected:** transport is *not* purely cookie-based — the web client
  (`src/api/client.ts`) sends `Authorization: Bearer <accessToken>` from its auth store
  **and** `credentials: "include"` cookies, plus a CSRF header `X-CSRF-Token` whose value
  is read from the `ui_csrf` cookie. The Android port must mirror Bearer + cookie + CSRF.
  **Corrected:** `GET /ui/me` does **not** return profile fields. Its response (`MeResp`,
  `src/api/types.ts`) is only `{ user_sub, session_id, ip }` — no `email`, `username`, or
  `display_name`. The only identity token available from `/ui/me` is `user_sub`; any richer
  display identity (email/username) must come from a different profile source and is an
  **open assumption** (see §16). This ticket does **not** issue its own auth calls.
- Module layering: `app -> feature-player -> core-*`. The overlay composable and its
  state live in `feature-player`; the identity model and the "current user" accessor
  live in `core-model` / `core-data`; reusable drawing primitives may live in `core-ui`.
- Canonical namespace: `com.testlogon.android`.
- Stack: Kotlin 2.0.21, Jetpack Compose + Material 3, Hilt (KSP), Coroutines/Flow,
  StateFlow<UiState>, Media3 1.4. minSdk 24, compileSdk/targetSdk 35.
- Web reference: **Corrected.** The web client has **no** client-side per-user watermark
  overlay. `src/components/shared/MediaPlayer.tsx` (HLS.js player) renders only
  loading/buffering/error/title/controls overlays — there is no identity burn-in, and
  `src/pages/videos/VideoPlayerPage.tsx` mounts `MediaPlayer` with no watermark layer. The
  backend's "watermark" concept is **server-side burned-in** per-viewer rendering for
  downloads (VOD-020: `POST /ui/vod/watermark-download/{video_id}`,
  `POST /ui/videos/{video_id}/download/watermarked`) plus forensic extraction
  (`POST /internal/watermark/extract`). Consequently **there is no backend "requires
  client overlay" flag and no web precedent** for this feature: AND-170 is an Android-only,
  net-new presentation-layer deterrent. The web's nearest gating signal is the boolean
  `VideoDetail.watermark_downloads` (`src/api/endpoints/videos.ts`), which only enables a
  server-side *download* render, **not** an on-screen overlay. See §5 and §16 OQ/assumptions.

## 3. Functional Requirements

FR-1. When a playable item's protection policy requires a watermark, an overlay MUST be
composited over the video surface for the entire playback session (playing, paused,
buffering, and seeking states all keep the overlay visible).

FR-2. The overlay text MUST include the signed-in user's identity (an account/user id —
verified-available as `user_sub` from `GET /ui/me`; email/username are preferred *if a
profile source provides them*, but are **not** available from `/ui/me` — see §5/§16) and a
coarse wall-clock timestamp (minute granularity) refreshed periodically.

FR-3. When the item does **not** require a watermark, no overlay is rendered and there
is zero added draw cost on the player surface (the overlay node is absent, not merely
transparent).

FR-4. The overlay MUST move on a slow schedule (anti-static-crop): its anchor position
cycles across a small grid of positions over time so a single crop cannot reliably
remove it across a clip.

FR-5. The overlay MUST persist correctly across: device rotation, inline↔fullscreen
transition, and entering/exiting Picture-in-Picture (PiP). In PiP the overlay MAY use a
reduced-size variant but MUST remain present.

FR-6. The overlay MUST be visually subordinate to the player: it sits below the AND-168
control chrome in z-order? — **No.** It MUST sit *above* the video frame but its
interaction policy is pass-through (it never consumes touch/clicks), so controls remain
fully operable.

FR-7. The overlay's required/identity/style inputs MUST be driven by a single
`StateFlow<WatermarkUiState>` exposed by the player ViewModel, so previews and tests can
deterministically force every state.

FR-8. If user identity cannot be resolved (e.g., profile not yet loaded), but the item
requires protection, playback of protected content MUST be gated: show a non-fatal
overlay placeholder ("Protected content") and request identity; do not silently play
protected content with no traceable overlay.

## 4. Technical Design

### 4.1 Module & file layout

```
feature-player/
  src/main/java/com/testlogon/android/feature/player/overlay/
    WatermarkOverlay.kt            // @Composable overlay
    WatermarkUiState.kt            // sealed state + spec data classes
    WatermarkPolicy.kt             // required? + text builder
    WatermarkMotion.kt             // position scheduler
core-model/
  .../model/WatermarkSpec.kt       // pure model (no Compose)
  .../model/UserIdentity.kt        // from /ui/me
core-data/
  .../data/CurrentUserRepository   // already exists post-auth; read-only here
```

### 4.2 State model

```kotlin
package com.testlogon.android.feature.player.overlay

// Pure, Compose-free spec carried in core-model.
data class WatermarkSpec(
    val primaryLine: String,        // email/username if available, else user_sub
    val secondaryLine: String,      // "id:<user_sub> · <HH:mm zzz>"
    val opacity: Float = 0.16f,     // 0f..1f, default subtle
    val rotationDeg: Float = -18f,
    val cellGrid: Int = 3,          // NxN anchor grid for motion
    val cycleMillis: Long = 7_000L, // dwell time per anchor cell
)

sealed interface WatermarkUiState {
    data object NotRequired : WatermarkUiState
    data class Required(val spec: WatermarkSpec) : WatermarkUiState
    // Required but identity unresolved -> render placeholder, gate playback.
    data object PendingIdentity : WatermarkUiState
}
```

The player ViewModel (introduced in AND-168) gains one field:

```kotlin
val watermark: StateFlow<WatermarkUiState>
```

Construction combines the playable item's protection flag with the cached identity:

```kotlin
val watermark: StateFlow<WatermarkUiState> =
    combine(currentItem, currentUserRepo.identity) { item, identity ->
        WatermarkPolicy.evaluate(item, identity, clock)
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), WatermarkUiState.NotRequired)
```

### 4.3 Policy

```kotlin
object WatermarkPolicy {
    fun evaluate(
        item: PlayableItem?,
        identity: UserIdentity?,
        clock: Clock,
    ): WatermarkUiState = when {
        item == null || !item.requiresWatermark -> WatermarkUiState.NotRequired
        identity == null -> WatermarkUiState.PendingIdentity
        else -> WatermarkUiState.Required(buildSpec(identity, clock))
    }

    internal fun buildSpec(identity: UserIdentity, clock: Clock): WatermarkSpec { /* … */ }
}
```

`PlayableItem.requiresWatermark: Boolean` is mapped from the backend media DTO (§5).

### 4.4 Composable & motion

The overlay is hosted in the player's `Box` slot, declared *after* the
`PlayerSurface` and *before* the AND-168 control chrome layer so chrome wins z-order
yet the overlay covers the video:

```kotlin
@Composable
fun WatermarkOverlay(
    state: WatermarkUiState,
    modifier: Modifier = Modifier,
    compact: Boolean = false,   // true in PiP
) {
    val spec = (state as? WatermarkUiState.Required)?.spec ?: run {
        if (state is WatermarkUiState.PendingIdentity) PlaceholderOverlay(modifier)
        return
    }
    val anchor by rememberWatermarkMotion(spec)   // animates 0..1 fractional offset
    Text(
        text = "${spec.primaryLine}\n${spec.secondaryLine}",
        modifier = modifier
            .fillMaxSize()
            .wrapContentSize(align = anchor.toAlignment())
            .graphicsLayer { rotationZ = spec.rotationDeg; alpha = spec.opacity }
            .clearAndSetSemantics { }          // not announced; not focusable
            .pointerInput(Unit) { /* no-op: never consume */ },
        style = MaterialTheme.typography.labelMedium.merge(
            color = Color.White, fontSize = if (compact) 9.sp else 13.sp,
        ),
    )
}
```

`WatermarkMotion` uses an infinite-transition stepping through the `cellGrid×cellGrid`
anchor cells, dwelling `cycleMillis` per cell with a short cross-fade. Motion derives
its phase from `System.currentTimeMillis()` so it is independent of recomposition count.

### 4.5 Lifecycle / PiP / fullscreen

The overlay is a child of the same `Box` that AND-168 reparents on fullscreen, so
fullscreen needs no extra wiring. For PiP, the player passes `compact = isInPipMode`
(observed via the existing `PictureInPictureModeChangedInfo` listener from AND-168).
Rotation is config-change safe because all state is in the ViewModel / derived from
`Clock`; the composable holds no retained position.

### 4.6 Touch pass-through

`pointerInput` is a no-op and no `clickable` is attached, so the overlay never consumes
gestures; the controls layer above it receives all input.

## 5. API Contract

This ticket introduces **no new endpoints**. It consumes two existing contracts:

1. Identity — `GET /ui/me` (already fetched and cached post-finalize). **Corrected:** the
   verified response schema (`MeResp` in `src/api/types.ts`; OpenAPI `GET /ui/me` →
   `op=ui_me_ui_me_get`) is only:

```json
{
  "user_sub": "usr_9f2c…",
  "session_id": "sess_…",
  "ip": "203.0.113.7"
}
```

There is **no** `email`, `username`, `display_name`, or `id` field on `/ui/me`. The
guaranteed-available identity token is therefore `user_sub`. Mapped to
`UserIdentity(userSub, email?, username?, displayName?)` where everything except `userSub`
is nullable. Watermark `primaryLine` prefers `email` then `username` then `displayName`
**when available**, else falls back to `userSub`; `secondaryLine` always carries `userSub`.

**Open assumption (OQ-1, §16):** a richer profile (email/username) is *not* obtainable
from `/ui/me`. If product requires email in the overlay, a separate profile endpoint must
be identified in AND-168/auth work; none was found in the reference sources. Until then the
overlay is guaranteed only to render `user_sub` + timestamp.

2. Protection flag — **Corrected.** There is **no** `GET /ui/media/{id}` endpoint and **no**
   `protected` boolean or `watermark_policy` object anywhere in the backend or web types.
   The verified playable-item endpoint is `GET /ui/videos/{video_id}` →
   `VideoDetail` (OpenAPI `op=…ui_videos__video_id__get` family;
   `src/api/endpoints/videos.ts: getVideoDetail`, `src/api/types.ts: VideoDetail`). Its
   verified, relevant fields are:

```json
{
  "video_id": "vid_123",
  "visibility": "private",
  "hls_manifest_url": "https://…/index.m3u8",
  "playback_token": "…",
  "playback_expires_at": 1733443200,
  "watermark_downloads": true,
  "access_mode": "ppv",
  "is_entitled": true
}
```

Notes on the corrected fields:
- The manifest field is **`hls_manifest_url`** (not `hls_url`).
- `watermark_downloads: boolean` gates **server-side watermarked downloads only**; it is
  the *closest* existing signal but does **not** mean "render a client overlay."
- The embedded `video_share` message DTO additionally exposes `drm_enabled: boolean`
  (`src/api/types.ts` ~line 1131) — also not an overlay flag.

Because no authoritative "requires client overlay" flag exists, `requiresWatermark` is a
**product-defined, Android-local policy input** (unverified assumption, §16 OQ-1). The
recommended interim mapping, pending product/AND-168 reconciliation, is:

```kotlin
@JsonClass(generateAdapter = true)
data class VideoDetailDto(
  @Json(name = "video_id") val videoId: String,
  @Json(name = "hls_manifest_url") val hlsManifestUrl: String? = null,
  val visibility: String? = null,
  @Json(name = "watermark_downloads") val watermarkDownloads: Boolean = false,
  @Json(name = "drm_enabled") val drmEnabled: Boolean = false,
)
```

`PlayableItem.requiresWatermark` is derived from whatever protection policy product
adopts; the safe default is `false` (unprotected) so absence never accidentally overlays.
The single boolean `requiresWatermark` is the only thing this ticket reads, and it should
be produced/owned by AND-168's media loader so the policy lives in one place.

Error/auth plumbing (verified, inherited, unchanged): backend errors use FastAPI shapes —
422 is `HTTPValidationError { detail: ValidationError[] }` where
`ValidationError { loc, msg, type }`; other errors are `{ detail: string }` or
`{ detail: { code, … } }` (e.g. `code: "geo_blocked"`). The 401→`POST /ui/session/refresh`
(once) → retry flow and `X-CSRF-Token`/Bearer handling live in core-network and AND-168's
loader (`src/api/client.ts`).

## 6. Data & State Management

- Single source of truth: `WatermarkUiState` `StateFlow` on the player ViewModel,
  derived (not stored). No Room/DataStore persistence is added — the overlay is ephemeral
  and recomputed each session.
- Identity is read from the existing in-memory/DataStore-backed `CurrentUserRepository`
  populated by the auth flow; this ticket adds a read-only `identity: StateFlow<UserIdentity?>`
  accessor if not already present.
- The coarse timestamp in `secondaryLine` is recomputed by `WatermarkMotion` on each
  anchor cycle (minute granularity), so the flow itself need not emit on every tick.
- Configuration changes (rotation, fullscreen) retain state via the ViewModel; the
  composable is fully stateless apart from the motion `InfiniteTransition`.

## 7. Error Handling & Resilience

- Identity unresolved while protected → `PendingIdentity`: render "Protected content"
  placeholder overlay and gate protected playback (FR-8). The loader retries `/ui/me`
  using core-network's bounded backoff for idempotent GETs (~20s timeout per dev-host
  guidance). Once identity arrives the state transitions to `Required` and playback proceeds.
- Missing/unknown protection policy → **Corrected** (no `watermark_policy`/`protected`
  fields exist; see §5). The rule is now a single policy boolean: when the product-defined
  `requiresWatermark` cannot be evaluated (e.g., item metadata not yet loaded) the safe
  default is `NotRequired` (do not overlay), while genuine protected items resolve to
  `Required`/`PendingIdentity` per §4.3. Absence of data must never silently overlay
  unprotected content nor silently drop the overlay for a known-protected item.
- Overlay draw must never crash playback: `WatermarkOverlay` is wrapped so any text/layout
  exception is caught at the composition boundary and downgraded to a logged warning,
  leaving the video playing (a deterrent failure must not become a playback outage).
- PiP/rotation race: state is derived, so transient nulls during transition resolve to
  the last `Required` spec; the overlay never flickers off mid-clip for protected content.

## 8. Security & Privacy

- This is a **deterrent, not DRM.** It does not prevent screen capture; it makes captured
  copies attributable. The spec MUST NOT claim it blocks recording.
- `FLAG_SECURE` / screenshot suppression for protected content is **out of scope here**
  and tracked separately (see §13); if/when added it complements this overlay.
- PII minimization: the overlay shows the user's own identity to that same user only, on
  their own session — no third-party data. The id used SHOULD be the account id already
  visible to the user, not internal secrets/tokens. Never render session cookies,
  `ui_csrf`, tokens, or password material in the overlay.
- The watermark text is never transmitted anywhere; it is composed locally from
  already-authenticated profile data. No new network egress is introduced.
- Logs MUST NOT contain the full email/id at info level (see §10).

## 9. Accessibility & i18n

- The overlay is decorative/forensic and MUST NOT interfere with assistive tech:
  `clearAndSetSemantics { }` removes it from the accessibility tree and TalkBack
  traversal; it is non-focusable and non-interactive.
- Because it is excluded from semantics, it does not affect content-description order of
  the AND-168 controls.
- Contrast: opacity is intentionally low (deterrent, not informational); accessibility
  contrast minimums do **not** apply because the overlay conveys no information the user
  needs to read. The "Protected content" placeholder, however, IS user-facing and uses an
  i18n string with adequate contrast.
- i18n: user-facing strings ("Protected content") live in `feature-player` `strings.xml`
  and are localizable. Identity text (email/id) is not translated. Timestamp uses the
  device locale's `HH:mm` and the device time zone abbreviation.
- RTL: overlay anchoring uses `Alignment` values that are RTL-aware via Compose layout
  direction; rotation is mirror-neutral.

## 10. Telemetry & Logging

- Emit a structured analytics event when an overlay is shown/hidden for a session:
  `player_watermark_shown { mediaId, required: Boolean, reason: "policy"|"protected_fallback"|"pending_identity" }`.
  Do **not** include the rendered identity string in analytics.
- Debug-build logging only for state transitions
  (`NotRequired→Required`, `→PendingIdentity`); identity is logged hashed/truncated
  (e.g. first 3 chars + length) — never the full email/id.
- A counter for `watermark_render_exception` feeds the resilience guarantee in §7 so
  silent downgrade is observable.
- No new endpoints; telemetry uses the app's existing analytics sink.

## 11. Testing Strategy

Unit (`core-testing`, JUnit + Turbine):
- `WatermarkPolicy.evaluate` truth table: {item null / not protected / protected+policy.required /
  protected+policy missing} × {identity present / null} → asserts exact `WatermarkUiState`.
- `buildSpec` produces `primaryLine` preference order (email→username→displayName) and
  `secondaryLine` containing the id and an `HH:mm` token.
- DTO mapping: `requiresWatermark` resolves from `watermark_policy.required` and falls
  back to `protected`; defaults to `false` when both absent.

Compose UI tests (`createAndroidComposeRule`):
- `NotRequired` → overlay node **absent** (assert no node with the overlay test tag),
  proving FR-3 zero-cost.
- `Required` → overlay node present, text contains identity; `pointerInput` does not
  consume — a click on the controls layer still toggles play (interaction pass-through).
- `PendingIdentity` → placeholder shown, and ViewModel reports playback gated.
- `compact=true` (PiP) → overlay still present with reduced font size.

Instrumented/behavioral:
- Rotate device during protected playback → overlay remains present and re-anchors
  (no crash, ViewModel state preserved).
- Enter/exit fullscreen and PiP → overlay persists (FR-5).

Manual against dev backend (`http://18.222.237.167:8000`):
- Play a known protected item → overlay with logged-in user's email appears and moves.
- Play an unprotected item → no overlay.

## 12. Dependencies & Sequencing

- **Depends on AND-168** (Reusable player UI): supplies the player composable `Box`
  slot, the PiP/fullscreen transition machinery, the playback item loader, and the
  ViewModel this ticket extends. AND-170 cannot land before AND-168's player surface and
  PiP listener exist.
- Soft dependency on the auth/identity flow already shipped (cookie session + `/ui/me`
  cache via `CurrentUserRepository`).
- Blocks: none recorded in backlog. (`blocks: []`.)
- Sequencing: implement after AND-168 merges; reconcile the protection DTO field with
  AND-168's media loader in the same PR to avoid duplicate DTO definitions.

## 13. Risks & Open Questions

- OQ-1: **Resolved against sources, and the answer is negative.** There is no protection /
  "requires client overlay" flag in the backend (`GET /ui/videos/{video_id}` → `VideoDetail`
  has no `protected`/`watermark_policy`; only `watermark_downloads`, `drm_enabled`,
  `visibility`, `access_mode`, `is_entitled`). The web client renders no per-user overlay at
  all. Therefore `requiresWatermark` is a **product/Android-local policy decision**, not a
  mirrored backend field. Resolution: product defines the policy; converge on a single
  `requiresWatermark` boolean in AND-168's `PlayableItem`. Conservative default = `false`
  (no overlay) so missing data never overlays unprotected content.
- Risk: Overlay is a client-side deterrent only — a determined attacker can root/mirror.
  Accepted; documented in §8. Hardware-level protection is a separate effort.
- OQ-2: Should `FLAG_SECURE` (screenshot/recording suppression) be set for protected
  media? Recommended as a **follow-up ticket** in M4/E23; it interacts with PiP (FLAG_SECURE
  blanks PiP previews) so it must be co-designed with AND-168. Out of scope here.
- Risk: Low-opacity moving text could be reported as a rendering glitch by QA. Mitigate
  with a documented expected-behavior note and the `player_watermark_shown` event for triage.
- OQ-3: Motion grid/dwell tuning (`cellGrid`, `cycleMillis`, `opacity`) values are
  initial defaults; confirm with product for the right deterrence/UX balance.

## 14. Acceptance Criteria

AC-1. When playing an item whose protection policy requires a watermark, an overlay
renders over the video for the full session and is visible in playing, paused, buffering,
and seeking states. *(Maps to source acceptance: "Overlay renders over playback when required.")*

AC-2. When playing a non-protected item, no overlay node is present (verified by
absence of the overlay test tag).

AC-3. The overlay text contains the signed-in user's identity — the account id
(`user_sub`, always present from `/ui/me`), and email/username when a profile source makes
them available — and updates its coarse timestamp over time.

AC-4. The overlay moves across at least a 3×3 anchor grid over time (anti-static-crop).

AC-5. The overlay persists and remains correct across rotation, fullscreen toggle, and
PiP enter/exit (reduced size allowed in PiP), with no playback crash.

AC-6. The overlay never consumes touch input; AND-168 controls remain fully operable
while the overlay is shown.

AC-7. When protection is required but identity is unresolved, a "Protected content"
placeholder shows and protected playback is gated until identity loads.

AC-8. The overlay is excluded from the accessibility tree (not announced by TalkBack,
not focusable).

## 15. Definition of Done

- All §14 acceptance criteria pass.
- `WatermarkOverlay`, `WatermarkUiState`, `WatermarkPolicy`, `WatermarkMotion`
  implemented in `feature-player` under `com.testlogon.android.feature.player.overlay`,
  with the player ViewModel exposing `watermark: StateFlow<WatermarkUiState>`.
- DTO field for protection mapped (Moshi) and reconciled with AND-168's media loader;
  unprotected is the safe default.
- Unit tests (policy truth table, spec builder, DTO mapping) and Compose UI tests
  (present/absent, pass-through, placeholder, PiP-compact) green in CI.
- Instrumented rotation/fullscreen/PiP persistence test green.
- Telemetry event `player_watermark_shown` emitted; no PII (full email/id) in analytics
  or info-level logs; identity logged only hashed/truncated in debug builds.
- No new lint/detekt regressions; module layering (`app→feature-player→core-*`) preserved.
- §8 security note (deterrent-not-DRM) reflected in code comments; FLAG_SECURE follow-up
  filed as a separate ticket.
- Manual verification against the dev backend recorded in the PR description.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer.

1. **Session start endpoint is `POST /ui/session/start` with `UiSessionStartReq` →
   `UiSessionStartResp`.** VERDICT: Verified. SOURCE: OpenAPI
   `POST /ui/session/start | op=ui_session_start_ui_session_start_post | req=UiSessionStartReq | resp=200:UiSessionStartResp`;
   `src/api/endpoints/auth.ts: sessionStart`; `src/api/types.ts: SessionStartResp`.
2. **MFA finalize endpoint is `POST /ui/session/finalize` with `UiSessionFinalizeReq`.**
   VERDICT: Verified. SOURCE: OpenAPI
   `POST /ui/session/finalize | op=ui_session_finalize_ui_session_finalize_post | req=UiSessionFinalizeReq`;
   `src/api/endpoints/auth.ts: sessionFinalize`; `src/api/types.ts: SessionFinalizeResp`.
3. **Identity endpoint `GET /ui/me` returns `{id, email, username, display_name}`.**
   VERDICT: Corrected. The real schema `MeResp` is `{ user_sub, session_id, ip }` — no
   email/username/display_name/id. SOURCE: OpenAPI
   `GET /ui/me | op=ui_me_ui_me_get`; `src/api/types.ts: MeResp`; `src/api/endpoints/auth.ts: getMe`.
4. **Watermark `primaryLine` prefers email→username→display_name from `/ui/me`.**
   VERDICT: Corrected → Unverified-assumption. `/ui/me` exposes only `user_sub`; richer
   profile fields are not obtainable from any reference source. Overlay is guaranteed only
   `user_sub` + timestamp; email/username remain an open assumption. SOURCE: `src/api/types.ts: MeResp`.
5. **Auth transport is "cookie-based session" only.** VERDICT: Corrected. Web client sends
   `Authorization: Bearer <accessToken>` from its auth store, `credentials:"include"`
   cookies, AND a CSRF header `X-CSRF-Token` whose value is read from the `ui_csrf` cookie.
   SOURCE: `src/api/client.ts` (lines ~157-171: Bearer header, `getCookie("ui_csrf")`,
   `headers.set("X-CSRF-Token", csrf)`, `credentials:"include"`).
6. **401 triggers a single `/ui/session/refresh` then retry.** VERDICT: Verified. SOURCE:
   `src/api/client.ts: refreshSession` + 401 branch (single-flight `refreshPromise`, retry
   once, logout on second 401); OpenAPI `POST /ui/session/refresh | op=ui_session_refresh_…`.
7. **Playable item is resolved via `GET /ui/media/{id}` returning `{id, hls_url, protected,
   watermark_policy}`.** VERDICT: Corrected. No `/ui/media/{id}` endpoint exists. Real
   endpoint: `GET /ui/videos/{video_id}` → `VideoDetail`; manifest field is
   `hls_manifest_url` (not `hls_url`); there is no `protected` boolean and no
   `watermark_policy` object. SOURCE: `src/api/endpoints/videos.ts: getVideoDetail`;
   `src/api/types.ts: VideoDetail` (fields `video_id`, `hls_manifest_url`, `visibility`,
   `watermark_downloads`, `access_mode`, `is_entitled`); OpenAPI `/ui/media/preferences`
   is the only `/ui/media*` path and is unrelated (preferences, not a media item).
8. **A backend flag tells the client to render a watermark overlay.** VERDICT: Corrected →
   Unverified-assumption. No such flag exists; the nearest signal `VideoDetail.watermark_downloads`
   gates a *server-side download render*, not an on-screen overlay. `requiresWatermark` is a
   product/Android-local policy decision. SOURCE: `src/api/types.ts: VideoDetail.watermark_downloads`;
   `src/pages/videos/VideoPlayerPage.tsx` (uses it only to mount `VodWatermarkDownloadButton`).
9. **The web app has a per-user watermark overlay over playback to mirror.** VERDICT:
   Corrected. The web `MediaPlayer` renders only loading/buffering/error/title/controls
   overlays — no identity burn-in. AND-170 is Android-only net-new. SOURCE:
   `src/components/shared/MediaPlayer.tsx` (render block, no identity overlay);
   `src/pages/videos/VideoPlayerPage.tsx` (`<MediaPlayer src={playbackUrl} .../>`).
10. **Backend "watermark" is server-side burned-in / forensic.** VERDICT: Verified.
    SOURCE: OpenAPI `POST /ui/vod/watermark-download/{video_id}`,
    `POST /ui/videos/{video_id}/download/watermarked`, `POST /internal/watermark/extract`
    (`resp=WatermarkExtractResponse`); `src/api/endpoints/watermark.ts`,
    `src/api/endpoints/vodWatermarkDownload.ts`.
11. **422 validation error shape is `HTTPValidationError { detail: ValidationError[] }`.**
    VERDICT: Verified. SOURCE: OpenAPI `components.schemas.HTTPValidationError` and
    `components.schemas.ValidationError { loc, msg, type }` (openapi.pretty.json ~L37133, ~L80337);
    `src/api/client.ts: normalizeErrorDetail` (handles array of `{msg}`).
12. **Non-validation errors carry `{ detail: string }` or `{ detail: { code } }` (e.g.
    `geo_blocked`).** VERDICT: Verified. SOURCE: `src/api/client.ts` (403 branch reads
    `detail.code === "geo_blocked"`; `mapAuthorizationError` maps `role_required*` codes).
13. **DRM is out of scope; this is a deterrent, not DRM.** VERDICT: Verified (design intent)
    — consistent with sources: backend `drm_enabled`/AES-128 key URL handle real DRM
    separately. SOURCE: `src/api/types.ts` (`drm_enabled` on `video_share`);
    `src/components/shared/MediaPlayer.tsx` (`drmKeyUrl`, `emeEnabled`).
14. **Media3/ExoPlayer 1.4, Jetpack Compose overlay, `graphicsLayer`, `clearAndSetSemantics`,
    Picture-in-Picture, `InfiniteTransition`.** VERDICT: Unverified-assumption (framework
    choices, not in repo sources). SOURCE (framework ref): Android Media3 docs
    (developer.android.com/media/media3), Compose `graphicsLayer`/semantics
    (developer.android.com/jetpack/compose/graphics, .../accessibility), PiP
    (developer.android.com/develop/ui/views/picture-in-picture). Carried from AND-168.
15. **Dev backend host `http://18.222.237.167:8000`.** VERDICT: Unverified-assumption — host
    not found in reference sources (web base URL comes from `VITE_API_BASE_URL` env, not a
    hardcoded literal). SOURCE: `src/api/client.ts` (`API_BASE_URL` from env). Treat the IP
    as an operational/dev-environment value supplied out-of-band.

### Corrections made

- §2: `/ui/me` does not return profile fields (only `user_sub`/`session_id`/`ip`);
  transport is Bearer + cookies + `X-CSRF-Token` (from `ui_csrf` cookie), not cookie-only.
- §2: Removed the false claim that the web app has a watermark overlay to mirror; clarified
  the backend watermark is server-side burned-in for downloads, and this feature is net-new.
- §5: Replaced fabricated `/ui/me` `{id,email,username,display_name}` body with the real
  `MeResp`; downgraded email/username to optional/assumed.
- §5: Replaced non-existent `GET /ui/media/{id}` + `hls_url`/`protected`/`watermark_policy`
  with the real `GET /ui/videos/{video_id}` → `VideoDetail` (`hls_manifest_url`,
  `watermark_downloads`, etc.); reframed `requiresWatermark` as a product/local policy.
- §5: Added verified error shapes (`HTTPValidationError`/`ValidationError`, `{detail}` /
  `{detail:{code}}`).
- FR-2, §4.2, AC-3: identity wording aligned to `user_sub` guaranteed, email/username optional.
- §7 & §13 OQ-1: removed the `watermark_policy.required`/`protected` fallback rule; replaced
  with the single product-defined `requiresWatermark` boolean and a safe `false` default.

### Open assumptions

- **OA-1:** Email/username for the overlay are unavailable from `/ui/me`; no profile
  endpoint exposing them was found in the reference sources. The overlay can guarantee only
  `user_sub` + timestamp until product/AND-168 identify a profile source. (Why: `MeResp`
  has no such fields; no `/ui/profile`-style endpoint in `src/api/endpoints/`.)
- **OA-2:** `requiresWatermark` has no backend authority; it is a product policy decision.
  (Why: no `protected`/`watermark_policy`/overlay flag exists in `VideoDetail` or OpenAPI.)
- **OA-3:** All framework choices (Media3 1.4, Compose overlay, PiP listener,
  `InfiniteTransition`) are inherited from AND-168 and not verifiable from these sources;
  validated only against Android framework docs (framework ref).
- **OA-4:** Dev backend host/IP is environment-supplied, not in sources (env-driven base URL).

## 17. Test Plan

Test target legend: JVM = JVM unit/Robolectric (local, no device); EMU = headless emulator
AVD `test35` (x86_64, API 35); PHYS = physical Samsung Galaxy A15 5G (SM-A156U,
R5CX821TA9R, API 34, arm64-v8a). Hardware-/ABI-/API-level-dependent cases prefer PHYS.

- **TC-AND-170-01** — Policy truth table.
  Type: unit. Target: JVM. Preconditions: `WatermarkPolicy.evaluate` available; fixed `Clock`.
  Steps: call `evaluate` over the matrix {item null / `requiresWatermark=false` /
  `requiresWatermark=true`} × {identity null / identity with only `userSub` / identity with
  email}. Expected: null/false ⇒ `NotRequired`; true+null identity ⇒ `PendingIdentity`;
  true+identity ⇒ `Required(spec)`. Traces: AC-1, AC-2, AC-7.

- **TC-AND-170-02** — `buildSpec` identity precedence + timestamp token.
  Type: unit. Target: JVM. Preconditions: fixed `Clock`. Steps: build spec for identities
  (email present), (username only), (`userSub` only). Expected: `primaryLine` =
  email→username→`userSub` in that precedence; `secondaryLine` always contains `user_sub`
  and an `HH:mm` token. Traces: AC-3.

- **TC-AND-170-03** — `VideoDetail` DTO → `requiresWatermark` mapping (Moshi, tolerant).
  Type: contract. Target: JVM (Moshi only) / MockWebServer for a real `GET /ui/videos/{id}`.
  Preconditions: MockWebServer serving a verified `VideoDetail` JSON (fields `video_id`,
  `hls_manifest_url`, `watermark_downloads`, `visibility`). Steps: parse payloads with the
  policy field present/absent. Expected: missing protection data ⇒ `requiresWatermark=false`
  (safe default); no crash on unknown/extra fields; `hls_manifest_url` mapped (not `hls_url`).
  Traces: AC-2.

- **TC-AND-170-04** — Required overlay renders over video with identity text.
  Type: Compose-UI. Target: EMU. Preconditions: ViewModel forced to
  `Required(spec)` via injected `StateFlow`. Steps: compose player + overlay; assert overlay
  node by test tag exists and its text contains `user_sub` and an `HH:mm` token. Expected:
  overlay present and legible. Traces: AC-1, AC-3.

- **TC-AND-170-05** — NotRequired ⇒ overlay node absent (zero draw cost, FR-3).
  Type: Compose-UI. Target: EMU. Preconditions: state `NotRequired`. Steps: compose; query
  overlay test tag. Expected: `assertDoesNotExist()` — node absent, not merely transparent.
  Traces: AC-2.

- **TC-AND-170-06** — Touch pass-through: controls operable beneath overlay.
  Type: Compose-UI. Target: EMU. Preconditions: state `Required`; play/pause control present.
  Steps: with overlay shown, perform click at the play/pause control location. Expected:
  control toggles (overlay never consumes the gesture). Traces: AC-6.

- **TC-AND-170-07** — Overlay excluded from accessibility tree.
  Type: Compose-UI (semantics) / instrumented TalkBack smoke. Target: EMU (semantics),
  PHYS for real TalkBack traversal. Preconditions: state `Required`. Steps: assert overlay
  node is not in the merged semantics tree (`clearAndSetSemantics`), not focusable; on PHYS
  enable TalkBack and swipe-traverse. Expected: overlay never announced/focused; control
  traversal order unaffected. Traces: AC-8.

- **TC-AND-170-08** — Anti-static-crop motion across ≥3×3 grid.
  Type: Compose-UI (test clock) / instrumented. Target: EMU. Preconditions: state `Required`
  with `cellGrid=3`; advance a controllable test clock past several `cycleMillis` dwells.
  Steps: sample the overlay anchor alignment at successive cycles. Expected: anchor occupies
  ≥3 distinct cells over time (covers the grid), independent of recomposition count.
  Traces: AC-4.

- **TC-AND-170-09** — PendingIdentity placeholder + playback gated.
  Type: Compose-UI + unit. Target: EMU. Preconditions: `requiresWatermark=true`, identity
  unresolved. Steps: compose; assert "Protected content" placeholder shown; assert ViewModel
  reports protected playback gated until identity arrives, then transitions to `Required`.
  Expected: placeholder visible, no un-watermarked protected playback. Traces: AC-7.

- **TC-AND-170-10** — Rotation + fullscreen + PiP persistence.
  Type: instrumented. Target: PHYS (real PiP + config-change + rotation behavior; API 34).
  Preconditions: protected item playing, overlay `Required`. Steps: rotate device; toggle
  fullscreen; enter and exit PiP. Expected: overlay persists and re-anchors across each
  transition (reduced-size `compact` variant allowed in PiP), identity text preserved, no
  playback crash. Traces: AC-5.

- **TC-AND-170-11** — PiP compact variant present.
  Type: Compose-UI / instrumented. Target: EMU (compact flag) + PHYS (real PiP window).
  Preconditions: state `Required`, `compact=true`. Steps: render compact overlay; in PHYS
  enter true PiP. Expected: overlay still present with reduced font; never hidden in PiP.
  Traces: AC-5.

- **TC-AND-170-12** — Overlay draw exception never crashes playback (resilience, §7).
  Type: unit/Compose-UI. Target: JVM/EMU. Preconditions: inject a spec that forces a
  layout/text exception. Steps: compose overlay around a failing text node. Expected:
  exception caught at composition boundary, downgraded to logged warning + a
  `watermark_render_exception` counter increment; video composable keeps playing.
  Traces: AC-1, AC-5.

- **TC-AND-170-13** — Flaky-dev-host / offline + 401-refresh path for identity load.
  Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer scripted to (a)
  fail/timeout `GET /ui/me`, then succeed; (b) return 401 once then 200 after
  `POST /ui/session/refresh`. Steps: drive the loader through both. Expected: while
  unresolved + protected ⇒ `PendingIdentity` (gated, placeholder); bounded retry/backoff
  recovers; single refresh-then-retry on 401; on persistent failure no un-watermarked
  protected playback. Traces: AC-7.

- **TC-AND-170-14** — Security/PII: no identity in analytics or info logs.
  Type: unit. Target: JVM. Preconditions: telemetry sink + logger captured. Steps: drive
  `NotRequired→Required→PendingIdentity` transitions. Expected: `player_watermark_shown`
  emitted with `{mediaId, required, reason}` and NO rendered identity string; info-level
  logs contain no full email/`user_sub` (only hashed/truncated in debug); never logs
  cookies/`ui_csrf`/tokens. Traces: AC-3, AC-8.

- **TC-AND-170-15** — Manual end-to-end against dev backend.
  Type: manual. Target: PHYS (real network HLS playback + true PiP on API 34). Preconditions:
  signed-in session; one known protected item and one unprotected item. Steps: play the
  protected item (observe moving overlay with `user_sub`), then the unprotected item.
  Expected: overlay appears and moves only for the protected item; absent for the unprotected
  one. Record result in PR description. Traces: AC-1, AC-2, AC-4.

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (overlay over playback when required) | TC-01, TC-04, TC-12, TC-15 |
| AC-2 (no overlay when not required) | TC-01, TC-03, TC-05, TC-15 |
| AC-3 (identity + timestamp) | TC-02, TC-04, TC-14 |
| AC-4 (≥3×3 motion) | TC-08, TC-15 |
| AC-5 (rotation/fullscreen/PiP persistence, no crash) | TC-10, TC-11, TC-12 |
| AC-6 (touch pass-through) | TC-06 |
| AC-7 (PendingIdentity placeholder + gating) | TC-01, TC-09, TC-13 |
| AC-8 (excluded from a11y tree) | TC-07, TC-14 |
