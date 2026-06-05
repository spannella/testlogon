---
id: AND-170
title: Watermark/overlay hooks
milestone: M4
epic: E23
priority: P1
size: M
status: draft
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
- Auth/identity: cookie-based session (`POST /ui/session/start` → MFA →
  `POST /ui/session/finalize` → `GET /ui/me`). The watermark identity is sourced from
  the already-cached `/ui/me` profile; this ticket does **not** issue its own auth calls.
- Module layering: `app -> feature-player -> core-*`. The overlay composable and its
  state live in `feature-player`; the identity model and the "current user" accessor
  live in `core-model` / `core-data`; reusable drawing primitives may live in `core-ui`.
- Canonical namespace: `com.testlogon.android`.
- Stack: Kotlin 2.0.21, Jetpack Compose + Material 3, Hilt (KSP), Coroutines/Flow,
  StateFlow<UiState>, Media3 1.4. minSdk 24, compileSdk/targetSdk 35.
- Web reference: the `frontend/` app's player overlay behavior and the protected-content
  flag exposed by the backend (see §5) are the source of truth for *when* the overlay is
  required. Inspect `frontend/src/api/endpoints/*.ts` for the media/playback DTO and
  `frontend/src/api/types.ts` for the protection flag field name to mirror it exactly.

## 3. Functional Requirements

FR-1. When a playable item's protection policy requires a watermark, an overlay MUST be
composited over the video surface for the entire playback session (playing, paused,
buffering, and seeking states all keep the overlay visible).

FR-2. The overlay text MUST include the signed-in user's identity (primary: email or
username from `/ui/me`), an account/user id, and a coarse wall-clock timestamp
(minute granularity) refreshed periodically.

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
    val primaryLine: String,        // email or username
    val secondaryLine: String,      // "id:<userId> · <HH:mm zzz>"
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

1. Identity — `GET /ui/me` (already fetched and cached post-finalize). Relevant subset:

```json
{
  "id": "usr_9f2c…",
  "email": "spannella@gmail.com",
  "username": "spannella",
  "display_name": "Sean P."
}
```

Mapped to `UserIdentity(id, email, username, displayName)`. Watermark `primaryLine`
prefers `email` then `username` then `display_name`; `secondaryLine` uses `id`.

2. Protection flag — carried on the media/playback DTO returned when AND-168 resolves a
   playable item (e.g. `GET /ui/media/{id}` or the playback descriptor). The exact field
   name MUST be mirrored from `frontend/src/api/types.ts`; the expected shape is a
   boolean/policy on the media item:

```json
{
  "id": "med_123",
  "hls_url": "http://18.222.237.167:8000/…/index.m3u8",
  "protected": true,
  "watermark_policy": { "required": true }
}
```

Moshi mapping (tolerant — default to `false` if absent so unprotected content is the
safe default):

```kotlin
@JsonClass(generateAdapter = true)
data class MediaDto(
  val id: String,
  @Json(name = "hls_url") val hlsUrl: String,
  val protected: Boolean = false,
  @Json(name = "watermark_policy") val watermarkPolicy: WatermarkPolicyDto? = null,
)
```

`PlayableItem.requiresWatermark = dto.watermarkPolicy?.required ?: dto.protected`.
FastAPI `detail` error mapping and the 401→`/ui/session/refresh`-once flow are owned by
core-network and AND-168's loader; this ticket inherits them unchanged. If the protection
flag's true name/shape differs in the live `/openapi.json`, reconcile in AND-168's DTO and
expose `requiresWatermark` as the single boolean this ticket reads (see §13 OQ-1).

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
- Missing/unknown protection flag → treated as **not required** is unsafe for protected
  media, so the rule is: `watermark_policy.required` missing AND `protected==true`
  ⇒ still `Required`; only when both are absent/false ⇒ `NotRequired`.
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

- OQ-1: Exact protection flag field name/shape on the live media DTO is unconfirmed.
  Resolution: inspect `/openapi.json` and `frontend/src/api/types.ts`; converge on a
  single `requiresWatermark` boolean in AND-168's `PlayableItem`. Until confirmed, the
  conservative default (`protected==true` ⇒ overlay) holds.
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

AC-3. The overlay text contains the signed-in user's identity (email or username) and
account id, and updates its coarse timestamp over time.

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
