---
id: AND-164
title: Legal holds / compliance (read)
milestone: M3
epic: E22
priority: P2
size: S
status: draft
depends_on: [AND-120]
blocks: []
---

# AND-164 — Legal holds / compliance (read)

## 1. Overview & Goal

Surface read-only legal-hold / compliance indicators in the Android client
wherever the backend exposes them, without ever offering a destructive or
state-changing action. A "legal hold" (also called a litigation hold or
preservation hold) is a server-side flag that prevents content from being
deleted, edited, or otherwise mutated while it is subject to a compliance or
legal-discovery obligation. The web reference app renders these as a small
badge plus an informational note; this ticket brings the same affordance to the
native app.

Concretely, the goal is: when a conversation, message, or the account/workspace
itself carries a hold (`legal_hold`, `compliance_hold`, `retention` / `wormLock`,
or equivalent fields returned by the messaging and account endpoints), the UI
must (a) display a clear, accessible "On legal hold" indicator, (b) optionally
expose the hold's reason/metadata in a read-only detail surface, and (c)
suppress or disable any client action that would mutate held content (delete
message, delete/leave conversation, edit, etc.). The feature is strictly
**read** — the client never creates, releases, or modifies a hold.

This is intentionally a small, additive, defensive ticket. It does not own the
messaging data layer (that is AND-120); it consumes the DTOs produced there,
extends the UI-state and Compose surfaces that render conversations and
messages, and adds the indicator + action-suppression logic. Where the dev
backend does not actually return hold fields, the feature degrades to "no hold"
(absent == not held) and renders nothing — there is no failure mode for missing
data.

Success means: a held conversation/message shows the indicator and its
destructive affordances are gone/disabled; an un-held one looks exactly as it
does today; and the mapping + suppression logic is covered by deterministic
tests against fixtures.

## 2. Context & References

- Repo `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. Namespace / applicationId base: `com.testlogon.android`.
- Stack: Kotlin 2.0.21, Jetpack Compose + Material 3, single-Activity
  Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12
  + Moshi 1.15, Room 2.6, DataStore, Paging 3. minSdk 24, compile/target 35,
  JDK 17, AGP 8.7.3, Gradle 8.9.
- Module layering: `app -> feature-* -> core-*`. Hold DTO fields live in
  `core-model` / `core-network`; the indicator composable lives in `core-ui`;
  the wiring lives in `feature-messaging` (and any other feature that renders
  holdable entities).
- **Depends on AND-120 (Messaging API + DTOs)** — provides `MessagingApi` and
  the `ConversationDto` / `MessageDto` / `ConfigDto` types for
  `/messaging/conversations`, `/messaging/conversations/{id}`,
  `/messaging/conversations/{id}/messages`, `/messaging/config`. This ticket
  adds the hold-related fields to those DTOs (or maps a passthrough map) and the
  domain models.
- Web reference: `frontend/src/api/endpoints/messaging.ts` and shared types in
  `frontend/src/api/types.ts` are the source of truth for the exact field names
  and badge copy. Confirm the on-the-wire names against `/openapi.json` from the
  dev backend `http://18.222.237.167:8000` (PLAINTEXT HTTP, unreliable: ~20s
  timeouts, bounded retry for idempotent GETs only).
- Error model + `ApiResult<T>` (AND-015 / AND-018) and state composables
  (AND-021) are reused as-is; this ticket adds no new networking primitives.

## 3. Functional Requirements

FR-1. **Hold detection.** The client treats an entity as "on hold" when any of
the recognized hold fields is truthy: `legal_hold == true`,
`compliance_hold == true`, a non-null `retention` object whose `locked`/`wormLock`
is true, or a non-empty `holds[]` array. Absent/null/false ⇒ not held.

FR-2. **Indicator display.** For a held conversation, show a hold badge in: the
conversation list row, the conversation detail/top-bar. For a held individual
message, show a per-message hold marker. For an account/workspace-level hold
(from `/messaging/config` or `/ui/me`), show a single dismissible-less banner at
the top of the messaging area.

FR-3. **Read-only detail.** Tapping/long-pressing the indicator opens a
read-only bottom sheet showing available hold metadata: reason/`label`,
`hold_id`, `created_at`, `custodian`/`requested_by` if present. No buttons that
mutate the hold; only "Close". If no metadata beyond the boolean exists, the
sheet shows a generic explanation string.

FR-4. **Destructive-action suppression.** When an entity is held, the client
must hide or disable every client-initiated mutation of that entity: delete
message, edit message, delete conversation, leave/archive conversation, clear
history. Disabled controls show a tooltip/supporting text "Unavailable: on legal
hold." The suppression is driven purely by the held flag in UI state, never by
trusting that the server will reject the call.

FR-5. **No destructive actions introduced.** This ticket adds zero write
endpoints and zero release/modify-hold UI. Any pre-existing destructive control
that is not gated by a hold field remains as-is for un-held entities.

FR-6. **Graceful absence.** If the backend returns none of the hold fields
(common on the dev host), the UI behaves identically to today — no badges, no
banners, no suppression.

## 4. Technical Design

Domain model additions in `core-model`:

```kotlin
data class LegalHold(
    val holdId: String?,        // hold_id
    val label: String?,         // human reason, e.g. "Litigation #4471"
    val createdAt: Instant?,    // created_at (ISO-8601)
    val custodian: String?,     // custodian / requested_by
    val source: HoldSource,     // ENTITY, CONVERSATION, ACCOUNT
)

enum class HoldSource { ACCOUNT, CONVERSATION, ENTITY }

interface Holdable { val legalHold: LegalHold? }   // null == not held
val Holdable.isOnHold: Boolean get() = legalHold != null
```

`Conversation` and `Message` domain models (owned by AND-120) implement
`Holdable`. Mapping happens in the existing AND-120 mappers; this ticket extends
them:

```kotlin
fun ConversationDto.toDomain(): Conversation = Conversation(
    /* existing fields … */
    legalHold = resolveHold(legalHold, complianceHold, retention, holds),
)

internal fun resolveHold(
    legalHold: Boolean?,
    complianceHold: Boolean?,
    retention: RetentionDto?,
    holds: List<HoldDto>?,
): LegalHold? { /* first matching source wins; see §5 */ }
```

UI state. `feature-messaging` already exposes `StateFlow<UiState>` per screen.
Add hold fields to the existing item/state types rather than new screens:

```kotlin
data class ConversationRowUi(/* … */, val onHold: Boolean, val hold: LegalHold?)
data class MessageUi(/* … */, val onHold: Boolean, val hold: LegalHold?)
data class MessagingScreenUi(/* … */, val accountHold: LegalHold?)
```

Action suppression is computed in the ViewModel when building UI state so the
Compose layer stays dumb:

```kotlin
fun MessageUi.allowedActions(): Set<MessageAction> =
    if (onHold) emptySet() else MessageAction.entries.toSet()
```

`core-ui` composable:

```kotlin
@Composable
fun LegalHoldBadge(
    hold: LegalHold,
    compact: Boolean = false,
    onClick: (() -> Unit)? = null,
    modifier: Modifier = Modifier,
)

@Composable
fun LegalHoldBanner(hold: LegalHold, modifier: Modifier = Modifier)

@Composable
fun LegalHoldDetailSheet(hold: LegalHold, onDismiss: () -> Unit)
```

The badge uses a Material 3 `AssistChip`/`Badge` with a lock-style icon and
`MaterialTheme.colorScheme.tertiaryContainer`. The detail sheet is a
`ModalBottomSheet` with read-only `Text` rows and a single "Close" affordance.

Wiring: the conversation list/detail screens render `LegalHoldBadge` when
`onHold`; the message bubble renders a compact marker; the screen renders
`LegalHoldBanner` when `accountHold != null`. The overflow/long-press menus
filter their items through `allowedActions()`.

## 5. API Contract

This ticket introduces **no new endpoints**. It reads hold fields already
present (or to be recognized) on the AND-120 endpoints. Confirm exact names
against `/openapi.json`; the recognized shapes are:

`GET /messaging/conversations` → array of:

```json
{
  "id": "conv_123",
  "title": "Acme matter",
  "legal_hold": true,
  "compliance_hold": false,
  "retention": { "locked": true, "wormLock": true, "policy": "7y" },
  "holds": [
    {
      "hold_id": "lh_4471",
      "label": "Litigation #4471",
      "created_at": "2026-03-02T14:05:00Z",
      "custodian": "legal@acme.test"
    }
  ]
}
```

`GET /messaging/conversations/{id}` → same object shape (single).

`GET /messaging/conversations/{id}/messages` → array of:

```json
{
  "id": "msg_9",
  "body": "…",
  "legal_hold": true,
  "holds": [{ "hold_id": "lh_4471", "label": "Litigation #4471" }]
}
```

`GET /messaging/config` (and/or `GET /ui/me`) may carry an account/workspace
hold:

```json
{ "compliance": { "legal_hold": true, "label": "Org-wide preservation" } }
```

DTO additions (Moshi, in `core-network`):

```kotlin
@JsonClass(generateAdapter = true)
data class HoldDto(
    @Json(name = "hold_id") val holdId: String? = null,
    @Json(name = "label") val label: String? = null,
    @Json(name = "created_at") val createdAt: String? = null,
    @Json(name = "custodian") val custodian: String? = null,
    @Json(name = "requested_by") val requestedBy: String? = null,
)

@JsonClass(generateAdapter = true)
data class RetentionDto(
    @Json(name = "locked") val locked: Boolean? = null,
    @Json(name = "wormLock") val wormLock: Boolean? = null,
    @Json(name = "policy") val policy: String? = null,
)
```

All fields are nullable with defaults so unknown/absent backends parse cleanly.
`resolveHold` precedence: explicit `holds[0]` metadata > `legal_hold`/
`compliance_hold` boolean > `retention.locked || retention.wormLock`; returns
`null` if none truthy. Errors map through the existing FastAPI `detail` mapper
(string | `[{msg}]` | `{code,…}`) from AND-015 — this ticket adds no new error
codes.

## 6. Data & State Management

- Hold state is derived, not separately fetched: it rides on the conversation /
  message / config payloads the messaging layer already loads, so it is cached
  exactly the way AND-120 caches those entities (Room for conversation/message
  cache, Paging 3 for the message stream). No new DataStore keys.
- The Room entities owned by AND-120 gain nullable hold columns
  (`legal_hold INTEGER`, `hold_id TEXT`, `hold_label TEXT`, `hold_created_at
  TEXT`, `hold_custodian TEXT`); add a schema migration if those entities are
  already persisted, otherwise include from first definition. Coordinate the
  column add with AND-120 to avoid duplicate migrations.
- ViewModel maps DTO → domain → UI state on the IO dispatcher; `onHold` and
  `allowedActions()` are pure functions of the cached entity, so offline/stale
  reads still render the correct (last-known) hold state and still suppress
  destructive actions while offline.
- No write path, no optimistic updates, no local mutation of hold state.

## 7. Error Handling & Resilience

- Missing fields are the expected default, not an error: any null/absent hold
  field ⇒ not held. JSON parse of unknown extra fields must not throw (Moshi
  tolerant defaults).
- Network failures are owned by AND-120's loaders; this ticket inherits their
  ~20s timeout, bounded backoff for idempotent GETs only, and offline/stale UI
  states (AND-016/AND-021). On stale/cached render, the last-known hold state is
  shown and destructive actions stay suppressed if the cached entity was held.
- Defense-in-depth: even if the UI failed to suppress a destructive control, the
  server is the authority and rejects mutations on held content; the client must
  surface that rejection (`detail` mapping) as a non-destructive error toast
  rather than silently failing.
- Conflicting fields (e.g. `legal_hold:false` but `holds:[…]` non-empty) resolve
  to **held** (fail-safe / most-restrictive wins).

## 8. Security & Privacy

- This is a preservation/compliance feature; the correct failure mode is
  fail-closed: when in doubt, treat content as held and suppress destruction.
- Hold metadata (custodian email, matter label) is potentially sensitive: render
  it only inside the read-only detail sheet, never in logs, crash reports, or
  analytics payloads (see §10). Do not include hold labels in screenshot-able
  notification text.
- All traffic remains over the existing cookie-based session (cookies +
  `X-CSRF-Token` from the `ui_csrf` cookie, 401 → single `POST
  /ui/session/refresh` retry). This ticket issues only GETs and adds no new
  auth surface.
- No new permissions, no PII written to DataStore. The Room hold columns hold
  the same sensitivity class as the conversation body they accompany and inherit
  its storage protections.

## 9. Accessibility & i18n

- The badge and marker must not rely on color alone: include a lock icon **and**
  text/`contentDescription` "On legal hold." Compact markers carry a
  `contentDescription`; the banner is a `Modifier.semantics { liveRegion =
  Polite }` region announced when it appears.
- Disabled destructive controls expose accessible state (`disabled`) plus a
  `stateDescription`/supporting text "Unavailable: on legal hold" so screen-
  reader users learn *why* an action is gone, not just that it is.
- Detail sheet is fully navigable by TalkBack; "Close" is the focus target on
  open. Touch targets ≥ 48dp; respects dynamic type and high-contrast themes.
- All strings (`legal_hold_badge`, `legal_hold_banner`, `legal_hold_reason`,
  `action_unavailable_legal_hold`, `legal_hold_detail_title`,
  `legal_hold_generic_explanation`) live in `strings.xml` for localization;
  dates rendered with the device locale/timezone via `java.time` formatting.

## 10. Telemetry & Logging

- Emit a single privacy-safe event when a hold indicator is shown:
  `legal_hold_indicator_shown { source: account|conversation|entity,
  has_metadata: Boolean }`. Never log `hold_id`, `label`, or `custodian`.
- Emit `legal_hold_action_suppressed { action: delete|edit|leave|… }` when a
  destructive control is hidden/disabled due to a hold, for compliance auditing
  of client behavior. No entity content in the payload.
- OkHttp logging stays at the AND-009 level; ensure hold metadata is not dumped
  at BODY level in release builds (already redacted by build flavor).
- All telemetry routes through the app's existing analytics abstraction; no
  direct logging of the detail-sheet contents.

## 11. Testing Strategy

Unit (JVM, `core-testing` + fixtures):

- `resolveHold` truth table: each field individually, precedence ordering,
  conflicting-fields → held, all-absent → null.
- `ConversationDto.toDomain` / `MessageDto.toDomain` map hold fields against
  JSON fixtures (held, un-held, partial metadata, account-level).
- `MessageUi.allowedActions()` returns empty when `onHold`, full set otherwise.

MockWebServer (contract):

- Enqueue conversation/message/config payloads with and without hold fields and
  assert the mapped domain `isOnHold` and `LegalHold` contents; assert tolerant
  parse of unknown extra fields.

Compose UI tests (`feature-messaging`):

- Held conversation row shows badge with `contentDescription` "On legal hold";
  un-held row shows none.
- Long-press menu on a held message contains no destructive items; on an un-held
  message it does.
- Tapping the badge opens the detail sheet showing the label and a "Close"
  button and **no** mutate-hold buttons.
- Account-hold banner renders and is announced as a live region.

All tests deterministic and offline (no live dev-host calls).

## 12. Dependencies & Sequencing

- **Hard dependency: AND-120 (Messaging API + DTOs)** — must land first; this
  ticket extends its DTOs, mappers, Room entities, and screens.
- Reuses (no changes required): AND-015 error mapping, AND-018 `ApiResult`,
  AND-021 state composables, AND-019/020 theme + core composables, AND-009
  OkHttp logging redaction.
- Coordinate the Room hold-column migration with whoever finalizes AND-120's
  schema to ship a single migration.
- Blocks: none currently. If a future write-side compliance ticket (release/
  apply hold) is added, it would depend on this ticket's models and copy.
- Sequencing within ticket: (1) DTO + domain fields & `resolveHold` + tests,
  (2) `core-ui` badge/banner/sheet, (3) `feature-messaging` state wiring &
  suppression, (4) UI tests.

## 13. Risks & Open Questions

- **Field names unconfirmed.** The dev backend may not expose any hold fields,
  and the exact names (`legal_hold` vs `compliance_hold` vs nested `compliance`)
  must be verified against `/openapi.json` and `frontend/src/api/types.ts`.
  Mitigation: tolerant nullable DTOs + `resolveHold` accepting all variants;
  absent ⇒ not held.
- **Granularity.** Whether holds apply per-message, per-conversation, or only
  account-wide on this backend is unknown; the design supports all three via
  `HoldSource`. If only one is real, the others render nothing (no harm).
- **Other holdable surfaces.** Scope here is messaging (per AND-120). If files/
  documents/recordings also carry holds, those are out of scope and would each
  reuse `LegalHold`/`LegalHoldBadge` in their own feature ticket.
- **Suppression completeness.** Risk that a destructive control is missed and
  left enabled on held content. Mitigation: enumerate destructive actions as a
  closed `MessageAction`/`ConversationAction` enum and gate centrally via
  `allowedActions()`; add a test per action.
- Open: should the badge be tappable to the detail sheet everywhere, or only in
  detail view? Current decision: tappable everywhere a full (non-compact) badge
  appears.

## 14. Acceptance Criteria

AC-1. A conversation whose payload carries any recognized hold field renders an
accessible "On legal hold" badge in both the list row and the detail top bar; an
un-held conversation renders no badge (maps to source acceptance "Hold state
displays").

AC-2. A held message renders a compact hold marker with a `contentDescription`;
an un-held message renders none.

AC-3. An account/workspace-level hold renders a single banner at the top of the
messaging area, announced to accessibility services.

AC-4. For any held entity, every client-initiated destructive action (delete
message, edit message, delete/leave/archive conversation, clear history) is
hidden or disabled with the reason "Unavailable: on legal hold"; the client
issues no mutation request for held content (maps to "no destructive actions").

AC-5. No new write/release/modify-hold endpoint or UI exists anywhere in the
feature.

AC-6. With a backend that returns no hold fields, the messaging UI is byte-for-
byte unchanged from pre-ticket behavior (no badges/banners/suppression).

AC-7. `resolveHold` resolves per the §5 precedence, treats conflicting fields as
held, and returns null only when no field is truthy — proven by unit tests.

AC-8. Tapping a full badge opens a read-only detail sheet showing available
metadata and only a "Close" action.

## 15. Definition of Done

- DTO hold fields, `LegalHold` domain model, `Holdable`, and `resolveHold`
  implemented in `core-model`/`core-network`, namespaced under
  `com.testlogon.android`, mapped through the AND-120 mappers.
- `LegalHoldBadge`, `LegalHoldBanner`, `LegalHoldDetailSheet` implemented in
  `core-ui` with full `contentDescription`/semantics and theme tokens.
- `feature-messaging` UI state carries `onHold`/`hold`/`accountHold`; overflow
  and long-press menus gated through `allowedActions()`; banner wired.
- Room hold columns + migration coordinated with AND-120; offline/stale reads
  preserve hold state and suppression.
- All strings externalized in `strings.xml`; dates locale/timezone-formatted.
- Telemetry events `legal_hold_indicator_shown` and
  `legal_hold_action_suppressed` emitted with no sensitive payload; no hold
  metadata in logs/crash reports.
- Tests: `resolveHold` truth-table unit tests, mapper fixture tests,
  MockWebServer contract tests, and the §11 Compose UI tests all green in CI;
  no live dev-host calls.
- Lint/detekt/ktlint clean; PR reviewed and merged to `android-port`; spec
  acceptance criteria AC-1…AC-8 demonstrably met.
