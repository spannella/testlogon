---
id: AND-164
title: Legal holds / compliance (read)
milestone: M3
epic: E22
priority: P2
size: S
status: reviewed
reviewed_on: 2026-06-06
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
legal-discovery obligation. (CORRECTED: the original draft claimed "the web
reference app renders these as a small badge plus an informational note." This
could NOT be verified — `frontend/src/` contains zero references to legal-hold /
compliance-hold rendering; treat the badge/copy as a NEW native affordance, not a
port of existing web UI. See §16.) This ticket introduces the indicator on the
native app.

Concretely, the goal is: when a conversation or message carries a hold (CORRECTED:
holds are NOT inline boolean fields on the conversation/message payloads as the
original draft assumed; the backend exposes them via a dedicated read endpoint
`GET /messaging/conversations/{conversation_id}/legal-holds` → `LegalHoldOut[]`,
each with `status: active|released`. An entity is "on hold" when an `active`
`LegalHoldOut` exists for it — conversation-level when `message_id` is null,
message-level when `message_id` is set. There is NO account/workspace-level hold
field on `/messaging/config` or `/ui/me`. See §5/§16.), the UI
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
  `/messaging/conversations`, `/messaging/conversations/{conversation_id}`,
  `/messaging/conversations/{conversation_id}/messages`, `/messaging/config`.
  CORRECTED: those payloads carry NO hold fields, so this ticket does NOT add hold
  fields to `ConversationDto`/`MessageDto`. Instead it adds a thin read binding for
  `GET /messaging/conversations/{conversation_id}/legal-holds` → `LegalHoldOut[]`
  (a NEW endpoint not currently on `MessagingApi`) plus the `LegalHoldDto`, and
  joins active holds onto conversations/messages by `conversation_id`/`message_id`.
- Web reference: `frontend/src/api/endpoints/messaging.ts` defines the messaging
  client calls (delete/edit/leave etc.) but does NOT call the legal-holds endpoint
  and renders NO hold UI (verified — no `legal`/`hold` matches under
  `frontend/src/`). The authoritative source for hold field names is therefore the
  OpenAPI spec's `LegalHoldOut` schema (and the `list_message_legal_holds`
  endpoint), NOT `frontend/src/api/types.ts`. Confirm on-the-wire names against
  `/openapi.json` from the dev backend `http://18.222.237.167:8000` (PLAINTEXT
  HTTP, unreliable: ~20s timeouts, bounded retry for idempotent GETs only).
- Error model + `ApiResult<T>` (AND-015 / AND-018) and state composables
  (AND-021) are reused as-is; this ticket adds no new networking primitives.

## 3. Functional Requirements

FR-1. **Hold detection.** (CORRECTED — original assumed inline boolean fields that
do not exist.) The client treats an entity as "on hold" when the legal-holds
endpoint returns at least one `LegalHoldOut` with `status == "active"` matching the
entity: a conversation is held when an active hold with `message_id == null` exists
for its `conversation_id`; a message is held when an active hold with that
`message_id` exists. Holds with `status == "released"` (or an empty list, or a
404/empty fetch) ⇒ not held.

FR-2. **Indicator display.** For a held conversation, show a hold badge in: the
conversation list row, the conversation detail/top-bar. For a held individual
message, show a per-message hold marker. (CORRECTED: there is NO account/workspace
hold field on `/messaging/config` (`MessagingConfigOut` exposes only the seven
`messaging_*_enabled` booleans) or `/ui/me`, so an "account-wide banner" cannot be
sourced. If ANY active hold exists in the current conversation, a single banner MAY
be shown at the top of that conversation's message area summarizing "This
conversation is under legal hold"; an org-wide banner is descoped as unverifiable —
see §16.)

FR-3. **Read-only detail.** Tapping the indicator opens a read-only bottom sheet
showing available `LegalHoldOut` metadata: `reason`, `case_id`, `hold_id`,
`status`, `created_at`, `created_by_user_id`, and (when present)
`released_at`/`released_by_user_id`/`report_id`. (CORRECTED: `LegalHoldOut` has NO
`label` and NO `custodian`/`requested_by` field — use `reason` and `case_id`
instead; `created_at` is an integer epoch, not an ISO-8601 string.) No buttons that
mutate the hold; only "Close". If only minimal metadata exists, the sheet shows a
generic explanation string.

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
// CORRECTED to match the real LegalHoldOut schema (no `label`/`custodian`;
// created_at is epoch seconds; reason/case_id are the human-facing fields).
data class LegalHold(
    val holdId: String,         // hold_id (required)
    val caseId: String,         // case_id (required)
    val reason: String,         // reason (required)
    val status: HoldStatus,     // active | released
    val createdAt: Instant?,    // created_at (epoch integer -> Instant.ofEpochSecond)
    val createdByUserId: String?,   // created_by_user_id
    val messageId: String?,     // message_id (null => conversation-level)
    val source: HoldSource,     // CONVERSATION or MESSAGE (no ACCOUNT — see §16)
)

enum class HoldStatus { ACTIVE, RELEASED }
enum class HoldSource { CONVERSATION, MESSAGE }

interface Holdable { val legalHold: LegalHold? }   // null == not held
val Holdable.isOnHold: Boolean get() = legalHold != null
```

`Conversation` and `Message` domain models (owned by AND-120) implement
`Holdable`. Mapping happens in the existing AND-120 mappers; this ticket extends
them:

```kotlin
// CORRECTED: holds are joined from a separate fetch (LegalHoldOut[]), not parsed
// from inline conversation/message fields. The mapper takes the (optional) hold
// list fetched for the conversation and picks the relevant active one.
fun ConversationDto.toDomain(holds: List<LegalHoldDto>): Conversation = Conversation(
    /* existing fields … */
    legalHold = resolveHold(holds, conversationId = conversation_id, messageId = null),
)

internal fun resolveHold(
    holds: List<LegalHoldDto>,
    conversationId: String,
    messageId: String?,   // null => conversation-level; non-null => that message
): LegalHold? =
    holds.firstOrNull {
        it.status == "active" &&
        it.conversationId == conversationId &&
        it.messageId == messageId
    }?.toDomain()
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

CORRECTED — this section was substantially wrong. Verified facts:

- The conversation/message payloads carry **no** inline hold fields. `ConversationOut`
  has `conversation_id`, `type`, `created_at`, `created_by`, `participant_count`,
  `status`, plus optional `title`/`topic`/`retention_days` (an int retention policy,
  unrelated to a WORM lock) — but no `legal_hold`, `compliance_hold`, `retention`
  object, or `holds[]`. `MessageOut` keys are `message_id`/`conversation_id`/`text`
  (not `id`/`body`) and likewise carry no hold fields. `MessagingConfigOut` exposes
  only seven `messaging_*_enabled` booleans — no compliance/hold object.

- Hold data is exposed by a **dedicated READ endpoint** (this ticket DOES add one
  binding; it is not "no new endpoints"):

  `GET /messaging/conversations/{conversation_id}/legal-holds`
  (op `list_message_legal_holds`) → `200: LegalHoldOut[]`.
  Query params: `status` (enum `active`|`released`, default `active`), `limit`.
  Errors: `401|403|404|422|429 → MessageControlsErrorOut`.

  The write siblings exist but are **out of scope** (read-only ticket — do NOT bind
  them): `POST .../legal-holds` (create, `LegalHoldCreateIn → LegalHoldOut`) and
  `POST .../legal-holds/{hold_id}/release` (`LegalHoldReleaseIn → LegalHoldOut`).

`LegalHoldOut` (the real shape):

```json
{
  "hold_id": "lh_...",
  "tenant_id": "...",
  "conversation_id": "conv_...",
  "message_id": null,
  "case_id": "CASE-4471",
  "report_id": null,
  "reason": "Litigation hold for matter 4471",
  "status": "active",
  "created_at": 1740926700,
  "created_by_user_id": "usr_...",
  "released_at": null,
  "released_by_user_id": null
}
```
Required: `hold_id, tenant_id, conversation_id, case_id, reason, status,
created_at, created_by_user_id`. `created_at`/`released_at` are integer epochs.
`message_id == null` ⇒ conversation-level hold; non-null ⇒ that specific message.

DTO additions (Moshi, in `core-network`):

```kotlin
@JsonClass(generateAdapter = true)
data class LegalHoldDto(
    @Json(name = "hold_id") val holdId: String,
    @Json(name = "tenant_id") val tenantId: String? = null,
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "message_id") val messageId: String? = null,
    @Json(name = "case_id") val caseId: String,
    @Json(name = "report_id") val reportId: String? = null,
    @Json(name = "reason") val reason: String,
    @Json(name = "status") val status: String,            // "active" | "released"
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "created_by_user_id") val createdByUserId: String? = null,
    @Json(name = "released_at") val releasedAt: Long? = null,
    @Json(name = "released_by_user_id") val releasedByUserId: String? = null,
)
```

Optional fields are nullable so unknown/absent variants parse cleanly.
`resolveHold` picks the first `active` hold matching `(conversation_id, message_id)`
(see §4). The legal-holds endpoints return `MessageControlsErrorOut`
(`{ detail: string, error_code?: string }`) for 401/403/404/422/429 — NOT the
generic FastAPI `detail` union; map them through AND-015's error mapper, adding a
small adapter for `error_code` if surfaced. This ticket adds no new error codes.

## 6. Data & State Management

- Hold state is derived, not separately fetched: it rides on the conversation /
  message / config payloads the messaging layer already loads, so it is cached
  exactly the way AND-120 caches those entities (Room for conversation/message
  cache, Paging 3 for the message stream). No new DataStore keys.
- Persist active holds. CORRECTED column set to match `LegalHoldOut` (no
  `hold_label`/`hold_custodian`): either nullable columns on the conversation/
  message entities (`hold_id TEXT`, `hold_case_id TEXT`, `hold_reason TEXT`,
  `hold_status TEXT`, `hold_created_at INTEGER`, `hold_created_by TEXT`) or a small
  separate `legal_holds` table keyed by `(conversation_id, message_id)` populated
  from the legal-holds fetch. Add a schema migration if those entities are already
  persisted, otherwise include from first definition. Coordinate the column/table
  add with AND-120 to avoid duplicate migrations.
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
- Fail-safe resolution: if the legal-holds fetch itself fails (timeout / network)
  for a conversation whose cached entity was previously held, keep showing the
  last-known held state and keep destructive actions suppressed (most-restrictive
  wins) rather than silently treating it as un-held. (Original referenced
  conflicting inline `legal_hold` vs `holds[]` fields, which do not exist.)

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

AC-3. (CORRECTED — no account/workspace hold field exists.) When a conversation
has one or more active holds, a single banner renders at the top of that
conversation's message area and is announced to accessibility services.

AC-4. For any held entity, every client-initiated destructive action (delete
message, edit message, delete/leave/archive conversation, clear history) is
hidden or disabled with the reason "Unavailable: on legal hold"; the client
issues no mutation request for held content (maps to "no destructive actions").

AC-5. No new write/release/modify-hold endpoint or UI exists anywhere in the
feature.

AC-6. With a backend that returns no active holds (empty `legal-holds` response or
404), the messaging UI is byte-for-byte unchanged from pre-ticket behavior (no
badges/banners/suppression).

AC-7. `resolveHold` selects the first `active` `LegalHoldOut` matching the entity's
`(conversation_id, message_id)`, ignores `released` holds, and returns null when no
active hold matches — proven by unit tests.

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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Legal holds are exposed via `GET /messaging/conversations/{conversation_id}/legal-holds` returning `LegalHoldOut[]`, with query params `status` (enum active|released, default active) and `limit`.** VERDICT: Verified. SOURCE: OpenAPI `GET /messaging/conversations/{conversation_id}/legal-holds` (op `list_message_legal_holds`); response array of `components.schemas.LegalHoldOut`; `status`/`limit` params confirmed in the path object.

2. **Conversation/message payloads carry NO inline hold fields (`legal_hold`, `compliance_hold`, `retention` object, `holds[]`).** VERDICT: Corrected (draft was wrong). SOURCE: OpenAPI `components.schemas.ConversationOut` (props: `conversation_id, type, created_at, created_by, participant_count, status`, optional `title/topic/retention_days`, etc. — no hold fields) and `components.schemas.MessageOut` (no hold fields).

3. **Entity id/body field names are `conversation_id` / `message_id` / `text`, not `id` / `body`.** VERDICT: Corrected. SOURCE: OpenAPI `ConversationOut.conversation_id`, `MessageOut.message_id`, `MessageOut.text`.

4. **`LegalHoldOut` fields are `hold_id, tenant_id, conversation_id, message_id?, case_id, report_id?, reason, status(active|released), created_at(int epoch), created_by_user_id, released_at?(int), released_by_user_id?`. There is NO `label` and NO `custodian`/`requested_by`.** VERDICT: Corrected (draft invented `label`/`custodian` and an ISO-8601 `created_at` string). SOURCE: OpenAPI `components.schemas.LegalHoldOut`.

5. **`message_id == null` ⇒ conversation-level hold; non-null ⇒ message-level hold.** VERDICT: Verified (inferred from schema — `message_id` is nullable on both `LegalHoldOut` and `LegalHoldCreateIn`). SOURCE: OpenAPI `LegalHoldOut.message_id` (anyOf string|null), `LegalHoldCreateIn.message_id`.

6. **`/messaging/config` (`MessagingConfigOut`) carries NO compliance/legal-hold object — only seven `messaging_*_enabled` booleans; `/ui/me` likewise has no documented hold field. No account/workspace-level hold source exists.** VERDICT: Corrected (draft's `{ "compliance": { "legal_hold": true } }` is fabricated). SOURCE: OpenAPI `components.schemas.MessagingConfigOut`; `GET /ui/me` (op `ui_me_ui_me_get`).

7. **The web reference app renders NO legal-hold UI and does not call the legal-holds endpoint.** VERDICT: Corrected (draft claimed it renders a badge + note). SOURCE: `frontend/src/` — zero matches for `legal`/`hold`/`compliance hold` anywhere under src; `src/api/endpoints/messaging.ts` defines `editMessage`/`deleteMessage`/leave etc. but no legal-holds call.

8. **The legal-holds READ endpoint requires a NEW `MessagingApi` binding; it is not satisfied by reading existing AND-120 payloads.** VERDICT: Corrected (draft said "introduces no new endpoints"). SOURCE: OpenAPI op `list_message_legal_holds` (distinct operationId / path).

9. **Write/release endpoints exist but are out of scope for this read ticket.** VERDICT: Verified. SOURCE: OpenAPI `POST /messaging/conversations/{conversation_id}/legal-holds` (op `create_message_legal_hold`, `LegalHoldCreateIn → LegalHoldOut`) and `POST .../legal-holds/{hold_id}/release` (op `release_message_legal_hold`, `LegalHoldReleaseIn → LegalHoldOut`).

10. **The legal-holds endpoints return `MessageControlsErrorOut { detail: string, error_code?: string }` for 401/403/404/422/429, not the generic FastAPI `detail` union.** VERDICT: Corrected/clarified. SOURCE: OpenAPI `list_message_legal_holds` responses (`401/403/404/422/429: MessageControlsErrorOut`); `components.schemas.MessageControlsErrorOut`.

11. **Auth/transport: web client sends cookies + `X-CSRF-Token` sourced from the `ui_csrf` cookie; on 401 it performs a single `POST /ui/session/refresh` then retries.** VERDICT: Verified. SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`; `refreshSession()` POSTs `/ui/session/refresh`; single-flight `refreshPromise` on `res.status === 401`); OpenAPI `POST /ui/session/refresh` (op `ui_session_refresh`).

12. **`created_at` is an integer epoch (seconds), requiring `Instant.ofEpochSecond` rather than ISO-8601 parsing.** VERDICT: Verified/Corrected. SOURCE: OpenAPI `LegalHoldOut.created_at` (`type: integer`).

13. **Defense-in-depth: server is authority and rejects mutations on held content.** VERDICT: Unverified-assumption. The OpenAPI does not document that delete/edit/revoke endpoints reject held-message mutations with a specific code; behavior is plausible but not in the spec. Treat client-side suppression as primary; surface any server rejection generically.

14. **Material 3 `AssistChip`/`Badge`, `ModalBottomSheet`, and `Modifier.semantics { liveRegion = LiveRegionMode.Polite }` are the right framework primitives for the badge/sheet/banner with accessible announcements.** VERDICT: Verified (framework ref). SOURCE (framework ref): developer.android.com/jetpack/compose/components/bottom-sheets, developer.android.com/reference/kotlin/androidx/compose/ui/semantics/LiveRegionMode, m3.material.io/components/chips.

### Corrections made

- Removed the fabricated inline hold fields (`legal_hold`, `compliance_hold`, `retention.{locked,wormLock,policy}`, `holds[]`) from §1/§3/§4/§5; replaced with the real dedicated-endpoint model (`list_message_legal_holds` → `LegalHoldOut[]`). (claims 2, 8)
- Replaced `HoldDto`/`RetentionDto` with `LegalHoldDto` matching the real schema; dropped `label`/`custodian`/`requested_by`; added `case_id`/`reason`/`status`/`tenant_id`/`created_by_user_id`/`released_*`. (claims 4)
- Fixed entity field names to `conversation_id`/`message_id`/`text`. (claim 3)
- `created_at` typed as epoch `Long` → `Instant.ofEpochSecond`, not ISO string. (claim 12)
- Removed the non-existent account/workspace banner source (`/messaging/config`/`/ui/me`); rescoped the banner to conversation-level. Updated FR-2 and AC-3. (claim 6)
- Rewrote `resolveHold` to match-by-`(conversation_id, message_id)` on `active` holds; updated AC-7. (claims 1, 5)
- Corrected error model to `MessageControlsErrorOut`. (claim 10)
- Corrected the "no new endpoints" / "web app renders holds" claims in §1/§2/§5. (claims 7, 8)
- Updated Room columns to drop `hold_label`/`hold_custodian`, add `hold_case_id`/`hold_reason`/`hold_status`/`hold_created_by`. (claim 4)

### Open assumptions

- **Banner sourcing / org-wide holds (claim 6):** no backend field supports an account/workspace-wide hold; the banner is rescoped to conversation-level. If product requires org-wide holds, a backend addition is needed — out of scope.
- **Server-side mutation rejection on held content (claim 13):** not documented in OpenAPI; cannot be verified. Client suppression is treated as authoritative; any server rejection is mapped to a non-destructive error.
- **How holds are fetched relative to conversation/message loading (N+1 vs batch):** AND-120 does not expose a batch holds endpoint and there is no `legal_hold` flag on list payloads, so the client must call `list_message_legal_holds` per opened conversation. Whether to prefetch holds for every list row is left to AND-120 perf coordination; unverifiable from current sources.
- **`status` param value beyond active/released:** the index hints at additional enum entries; only `active`/`released` are confirmed in `LegalHoldOut.status`. Treat anything not `active` as not-held.

## 17. Test Plan

Test targets: **JVM/Robolectric** (local, no device); **emulator AVD `test35`** (x86_64, API 35); **physical device** Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). This ticket is read-only UI + JSON mapping with no camera/biometrics/WebRTC/push, so most cases run on JVM or the emulator; the physical device is used only for the arm64/API-34 parity and TalkBack-on-real-hardware checks.

- **TC-AND-164-01** — Type: unit (JVM). Target: JVM/Robolectric. Preconditions: `LegalHoldDto` list fixtures. Steps: call `resolveHold(holds, conversationId="conv_1", messageId=null)` with one `active` conversation-level hold (`message_id=null`). Expected: returns a `LegalHold` with `status=ACTIVE`, `caseId`/`reason` populated, `source=CONVERSATION`. Traces: AC-1, AC-7.

- **TC-AND-164-02** — Type: unit (JVM). Target: JVM. Preconditions: fixture list with a `released` hold and an `active` hold for the same conversation. Steps: call `resolveHold`. Expected: the `active` hold is selected; a list containing only `released` holds returns `null`. Traces: AC-6, AC-7.

- **TC-AND-164-03** — Type: unit (JVM). Target: JVM. Preconditions: fixture with an active hold whose `message_id="msg_9"`. Steps: `resolveHold(holds, "conv_1", "msg_9")` and `resolveHold(holds, "conv_1", null)`. Expected: message-level call returns the hold (`source=MESSAGE`); conversation-level call returns `null` (a message-scoped hold does not mark the whole conversation held). Traces: AC-2, AC-7.

- **TC-AND-164-04** — Type: unit (JVM). Target: JVM. Preconditions: a held `MessageUi` and an un-held one. Steps: call `allowedActions()`. Expected: held ⇒ empty set; un-held ⇒ full `MessageAction.entries`. Traces: AC-4.

- **TC-AND-164-05** — Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer enqueues a 200 `LegalHoldOut[]` body (mixed active/released, one with epoch `created_at`). Steps: invoke the `listLegalHolds(conversationId)` API binding and map to domain. Expected: request path is `/messaging/conversations/{id}/legal-holds`, method GET; `created_at` maps to `Instant.ofEpochSecond`; only `active` holds drive `isOnHold`; unknown extra JSON fields do not throw (Moshi tolerant). Traces: AC-1, AC-7.

- **TC-AND-164-06** — Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer enqueues 404 with `MessageControlsErrorOut` body `{"detail":"...","error_code":"not_found"}`. Steps: call the binding. Expected: error maps through AND-015 mapper to a non-destructive failure (treated as "no holds" / not-held for that conversation); `error_code` available to the mapper; no crash, no badge. Traces: AC-6.

- **TC-AND-164-07** — Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer configured to delay > timeout then a cached entity previously marked held. Steps: trigger a holds refresh that times out. Expected: last-known held state is preserved and destructive actions stay suppressed (fail-safe); UI surfaces a non-destructive stale/offline indicator, never silently un-holds. Traces: AC-4, AC-6. (Flaky-dev-host/offline path.)

- **TC-AND-164-08** — Type: Compose-UI. Target: emulator `test35`. Preconditions: held conversation row UI state. Steps: render the conversation list. Expected: held row shows `LegalHoldBadge` with `contentDescription` "On legal hold"; an un-held row shows no badge. Traces: AC-1.

- **TC-AND-164-09** — Type: Compose-UI. Target: emulator `test35`. Preconditions: held message + un-held message in a conversation. Steps: open the long-press/overflow menu on each. Expected: held message menu contains no destructive items (delete/edit/revoke/leave/clear) and shows supporting text "Unavailable: on legal hold"; un-held message shows them. Assert no mutation request is issued for the held message. Traces: AC-4, AC-5.

- **TC-AND-164-10** — Type: Compose-UI. Target: emulator `test35`. Preconditions: held conversation, full (non-compact) badge. Steps: tap the badge. Expected: `LegalHoldDetailSheet` opens showing `reason`, `case_id`, `status`, formatted `created_at`; only a "Close" affordance; no create/release/modify-hold buttons anywhere. Traces: AC-8, AC-5.

- **TC-AND-164-11** — Type: Compose-UI. Target: emulator `test35`. Preconditions: conversation with one or more active holds. Steps: open the conversation. Expected: a single `LegalHoldBanner` renders at the top of the message area and is exposed as a polite live region (`liveRegion = Polite`) announced when it appears. Traces: AC-3.

- **TC-AND-164-12** — Type: instrumented/e2e (accessibility). Target: **physical device (SM-A156U, API 34)** — must run on the physical device to validate real TalkBack focus order and announcements (emulator TalkBack is unreliable). Preconditions: TalkBack enabled; held conversation open. Steps: navigate to the badge, open the detail sheet, navigate disabled destructive controls. Expected: badge announces "On legal hold"; banner announced as live region; detail sheet sets initial focus on "Close" and is fully navigable; disabled controls announce state `disabled` plus `stateDescription` "Unavailable: on legal hold"; touch targets ≥ 48dp. Traces: AC-1, AC-3, AC-4, AC-8.

- **TC-AND-164-13** — Type: instrumented (ABI/API parity). Target: **physical device (arm64-v8a, API 34)** vs emulator (x86_64, API 35). Preconditions: same held fixture. Steps: run TC-08…TC-11 on both. Expected: identical hold detection, rendering, suppression, and epoch→`Instant` date formatting across arm64/API-34 and x86_64/API-35 (no ABI- or API-level divergence). Traces: AC-1, AC-2, AC-3, AC-4.

- **TC-AND-164-14** — Type: manual (security/privacy + auth). Target: emulator `test35` (or physical). Preconditions: app authenticated; logcat capture; held conversation with sensitive `reason`/`case_id`. Steps: open conversation/detail sheet; inspect logcat, crash-report payloads, and analytics events; force a 401 on the holds fetch. Expected: no `hold_id`/`reason`/`case_id`/`created_by_user_id` in logs/crash/analytics (only `legal_hold_indicator_shown {source, has_metadata}` and `legal_hold_action_suppressed {action}` are emitted); the GET carries the session cookie + `X-CSRF-Token`; 401 triggers exactly one `POST /ui/session/refresh` then a single retry. Traces: AC-1, AC-4, AC-5.

### Coverage matrix

| Acceptance criterion | Covered by |
|---|---|
| AC-1 (conversation badge, list + detail) | TC-01, TC-05, TC-08, TC-12, TC-13, TC-14 |
| AC-2 (per-message marker) | TC-03, TC-13 |
| AC-3 (conversation banner, announced) | TC-11, TC-12, TC-13 |
| AC-4 (destructive-action suppression, no mutation) | TC-04, TC-07, TC-09, TC-12, TC-13, TC-14 |
| AC-5 (no write/release/modify-hold endpoint or UI) | TC-09, TC-10, TC-14 |
| AC-6 (no active holds ⇒ unchanged UI) | TC-02, TC-06, TC-07 |
| AC-7 (resolveHold active-match semantics) | TC-01, TC-02, TC-03, TC-05 |
| AC-8 (read-only detail sheet, Close only) | TC-10, TC-12 |
