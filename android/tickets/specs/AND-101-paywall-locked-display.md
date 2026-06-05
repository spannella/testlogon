---
id: AND-101
title: Paywall / locked display
milestone: M2
epic: E14
priority: P1
size: M
status: draft
depends_on: [AND-099]
blocks: []
---

# AND-101 — Paywall / locked display

## 1. Overview & Goal

This ticket delivers the **locked-content presentation layer** for posts that the
current viewer is not entitled to see. When a post is gated behind a paywall,
the feed and detail surfaces must render a **paywall affordance** — a placeholder
that communicates *why* the content is hidden, *what it costs*, and offers a
clear call-to-action (CTA) — instead of leaking the protected text, media, or
link previews.

The scope is **display-only**. The actual purchase/unlock transaction (entering
payment, granting entitlement, refreshing the entitlement after purchase) is
explicitly **deferred to milestone M4, epic E24**. This ticket's CTA therefore
terminates in a non-functional (or stub) handler hook that downstream M4 work
will wire to the purchase flow. The single authoritative acceptance criterion
from the backlog is: **locked posts show a paywall affordance, not content.**

Goal in one sentence: extend the post item composable (AND-099) so that a
`Post.locked == true` (or equivalent gating state) renders a deterministic,
accessible, non-leaking `PaywallCard` showing price + CTA, and a corresponding
locked variant exists in the post **detail** route.

## 2. Context & References

- **Depends on:** AND-099 (Post item composable) — provides `PostItem`, the
  author header, media grid, text body, and link-preview sub-composables. This
  ticket inserts a branch into that composable's rendering and reuses its author
  header so a locked post still shows attribution.
- **Defers unlock to:** M4 / E14→E24 (purchase + entitlement). This ticket owns
  the *locked* state; E24 owns the *transition out of* the locked state.
- **Module placement:** `feature-feed` (and the shared post rendering it hosts)
  for the composable; `core-model` for the locked/price domain fields;
  `core-ui` for the reusable `PaywallCard` primitive and price formatting.
- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, Hilt, Coroutines/Flow,
  Moshi 1.15 for JSON. Package base `com.testlogon.android`.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext, unreliable). Post payloads are sourced from the existing feed
  endpoints already consumed by AND-099; this ticket consumes additional gating
  fields off the same DTO rather than calling new endpoints.
- **Web reference:** `frontend/src/api/types.ts` (post shape, monetization
  fields) and `frontend/src/api/endpoints/*.ts` for the canonical naming of
  locked/price fields. Confirm field names against `/openapi.json`
  (`components.schemas.Post`) before finalizing the Moshi DTO.

## 3. Functional Requirements

FR-1. A post whose gating state indicates it is locked for the current viewer
MUST render a `PaywallCard` in place of its protected content (body text, media
grid, link previews).

FR-2. The locked rendering MUST still display the **author header** (avatar,
display name, handle, timestamp) from AND-099, so the post remains attributable
and the feed layout stays stable.

FR-3. The `PaywallCard` MUST display, when available: a lock icon, a short
explanatory label ("Subscribers only" / "Paid content"), the **price**
formatted with currency, and a primary **CTA button** (e.g. "Unlock for
$4.99").

FR-4. If price/currency is absent or malformed, the card MUST degrade
gracefully: show the lock + label + a generic CTA ("Unlock") with no crashing
and no "$null"/"undefined" text.

FR-5. The CTA in this ticket MUST invoke an injected callback
(`onUnlockClick: (postId) -> Unit`). The default wiring is a no-op/stub that
logs intent; it MUST NOT attempt a purchase. Tapping the card body (excluding
the CTA) MAY navigate to the locked **detail** view but MUST NOT reveal content.

FR-6. The post **detail** route MUST render a locked variant of the same
`PaywallCard` (larger, full-width) when the opened post is locked, again
omitting all protected content.

FR-7. No protected field (`body`, `media`, `linkPreview`, attachment URLs) for a
locked post may be rendered, copied to clipboard, or placed in
content-description/semantics text. The teaser/preview text, if the API provides
an explicitly non-protected `teaser`, MAY be shown.

FR-8. The locked state MUST be derived purely from data already present in the
post DTO/UI model — no extra network call is required to decide locked vs
unlocked.

## 4. Technical Design

**Domain model (`core-model`).** Extend the existing post model with a typed
monetization block rather than loose booleans:

```kotlin
// com.testlogon.android.core.model.post
data class Post(
    val id: String,
    val author: Author,
    val createdAt: Instant,
    val body: String?,            // null when locked & not entitled
    val media: List<MediaItem>,   // empty when locked & not entitled
    val linkPreview: LinkPreview?,// null when locked & not entitled
    val access: PostAccess,
)

sealed interface PostAccess {
    data object Open : PostAccess
    data class Locked(
        val price: Price?,        // null => generic CTA
        val teaser: String?,      // non-protected preview text, may be null
        val reason: LockReason,   // SUBSCRIPTION, PAID_POST, AGE/etc.
    ) : PostAccess
}

data class Price(val amountMinor: Long, val currency: String) // ISO-4217
enum class LockReason { SUBSCRIPTION, PAID_POST, OTHER }
```

`Price` stores **minor units** (cents) to avoid floating-point money. A
`PriceFormatter` in `core-ui` maps it to a display string using
`java.util.Currency` + `NumberFormat.getCurrencyInstance(locale)`.

**UI primitive (`core-ui`).**

```kotlin
// com.testlogon.android.core.ui.component
@Composable
fun PaywallCard(
    access: PostAccess.Locked,
    style: PaywallStyle = PaywallStyle.Feed,   // Feed | Detail
    onUnlockClick: () -> Unit,
    modifier: Modifier = Modifier,
)

enum class PaywallStyle { Feed, Detail }
```

**Integration into AND-099's `PostItem`.** Branch on `post.access`:

```kotlin
@Composable
fun PostItem(post: Post, onUnlockClick: (String) -> Unit, /* ... */) {
    Column {
        AuthorHeader(post.author, post.createdAt) // reused from AND-099
        when (val a = post.access) {
            is PostAccess.Open ->
                PostBody(post)                     // existing AND-099 path
            is PostAccess.Locked ->
                PaywallCard(
                    access = a,
                    style = PaywallStyle.Feed,
                    onUnlockClick = { onUnlockClick(post.id) },
                )
        }
    }
}
```

Because `body`/`media`/`linkPreview` are nulled/emptied for locked posts at the
mapper layer (see §6), the protected branch is structurally unreachable for
locked content — defense in depth beyond the `when` branch.

**Detail route.** The detail screen's content slot performs the same `when`,
selecting `PaywallStyle.Detail`. The CTA callback is threaded from the screen's
ViewModel-provided lambda.

## 5. API Contract

This ticket introduces **no new endpoints**. It consumes additional fields on
the existing post payload returned by the feed/detail endpoints already used by
AND-099 (e.g. `GET /ui/feed`, `GET /ui/posts/{id}`). Confirm exact field names
against `/openapi.json` `components.schemas.Post` and
`frontend/src/api/types.ts`.

Expected locked-post JSON shape (representative; reconcile names with OpenAPI):

```json
{
  "id": "post_123",
  "author": { "id": "u_9", "display_name": "Ada", "handle": "ada", "avatar_url": "..." },
  "created_at": "2026-05-30T12:00:00Z",
  "body": null,
  "media": [],
  "link_preview": null,
  "access": {
    "state": "locked",
    "reason": "paid_post",
    "teaser": "First 200 chars maybe...",
    "price": { "amount_minor": 499, "currency": "USD" }
  }
}
```

An open post returns `"access": { "state": "open" }` (or omits `price`/`teaser`)
with `body`/`media` populated. The Moshi adapter maps `access.state` to the
`PostAccess` sealed type; unknown `state`/`reason` values map to
`Locked(reason = OTHER)` / `Open` conservatively — **fail closed**: if the
client cannot determine the post is open, treat it as locked so protected
content is never shown by accident.

If the backend does not yet expose `access`/`price` fields, the mapper falls
back to legacy booleans (`is_locked`, `price`) if present; absence of any gating
signal means `Open`. This fallback is documented as an open question (§13).

## 6. Data & State Management

- **No new ViewModel.** Locked state is a pure function of the already-loaded
  post in the existing feed/detail `StateFlow<UiState>` (Paging 3 `PagingData`
  for the feed). No additional loading/error sub-state is required.
- **Mapper hardening (`core-data`).** `PostDto.toDomain()` MUST null out
  `body`, empty `media`, and null `linkPreview` whenever `access.state` is
  locked, even if the server erroneously included them. This guarantees no
  protected payload survives into the UI layer.

```kotlin
fun PostDto.toDomain(): Post {
    val access = accessDto.toAccess()
    val locked = access is PostAccess.Locked
    return Post(
        id = id,
        author = author.toDomain(),
        createdAt = createdAt,
        body = if (locked) null else body,
        media = if (locked) emptyList() else media.map { it.toDomain() },
        linkPreview = if (locked) null else linkPreview?.toDomain(),
        access = access,
    )
}
```

- **Room cache (2.6).** Persisted post rows MUST store the access/price fields
  and MUST NOT persist protected fields for locked posts (they are already null
  post-mapping). The locked affordance therefore renders correctly from cache
  while offline.
- **CTA intent (deferred).** The `onUnlockClick` callback in this ticket emits
  no state change. A `// TODO(AND-E24)` marks the integration point where M4
  will dispatch a purchase event into the ViewModel.

## 7. Error Handling & Resilience

- **Fail-closed gating:** ambiguous or unparseable access data is treated as
  `Locked`, never `Open` (see §5). This is the central resilience invariant.
- **Missing price:** renders a generic "Unlock" CTA (FR-4); `PriceFormatter`
  returns `null` for an invalid currency code and the card falls back to the
  generic label.
- **Offline / stale:** because the locked decision needs no network call, the
  paywall renders identically online and from Room cache. The unreliable dev
  host (~20s timeout, bounded backoff for idempotent GETs only) affects the feed
  load owned by AND-099, not this ticket; a partially loaded/stale feed still
  shows correct locked affordances for whatever posts loaded.
- **CTA failure:** N/A in this ticket — the CTA performs no network work.
  Purchase error handling is owned by E24.

## 8. Security & Privacy

- **Content non-leakage is the security goal.** Protected `body`/`media`/
  `linkPreview`/attachment URLs MUST NOT appear in: the rendered tree, Compose
  `semantics`/content-descriptions, accessibility node text, clipboard actions,
  logs, or telemetry. The mapper-level nulling (§6) enforces this even if the
  server over-shares.
- No image/media requests (Coil) may be issued for locked posts' protected
  media — locked posts have empty `media`, so no `AsyncImage` is constructed.
- **Auth:** unchanged. The existing cookie-based session (`/ui/session/*`,
  `ui_csrf` echoed as `X-CSRF-Token`, single `/ui/session/refresh` retry on 401,
  persistent cookie jar) governs feed access; this ticket adds no auth surface.
- **Privacy:** telemetry (§10) logs only `postId` + lock reason + price presence
  — never teaser content, author PII beyond id, or protected fields.

## 9. Accessibility & i18n

- The `PaywallCard` is a single focusable semantic group with a
  `contentDescription` such as "Locked post. Subscribers only. Unlock for
  $4.99." The CTA button is independently focusable with role `Button`.
- Touch target for the CTA ≥ 48x48dp; meets Material 3 `Button` minimums.
- Color contrast for the lock label/CTA text MUST meet WCAG AA (4.5:1); verified
  in both light and dark Material 3 themes.
- **i18n:** all literals ("Subscribers only", "Paid content", "Unlock",
  "Unlock for %s") are string resources in `core-ui` / `feature-feed`
  `strings.xml`, supporting RTL and pluralization where relevant. Price uses
  locale-aware `NumberFormat.getCurrencyInstance(Locale.getDefault())` so
  currency symbol/placement is correct per locale; the ISO-4217 code comes from
  the server.

## 10. Telemetry & Logging

- **Impression:** emit `paywall_impression { post_id, reason, has_price }` when
  a `PaywallCard` enters composition in the feed (debounced per visible item).
- **CTA tap:** emit `paywall_cta_click { post_id, reason, price_minor,
  currency }` from `onUnlockClick`. This event is the hand-off signal E24 will
  build on.
- Events route through the app's existing analytics abstraction (interface
  injected via Hilt); no PII or protected content in payloads.
- Logging uses the standard tagged logger at `DEBUG`; production builds strip
  verbose logs. No protected fields are ever logged.

## 11. Testing Strategy

**Unit (`core-data` / `core-model`, JUnit + `core-testing`):**
- `PostDto.toDomain()` nulls `body`/`media`/`linkPreview` when access is locked,
  even when the DTO populates them.
- Moshi adapter maps `access.state == "locked"` → `PostAccess.Locked` with price
  parsed to minor units; unknown `state` → fail-closed `Locked`.
- `PriceFormatter`: 499/USD → "$4.99"; invalid currency → null/generic;
  locale variation (e.g. de-DE) formats correctly.

**Compose UI tests (`createComposeRule`):**
- Given a locked post, `PaywallCard` is displayed and the post body/media test
  tags are **absent** (asserts non-leakage — the core acceptance check).
- CTA shows formatted price when present; shows "Unlock" when price is null.
- Tapping the CTA invokes `onUnlockClick` exactly once with the correct
  `postId`; performs no navigation/content reveal.
- Detail route renders `PaywallStyle.Detail` for a locked post.
- Semantics assertion: no protected text appears in the merged semantics tree.

**Snapshot/visual (optional, if Paparazzi/Roborazzi configured):** feed and
detail locked cards in light/dark.

## 12. Dependencies & Sequencing

- **Hard dependency:** AND-099 (Post item composable) must merge first — this
  ticket branches inside `PostItem` and reuses `AuthorHeader`. Begin once
  AND-099's composable API is stable.
- **Downstream / blocks:** none in M2. The CTA callback is the seam for **M4 /
  E24** (purchase + entitlement refresh); coordinate the `onUnlockClick`
  signature with that team so the contract is stable before E24 starts.
- **Cross-cutting:** confirm post DTO field names with whoever owns the feed
  network layer (AND-099's network deps) to avoid a second Moshi schema change.

## 13. Risks & Open Questions

- **R1 — Backend field names unknown.** Whether the API exposes a structured
  `access` object vs legacy `is_locked`/`price` booleans is unconfirmed.
  *Mitigation:* mapper supports both; verify against `/openapi.json` and
  `frontend/src/api/types.ts` before merge. **Open question for backend owner.**
- **R2 — Server over-sharing protected fields.** If the API returns `body` for
  locked posts, mapper nulling protects us; confirm whether teaser vs full body
  is sent.
- **R3 — Teaser definition.** Is `teaser` an explicit non-protected field, or
  should the client truncate `body`? **Client MUST NOT truncate `body`** — only
  a server-provided `teaser` may be shown (FR-7). Needs confirmation.
- **R4 — CTA copy & legal.** "Unlock for $X" wording and any required
  subscription disclosure may need product/legal sign-off (defer to E24, but
  the string resources live here).

## 14. Acceptance Criteria

AC-1. **(Primary, from backlog)** A post in a locked state renders a paywall
affordance and **does not render** its protected body, media, or link previews,
in both feed and detail surfaces.

AC-2. The locked card shows the author header, a lock label, and a CTA; when
price + currency are present it shows the locale-formatted price (e.g.
"Unlock for $4.99"); when absent it shows a generic "Unlock".

AC-3. Tapping the CTA invokes `onUnlockClick(postId)` exactly once and performs
no purchase and no content reveal (unlock deferred to M4/E24).

AC-4. Mapping is fail-closed: ambiguous/unknown access data renders as locked,
never as open content.

AC-5. No protected field appears in the semantics tree, clipboard, logs, or
telemetry for a locked post (asserted by UI/unit tests).

AC-6. The paywall renders correctly from Room cache while offline.

## 15. Definition of Done

- Code merged to `android-port` under `com.testlogon.android` (`core-model`,
  `core-ui`, `core-data`, `feature-feed`) following the app→feature→core
  layering.
- `PaywallCard`, `PostAccess`/`Price` model, `PriceFormatter`, and `PostItem`
  branch implemented per §4; mapper hardening per §6.
- Unit + Compose tests from §11 written and green in CI; non-leakage test
  present and asserts absence of protected content.
- All user-facing strings externalized; AA contrast and 48dp CTA target
  verified in light/dark.
- Telemetry events (`paywall_impression`, `paywall_cta_click`) emitted with
  no PII/protected payload.
- `// TODO(AND-E24)` markers in place at the `onUnlockClick` seam; no purchase
  logic shipped.
- KSP/Hilt build clean (JDK 17, AGP 8.7.3, Gradle 8.9); lint passes.
- Open questions R1/R3 resolved or explicitly accepted with backend owner sign-off
  recorded in the PR.
