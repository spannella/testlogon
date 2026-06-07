---
id: AND-101
title: Paywall / locked display
milestone: M2
epic: E14
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
  endpoints already consumed by AND-099 — **verified** as `GET /feed`
  (op `view_feed_feed_get`) and `GET /posts/{post_id}` (op `get_post`), NOT the
  `/ui/feed` / `/ui/posts/{id}` paths an earlier draft assumed. This ticket
  consumes additional gating fields off the same DTO rather than calling new
  endpoints.
- **Web reference:** `src/api/types.ts` interface `FeedPost` (post shape,
  monetization fields) and `src/api/endpoints/newsfeed.ts` (`getFeed`,
  `getPost`, `unlockPost`) for the canonical naming of locked/price fields.
  The locked-rendering contract lives in `src/pages/feed/PostCard.tsx`. NOTE
  (verified): the OpenAPI `/feed` and `/posts/{post_id}` responses have an
  empty/untyped response schema in the index (`resp=200:`), so the **frontend
  `FeedPost` interface is the authoritative field source**, not a
  `components.schemas.Post` (which does not exist by that name).

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
content-description/semantics text. **CORRECTION:** the API exposes **no
non-protected `teaser` field** (verified — `FeedPost` has none; the web only
CSS-blurs the full `body`). The Android locked card therefore shows NO
body-derived preview text. The client MUST NOT truncate `body` to fake a teaser.

FR-8. The locked state MUST be derived purely from data already present in the
post DTO/UI model — no extra network call is required to decide locked vs
unlocked.

## 4. Technical Design

**Domain model (`core-model`).** Extend the existing post model with a typed
monetization block rather than loose booleans. This is a deliberate Android-side
abstraction over the backend's loose wire fields (`locked`, `unlocked`,
`lock_type`, `unlock_price_cents`); see the correction note below.

```kotlin
// com.testlogon.android.core.model.post
data class Post(
    val id: String,               // <- mapped from wire field `post_id`
    val author: Author,           // <- derived from `author_id` (+ profile join)
    val createdAt: Instant,       // <- ISO-8601 string `created_at`
    val body: String?,            // see CORRECTION: dropped at mapper for locked
    val media: List<MediaItem>,   // emptied at mapper when locked
    val linkPreview: LinkPreview?,// nulled at mapper when locked
    val access: PostAccess,
)

sealed interface PostAccess {
    data object Open : PostAccess
    data class Locked(
        val price: Price?,        // null => generic CTA
        val reason: LockReason,   // FIXED_PRICE | TIP_LOTTERY | OTHER
        val lockExpired: Boolean = false,  // wire `lock_expired`
        val soldOut: Boolean = false,      // wire `unlock_limit_reached`
    ) : PostAccess
}

data class Price(val amountMinor: Long, val currency: String = "USD") // see note
enum class LockReason { FIXED_PRICE, TIP_LOTTERY, OTHER }
```

> **CORRECTION (verified against `src/api/types.ts: FeedPost` and
> `src/pages/feed/PostCard.tsx`):**
> 1. There is **no structured `access` object on the wire and no `teaser`
>    field.** The backend signals locking with flat fields on `FeedPost`:
>    `locked: boolean`, `unlocked: boolean`, `lock_type: "fixed_price" |
>    "tip_lottery"`, `unlock_price_cents: number | null`, plus
>    `lock_expired`, `unlock_limit` / `unlock_count` / `unlock_limit_reached`.
>    The web computes `isLocked = !!post.locked && !post.unlocked`. The
>    `PostAccess` sealed type above is a client-side abstraction the **mapper
>    constructs from these flat fields** — it is NOT the wire shape.
> 2. The earlier "`reason`: SUBSCRIPTION/PAID_POST/AGE" enum was unverified
>    invention; the real lock taxonomy is `fixed_price` vs `tip_lottery`
>    (`FeedPost.lock_type`), mapped to `FIXED_PRICE` / `TIP_LOTTERY`.
> 3. **No currency field exists on the wire.** Prices are integer cents
>    (`unlock_price_cents`) and the web hardcodes `"$" + (cents/100).toFixed(2)`
>    (USD). `Price.currency` therefore defaults to `"USD"`; treat any
>    locale-aware formatting as a deliberate Android enhancement, not a
>    server-provided ISO-4217 code (mark in telemetry/QA that currency is
>    assumed USD until the backend exposes one).
> 4. There is **no `teaser`** — the removed field above replaces the dropped
>    `teaser`. See the §5 / §7 / §8 corrections: the server actually returns the
>    **full `body`** for locked posts (the web only blurs it client-side), so
>    the Android mapper MUST drop `body` itself.

`Price` stores **minor units** (cents) to avoid floating-point money. A
`PriceFormatter` in `core-ui` maps it to a display string using
`java.util.Currency` + `NumberFormat.getCurrencyInstance(locale)`, defaulting to
USD since the wire carries no currency code.

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
AND-099 — **verified** as `GET /feed` (op `view_feed_feed_get`) and
`GET /posts/{post_id}` (op `get_post`), not `/ui/feed` / `/ui/posts/{id}`. Field
names are **verified** against `src/api/types.ts: FeedPost` and the rendering
logic in `src/pages/feed/PostCard.tsx`; the OpenAPI index lists these endpoints
with an empty 200 response schema, so `FeedPost` is the authoritative shape (no
`components.schemas.Post` exists).

**CORRECTED locked-post JSON shape** (the wire uses flat fields — there is NO
`access` object and NO `teaser`):

```json
{
  "post_id": "post_123",
  "author_id": "u_9",
  "created_at": "2026-05-30T12:00:00Z",
  "body": "Full body text IS sent even when locked (web only blurs it)",
  "image_urls": ["..."],
  "locked": true,
  "unlocked": false,
  "lock_type": "fixed_price",
  "unlock_price_cents": 499,
  "lock_expired": false,
  "unlock_limit": 50,
  "unlock_count": 50,
  "unlock_limit_reached": true
}
```

An **open / already-unlocked** post has `"locked": false` (or `"unlocked":
true`). The web rule is exactly `isLocked = !!post.locked && !post.unlocked`
(`PostCard.tsx`). The Moshi adapter / mapper builds the `PostAccess` sealed type
from these flat fields:
`lock_type == "fixed_price"` → `LockReason.FIXED_PRICE`,
`lock_type == "tip_lottery"` → `LockReason.TIP_LOTTERY`,
any other/absent value while still locked → `LockReason.OTHER`.

**Fail closed:** if `locked == true` and `unlocked` is missing/false/ambiguous,
or if gating fields cannot be parsed, treat the post as `Locked` so protected
content is never shown by accident; only an unambiguous `locked == false` (or
`unlocked == true`) yields `Open`.

> **CORRECTION:** the earlier "`access.state`/`reason`/`teaser`/`price.amount_minor`/
> `price.currency`" object and the "legacy `is_locked`/`price` boolean fallback"
> were unverified inventions and do not exist in the contract. The real fields
> are `locked`, `unlocked`, `lock_type`, `unlock_price_cents`, `lock_expired`,
> `unlock_limit*`. Currency is implicit USD (cents only).

## 6. Data & State Management

- **No new ViewModel.** Locked state is a pure function of the already-loaded
  post in the existing feed/detail `StateFlow<UiState>` (Paging 3 `PagingData`
  for the feed). No additional loading/error sub-state is required.
- **Mapper hardening (`core-data`) — NOW LOAD-BEARING, not just belt-and-braces.**
  Verified against `PostCard.tsx`: the backend **does send the full `body`** (and
  `image_urls`, etc.) for locked posts; the web client merely CSS-blurs it
  (`blur-sm select-none`), which is *not* real protection. The Android port MUST
  therefore drop `body`, empty `media`, and null `linkPreview` itself at the
  mapper whenever the post is locked. This is the primary non-leakage mechanism
  (see §8), since we cannot rely on the server withholding protected fields.

```kotlin
fun PostDto.toDomain(): Post {
    val access = toAccess()                 // built from flat fields: locked,
                                            // unlocked, lock_type, unlock_price_cents,
                                            // lock_expired, unlock_limit_reached
    val locked = access is PostAccess.Locked
    return Post(
        id = postId,                        // wire `post_id`
        author = resolveAuthor(authorId),   // wire `author_id`
        createdAt = Instant.parse(createdAt),
        body = if (locked) null else body,           // body IS present on wire even when locked -> drop it
        media = if (locked) emptyList() else imageUrls.orEmpty().map { it.toMedia() },
        linkPreview = if (locked) null else linkPreview?.toDomain(),
        access = access,
    )
}

// Fail-closed: only an explicit unlocked post is Open.
private fun PostDto.toAccess(): PostAccess =
    if (locked == false || unlocked == true) PostAccess.Open
    else PostAccess.Locked(
        price = unlockPriceCents?.let { Price(amountMinor = it) },  // currency defaults USD
        reason = when (lockType) {
            "fixed_price" -> LockReason.FIXED_PRICE
            "tip_lottery" -> LockReason.TIP_LOTTERY
            else -> LockReason.OTHER
        },
        lockExpired = lockExpired == true,
        soldOut = unlockLimitReached == true,
    )
```

> **CORRECTION:** the prior mapper read a non-existent `accessDto`/`access.state`.
> Locked-ness is derived from flat `FeedPost` fields per `PostCard.tsx`
> (`isLocked = !!post.locked && !post.unlocked`). FR-7's "show server `teaser`"
> is unsatisfiable — there is no `teaser` field — so the Android locked card
> shows NO body-derived text at all (stronger than web, which leaks blurred body).

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
  logs, or telemetry. The mapper-level dropping (§6) enforces this — and is
  **required, not optional**: it is verified (`src/pages/feed/PostCard.tsx`)
  that the server DOES return the full `body`/`image_urls` for locked posts and
  the web client only CSS-blurs them. A blur is trivially defeated (DOM/devtools);
  the Android port must genuinely drop the fields before they reach the UI/cache.
- No image/media requests (Coil) may be issued for locked posts' protected
  media — locked posts have empty `media`, so no `AsyncImage` is constructed.
- **Auth:** unchanged, and **verified** against `src/api/client.ts`: cookie-based
  session (`credentials: "include"`), the `ui_csrf` cookie is read and echoed as
  the `X-CSRF-Token` request header, and on a `401` for an authenticated user the
  client makes a single `POST /ui/session/refresh` and retries once (a second 401
  is fatal). `POST /ui/session/start` (req `UiSessionStartReq` → `UiSessionStartResp`)
  establishes the session. This ticket adds no auth surface. (Note: the public
  `/feed` and `/posts/{post_id}` endpoints in the index also advertise
  `X-SESSION-ID` / `X-IMPERSONATION-TOKEN` params used by non-browser callers; the
  Android client follows the web cookie+CSRF model owned by AND-099.)
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
  currency symbol/placement is correct per locale. **CORRECTION:** the ISO-4217
  code does NOT come from the server (no currency field on the wire); it defaults
  to USD and SHOULD be made configurable when the backend exposes a currency.

## 10. Telemetry & Logging

- **Impression:** emit `paywall_impression { post_id, reason, has_price }` when
  a `PaywallCard` enters composition in the feed (debounced per visible item).
- **CTA tap:** emit `paywall_cta_click { post_id, reason, price_minor,
  currency }` from `onUnlockClick` (`reason` = `fixed_price`|`tip_lottery`|`other`;
  `currency` is the assumed-USD default until the backend exposes one). This event
  is the hand-off signal E24 will build on; E24's unlock call is the verified
  `POST /posts/unlock` with `{ post_id, payment_method_id }`.
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

- **R1 — Backend field names. RESOLVED (verified).** There is no structured
  `access` object and no legacy `is_locked`/`price`. The wire fields are flat on
  `FeedPost` (`src/api/types.ts`): `locked`, `unlocked`, `lock_type`
  (`fixed_price`|`tip_lottery`), `unlock_price_cents`, `lock_expired`,
  `unlock_limit`/`unlock_count`/`unlock_limit_reached`. Single source of truth:
  `FeedPost` (the `/feed` & `/posts/{post_id}` OpenAPI responses are untyped).
- **R2 — Server over-sharing protected fields. CONFIRMED REAL (not hypothetical).**
  The API returns the full `body` (and media URLs) for locked posts; the web only
  CSS-blurs them (`src/pages/feed/PostCard.tsx`). Android mapper dropping (§6) is
  therefore mandatory, not defensive.
- **R3 — Teaser definition. RESOLVED (verified).** There is **no `teaser`**
  field. The client MUST NOT truncate `body`; the locked card shows no
  body-derived text (FR-7). No further confirmation needed.
- **R5 — Currency. OPEN (verified gap).** The wire carries only integer
  `unlock_price_cents`; there is no currency field and the web hardcodes USD
  (`$` + cents/100). Android defaults to USD; multi-currency needs a backend
  field. Open question for backend owner.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Feed list endpoint is `GET /feed`** (op `view_feed_feed_get`) — *Corrected*
   (draft said `GET /ui/feed`). Source: OpenAPI index `GET /feed` (op
   `view_feed_feed_get`); frontend `src/api/endpoints/newsfeed.ts: getFeed` →
   `api.get("/feed", ...)`.
2. **Post detail endpoint is `GET /posts/{post_id}`** (op `get_post`) —
   *Corrected* (draft said `GET /ui/posts/{id}`). Source: OpenAPI index
   `GET /posts/{post_id}` (op `get_post_posts__post_id__get`); frontend
   `src/api/endpoints/newsfeed.ts: getPost` → `api.get("/posts/${postId}")`.
3. **Post wire shape is `FeedPost`, not `components.schemas.Post`** — *Corrected*.
   The `/feed` and `/posts/{post_id}` 200 responses are untyped in the index
   (`resp=200:`); no `components.schemas.Post` exists. Source: `src/api/types.ts:
   FeedPost` (line ~2181); OpenAPI index lines for `/feed` and `/posts/{post_id}`.
4. **Locked-ness is flat fields, not a structured `access` object** — *Corrected*.
   Wire fields: `locked: boolean`, `unlocked: boolean`,
   `lock_type: "fixed_price"|"tip_lottery"`, `unlock_price_cents: number|null`,
   `lock_expired`, `unlock_limit`/`unlock_count`/`unlock_limit_reached`. Source:
   `src/api/types.ts: FeedPost` (fields at lines ~2207-2225).
5. **Web "is locked" rule = `!!post.locked && !post.unlocked`** — *Verified*.
   Source: `src/pages/feed/PostCard.tsx` (`const isLocked = !!post.locked &&
   !post.unlocked;`, line ~353).
6. **There is no `teaser` field** — *Corrected* (draft assumed a server `teaser`).
   Source: `src/api/types.ts: FeedPost` (no teaser member);
   `src/pages/feed/PostCard.tsx` shows the locked branch blurs the full body, no
   teaser path.
7. **Server returns full `body` for locked posts (over-share)** — *Verified*.
   Source: `src/pages/feed/PostCard.tsx` lines ~493-503: the `isLocked` branch
   renders `<RichContentRenderer body={post.body} ... />` inside a `blur-sm
   select-none` wrapper. Implication: Android mapper MUST drop body itself.
8. **Lock taxonomy is `fixed_price` vs `tip_lottery`** — *Corrected* (draft said
   SUBSCRIPTION/PAID_POST/AGE). Source: `src/api/types.ts: FeedPost.lock_type`;
   `src/pages/feed/PostCard.tsx` (`isLotteryLock`, `isFixedPriceLock`, lines
   ~351-352).
9. **Price is integer cents with NO currency field (USD hardcoded)** —
   *Corrected* (draft claimed a server ISO-4217 currency). Source:
   `src/api/types.ts: FeedPost.unlock_price_cents`; `src/pages/feed/PostCard.tsx`
   formats `` `Unlock for $${((post.unlock_price_cents ?? 0)/100).toFixed(2)}` ``
   (lines ~529, ~614).
10. **Sold-out / lock-expired states exist** — *Verified*. Source:
    `src/pages/feed/PostCard.tsx` `soldOut` from `unlock_limit_reached` /
    `unlock_count >= unlock_limit` (lines ~212-216) and `lockExpired` →
    "Lock expired" copy (line ~507).
11. **Unlock transaction (M4/E24) is `POST /posts/unlock` with
    `{post_id, payment_method_id}`** — *Verified*. Source:
    `src/api/endpoints/newsfeed.ts: unlockPost` → `api.post("/posts/unlock",
    {post_id, payment_method_id})`; OpenAPI index `POST /posts/unlock`. (Note
    the per-post `POST /posts/{post_id}/video/entitlement` exists for video, also
    out of scope here.)
12. **Real unlock error codes** (relevant to E24, used in error-shape tests):
    `unlock_limit_reached`, `lock_expired`, `unlock_attempt_throttled` —
    *Verified*. Source: `src/pages/feed/PostCard.tsx` unlock mutation `onError`
    reads `error.body.detail.code` (lines ~300-321).
13. **Generic backend validation error is `HTTPValidationError` (HTTP 422)** —
    *Verified*. Source: OpenAPI index `resp=...;422:HTTPValidationError` on
    `/feed` and `/posts/{post_id}`.
14. **Auth: cookie session + `ui_csrf`→`X-CSRF-Token`, single refresh on 401** —
    *Verified*. Source: `src/api/client.ts`: `getCookie("ui_csrf")` →
    `headers.set("X-CSRF-Token", csrf)` (lines ~168-170); `credentials:
    "include"` (lines ~183, ~220); 401 handling → one `refreshSession()` →
    `POST /ui/session/refresh` then retry (lines ~119-224). Session bootstrap
    `POST /ui/session/start` (`UiSessionStartReq`→`UiSessionStartResp`), OpenAPI
    index `POST /ui/session/start`.
15. **No new endpoints / no extra network call to decide locked** — *Verified*.
    Locked state is computed from already-loaded `FeedPost` fields client-side
    (`src/pages/feed/PostCard.tsx`); no gating fetch exists.
16. **Stack & toolchain choices** (Kotlin 2.0.21, Compose + Material 3, Hilt,
    Moshi, Paging 3, Coil, Room, JDK 17 / AGP 8.7.3 / Gradle 8.9) —
    *Unverified-assumption* (inherited from AND-099 / repo conventions; not
    checkable from the backend or frontend sources). Framework refs:
    Compose `Modifier.semantics`/`clearAndSetSemantics` —
    https://developer.android.com/jetpack/compose/semantics ;
    minimum 48dp touch target —
    https://support.google.com/accessibility/android/answer/7101858 ;
    currency formatting via `NumberFormat.getCurrencyInstance` —
    https://developer.android.com/reference/java/text/NumberFormat .
17. **Dev host `http://18.222.237.167:8000`, plaintext/unreliable, ~20s timeout,
    backoff for idempotent GETs** — *Unverified-assumption* (operational detail
    not present in the OpenAPI or frontend sources; owned by AND-099 network
    layer).

### Corrections made

- C1 — Feed endpoint `/ui/feed` → **`GET /feed`** (§2, §5). [citation 1]
- C2 — Detail endpoint `/ui/posts/{id}` → **`GET /posts/{post_id}`** (§2, §5).
  [citation 2]
- C3 — `components.schemas.Post` → authoritative shape is frontend **`FeedPost`**
  (§2, §5). [citation 3]
- C4 — Structured `access:{state,reason,teaser,price:{amount_minor,currency}}`
  object → **flat fields** `locked`/`unlocked`/`lock_type`/`unlock_price_cents`/
  `lock_expired`/`unlock_limit*`; mapper builds the sealed `PostAccess` from them
  (§4, §5, §6). [citations 4, 5]
- C5 — `teaser` field removed; client shows no body-derived preview text (§3 FR-7,
  §4, §6). [citation 6]
- C6 — "server may over-share body" reframed from hypothetical to **verified
  fact**; mapper dropping is mandatory primary protection (§6, §8, §13 R2).
  [citation 7]
- C7 — Lock taxonomy SUBSCRIPTION/PAID_POST/OTHER → **FIXED_PRICE/TIP_LOTTERY/
  OTHER** (§4). [citation 8]
- C8 — Server-provided ISO-4217 currency → **no currency on wire; USD default**
  (§4, §9, §10, §13 R5). [citation 9]
- C9 — Removed the invented "legacy `is_locked`/`price` boolean fallback" (§5).
  [citation 4]
- C10 — Added verified unlock endpoint/error codes for the E24 seam (§10, §13 R2).
  [citations 11, 12]

### Open assumptions

- OA1 — **Currency is USD.** Wire carries only `unlock_price_cents`; no currency
  code exists (citation 9). Unverifiable beyond "web hardcodes USD"; needs a
  backend field for multi-currency. (§13 R5)
- OA2 — **Toolchain/library versions** (citation 16) are inherited from AND-099 /
  repo convention and cannot be confirmed from the backend/frontend sources.
- OA3 — **Dev-host transport behavior** (timeout/backoff, citation 17) is an
  AND-099-owned operational assumption, not in the authoritative sources.
- OA4 — **Author header data for a locked post.** The wire post exposes
  `author_id` only (citation 4); how avatar/display-name/handle are resolved
  (embedded vs profile join) is owned by AND-099 and is assumed available to the
  reused `AuthorHeader`. Unverified here.
- OA5 — **Detail screen reuses `FeedPost`.** `getPost` returns `FeedPost`
  (citation 2), so the locked decision is identical to feed; assumed the detail
  ViewModel exposes the same model (AND-099 territory).

## 17. Test Plan

Test target legend: **JVM** = local JVM unit/Robolectric (no device);
**Emu35** = headless AVD `test35` (x86_64, Android 15 / API 35) in CI;
**A15** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, Android
14 / API 34, arm64-v8a). This ticket is display-only (no camera/biometrics/
WebRTC/FCM), so most cases run on JVM or Emu35; one ABI/API-parity case is
pinned to the physical device.

- **TC-AND-101-01 — Mapper drops protected fields for a locked post.**
  Type: unit. Target: JVM (`core-data`). Preconditions: a `FeedPost` JSON with
  `locked=true`, `unlocked=false`, non-empty `body`, non-empty `image_urls`, a
  `link_preview`, `lock_type="fixed_price"`, `unlock_price_cents=499`. Steps:
  call `PostDto.toDomain()`. Expected: result `access` is `PostAccess.Locked(
  price=Price(499,"USD"), reason=FIXED_PRICE)`; `body==null`, `media` empty,
  `linkPreview==null` (proving the server's over-shared body is dropped — see
  citation 7). Traces: AC-1, AC-5.
- **TC-AND-101-02 — Fail-closed mapping on ambiguous gating.** Type: unit.
  Target: JVM. Preconditions: three DTOs — (a) `locked=true, unlocked` absent;
  (b) `lock_type` = unknown string while `locked=true`; (c) malformed/missing
  gating fields. Steps: map each. Expected: all → `PostAccess.Locked` (case b
  with `reason=OTHER`); never `Open`. A DTO with `locked=false` (or
  `unlocked=true`) → `PostAccess.Open` with body populated. Traces: AC-4.
- **TC-AND-101-03 — Lock-type / reason mapping.** Type: unit. Target: JVM.
  Preconditions: DTOs with `lock_type` = `fixed_price`, `tip_lottery`, and an
  unknown value. Steps: map. Expected: `FIXED_PRICE`, `TIP_LOTTERY`, `OTHER`
  respectively (citation 8). Also `unlock_limit_reached=true` → `soldOut=true`;
  `lock_expired=true` → `lockExpired=true` (citation 10). Traces: AC-2, AC-4.
- **TC-AND-101-04 — PriceFormatter.** Type: unit. Target: JVM. Preconditions:
  `Price(499,"USD")`; `Price(0,"USD")`; an invalid currency code; locale `de-DE`.
  Steps: format. Expected: `"$4.99"` (en-US), graceful handling of 0, `null`/
  generic for invalid currency (drives FR-4 generic CTA), and locale-correct
  symbol/placement for de-DE. Traces: AC-2.
- **TC-AND-101-05 — Contract test against recorded `/feed` & `/posts/{id}`
  payloads (MockWebServer).** Type: contract/MockWebServer. Target: JVM. Pre:
  MockWebServer enqueues a representative `GET /feed` body and a
  `GET /posts/{post_id}` body each containing one locked and one open post, shaped
  per §5 (flat fields; locked item includes full `body`). Steps: run the feed/
  detail repository load through the real Moshi adapter + mapper. Expected:
  request paths are exactly `/feed` and `/posts/{post_id}` (citations 1, 2);
  locked items map to `Locked` with body dropped, open items keep body; parsing
  tolerates unknown extra fields. Traces: AC-1, AC-4.
- **TC-AND-101-06 — 422 validation / error-shape handling.** Type:
  contract/MockWebServer. Target: JVM. Pre: MockWebServer returns `422` with an
  `HTTPValidationError` body for `/feed`. Steps: load feed. Expected: error
  surfaces via AND-099's error state without crashing; no paywall rendered for a
  failed load; the error shape matches `HTTPValidationError` (citation 13).
  Traces: AC-6 (resilience), AC-1.
- **TC-AND-101-07 — PaywallCard renders, no protected content (feed).** Type:
  Compose-UI. Target: Emu35. Pre: locked `Post` (body already dropped by mapper)
  with `Price(499,"USD")`. Steps: render `PostItem`. Expected: `PaywallCard`
  shown with author header, lock label, and CTA "Unlock for $4.99"; the post-body
  / media test tags are **absent**; no node anywhere contains the original body
  text. Traces: AC-1, AC-2, AC-5.
- **TC-AND-101-08 — Generic CTA when price missing/malformed.** Type: Compose-UI.
  Target: Emu35. Pre: locked `Post` with `price=null` (e.g.
  `unlock_price_cents` was null). Steps: render. Expected: card shows lock + label
  + generic "Unlock"; no "$null"/"undefined"/"$0.00-from-null" text. Traces:
  AC-2 (FR-4).
- **TC-AND-101-09 — CTA invokes callback exactly once, no reveal/navigation.**
  Type: Compose-UI. Target: Emu35. Pre: locked `Post`, spy `onUnlockClick`.
  Steps: tap CTA. Expected: `onUnlockClick(postId)` called exactly once with the
  correct id; no purchase/network call; no protected content becomes visible.
  Traces: AC-3.
- **TC-AND-101-10 — Detail route locked variant.** Type: Compose-UI. Target:
  Emu35. Pre: detail screen opened on a locked post (`getPost` → `FeedPost`,
  citation 2). Steps: render detail content slot. Expected: `PaywallCard` with
  `PaywallStyle.Detail` (full-width); no body/media/link-preview rendered.
  Traces: AC-1.
- **TC-AND-101-11 — Semantics non-leakage assertion.** Type: Compose-UI. Target:
  Emu35. Pre: locked `Post`; the source DTO body string is known. Steps: render,
  then traverse the merged semantics tree and assert no `Text`/`contentDescription`
  node contains the body/media-URL strings; the card's own `contentDescription`
  is a single focusable group ("Locked post. … Unlock for $4.99.") and the CTA
  has role `Button`. Traces: AC-5, AC-2.
- **TC-AND-101-12 — Accessibility: touch target & contrast.** Type:
  instrumented (Compose-UI + a11y checks via `AccessibilityChecks` /
  Espresso-a11y). Target: Emu35. Pre: locked card in light and dark Material 3
  themes. Steps: enable accessibility checks; assert. Expected: CTA ≥ 48x48dp;
  label/CTA text meets WCAG AA 4.5:1 in both themes; no a11y violations.
  Traces: AC-2, AC-5.
- **TC-AND-101-13 — Offline render from Room cache.** Type: instrumented/e2e.
  Target: Emu35 (airplane mode toggled via adb). Pre: feed loaded once online so
  a locked post (body already null per mapper) is persisted to Room; then go
  offline. Steps: relaunch / scroll to the cached locked post with no network.
  Expected: `PaywallCard` renders identically from cache; the unreliable dev host
  being unreachable does not affect the locked affordance; no protected body in
  the cached row. Traces: AC-6, AC-1, AC-5.
- **TC-AND-101-14 — No protected-content leak to clipboard/logs.** Type:
  instrumented. Target: Emu35. Pre: locked post; logcat captured. Steps: attempt
  long-press/select on the card; inspect clipboard and logcat/telemetry sink.
  Expected: nothing selectable/copyable exposes body/media; logcat and the
  analytics payloads (`paywall_impression`/`paywall_cta_click`) contain only
  `post_id` + reason + price presence — no body, no media URL, no author PII
  beyond id. Traces: AC-5.
- **TC-AND-101-15 — ABI / API-level parity on physical device.** Type:
  instrumented/e2e. Target: **A15 (physical, MUST run here)** — arm64-v8a,
  API 34, vs the x86_64/API-35 emulator used elsewhere. Pre: app installed via
  adb on serial R5CX821TA9R; a locked fixed-price post available. Steps: render
  feed + detail locked cards; verify `NumberFormat`/`java.util.Currency` price
  formatting and the mapper behavior. Expected: identical paywall rendering and
  body-dropping as on Emu35; no arm64-vs-x86 or API34-vs-API35 difference in
  currency formatting or content non-leakage. (Pinned to hardware to catch
  ABI/locale/ICU differences; no camera/biometric/WebRTC needed.) Traces: AC-1,
  AC-2, AC-5.

### Coverage matrix

| Acceptance criterion (§14) | Covering test cases |
|---|---|
| AC-1 (paywall shown, no protected content; feed + detail) | TC-01, TC-05, TC-07, TC-10, TC-13, TC-15 |
| AC-2 (author header, label, formatted/generic price CTA) | TC-03, TC-04, TC-07, TC-08, TC-11, TC-12, TC-15 |
| AC-3 (CTA invokes `onUnlockClick` once, no purchase/reveal) | TC-09 |
| AC-4 (fail-closed mapping) | TC-02, TC-03, TC-05 |
| AC-5 (no leak: semantics/clipboard/logs/telemetry) | TC-01, TC-07, TC-11, TC-12, TC-13, TC-14, TC-15 |
| AC-6 (renders from Room cache offline) | TC-06, TC-13 |
