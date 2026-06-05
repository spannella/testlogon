---
id: AND-099
title: Post item composable
milestone: M2
epic: E14
priority: P0
size: M
status: draft
depends_on: [AND-098, AND-103]
blocks: []
---

# AND-099 — Post item composable

## 1. Overview & Goal

Deliver the canonical, reusable `PostItem` composable that renders a single feed post in the read-only TestLogon feed. The feed list scaffolding, Paging 3 source, and refresh/pagination footers are owned by AND-098; this ticket owns the per-row presentation: the author header (avatar, display name, handle, relative timestamp), the post body text (with inline link detection), the media grid (1–4+ images/video thumbnails with correct aspect handling), and the link-preview card. Image loading itself (Coil pipeline, placeholders, data-saver, scroll cancellation) is owned by AND-103; `PostItem` consumes that pipeline through the shared `core-ui` image components and must not duplicate it.

The goal is a single, deterministic composable that correctly renders all common post shapes — text-only, single image, 2/3/4-image grids, video thumbnail, link-only with preview, and mixed text+media+link — with stable layout, no jank during scroll, and full accessibility/RTL support. Success is measured by Compose UI/screenshot tests asserting each shape renders correctly and by the absence of recomposition or layout regressions in the feed list under AND-098.

This is a pure presentation/UI ticket. It introduces no new ViewModel, no new network call, and no new persistence; it maps an already-fetched `Post` domain model (from `core-model`, populated by AND-098's paging source) into Compose UI.

## 2. Context & References

- Repo: `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- Module placement: composable lives in `feature-feed` (consumer feature), built on primitives from `core-ui` and the `Post` model from `core-model`. Layering rule `app -> feature-* -> core-*` must hold; `feature-feed` may depend on `core-ui`, `core-model`, `core-data` but not on other feature modules.
- Package root for this ticket: `com.testlogon.android.feature.feed.ui`.
- Upstream dependency AND-098 (`feed-list-paging-3`): provides `FeedScreen`, `FeedViewModel`, `Pager<…, Post>`, and the `LazyColumn` that places `PostItem` as its row content. AND-099 plugs into AND-098's `items(...)` block.
- Upstream dependency AND-103 (`feed-media-thumbnails`): provides the Coil-backed image component (referred to here as `FeedAsyncImage`) including placeholders, aspect handling, data-saver respect, and scroll cancellation. `PostItem` calls this component; it does not configure Coil directly.
- Web reference: `frontend/src/api/types.ts` (post/media/author shapes), `frontend/src/api/endpoints/*.ts` (feed endpoints), and the React post card under `frontend/src/` for layout parity. Field names below are mirrored from the web types; the Moshi-mapped Kotlin `Post` is the source of truth on Android.
- OpenAPI: `GET /openapi.json` on dev backend `http://18.222.237.167:8000` for the feed item schema.
- Material 3 + Jetpack Compose, Kotlin 2.0.21, minSdk 24, compileSdk/targetSdk 35.

## 3. Functional Requirements

FR-1 Author header. Render an avatar (circular, 40dp), display name (titleMedium, bold), handle (`@username`, bodySmall, muted), and a relative timestamp ("3m", "2h", "Apr 12") right-aligned. Verified badge shown inline after display name when `author.verified == true`. Tapping the header invokes an `onAuthorClick` callback (navigation is owned elsewhere; this ticket only exposes the lambda).

FR-2 Body text. Render `post.text` with `Text` using `bodyLarge`. URLs, @mentions, and #hashtags are detected and styled as clickable spans via Compose `AnnotatedString` + `LinkAnnotation`/`withLink`. Long text is shown in full (no truncation in the list per current scope); empty/blank text renders no body block at all (no empty space).

FR-3 Media grid. Render `post.media` (0..n) as a grid:
- 0 items: no grid.
- 1 item: single thumbnail, aspect ratio from media metadata (clamped to 4:5..16:9), max height 480dp.
- 2 items: side-by-side, 1:1 cells.
- 3 items: one large left (2:1 portion) + two stacked right, or 3-up row per design token; default to one-large-two-stacked.
- 4 items: 2x2 grid, 1:1 cells.
- 5+ items: 2x2 grid with a "+N" overlay on the 4th cell.
Each cell delegates loading to AND-103's `FeedAsyncImage`. Video items show a centered play overlay and (if present) duration badge; tapping any media invokes `onMediaClick(index)`.

FR-4 Link preview. When `post.linkPreview != null` and no media is present (or per design when both exist — default: show preview only if media is empty), render a bordered card: leading thumbnail (if `imageUrl`), title (titleSmall, max 2 lines, ellipsized), domain/site name (labelSmall, muted), and optional description (bodySmall, max 2 lines). Tapping invokes `onLinkClick(url)`.

FR-5 Pure & stateless. `PostItem` holds no remembered network/business state. All inputs arrive via an immutable `Post` plus stable callback lambdas. It must be safe to place inside a `LazyColumn` and survive recomposition without leaking or re-fetching.

FR-6 Common-shape correctness (acceptance driver). Text-only, single-image, 2/3/4-image, video, link-only, and text+media+link posts each render without overlap, clipping (except intended ellipsis), or unbounded height, in both light and dark themes and in LTR and RTL.

## 4. Technical Design

New files under `feature-feed/src/main/java/com/testlogon/android/feature/feed/ui/`:

- `PostItem.kt` — the public composable and its sub-composables.
- `RelativeTime.kt` — pure timestamp formatting helper.
- `PostText.kt` — `AnnotatedString` builder for body text with link/mention/hashtag spans.

Public API:

```kotlin
@Composable
fun PostItem(
    post: Post,
    modifier: Modifier = Modifier,
    onAuthorClick: (authorId: String) -> Unit = {},
    onMediaClick: (post: Post, index: Int) -> Unit = { _, _ -> },
    onLinkClick: (url: String) -> Unit = {},
    onPostClick: (post: Post) -> Unit = {},
)
```

Internal decomposition (each `@Composable private fun`):

```kotlin
@Composable private fun PostAuthorHeader(author: Author, createdAt: Instant, onClick: () -> Unit)
@Composable private fun PostBody(text: String, onLinkClick: (String) -> Unit, onMentionClick: (String) -> Unit)
@Composable private fun PostMediaGrid(media: List<MediaItem>, onClick: (Int) -> Unit)
@Composable private fun PostLinkPreview(preview: LinkPreview, onClick: () -> Unit)
```

Layout: outer `Column` inside a `Surface`/`Card` (tonal, no elevation) with 16dp horizontal / 12dp vertical padding and a bottom `HorizontalDivider`. Order: header → body → (media grid XOR link preview) → footer-spacer. The whole row is clickable via `Modifier.clickable { onPostClick(post) }` with media/header/link sub-targets consuming their own clicks.

Media grid uses a custom `Layout`/nested `Row`+`Column` (not `LazyVerticalGrid`, which cannot nest in `LazyColumn` without a fixed height). Cells use `Modifier.aspectRatio(...)` and `Modifier.clip(RoundedCornerShape(12.dp))`. The grid container computes a single intrinsic height from the chosen template so the `LazyColumn` can measure rows efficiently.

Stability: `Post`, `Author`, `MediaItem`, `LinkPreview` must be `@Immutable`/`@Stable` (data classes with stable fields, lists wrapped or treated as stable via Compose compiler 2.0 strong-skipping). Callbacks should be hoisted/`remember`ed by AND-098's caller to keep `PostItem` skippable.

Performance: no allocation of formatters per recomposition — `RelativeTime` uses a cached `Clock`/formatter; `PostText` annotated string is wrapped in `remember(text)`.

## 5. API Contract

No new endpoint is introduced by this ticket. `PostItem` consumes the already-deserialized `Post` produced by AND-098's paging source from the feed endpoint (e.g. `GET /ui/feed?cursor=...`, exact path owned by AND-098/AND-097). The relevant item JSON shape (mirrored from `frontend/src/api/types.ts` and `/openapi.json`) that the composable depends on:

```json
{
  "id": "post_01H...",
  "author": {
    "id": "user_42",
    "display_name": "Ada Lovelace",
    "username": "ada",
    "avatar_url": "https://.../a.jpg",
    "verified": true
  },
  "text": "Shipping the feed today https://testlogon.dev/blog #android @sean",
  "created_at": "2026-06-05T13:01:22Z",
  "media": [
    { "id": "m1", "type": "image", "url": "https://.../1.jpg",
      "width": 1600, "height": 900, "blurhash": "L6Pj0^..." },
    { "id": "m2", "type": "video", "url": "https://.../v.m3u8",
      "thumbnail_url": "https://.../t.jpg", "duration_ms": 42000,
      "width": 1280, "height": 720 }
  ],
  "link_preview": {
    "url": "https://testlogon.dev/blog",
    "title": "Native Android port",
    "description": "How we built it",
    "image_url": "https://.../og.png",
    "site_name": "testlogon.dev"
  }
}
```

Corresponding `core-model` types consumed by this ticket:

```kotlin
@Immutable
data class Post(
    val id: String,
    val author: Author,
    val text: String,
    val createdAt: Instant,
    val media: List<MediaItem> = emptyList(),
    val linkPreview: LinkPreview? = null,
)

@Immutable
data class Author(
    val id: String,
    val displayName: String,
    val username: String,
    val avatarUrl: String?,
    val verified: Boolean = false,
)

@Immutable
data class MediaItem(
    val id: String,
    val type: MediaType,            // IMAGE | VIDEO | GIF | UNKNOWN
    val url: String,
    val thumbnailUrl: String? = null,
    val width: Int? = null,
    val height: Int? = null,
    val durationMs: Long? = null,
    val blurhash: String? = null,
)

@Immutable
data class LinkPreview(
    val url: String,
    val title: String?,
    val description: String?,
    val imageUrl: String?,
    val siteName: String?,
)
```

If `core-model` does not yet define `LinkPreview`/`MediaType`, this ticket adds them to `core-model` (additive, no behavior change). Unknown `type` strings deserialize to `MediaType.UNKNOWN` and render as a generic file/placeholder cell — never crash. Null `avatar_url`/`image_url`/`width`/`height` are tolerated.

## 6. Data & State Management

`PostItem` is stateless presentation. No `StateFlow`, no `ViewModel`, no Room/DataStore access in this ticket — the `Post` is supplied by the caller (AND-098's `LazyPagingItems<Post>`). Any UI-local state is limited to:

- `remember(post.text) { buildPostAnnotatedString(post.text) }` — memoized annotated body.
- `remember(post.media.size) { gridTemplateFor(post.media.size) }` — chosen grid template.
- Optional `rememberSaveable` for a per-row "show more" toggle is OUT OF SCOPE (no truncation this milestone).

Image bitmap caching, prefetch, and lifecycle are owned by AND-103 (Coil `ImageLoader`). Feed cache (Room) is owned by AND-097/AND-098. This ticket reads from those layers only via the injected/shared components.

State immutability: all model types are `@Immutable`; lists are stable so the Compose compiler can skip `PostItem` when the `Post` reference is unchanged across recompositions (verified via layout-inspector / `composition` counting in tests).

## 7. Error Handling & Resilience

This is a render-only component; there is no network call to fail here, so retry/backoff/refresh logic is N/A and owned by AND-098 (list-level error/loading footers) and the auth/cookie layer (M1). `PostItem` must degrade gracefully on partial/dirty data:

- Missing avatar: render an initials/monogram placeholder derived from `displayName` (no broken-image flash).
- Missing media dimensions: fall back to 16:9 aspect for the cell so layout stays bounded.
- Broken/failing image URL: AND-103's `FeedAsyncImage` shows its error/placeholder state; `PostItem` reserves the cell box so layout does not shift.
- Empty `text` and empty `media` and null `linkPreview` simultaneously (degenerate post): render only the header + divider; never throw.
- Malformed/relative link in body or preview: link spans still render but the `onLinkClick` consumer is responsible for validation; `PostItem` passes the raw URL string and does not crash on unparseable URLs.
- Extremely large media counts: clamp the rendered grid to 4 cells + "+N" overlay; do not attempt to lay out hundreds of cells.

## 8. Security & Privacy

- No credentials, cookies, CSRF tokens, or PII are handled in this composable; it renders already-fetched public-feed content. The cookie-based session / `X-CSRF-Token` flow is entirely in `core-network` (M1) and not touched here.
- All outbound media/avatar/link-image requests go through AND-103's Coil `ImageLoader`, which uses the app's OkHttp client (cookie jar + dev plaintext-HTTP tolerance). `PostItem` must not construct its own HTTP client or expose URLs to any logger.
- Link taps: `onLinkClick`/`onMediaClick`/`onAuthorClick` only forward the value; opening a Custom Tab / external browser (and its scheme allowlist, e.g. reject `javascript:`/`file:`) is the responsibility of the caller/navigation layer. Document this contract so the consumer enforces scheme validation.
- Body text is rendered as Compose `Text` (no HTML/WebView), so there is no injection surface from post content.

## 9. Accessibility & i18n

- All interactive targets (header, each media cell, link preview, whole-row) expose `Modifier.semantics` with meaningful `contentDescription` and `Role.Button` where tappable; minimum 48dp touch targets even when visual size is smaller.
- Media cells: `contentDescription` = media alt text if present, else a localized "Image"/"Video, {duration}" string; the "+N more" overlay announces the remaining count.
- Avatar `contentDescription` = "{displayName} avatar"; verified badge announced as "Verified".
- Timestamp: visible relative label plus a `stateDescription`/`contentDescription` with the absolute localized date-time for screen readers.
- Full RTL support: media grid templates and header arrangement use `start`/`end` (not left/right); test in RTL pseudo-locale. The "+N" overlay and play badge mirror correctly.
- All user-facing strings (placeholders, "+N more", "Verified", media type labels) live in `feature-feed` `strings.xml` and use plurals/`pluralStringResource` for counts. Relative-time strings use Android's `DateUtils.getRelativeTimeSpanString` or a localized formatter, not hardcoded English.
- Respects Dynamic Type / font scale: no fixed text heights; layout uses `wrapContentHeight` for text blocks.

## 10. Telemetry & Logging

- Lightweight, sampled view/interaction events only; the telemetry API is owned by the core analytics ticket. `PostItem` exposes click callbacks (`onPostClick`, `onMediaClick`, `onAuthorClick`, `onLinkClick`) that the AND-098 caller wires to analytics — `PostItem` itself emits nothing, keeping it pure.
- No URLs, post text, or author identifiers are written to logcat. Debug-only `Log.v` guarded by `BuildConfig.DEBUG` may record grid-template selection for layout debugging, with no PII.
- An optional `Modifier.testTag("post_item_<id>")` and per-region tags (`post_header`, `post_media_grid`, `post_link_preview`) are added for Espresso/Compose test selection.

## 11. Testing Strategy

Unit (JVM, `RelativeTime.kt` / `PostText.kt`):
- `RelativeTime` returns "now"/"3m"/"2h"/"Apr 12"/"Apr 12, 2025" at fixed `Clock` boundaries.
- `buildPostAnnotatedString` detects URLs, @mentions, #hashtags, handles adjacent punctuation, no false positives on plain text, and yields correct `LinkAnnotation` ranges.

Compose UI tests (`createComposeRule`, `core-testing` harness):
- `gridTemplateFor(n)` and the rendered grid produce the expected number of visible cells for n = 0,1,2,3,4,7 (assert via `onAllNodesWithTag("media_cell").assertCountEquals(...)`, "+N" overlay shows for n=7 with text "+3").
- Text-only post: no media grid node, no link-preview node.
- Link-only post: link-preview node present, media grid absent.
- Degenerate post (no text/media/link): header present, body/grid/preview absent, no crash.
- Click propagation: clicking header fires `onAuthorClick(author.id)`; clicking cell index 2 fires `onMediaClick(post, 2)`; clicking preview fires `onLinkClick(url)`.
- Accessibility: every tappable node has a non-empty `contentDescription`; verified badge announced.

Screenshot tests (Roborazzi or Paparazzi via `core-testing`): golden images for the 7 common shapes × {light, dark} × {LTR, RTL}, asserting "common post shapes render correctly" (the ticket's acceptance). Goldens checked into `feature-feed/src/test/screenshots/`.

Stability/perf check: a recomposition-count test asserting `PostItem` is skipped when the same `Post` instance is recomposed (compiler strong-skipping holds).

## 12. Dependencies & Sequencing

- Depends on AND-098 (`feed-list-paging-3`): provides `FeedScreen`/`LazyColumn` host and `LazyPagingItems<Post>`; `PostItem` is the row content. AND-099 can be developed against a fake `List<Post>` in previews/tests before AND-098 lands, but final integration requires AND-098.
- Depends on AND-103 (`feed-media-thumbnails`): provides `FeedAsyncImage` (Coil pipeline, placeholders, aspect, data-saver, scroll cancellation). Until AND-103 is ready, media cells use a temporary placeholder box behind the same call signature so this ticket is not blocked from layout work; the final media render must call AND-103's component.
- Indirect: AND-097 (feed repository/source) and AND-019 (Coil/image core, via AND-103) underpin the data and image stack.
- Blocks: none declared in backlog. Logically enables E24 (feed interactions) and the post-detail screen, which reuse/extend `PostItem`, but no AND-### is listed as blocked.
- Sequencing: land model additions (`LinkPreview`, `MediaType`) in `core-model` first, then `PostItem` previews/tests, then integrate with AND-098 and swap in AND-103's image component.

## 13. Risks & Open Questions

- R1 Media grid + `LazyColumn`: `LazyVerticalGrid` cannot nest without a fixed height; mitigation is a custom `Row`/`Column` template (chosen design). Risk of intrinsic-measurement cost — covered by perf/recomposition test.
- R2 Co-existence of media and link preview: backend may return both. Default decision: show media, suppress preview. OPEN — confirm desired behavior against web reference card.
- R3 Aspect-ratio clamping bounds (4:5..16:9) are assumed; confirm against design tokens. Wrong clamping causes letterboxing or over-tall rows.
- R4 Field-name drift: `link_preview` vs `linkPreview`, `avatar_url` presence, and `media[].type` enum values must be verified against live `/openapi.json` — dev backend is unreliable, so verify when reachable and keep Moshi adapters tolerant.
- R5 GIF/animated media handling is deferred to AND-103's Coil config; `PostItem` treats GIF as image with the same cell.
- R6 "3-image" template (one-large-two-stacked vs 3-up) is a design choice; default chosen, pending design confirmation.

## 14. Acceptance Criteria

AC-1 Given a text-only post, `PostItem` renders header + body, with no media grid and no link-preview node. (Backlog: "Text … render correctly.")
AC-2 Given posts with 1, 2, 3, and 4 media items, the grid renders the correct template and exact visible cell count; 5+ shows a 2x2 grid with a correct "+N" overlay. (Backlog: "media grid".)
AC-3 The author header shows avatar (or monogram fallback), display name, `@username`, verified badge when applicable, and a relative timestamp; tapping fires `onAuthorClick(author.id)`. (Backlog: "author header, timestamps".)
AC-4 Body URLs/@mentions/#hashtags render as clickable spans; tapping a URL fires `onLinkClick(url)`. (Backlog: "Render text … link previews".)
AC-5 Given `linkPreview` and no media, a bordered preview card renders title/site/optional description/optional image; tapping fires `onLinkClick(url)`. (Backlog: "link previews".)
AC-6 Video media shows a play overlay and duration badge; tapping fires `onMediaClick(post, index)`.
AC-7 A degenerate post (no text/media/link) renders header + divider only and does not crash; missing avatar/dimensions/broken images degrade gracefully with no layout shift.
AC-8 All 7 common shapes pass screenshot goldens in light, dark, LTR, and RTL. (Backlog acceptance: "Common post shapes render correctly.")
AC-9 Every interactive region has a non-empty, localized `contentDescription`; touch targets ≥ 48dp.
AC-10 `PostItem` is skippable: a recomposition with an unchanged `Post` instance does not re-execute the body (verified by test).

## 15. Definition of Done

- `PostItem` and helpers implemented under `com.testlogon.android.feature.feed.ui` in the `feature-feed` module, respecting `app -> feature-* -> core-*` layering (no feature-to-feature deps).
- `core-model` contains `Post`, `Author`, `MediaItem` (`MediaType`), and `LinkPreview` as `@Immutable` types with tolerant Moshi mapping (unknown enum → `UNKNOWN`, nullable optional fields).
- Media rendering delegates to AND-103's `FeedAsyncImage`; no Coil `ImageLoader` is constructed in this ticket.
- All unit, Compose UI, and screenshot tests (Section 11) pass in CI; goldens committed.
- All user-facing strings externalized to `strings.xml` with plurals; RTL and dynamic-font-scale verified.
- `@Preview`s exist for all 7 common shapes (light + dark) and render in Android Studio.
- Lint/Detekt/ktlint clean; `PostItem` confirmed skippable via Compose compiler metrics or recomposition test.
- Integrated into AND-098's `LazyColumn` (or behind a stub list) and reviewed/merged to `android-port`; no regression in feed scroll performance.
- Open questions R2, R3, R6 resolved or explicitly ticketed before merge.
