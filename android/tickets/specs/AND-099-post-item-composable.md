---
id: AND-099
title: Post item composable
milestone: M2
epic: E14
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- Web reference: `src/api/types.ts` (the `FeedPost` interface is the authoritative item shape), `src/api/endpoints/newsfeed.ts` (`getFeed` → `GET /feed`), `src/api/client.ts` (transport/auth), and `src/pages/feed/PostCard.tsx` + `RichContentRenderer.tsx` for layout parity. NOTE (corrected during review): the web `FeedPost` shape differs materially from the field names previously assumed in §5 — see §5 and the §16 audit. The Moshi-mapped Kotlin `Post` is the Android source of truth, but its mapping must be derived from `FeedPost`, not from the invented shape that earlier drafts of this spec used.
- OpenAPI: feed endpoint is `GET /feed` (operationId `view_feed_feed_get`, tag `newsfeed`). Its 200 response in `openapi.pretty.json` is declared with an EMPTY schema (`"schema": {}`) — i.e. the backend OpenAPI does not type the feed item; the only typed contract for the item is the frontend `FeedPost` interface. Treat `FeedPost` as the contract of record and keep Moshi adapters tolerant. (Dev backend host previously cited as `http://18.222.237.167:8000` is unverified and not relied on here.)
- Material 3 + Jetpack Compose, Kotlin 2.0.21, minSdk 24, compileSdk/targetSdk 35.

## 3. Functional Requirements

FR-1 Author header. Render an avatar (circular), an author label, and a relative timestamp ("3m", "2h", "Apr 12") right-aligned. Tapping the header invokes an `onAuthorClick(authorId)` callback (navigation is owned elsewhere; this ticket only exposes the lambda).

> CORRECTED (review): the web `FeedPost` contract has NO embedded author object — it carries only `author_id: string`. There are no `display_name`, `username`, `avatar_url`, or `verified` fields on the feed item, and the web `PostCard` renders the avatar as an initials fallback derived from `author_id.slice(0,2)` and shows `author_id` as the label (avatar size `h-9 w-9` ≈ 36dp, not 40dp). Author display name / handle / avatar image / verified badge therefore CANNOT come from the feed item alone; they require a separate profile lookup that is out of scope for this presentation ticket and not provided by AND-098's `/feed` source. The Android `Author` rich-header design below is an aspirational/forward-looking model that depends on a not-yet-confirmed enrichment step. Until that enrichment exists, `PostItem` MUST render correctly from `author_id` only (monogram avatar + author-id/display-name-if-present label) and treat display name, username, avatar URL, and verified badge as OPTIONAL/nullable. See §16 (Open assumptions) and §5.

FR-2 Body text. Render the post body with `Text`. The web body is multi-format: fields `body`, `body_plain`, `body_markdown`, `body_markdown_html`, `body_rich`, and a `body_format` discriminator (`plain | markdown | rich`); the web `RichContentRenderer` selects on `body_format` and falls back to `body_plain ?? body`. For Android M2 scope, render the plain-text projection (`body_plain ?? body`) as `bodyLarge`; markdown/rich rendering is a follow-up. CORRECTED: the web client does NOT detect inline @mentions or #hashtags as clickable spans — hashtags are carried in a separate `tags: string[]` field rendered as chips, and there is no client-side @mention linkification. Inline URL linkification via `AnnotatedString` + `LinkAnnotation`/`withLink` is an Android-only enhancement (mark as such); do not claim web parity for mention/hashtag spans. Empty/blank body renders no body block at all (no empty space). NOTE: unlike this spec's earlier "shown in full" claim, the web DOES collapse long bodies (>380 chars or >8 lines) behind a "Show more" toggle; Android deliberately defers truncation to a later milestone (§6 marks the toggle OUT OF SCOPE) — this is an intentional deviation, not parity.

FR-3 Media grid. CORRECTED: the web `FeedPost` does NOT expose a unified `media: MediaItem[]` array. Images come from `image_urls: string[]` (with optional `image_variants`), and video is a SEPARATE singular object `video: { video_id, title, thumbnail_url?, duration_seconds?, hls_manifest_url?, playback_token?, playback_expires_at? } | null`. There is no per-image `type`/`width`/`height`/`blurhash` on the feed item (blurhash is not present anywhere in `FeedPost`; `image_variants` carries responsive variants instead). The Android `MediaItem` model below is an Android-side normalization the mapping layer must SYNTHESIZE from `image_urls` (+ `image_variants`) and `video`; it is not a 1:1 field copy. Render rules (matching the web `PostImageGrid` cell counts):
- 0 images: no image grid.
- 1 image: single thumbnail; web uses `object-cover` with `max-h-80` (≈320dp), not 480dp — adjust the max-height token to match or document the deviation. Per-image intrinsic aspect is not available from the feed item, so default the cell (web crops with `object-cover`).
- 2 images: side-by-side, 1:1 (`aspect-square`) cells.
- 3 images: one large TOP cell (16:9, full width / `col-span-2`) + two square cells BELOW (NOT left-large/right-stacked). Update R6's default to this top-large/two-below template to match web; left/right was a wrong assumption.
- 4 images: 2x2 grid, 1:1 cells.
- 5+ images: 2x2 grid with a "+N" overlay on the 4th cell, where N = count − 4.
Each image cell delegates loading to AND-103's `FeedAsyncImage`. Video (the singular `post.video`) renders its `thumbnail_url` with a centered play overlay and, if `duration_seconds` is present, a duration badge (note: web field is `duration_seconds`, NOT `duration_ms`). Tapping any image/video invokes `onMediaClick(post, index)`.

FR-4 Link preview. UNVERIFIED ASSUMPTION (could not confirm against sources): the web `FeedPost` contract has NO link-preview field, and the web `PostCard` renders no link-preview card — `LinkPreview` exists in `src/api/types.ts` only on the messaging `Message` type (fields `url?`, `title?`, `description?`, `image_url?`, `site_name?`), not on feed posts. Therefore an Android feed link-preview card has no web/feed-contract parity today. Either (a) drop FR-4 from this ticket until the backend adds a link-preview field to the feed item, or (b) keep it as an explicitly Android-only, forward-looking feature gated on a future `Post.linkPreview`. If kept: when `post.linkPreview != null` and no media is present (default: show preview only if media is empty), render a bordered card: leading thumbnail (if `imageUrl`), title (titleSmall, max 2 lines, ellipsized), domain/site name (labelSmall, muted), optional description (bodySmall, max 2 lines); tapping invokes `onLinkClick(url)`. The `LinkPreview` field names below (`url/title/description/imageUrl/siteName`) DO match the web `LinkPreview` interface (snake_case `image_url`/`site_name`), so the shape is correct even though feed posts don't carry it. See §16.

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

No new endpoint is introduced by this ticket. `PostItem` consumes the already-deserialized `Post` produced by AND-098's paging source.

CORRECTED — endpoint & item shape: the feed endpoint is `GET /feed` (operationId `view_feed_feed_get`, tag `newsfeed`; the earlier `GET /ui/feed` path was wrong). The web wrapper `getFeed` (`src/api/endpoints/newsfeed.ts`) calls `api.get<{ items: FeedPost[]; next_cursor?: string }>("/feed", ...)` with query params `limit, cursor, author_id, q, from, to, has_media` (auth/impersonation headers are transport-level). The 200 body in OpenAPI is an untyped `{}` schema, so the authoritative item contract is the `FeedPost` interface in `src/api/types.ts`. The JSON shape this composable ACTUALLY depends on (relevant subset of `FeedPost`):

```json
{
  "post_id": "post_01H...",
  "author_id": "user_42",
  "body": "Shipping the feed today https://testlogon.dev/blog",
  "body_plain": "Shipping the feed today https://testlogon.dev/blog",
  "body_format": "plain",
  "created_at": "2026-06-05T13:01:22Z",
  "image_urls": ["https://.../1.jpg", "https://.../2.jpg"],
  "image_variants": [ { "thumb": { "url": "https://.../1-thumb.jpg", "width": 320, "height": 180 } } ],
  "video": {
    "video_id": "vid_1",
    "title": "Clip",
    "thumbnail_url": "https://.../t.jpg",
    "duration_seconds": 42,
    "hls_manifest_url": "https://.../v.m3u8"
  },
  "tags": ["android"],
  "like_count": 0,
  "comment_count": 0
}
```

The previously documented shape (`id`, nested `author{display_name,username,avatar_url,verified}`, `text`, unified `media[]` with `type/width/height/blurhash`, `duration_ms`, top-level `link_preview`) was INCORRECT and is replaced above. Key field-name corrections: `post_id` (not `id`); `author_id` only (no nested author); `body`/`body_plain` (not `text`); `image_urls[]` + `image_variants[]` (no unified `media[]`); singular `video{...}` with `duration_seconds` (not `duration_ms`); hashtags in `tags[]`; NO `blurhash`; NO `link_preview` on feed posts.

Corresponding `core-model` types consumed by this ticket (these are an Android-side NORMALIZED projection that the Moshi/mapping layer must build from `FeedPost`, NOT a direct field copy — `Author` enrichment and `LinkPreview` are forward-looking, see §5 note and §16):

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

- No credentials, cookies, CSRF tokens, or PII are handled in this composable; it renders already-fetched feed content. The auth/transport flow is entirely in `core-network` (M1) and not touched here. CLARIFIED (review, against `src/api/client.ts`): the web transport actually combines an `Authorization: Bearer <accessToken>` header, a CSRF header `X-CSRF-Token` read from the `ui_csrf` cookie, `credentials: "include"` (cookies), and an optional `X-IMPERSONATION-TOKEN`; the OpenAPI also lists `X-SESSION-ID`/`X-IMPERSONATION-TOKEN` header params. So this is not a pure "cookie session + CSRF" flow — it is Bearer-token + CSRF + cookies. This composable touches none of it; the note here is corrected only for accuracy.
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
- R2 Co-existence of media and link preview: RESOLVED by review — the web feed item carries no link-preview field and the web card renders none, so there is no media-vs-preview conflict in current scope. Treat link preview as Android-only/forward-looking (FR-4). Default decision (show media, suppress preview) only applies if/when a feed link-preview field is added.
- R3 Aspect-ratio clamping bounds (4:5..16:9) are assumed; confirm against design tokens. NOTE: the feed item has no per-image dimensions, and the web uses `object-cover` with fixed aspects (single image `max-h-80`, 3-up top cell `aspect-video`, others `aspect-square`); clamping by intrinsic ratio is not possible from the contract, so adopt the web's fixed aspects or document the deviation.
- R4 Field-name drift: RESOLVED by review against `src/api/types.ts` `FeedPost`. Confirmed real fields: `post_id`, `author_id` (no nested author), `body`/`body_plain`/`body_format`, `image_urls[]`/`image_variants[]`, singular `video{...duration_seconds}`, `tags[]`. No `link_preview`, no `blurhash`, no `media[].type`, no `duration_ms`, no `avatar_url`/`display_name`/`verified` on the item. Keep Moshi adapters tolerant (unknown enum → UNKNOWN, nullable optionals) and map from these real names.
- R5 GIF/animated media handling is deferred to AND-103's Coil config; `PostItem` treats GIF as image with the same cell.
- R6 "3-image" template: RESOLVED by review — the web uses a top-large (16:9, full-width) cell with two square cells below. Adopt that (top-large/two-below), not the previously assumed left-large/right-stacked. Still pending design sign-off if a different look is desired.

## 14. Acceptance Criteria

AC-1 Given a text-only post, `PostItem` renders header + body, with no media grid and no link-preview node. (Backlog: "Text … render correctly.")
AC-2 Given posts with 1, 2, 3, and 4 media items, the grid renders the correct template and exact visible cell count; 5+ shows a 2x2 grid with a correct "+N" overlay. (Backlog: "media grid".)
AC-3 The author header shows an avatar (monogram fallback from `author_id` when no avatar URL is available), an author label, and a relative timestamp; tapping fires `onAuthorClick(authorId)`. Display name / `@username` / avatar image / verified badge render ONLY when supplied by a future enrichment step (the `/feed` item carries `author_id` only) and MUST degrade to the monogram + author-id label otherwise. (Backlog: "author header, timestamps".)
AC-4 Body text renders from `body_plain ?? body`; URLs are rendered as clickable spans (Android-only enhancement) and tapping a URL fires `onLinkClick(url)`. @mention/#hashtag inline span linkification is NOT required for web parity (web has no mention linkification; hashtags live in `tags[]`); if tag chips are rendered they come from `post.tags`. (Backlog: "Render text".)
AC-5 (Forward-looking — see §16 Open assumptions; the feed item has no link-preview field today.) If `linkPreview` is present and no media, a bordered preview card renders title/site/optional description/optional image; tapping fires `onLinkClick(url)`. When `linkPreview` is absent (the current real case), no preview node renders. (Backlog: "link previews".)
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
- Open questions R2, R3, R6 resolved (see §13/§16); remaining open assumptions (author enrichment, link-preview on feed) ticketed before merge.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources: OpenAPI index `reference/openapi.index.txt`, OpenAPI spec `reference/openapi.pretty.json`, frontend under `reference/src/`.

1. Feed endpoint is `GET /feed`. VERDICT: Verified (Corrected from earlier `GET /ui/feed`). SOURCE: OpenAPI `GET /feed` (op `view_feed_feed_get`, tag `newsfeed`); `src/api/endpoints/newsfeed.ts: getFeed` calls `api.get(..., "/feed")`.
2. Feed response shape is `{ items: FeedPost[]; next_cursor?: string }`. VERDICT: Verified. SOURCE: `src/api/endpoints/newsfeed.ts: getFeed` (`api.get<{ items: FeedPost[]; next_cursor?: string }>`).
3. Feed query params: `limit, cursor, author_id, q, from, to, has_media` (+ `user_sub`, `X-SESSION-ID`, `X-IMPERSONATION-TOKEN`). VERDICT: Verified. SOURCE: OpenAPI index line `GET /feed | params=limit,cursor,author_id,q,from,to,has_media,user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN`.
4. The `/feed` 200 body has an empty (untyped) schema in OpenAPI; the typed item contract is the frontend `FeedPost`. VERDICT: Verified. SOURCE: `openapi.pretty.json` `/feed` → `responses.200.content.application/json.schema = {}`; `src/api/types.ts: FeedPost`.
5. Feed item id field is `post_id` (not `id`). VERDICT: Corrected. SOURCE: `src/api/types.ts: FeedPost.post_id`; usage `src/pages/feed/PostCard.tsx` (`post.post_id`).
6. Feed item has only `author_id`, no nested author / `display_name` / `username` / `avatar_url` / `verified`. VERDICT: Corrected. SOURCE: `src/api/types.ts: FeedPost.author_id` (no author object); `src/pages/feed/PostCard.tsx` renders `initials = post.author_id.slice(0,2)` and label `{post.author_id}` with `AvatarFallback` (avatar `h-9 w-9`).
7. Body field is `body`/`body_plain` (+ `body_markdown`, `body_markdown_html`, `body_rich`, `body_format`), not `text`. VERDICT: Corrected. SOURCE: `src/api/types.ts: FeedPost.body / body_plain / body_format`; `src/pages/feed/RichContentRenderer.tsx` (`plainTextFromProps` = `bodyPlain ?? body ?? bodyMarkdown`).
8. No client-side @mention/#hashtag span linkification on web; hashtags are a separate `tags: string[]` rendered as chips. VERDICT: Corrected (the inline-span claim was wrong for web parity). SOURCE: `src/pages/feed/RichContentRenderer.tsx` (no mention/hashtag/url logic); `src/api/types.ts: FeedPost.tags`; `src/pages/feed/PostCard.tsx` tag chips (`post.tags`, `data-testid="post-tags"`).
9. Web collapses long bodies (>380 chars or >8 lines) behind "Show more"; Android intentionally renders in full this milestone. VERDICT: Corrected/clarified (intentional deviation). SOURCE: `src/pages/feed/RichContentRenderer.tsx` (`COLLAPSE_CHAR_THRESHOLD = 380`, `COLLAPSE_LINE_THRESHOLD = 8`).
10. Images are `image_urls: string[]` (+ `image_variants`), not a unified `media[]`. VERDICT: Corrected. SOURCE: `src/api/types.ts: FeedPost.image_urls / image_variants`; `src/pages/feed/PostCard.tsx: PostImageGrid({ urls })`.
11. Video is a singular `video` object with `duration_seconds` (not `duration_ms`), `thumbnail_url`, `hls_manifest_url`. VERDICT: Corrected. SOURCE: `src/api/types.ts: FeedPost.video {video_id,title,thumbnail_url,duration_seconds,hls_manifest_url,...}`.
12. No `blurhash` field on the feed item. VERDICT: Corrected. SOURCE: `src/api/types.ts: FeedPost` (no blurhash; `image_variants` carries responsive variants instead).
13. Image grid cell-count templates: 1=single (`max-h-80`/object-cover), 2=2×1 square, 3=top 16:9 full-width + 2 square below, 4=2×2 square, 5+=2×2 with "+N" (N=count−4) overlay on cell index 3. VERDICT: Verified (Corrected the 3-image layout from left-large/right-stacked to top-large/two-below). SOURCE: `src/pages/feed/PostCard.tsx: PostImageGrid` (count branches 1/2/3/4/else; `extra = count - 4`).
14. Feed item has NO link-preview field; web `PostCard` renders no link-preview card. `LinkPreview` exists only on the messaging `Message` type. VERDICT: Corrected (FR-4 has no current feed parity). SOURCE: `src/api/types.ts: FeedPost` (no link_preview field); `src/api/types.ts: LinkPreview` referenced from `Message.preview` / `SendTextMessageReq.preview`; no link-preview match under `src/pages/feed/`.
15. `LinkPreview` field shape (`url`, `title`, `description`, `image_url`, `site_name`, all optional) matches the spec's `LinkPreview` mapping. VERDICT: Verified (shape correct even though feed posts don't carry it). SOURCE: `src/api/types.ts: LinkPreview`.
16. Transport auth = `Authorization: Bearer <accessToken>` + `X-CSRF-Token` from `ui_csrf` cookie + `credentials: "include"` + optional `X-IMPERSONATION-TOKEN`; OpenAPI also lists `X-SESSION-ID`. VERDICT: Corrected/clarified (not a pure cookie-session+CSRF flow). SOURCE: `src/api/client.ts` (`Authorization: Bearer`, `getCookie("ui_csrf")` → `X-CSRF-Token`, `credentials: "include"`, `X-IMPERSONATION-TOKEN`); OpenAPI index `params=...X-SESSION-ID,X-IMPERSONATION-TOKEN`.
17. 422 validation error shape is `HTTPValidationError { detail: ValidationError[] }`. VERDICT: Verified. SOURCE: `openapi.pretty.json components.schemas.HTTPValidationError` (`detail` → array of `ValidationError`); `/feed` `responses.422` → `$ref HTTPValidationError`.
18. Feed request is wrapped in an offline cache (relevant to the flaky-dev-host/offline path). VERDICT: Verified. SOURCE: `src/api/endpoints/newsfeed.ts: getFeed` (`withOfflineCache(networkFn, { endpoint: "feed", cacheKey }, userId)`).
19. This ticket introduces no new endpoint / ViewModel / network call (pure presentation). VERDICT: Verified (internal-consistency; nothing in §1–§15 issues a network call). SOURCE: spec §1/§5/§6; no endpoint added in OpenAPI for `PostItem`.
20. Jetpack Compose `LinkAnnotation`/`withLink` is the supported API for clickable text spans (Android-only enhancement). VERDICT: Unverified-assumption (framework choice). SOURCE: framework ref — Compose `androidx.compose.ui.text` `LinkAnnotation` / `withLink` (Compose Foundation/UI 1.7+); confirm the project's Compose BOM exposes it.
21. `LazyVerticalGrid` cannot nest in `LazyColumn` without a fixed height; use a custom Row/Column template. VERDICT: Unverified-assumption (framework choice/design). SOURCE: framework ref — Android Compose lists/grids guidance; not contradicted by any source here.
22. Compose compiler 2.0 strong-skipping makes `PostItem` skippable when `Post`/`Author`/`MediaItem`/`LinkPreview` are `@Immutable` with stable fields. VERDICT: Unverified-assumption (framework choice). SOURCE: framework ref — Kotlin 2.0.21 / Compose compiler strong-skipping.

### Corrections made

- §2 / §5: feed endpoint corrected `GET /ui/feed` → `GET /feed`; noted the OpenAPI 200 schema is untyped and `FeedPost` is the contract of record; removed reliance on the unverified dev-host URL.
- §5 / §1 / FR-1: removed the invented nested `author{display_name,username,avatar_url,verified}`; feed item carries `author_id` only. Author rich-header recast as forward-looking/enrichment-dependent.
- §5 / FR-2: body field corrected `text` → `body`/`body_plain` with `body_format`; removed false claim of web @mention/#hashtag span detection; flagged URL linkification as Android-only; noted web "Show more" collapse vs Android full-render deviation.
- §5 / FR-3 / R3 / R6: corrected media model — `image_urls[]` + singular `video{...duration_seconds}` instead of unified `media[]` with `type/width/height/blurhash/duration_ms`; corrected 3-image template to top-large/two-below; corrected single-image max height note (web `max-h-80`); removed non-existent `blurhash`.
- §3 FR-4 / §13 R2 / §14 AC-5: corrected — no link-preview field on the feed item; recast FR-4 as forward-looking/Android-only.
- §8: corrected the auth description to Bearer + CSRF(`ui_csrf`→`X-CSRF-Token`) + cookies + impersonation (not pure cookie session).
- §14 AC-3/AC-4/AC-5: tightened to match the real contract (author enrichment optional, no mandatory mention/hashtag spans, link preview forward-looking).

### Open assumptions

- Author enrichment (display name, `@username`, avatar image, verified badge): the `/feed` item provides only `author_id`. There is no confirmed source/endpoint that AND-098's feed source joins author profile data into `Post`. UNVERIFIED — depends on AND-097/AND-098 or a profile-batch lookup not found in the feed contract. `PostItem` must render correctly from `author_id` alone until resolved.
- Link-preview on feed posts (FR-4): no field exists on `FeedPost` and no web feed card renders it. UNVERIFIED whether the backend will add one; kept only as forward-looking. Cannot be exercised against any current source.
- Aspect-ratio clamp 4:5..16:9 (R3) and single-image max height 480dp: no per-image dimensions exist on the feed item and the web uses fixed aspects (`object-cover`, `max-h-80`, `aspect-video`/`aspect-square`). UNVERIFIED against design tokens; adopt web fixed aspects or confirm tokens.
- Compose framework behaviors (strong-skipping skippability, `LinkAnnotation`/`withLink`, non-nesting of `LazyVerticalGrid`): framework assumptions, not verifiable from the backend/frontend sources; confirm against the Compose BOM in use.
- Dev backend host `http://18.222.237.167:8000`: not reachable/verified during review; not relied upon.

## 17. Test Plan

Test targets: JVM = JVM unit/Robolectric (local, no device); EMU = headless emulator AVD `test35` (x86_64, Android 15 / API 35); DEVICE = physical Samsung Galaxy A15 5G (SM-A156U, Android 14 / API 34, arm64-v8a). This is a pure-UI ticket with no camera/biometrics/FCM/WebRTC/telecom/streaming surface, so most cases run on JVM (Robolectric/Paparazzi) or the emulator; the DEVICE is used only to confirm arm64-v8a / API-34 parity for the screenshot goldens and real-font-scale/RTL rendering, where x86/API-35 emulator rendering could differ.

- TC-AND-099-01 — Text-only post renders header + body, no media/preview nodes.
  - Type: Compose-UI (createComposeRule). Target: JVM (Robolectric). 
  - Preconditions: `Post` with non-blank `body`, empty images, null video, null linkPreview.
  - Steps: Set content to `PostItem(post)`; query nodes by test tags.
  - Expected: `post_header` + body text present; `post_media_grid` and `post_link_preview` absent; no crash.
  - Traces: AC-1, AC-4.

- TC-AND-099-02 — Image grid cell counts and "+N" overlay for n = 0,1,2,3,4,7.
  - Type: Compose-UI. Target: JVM (Robolectric).
  - Preconditions: Posts with `image_urls` of size 0,1,2,3,4,7 (mapped to Android `MediaItem`s); `FeedAsyncImage` stubbed with a placeholder box.
  - Steps: For each n, render and `onAllNodesWithTag("media_cell").assertCountEquals(min(n,4))`; for n=7 assert overlay text "+3" on cell index 3; for n=3 assert the top cell uses the 16:9 template and the two below are square; n=0 asserts no grid.
  - Expected: Correct visible cell counts and templates; "+N" = count−4.
  - Traces: AC-2.

- TC-AND-099-03 — Author header from `author_id` only, with monogram fallback and timestamp; tap fires callback.
  - Type: Compose-UI. Target: JVM (Robolectric).
  - Preconditions: `Post` whose author has no display name/avatar/verified (enrichment absent), `author_id = "user_42"`, `createdAt` 3 minutes before a fixed `Clock`.
  - Steps: Render; assert monogram avatar shows initials derived from author label, author label visible, relative timestamp "3m"; perform click on `post_header`.
  - Expected: `onAuthorClick("user_42")` invoked exactly once; no crash when display name/avatar/verified are null.
  - Traces: AC-3.

- TC-AND-099-04 — RelativeTime boundaries (pure unit).
  - Type: unit. Target: JVM.
  - Preconditions: Fixed `Clock`; inputs at now, 3m, 2h, same-year date, prior-year date.
  - Steps: Call `RelativeTime.format(instant, clock)` for each boundary.
  - Expected: "now"/"Just now", "3m", "2h", "Apr 12", "Apr 12, 2025" (or localized equivalents) — and matches the web `formatRelative` thresholds (m < 60, h < 24, d < 7, then short date).
  - Traces: AC-3.

- TC-AND-099-05 — Body annotated-string URL linkification (Android-only enhancement).
  - Type: unit. Target: JVM.
  - Preconditions: Bodies: plain text; text with one URL; URL with trailing punctuation; text with `@name`/`#tag` literals.
  - Steps: Call `buildPostAnnotatedString(body)`; inspect `LinkAnnotation` ranges.
  - Expected: URLs get a `LinkAnnotation` over the correct range (trailing punctuation excluded); `@name`/`#tag` are NOT linkified (no web parity); plain text yields zero annotations.
  - Traces: AC-4.

- TC-AND-099-06 — Video item: play overlay + duration badge from `duration_seconds`; tap fires `onMediaClick`.
  - Type: Compose-UI. Target: JVM (Robolectric).
  - Preconditions: `Post` with `video.thumbnail_url` set and `duration_seconds = 42` (mapped), no images.
  - Steps: Render; assert play overlay present and duration badge shows formatted "0:42"; click the media cell index 0.
  - Expected: `onMediaClick(post, 0)` invoked; badge derives from seconds (not ms).
  - Traces: AC-6.

- TC-AND-099-07 — Click propagation for media-by-index and link preview.
  - Type: Compose-UI. Target: JVM (Robolectric).
  - Preconditions: `Post` with ≥3 images; separately a `Post` with `linkPreview` (forward-looking) and no media.
  - Steps: Click media cell index 2 → expect `onMediaClick(post, 2)`. For the preview post, click `post_link_preview` → expect `onLinkClick(previewUrl)`.
  - Expected: Correct index and URL forwarded exactly once each.
  - Traces: AC-2, AC-5.

- TC-AND-099-08 — Degenerate / dirty-data resilience.
  - Type: Compose-UI. Target: JVM (Robolectric).
  - Preconditions: (a) Post with blank body, no images, null video, null linkPreview; (b) Post with one image whose URL is broken; (c) Post with a media item of unknown/UNKNOWN type.
  - Steps: Render each.
  - Expected: (a) header + divider only, no body/grid/preview, no crash; (b) `FeedAsyncImage` error/placeholder shown, cell box reserved (no layout shift); (c) generic placeholder cell, never crashes.
  - Traces: AC-7.

- TC-AND-099-09 — Offline/flaky-host path: PostItem renders from cached `Post` with no live network.
  - Type: integration. Target: EMU.
  - Preconditions: Feed served from the offline cache layer (`withOfflineCache` analogue) with no reachable backend; AND-098 supplies `LazyPagingItems<Post>` from cache.
  - Steps: With network disabled, scroll the feed list; observe `PostItem` rows.
  - Expected: Rows render fully from cached data; `PostItem` issues no network call itself (it has none); no error UI originates from `PostItem` (list-level errors are AND-098's). 
  - Traces: AC-1, AC-7.

- TC-AND-099-10 — Security: link/media/author callbacks forward raw values only; no Custom Tab / browser opened by PostItem; no PII to logcat.
  - Type: instrumented. Target: EMU.
  - Preconditions: `Post` body containing `javascript:` and `file:` URLs plus an `http(s)` URL; logcat captured; a no-op callback set.
  - Steps: Tap each link/media/author target; inspect that `PostItem` only invokes the lambda (no Intent launched), and grep captured logcat.
  - Expected: `PostItem` launches no Intent and constructs no HTTP client; raw URL string passed to `onLinkClick` (scheme validation is the consumer's duty); no URLs/body/author ids written to logcat (only DEBUG-guarded grid-template logs, no PII).
  - Traces: AC-7 (resilience), and §8 security contract.

- TC-AND-099-11 — Accessibility: every interactive region has non-empty contentDescription, ≥48dp targets, RTL mirroring.
  - Type: Compose-UI. Target: JVM (Robolectric) for semantics; RTL pseudo-locale.
  - Preconditions: Post with images + video + (forward-looking) preview.
  - Steps: Assert each tappable node (`post_header`, each `media_cell`, `post_link_preview`, whole row) has a non-empty localized `contentDescription` and `Role.Button`; assert minimum 48dp touch target; render under RTL and assert "+N" overlay and play badge mirror to the correct corner.
  - Expected: All assertions pass; no hardcoded English strings (resources used).
  - Traces: AC-9.

- TC-AND-099-12 — Skippability / recomposition count.
  - Type: Compose-UI (recomposition counter). Target: JVM (Robolectric).
  - Preconditions: Same immutable `Post` instance; stable hoisted callbacks.
  - Steps: Trigger a recomposition of the parent with the unchanged `Post`; count `PostItem` body executions.
  - Expected: `PostItem` body is skipped (not re-executed) when the `Post` reference is unchanged.
  - Traces: AC-10.

- TC-AND-099-13 — Screenshot goldens for the common shapes × {light, dark} × {LTR, RTL} (emulator/host render).
  - Type: Compose-UI / screenshot (Paparazzi or Roborazzi). Target: JVM/EMU.
  - Preconditions: Fixture posts for text-only, 1/2/3/4 image, video, link-only (forward-looking), text+media; fonts pinned.
  - Steps: Capture goldens for each shape across the matrix; compare to committed baselines.
  - Expected: Pixel match within tolerance; goldens committed under `feature-feed/src/test/screenshots/`.
  - Traces: AC-8.

- TC-AND-099-14 — Physical-device parity: goldens / font-scale / RTL on arm64-v8a, API 34.
  - Type: instrumented/e2e (screenshot capture). Target: DEVICE (MUST run on the Samsung Galaxy A15 5G — arm64-v8a, API 34 — because the CI emulator is x86_64/API 35 and text/AA rasterization and font-scale layout can differ from real arm64/older API).
  - Preconditions: App installed on the device; max system font scale enabled; device set to an RTL locale for one pass.
  - Steps: Render the same fixture shapes as TC-13 on-device; capture screenshots; compare against device-class baselines; verify no clipping/overlap at max font scale and correct RTL mirroring.
  - Expected: Layout stays bounded (no overlap/clipping beyond intended ellipsis); RTL mirrors correctly; on-device rendering matches the device baseline. Confirms API-34/arm64 parity not covered by the EMU/JVM goldens.
  - Traces: AC-8, AC-9.

### Coverage matrix

| AC | Covered by |
| --- | --- |
| AC-1 (text-only renders header+body, no media/preview) | TC-01, TC-09 |
| AC-2 (1/2/3/4 templates + 5+ "+N" overlay) | TC-02, TC-07 |
| AC-3 (author header from author_id, monogram, timestamp, onAuthorClick) | TC-03, TC-04 |
| AC-4 (body text; URL spans → onLinkClick; mention/hashtag not required) | TC-01, TC-05 |
| AC-5 (link-preview card when present, forward-looking) | TC-07 |
| AC-6 (video play overlay + duration badge; onMediaClick) | TC-06 |
| AC-7 (degenerate/dirty data degrade gracefully, no crash/shift) | TC-08, TC-09, TC-10 |
| AC-8 (7 shapes pass goldens light/dark/LTR/RTL) | TC-13, TC-14 |
| AC-9 (non-empty localized contentDescription; ≥48dp targets) | TC-11, TC-14 |
| AC-10 (PostItem skippable on unchanged Post) | TC-12 |
