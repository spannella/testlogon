---
id: AND-335
title: Share links (+ public download)
milestone: M7
epic: E43
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-331, AND-022]
blocks: []
---

# AND-335 — Share links (+ public download)

## 1. Overview & Goal

Provide the ability to create and revoke shareable links for files in TestLogon, and to open a public, **unauthenticated** download page for a shared file via a deep-linkable route (`/share/:linkId`). This ticket ports the web reference behavior in `frontend/src/api/endpoints/fileShareLinks.ts` to native Android.

Two distinct surfaces are in scope:

1. **Authenticated owner flow** — from a file's detail/row UI an authenticated user creates a share link (optionally with expiry/password/download-limit), sees existing links, copies the link URL, and revokes a link. This runs through the cookie-based session established in earlier auth tickets.
2. **Public consumer flow** — anyone opening `https://<host>/share/<linkId>` (the web *page* route; verified `App.tsx: /share/:linkId`) or the app's deep link lands on a public screen that resolves link metadata via `GET /public/files/share/{link_id}/info` and downloads the underlying file via `POST /public/files/share/{link_id}/download` **without** a logged-in session. The public endpoints accept the `link_id` (plus an optional password) only; no `ui_csrf` cookie, `Authorization: Bearer` token, or session is assumed (the web client calls them with raw `fetch`, not the authed `api` client). **Note:** the user-facing/deep-link path `/share/{linkId}` is distinct from the backend API paths `/public/files/share/{link_id}/{info,download}` — the app resolves the former into a call against the latter.

The deliverable is a self-contained `feature-share` module plus the `FileShareLinksApi` Retrofit service and DTOs in `core-network`/`core-model`, wired into the typed `NavHost` from AND-022. Goal: a creator can mint a link, hand it off, and a recipient with no account can download the file; revoking the link makes the public page fail closed.

## 2. Context & References

- **Web reference:** `frontend/src/api/endpoints/fileShareLinks.ts` (create/list/revoke + public resolve/download), shared types in `frontend/src/api/types.ts`.
- **Backend:** FastAPI + DynamoDB; OpenAPI at `/openapi.json`. Dev host `http://18.222.237.167:8000` is plaintext HTTP and unreliable — design for ~20s timeouts, bounded retry for idempotent GETs only, offline/stale states.
- **Dependencies:**
  - **AND-331 (Files API + DTOs, P0):** provides `FilesApi`, `FileDto`, and the `core-model` file identity (`fileId`) this ticket links against. Share creation references a `fileId` produced by AND-331.
  - **AND-022 (Navigation host & routes, P0):** provides the single-Activity typed `NavHost`. This ticket registers the `Share` (owner sheet) and `PublicShare` (deep-link) destinations.
- **Auth model (verified against `src/api/client.ts`):** Owner endpoints (`/ui/files/share-links*`) ride the authed `api` client, which sends **three** things: `Authorization: Bearer <accessToken>` (from the auth store), `X-CSRF-Token` (read from the `ui_csrf` cookie), and `credentials: include` (cookie session). On a `401` *for an already-authenticated user*, the client calls `POST /ui/session/refresh` once and retries the original request; a second 401 logs the user out. (An unauthenticated 401 propagates directly.) **Public endpoints are exempt** and must run on a token/cookie/CSRF-free request path — the web client uses raw `fetch` with no `Authorization`, no `X-CSRF-Token`, and no `credentials: include` for `/public/files/share/...`.
- **Package base:** `com.testlogon.android` (namespace `com.testlogon.android.feature.share`, `com.testlogon.android.core.*`).

## 3. Functional Requirements

FR-1. **Create link.** From a file UI affordance, the user opens a "Share" bottom sheet. They may set: expiry as an **hour count** (`expiry_hours`, server range 1–720 ≈ 30 days, default 24 — present as presets 1h / 24h / 7d / 30d, not a free-form future timestamp, since the API takes hours not an ISO instant), a password (4–128 chars when set), and a max-download count (`max_downloads`, 1–100, default 1). Submitting calls `POST /ui/files/share-links` and shows the resulting absolute `share_url`. (`file_node_id` is sent in the body, not the path.)

FR-2. **List existing links.** The share sheet lists all active links for the file, each showing the truncated URL, expiry, download count vs. limit, and a revoke action.

FR-3. **Copy URL.** Tapping a link copies the full public URL to the clipboard and shows a confirmation snackbar.

FR-4. **Revoke link.** Revoke removes the link; the row disappears optimistically and the public page for that `linkId` must subsequently fail closed (404/410).

FR-5. **Public resolve.** Opening `/share/:linkId` (in-app deep link or pasted URL) navigates to `PublicShareScreen`, which resolves link metadata (file name, size, mime, expiry, whether password is required) **without** an authenticated session.

FR-6. **Password gate.** If the link requires a password, the public screen prompts for it before enabling download; a wrong password yields a clear, non-leaking error.

FR-7. **Public download.** A download button streams the file to the device's Downloads via the platform `DownloadManager` (or a `core-data` download helper), showing progress and a completion/open action.

FR-8. **Expired/revoked/exhausted states.** The public screen renders distinct terminal states for expired, revoked, and download-limit-exhausted links, plus a generic "link unavailable" fallback.

FR-9. **Deep link.** The app declares an intent filter for `https://<host>/share/*` (and `testlogon://share/*`) so links open the app directly; cold-start deep links resolve correctly into `PublicShareScreen`.

## 4. Technical Design

New Gradle module `:feature:share` (namespace `com.testlogon.android.feature.share`), depending on `:core-network`, `:core-model`, `:core-ui`, `:core-data`, and `:core-testing` (test only). The API service and DTOs live in `:core-network`/`:core-model` so non-feature callers can reuse them.

**Retrofit service** (`core-network`):

> **CORRECTED against OpenAPI + `fileShareLinks.ts`.** The owner endpoints are **collection-level, not nested under a file**: `GET/POST /ui/files/share-links` and `DELETE /ui/files/share-links/{link_id}`. The `fileId` is **not** a path parameter — it is the `file_node_id` field in the *create* request body. Listing returns **all** of the caller's share links (server scopes by session), not links for one file; client-side filtering by `file_node_id` is required if a per-file view is desired. The public endpoints are `GET /public/files/share/{link_id}/info` (resolve) and `POST /public/files/share/{link_id}/download` (download, password in JSON body). There is **no** `X-Share-Password` header anywhere and **no** `downloadUrl` field in any response.

```kotlin
interface FileShareLinksApi {
    @GET("ui/files/share-links")
    suspend fun list(): Response<ShareLinkListDto>            // all of the caller's links; filter by file_node_id client-side

    @POST("ui/files/share-links")
    suspend fun create(
        @Body body: CreateShareLinkRequest,                  // carries file_node_id, expiry_hours, max_downloads, password
    ): Response<ShareLinkDto>                                  // 201

    @DELETE("ui/files/share-links/{linkId}")
    suspend fun revoke(
        @Path("linkId") linkId: String,
    ): Response<RevokeShareLinkDto>                            // 200 { ok, link_id }  (NOT 204)

    // Public, session-free. Tagged so the auth/CSRF/Bearer interceptors skip it.
    @GET("public/files/share/{linkId}/info")
    @Tag(PublicRequest::class) // or @Headers("X-TL-Public: 1")
    suspend fun resolvePublic(
        @Path("linkId") linkId: String,
    ): Response<PublicShareDto>                                // 200 ShareLinkPublicInfoOut (state via boolean flags)

    // Download: POST with JSON body { "password": <string|null> }; password is NOT a header.
    @POST("public/files/share/{linkId}/download")
    @Tag(PublicRequest::class)
    @Streaming
    suspend fun downloadPublic(
        @Path("linkId") linkId: String,
        @Body body: PublicDownloadRequest,                    // { password: String? }
    ): Response<ResponseBody>
}
```

**Public download.** The `/info` response contains **no** `downloadUrl`; the download is a direct `POST /public/files/share/{link_id}/download` with the password (if any) in the JSON body. Because the password must travel in a POST body, Android `DownloadManager` (URL/header-oriented, GET-only for added headers) is **not** a clean fit for password-protected links — prefer a streamed OkHttp download (`@Streaming` `ResponseBody`) on the public, cookie/CSRF/Bearer-free request path, writing to `MediaStore`/Downloads via `core-data` `ShareDownloader`. (A GET variant `GET /public/files/share/{link_id}/download?password=...` also exists in the API and could feed `DownloadManager` for the no-password case, but putting a password in a query string is discouraged — see §13.) The download request must **not** carry session cookies, the `ui_csrf` CSRF header, or the `Authorization: Bearer` token.

**Repository** (`feature-share`):

```kotlin
interface ShareRepository {
    suspend fun listLinks(fileId: String): ApiResult<List<ShareLink>>
    suspend fun createLink(fileId: String, options: ShareLinkOptions): ApiResult<ShareLink>
    suspend fun revokeLink(fileId: String, linkId: String): ApiResult<Unit>
    suspend fun resolvePublic(linkId: String, password: String?): ApiResult<PublicShare>
}
```

`ShareRepositoryImpl` is `@Inject`ed, maps DTO ↔ domain, and translates FastAPI `detail` (string | `[{msg}]` | `{code,...}`) into typed errors via the shared `ApiResult` mapper.

**ViewModels** expose `StateFlow<UiState>`:

```kotlin
@HiltViewModel
class ShareSheetViewModel @Inject constructor(
    private val repo: ShareRepository,
    savedState: SavedStateHandle,
) : ViewModel() {
    val state: StateFlow<ShareSheetUiState>
    fun create(options: ShareLinkOptions)
    fun revoke(linkId: String)
    fun copy(linkId: String)
}

@HiltViewModel
class PublicShareViewModel @Inject constructor(
    private val repo: ShareRepository,
    private val downloader: ShareDownloader,
    savedState: SavedStateHandle, // linkId from route
) : ViewModel() {
    val state: StateFlow<PublicShareUiState>
    fun submitPassword(password: String)
    fun download()
}
```

**Navigation (AND-022 NavHost).** Typed routes:

```kotlin
@Serializable data class Share(val fileId: String)         // owner sheet host
@Serializable data class PublicShare(val linkId: String)   // public page
```

`PublicShare` registers a `navDeepLink { uriPattern = "https://$HOST/share/{linkId}" }` and a `testlogon://share/{linkId}` pattern. The `AndroidManifest` intent filter (autoVerify for the https scheme) routes both warm and cold starts to the single Activity.

**Compose UI.** `ShareSheet` (Material 3 `ModalBottomSheet`) with the options form + link list. `PublicShareScreen` is a top-level `Scaffold` with file summary, optional password field, primary download button, and `LinearProgressIndicator` bound to download progress. Public screen uses no app chrome that assumes a session (no profile/avatar).

## 5. API Contract

Base path under the FastAPI host. Owner endpoints require the authed transport (`Authorization: Bearer` + `X-CSRF-Token` cookie-derived header + cookie session); public endpoints do not. **Field names and shapes below are now reconciled against `components.schemas` in OpenAPI and `src/api/types.ts`.**

**Create** — `POST /ui/files/share-links` (schema `CreateShareLinkIn`). The `fileId` is **in the body** as `file_node_id`; there is no file path param. Expiry is an **integer hour count** (`expiry_hours`), not an ISO timestamp.
Request:
```json
{ "file_node_id": "f_123", "expiry_hours": 168, "max_downloads": 50, "password": "hunter2" }
```
Field rules (from `CreateShareLinkIn`): `file_node_id` **required** (1–2048 chars); `expiry_hours` integer, default `24`, range `1–720` (max 30 days); `max_downloads` integer, default `1`, range `1–100`; `password` optional/nullable string, 4–128 chars when present. Response `201` (schema `ShareLinkOut`):
```json
{
  "link_id": "lk_8fa3...",
  "file_node_id": "f_123",
  "file_name": "report.pdf",
  "file_size_bytes": 482133,
  "content_type": "application/pdf",
  "created_at": 1749117600,
  "expires_at": 1749722400,
  "max_downloads": 50,
  "download_count": 0,
  "has_password": true,
  "is_revoked": false,
  "share_url": "http://18.222.237.167:8000/share/lk_8fa3..."
}
```
Note corrected field names vs. the original draft: `file_node_id` (not `file_id`), `file_size_bytes`, `content_type`, `share_url` (not `url`), `has_password` (not `password_protected`), `is_revoked` (not `revoked`). `created_at`/`expires_at` are **epoch-second integers**, not ISO strings.

**List** — `GET /ui/files/share-links` → `200` `ShareLinkListOut` = `{ "items": [ShareLinkOut, ...] }`. Returns **all** of the caller's links (server scopes by session); there is no per-file server filter, so filter by `file_node_id` on the client if showing one file's links.

**Revoke** — `DELETE /ui/files/share-links/{linkId}` → **`200`** with body `{ "ok": true, "link_id": "lk_8fa3..." }` (per `fileShareLinks.ts`). It is **not** `204`.

**Public resolve** — `GET /public/files/share/{linkId}/info` (schema `ShareLinkPublicInfoOut`). **No password header** — `/info` takes only the `link_id` path param. → `200`:
```json
{
  "file_name": "report.pdf",
  "file_size_bytes": 482133,
  "content_type": "application/pdf",
  "requires_password": true,
  "is_expired": false,
  "is_revoked": false,
  "is_used": false,
  "remaining_downloads": 3
}
```
**Terminal states are conveyed as boolean flags on a `200` body, not via 404/410 status codes** (verified in `PublicDownloadPage.tsx`): the web client reads `is_revoked` / `is_expired` / `is_used` and renders the corresponding terminal message; only a transport-level failure (`isError`/no `data`) renders "Share link not found." Note there is **no** `link_id`, `expires_at`, `password_required`, `password_ok`, or `download_url` in this response — corrected vs. the original draft. (`requires_password` replaces `password_required`; `remaining_downloads` replaces a `download_count`/`max_downloads` pair here.)

**Public download** — `POST /public/files/share/{linkId}/download` with JSON body `{ "password": <string|null> }` (password in **body**, not a header). Streams bytes with `Content-Disposition`/`Content-Type`; the filename is parsed from `Content-Disposition`. Error mapping observed in `PublicDownloadPage.tsx`: `403 → "Invalid password."`, `410 → "This link is no longer available."`, anything else → generic "Download failed." (A `GET /public/files/share/{linkId}/download?password=...` variant also exists per the OpenAPI index.) OpenAPI only declares `200` and `422 HTTPValidationError` for these public routes; the `403`/`410` codes are inferred from the verified web client behavior, not the OpenAPI response map.

DTO field names above are now reconciled against OpenAPI `components.schemas` and `src/api/types.ts`; keep Moshi `@Json(name=...)` mappings centralized in `core-network`. The only fields still NOT individually documented in OpenAPI are the exact error `detail` payloads (see §16 Open assumptions).

## 6. Data & State Management

Domain models in `core-model`:

```kotlin
// Mapped from ShareLinkOut. Note: server returns the full file metadata on each link,
// and epoch-second integers for timestamps (convert to Instant via Instant.ofEpochSecond).
data class ShareLink(
    val linkId: String, val fileNodeId: String, val shareUrl: String,
    val fileName: String, val fileSizeBytes: Long, val contentType: String,
    val createdAt: Instant, val expiresAt: Instant,
    val maxDownloads: Int, val downloadCount: Int,
    val hasPassword: Boolean, val isRevoked: Boolean,
)
// Maps to CreateShareLinkIn. Expiry is an integer hour count (1..720), not a timestamp.
data class ShareLinkOptions(
    val fileNodeId: String, val expiryHours: Int = 24,
    val maxDownloads: Int = 1, val password: String? = null,
)
// Mapped from ShareLinkPublicInfoOut. There is NO downloadUrl; the download is a direct
// POST to /public/files/share/{linkId}/download. Terminal state comes from the flags.
data class PublicShare(
    val fileName: String, val fileSizeBytes: Long, val contentType: String,
    val requiresPassword: Boolean, val remainingDownloads: Int,
    val isExpired: Boolean, val isRevoked: Boolean, val isUsed: Boolean,
)
```

UI state:

```kotlin
sealed interface ShareSheetUiState {
    data object Loading : ShareSheetUiState
    data class Ready(val links: List<ShareLink>, val creating: Boolean = false,
                     val error: UiError? = null) : ShareSheetUiState
    data class Failed(val error: UiError) : ShareSheetUiState
}
sealed interface PublicShareUiState {
    data object Resolving : PublicShareUiState
    data class PasswordRequired(val fileName: String, val attemptError: UiError? = null) : PublicShareUiState
    data class Ready(val share: PublicShare, val download: DownloadState) : PublicShareUiState
    data class Unavailable(val reason: UnavailableReason) : PublicShareUiState // Expired, Revoked, Exhausted, Generic
}
```

**No Room persistence.** Share links are not cached in Room; the list is fetched live each time the sheet opens (links are sensitive and short-lived). `download_count` is authoritative server-side. Transient UI inputs (entered password, selected expiry) survive rotation via `SavedStateHandle`; the entered password is **not** persisted to DataStore or Room. `linkId` is the only thing held in the back-stack arguments for `PublicShare`.

## 7. Error Handling & Resilience

- **Owner mutations** (create/revoke) are **not** retried automatically (non-idempotent POST/DELETE); failures surface inline with a retry button.
- **GETs** (list, public resolve) use the shared bounded-backoff policy for idempotent reads against the unreliable dev host: ~20s timeout, max 2 retries with jitter.
- **401 on owner endpoints** triggers the single `POST /ui/session/refresh` + retry in the network layer (existing behavior, verified in `client.ts`); public endpoints never hit this path.
- **Public terminal mapping (CORRECTED — flags on a `200`, not status codes):** `/info` returns `200` with boolean flags; map `is_revoked → Unavailable.Revoked`, `is_expired → Unavailable.Expired`, `is_used → Unavailable.Exhausted` (limit consumed), and a transport failure / non-2xx / missing body → `Unavailable.Generic` (web shows "Share link not found"). The password gate is driven by `requires_password` (show `PasswordRequired`), not by an error code on resolve. **On download:** `403 → PasswordRequired(attemptError="Invalid password")` (NOT `401`), `410 → Unavailable.Generic` ("no longer available"), other/timeout → download error with retry. (These download codes are inferred from `PublicDownloadPage.tsx`; OpenAPI documents only `200`/`422`.)
- **Download failures** (DownloadManager `STATUS_FAILED`, no network, insufficient storage) show a snackbar with retry; partial downloads are cleaned up.
- **Optimistic revoke** rolls back (re-inserts the row) if the DELETE fails.
- **Offline:** owner sheet shows a stale/offline banner; public screen shows offline state with retry.

## 8. Security & Privacy

- Public endpoints must execute on a **session-free request path**: a dedicated OkHttp call (or `@Tag(PublicRequest::class)`) that bypasses the persistent cookie jar, the `X-CSRF-Token` interceptor, **and** the `Authorization: Bearer` interceptor, so a logged-in user's session/token never leaks into a public download and the flow works for unauthenticated recipients. (The web client achieves this by using raw `fetch` for `/public/files/share/...` instead of the authed `api` client — verified in `fileShareLinks.ts`.)
- `linkId` is an unguessable, capability-bearing token: never logged in full (log a redacted prefix only), never echoed into telemetry, never placed in a screenshot-eligible widget without care.
- Entered link passwords are kept in memory only (`SavedStateHandle`), sent in the **JSON body** of the download POST (`{ "password": ... }`) — **not** an `X-Share-Password` header (that header does not exist in the verified contract) — and never persisted. Password fields use `PasswordVisualTransformation` and `KeyboardType.Password`.
- Wrong-password errors are generic ("Incorrect password") and do not reveal whether the link/file exists.
- The dev host is plaintext HTTP; production must use HTTPS and `autoVerify` App Links. The download must not be cached to a world-readable location beyond the user-chosen Downloads directory.
- Revocation must fail closed: after revoke, the public page returns 404/410 and any in-flight download URL is invalidated server-side (verified by acceptance test).

## 9. Accessibility & i18n

- All actions (Create, Copy, Revoke, Download) have `contentDescription`/semantics; icon-only buttons are labeled.
- Download `LinearProgressIndicator` exposes `progressSemantics`; completion is announced via a live-region snackbar.
- Touch targets ≥ 48dp; share sheet and public screen support TalkBack focus order (file name → metadata → password → download).
- All copy lives in `strings.xml` (no hardcoded literals): titles, expiry presets, error strings, terminal-state messages. File sizes/dates formatted via locale-aware `android.text.format.Formatter` and `java.time` with the device locale/zone.
- Layouts tested at 200% font scale and in RTL.

## 10. Telemetry & Logging

Events (via the app analytics abstraction; no PII, no raw `linkId`):
- `share_link_created` { fileId(hashed), has_password, has_expiry, has_limit }
- `share_link_revoked` { fileId(hashed) }
- `share_link_copied`
- `public_share_resolved` { result: ok|password|expired|revoked|exhausted|error }
- `public_share_download` { result: started|completed|failed }

Logging uses the app's `Logger`; network failures log status + redacted endpoint (`/share/lk_8f…`). No passwords, no full tokens, no file contents in logs. Debug builds may log full request lines via OkHttp logging interceptor gated to `BuildConfig.DEBUG`.

## 11. Testing Strategy

- **DTO mapping (unit):** `ShareLinkDto`/`PublicShareDto` ↔ domain round-trips, including epoch-second `created_at`/`expires_at` → `Instant`, `requires_password` true/false, each `is_*` flag combination, and the `RevokeShareLinkDto` `{ ok, link_id }` shape — mirrors the AND-331 "payloads map (tested)" standard.
- **Repository (unit):** MockWebServer drives create (201 `ShareLinkOut`), list (200 `ShareLinkListOut`), revoke (**200** `{ ok, link_id }`), public resolve `/info` (200 with `is_revoked`/`is_expired`/`is_used`/`requires_password` permutations), and download (200 stream, **403** invalid password, **410** gone); assert correct `ApiResult`/`UnavailableReason` mapping and that the public calls carry **no** cookie, **no** `X-CSRF-Token`, and **no** `Authorization: Bearer` header while the owner calls carry all three.
- **ViewModel (unit, `core-testing`):** `ShareSheetViewModel` create/revoke/optimistic-rollback; `PublicShareViewModel` password gate, terminal states, and download dispatch (fake `ShareDownloader`). Use `Turbine` over the `StateFlow`.
- **Navigation/deep link (instrumented):** opening `https://<host>/share/{linkId}` cold and warm routes to `PublicShareScreen` with the correct `linkId`.
- **UI (Compose test):** share sheet renders links and revoke removes a row; public screen shows password prompt, then download button; expired/revoked render terminal copy.
- **E2E happy path (acceptance):** create link (owner) → resolve + download (public, no session) → revoke → public resolve fails closed.

## 12. Dependencies & Sequencing

- **Blocked by AND-331 (P0):** needs `FilesApi`/`FileDto` and the canonical `fileId`; share links are created against a file from the files list.
- **Blocked by AND-022 (P0):** needs the typed `NavHost` to register `Share`/`PublicShare` and the deep-link patterns.
- **Soft dependency:** the cookie/CSRF network stack and the `ApiResult` + FastAPI `detail` mapper from the core-network/auth tickets must expose a way to mark a request public (tag/header). If not yet present, add the `@Tag(PublicRequest::class)` interceptor bypass as part of this ticket.
- **Sequencing:** land `FileShareLinksApi` + DTOs + repository (testable in isolation) first, then the owner share sheet, then the public screen + deep link, then download + E2E.
- **Blocks:** none recorded in backlog.

## 13. Risks & Open Questions

- **OpenAPI field names — NOW VERIFIED (resolved).** Paths/fields are confirmed against OpenAPI `components.schemas` and `fileShareLinks.ts`: owner routes are `/ui/files/share-links*` (collection-level, `file_node_id` in body), expiry is `expiry_hours` (int 1–720, default 24), `max_downloads` (int 1–100, default 1), list envelope is `{ items: [...] }`, and the response field names are `file_node_id`/`file_size_bytes`/`content_type`/`share_url`/`has_password`/`is_revoked`. The original draft's `expires_at` timestamp, `file_id`, `url`, `password_protected`, `revoked` were all wrong and have been corrected in §4–§6. Residual risk is minimal (DTO layer only).
- **Public auth bypass — VERIFIED.** The web client calls `/public/files/share/{linkId}/{info,download}` with raw `fetch` and no auth/cookies/CSRF, so the backend serves them session-free (confirmed in `fileShareLinks.ts`). The session-free Android path is therefore the correct design.
- **Download authorization — RESOLVED to a design decision.** There is no `download_url`; download is a direct `POST /public/files/share/{linkId}/download` with the password in the JSON body. Because the password is a POST body, plain `DownloadManager` (GET + headers only) is not a clean fit for password-protected links → use streamed OkHttp. The no-password case could use the `GET .../download?password=...` variant with `DownloadManager`, but a password in the query string is discouraged; standardize on the streamed OkHttp `ShareDownloader` for both. Resolve the MediaStore vs. app-private destination before implementing FR-7.
- **App Links verification** requires a `assetlinks.json` on the production host; dev plaintext host cannot autoVerify. Tracked as a deployment dependency.
- **Password transport over plaintext dev HTTP** is insecure by nature of the dev environment; acceptable for dev only.

## 14. Acceptance Criteria

AC-1. An authenticated user can create a share link for a file; the returned absolute URL is displayed and copyable. *(Backlog: "Share link works.")*
AC-2. The share sheet lists existing links with expiry and download-count, and revoke removes a link (optimistic, rolled back on failure).
AC-3. Opening `/share/:linkId` (deep link, cold and warm start) renders `PublicShareScreen` resolving metadata **without** an authenticated session.
AC-4. A password-protected link prompts for the password and rejects wrong passwords with a generic error; a correct password enables download.
AC-5. The public page downloads the file to the device, showing progress and completion. *(Backlog: "public page downloads.")*
AC-6. Expired, revoked, and download-limit-exhausted links each render a distinct terminal state; a revoked link's public page fails closed. *(Mechanism corrected: `/info` returns `200` with `is_expired`/`is_revoked`/`is_used` flags that drive the terminal state; a download attempt on a gone link returns `410`. The page does not rely on a `404`/`410` on resolve.)*
AC-7. DTO/error mapping is covered by passing unit tests; public requests carry no session cookie, no `X-CSRF-Token`, and no `Authorization: Bearer` header, while owner requests carry all three (asserted in test).

## 15. Definition of Done

- `:feature:share` module + `FileShareLinksApi`/DTOs/domain models merged on `android-port`, namespaced `com.testlogon.android.*`.
- Owner share sheet (create/list/copy/revoke) and `PublicShareScreen` (resolve/password/download/terminal states) implemented per FRs.
- `Share`/`PublicShare` routes and `https`/`testlogon` deep links registered in the AND-022 NavHost and manifest; cold-start deep link verified.
- Unit + ViewModel + Compose + deep-link instrumented tests pass in CI; E2E happy path (create → public download → revoke → fail-closed) green.
- No hardcoded strings; a11y semantics and 200%/RTL checks pass; no PII/tokens/passwords in logs (verified).
- Code review approved; OpenAPI/`fileShareLinks.ts` field reconciliation completed or open questions explicitly ticketed.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **Create endpoint is `POST /ui/files/share-links`** (not `POST /files/{fileId}/share-links`). VERDICT: **Corrected.** SOURCE: OpenAPI `POST /ui/files/share-links` (op `create_share_link_endpoint_ui_files_share_links_post`, req `CreateShareLinkIn`, resp `201:ShareLinkOut`); `src/api/endpoints/fileShareLinks.ts: createShareLink`.
2. **List endpoint is `GET /ui/files/share-links` returning `{ items: [...] }` of ALL the caller's links** (not per-file). VERDICT: **Corrected.** SOURCE: OpenAPI `GET /ui/files/share-links` (resp `200:ShareLinkListOut`); schema `ShareLinkListOut` (`items: ShareLinkOut[]`); `fileShareLinks.ts: listShareLinks`.
3. **Revoke endpoint is `DELETE /ui/files/share-links/{link_id}` returning `200 { ok, link_id }`** (not `204`, not nested under a file). VERDICT: **Corrected.** SOURCE: OpenAPI `DELETE /ui/files/share-links/{link_id}` (op `revoke_share_link_endpoint...`, resp `200`); `fileShareLinks.ts: revokeShareLink` (`del<{ ok: boolean; link_id: string }>`).
4. **`fileId` is sent in the create body as `file_node_id`, not a path param; create also takes `expiry_hours` (int) and `max_downloads` (int).** VERDICT: **Corrected.** SOURCE: schema `CreateShareLinkIn` — `file_node_id` (required), `expiry_hours` (int, default 24, 1–720), `max_downloads` (int, default 1, 1–100), `password` (str|null, 4–128); `src/api/types.ts: CreateShareLinkInput`.
5. **Expiry is an integer hour count (`expiry_hours`), NOT an ISO `expires_at` request field.** VERDICT: **Corrected.** SOURCE: schema `CreateShareLinkIn.expiry_hours`.
6. **`ShareLinkOut` response field names: `link_id`, `file_node_id`, `file_name`, `file_size_bytes`, `content_type`, `created_at` (epoch int), `expires_at` (epoch int), `max_downloads`, `download_count`, `has_password`, `is_revoked`, `share_url`.** Draft's `file_id`/`url`/`password_protected`/`revoked`/ISO timestamps were wrong. VERDICT: **Corrected.** SOURCE: schema `ShareLinkOut`; `src/api/types.ts: ShareLink`.
7. **Public resolve is `GET /public/files/share/{link_id}/info` → `ShareLinkPublicInfoOut`.** VERDICT: **Corrected** (draft said `GET /share/{linkId}`). SOURCE: OpenAPI `GET /public/files/share/{link_id}/info` (resp `200:ShareLinkPublicInfoOut`); `fileShareLinks.ts: getShareLinkInfo`.
8. **`ShareLinkPublicInfoOut` fields are `file_name`, `file_size_bytes`, `content_type`, `requires_password`, `is_expired`, `is_revoked`, `is_used`, `remaining_downloads` — and contain NO `link_id`, `expires_at`, `password_ok`, or `download_url`.** VERDICT: **Corrected.** SOURCE: schema `ShareLinkPublicInfoOut`; `src/api/types.ts: ShareLinkPublicInfo`.
9. **Public terminal state (revoked/expired/used) is conveyed via boolean flags on a `200` body, not via `404`/`410` on resolve.** VERDICT: **Corrected.** SOURCE: `src/pages/files/PublicDownloadPage.tsx` (`unavailableMessage()` reads `is_revoked`/`is_expired`/`is_used`; transport error → "Share link not found").
10. **Public download is `POST /public/files/share/{link_id}/download` with password in JSON body `{ password }`, not an `X-Share-Password` header.** VERDICT: **Corrected.** SOURCE: OpenAPI `POST /public/files/share/{link_id}/download`; `fileShareLinks.ts: downloadShareLink` (body `JSON.stringify({ password })`). A `GET .../download?password=...` variant also exists (OpenAPI `GET /public/files/share/{link_id}/download`, param `password`).
11. **There is NO `download_url` field anywhere; the public screen calls the download endpoint directly.** VERDICT: **Corrected.** SOURCE: schema `ShareLinkPublicInfoOut` (absent); `PublicDownloadPage.tsx: handleDownload` (calls `downloadShareLink(linkId, password)`).
12. **Download error mapping: `403` = invalid password, `410` = link no longer available, else generic.** (Draft claimed `401 invalid_password`.) VERDICT: **Corrected.** SOURCE: `PublicDownloadPage.tsx: handleDownload` catch (`err.status === 403 → "Invalid password."`, `=== 410 → "no longer available"`). Not in OpenAPI response map (only `200`/`422` declared).
13. **Owner auth = `Authorization: Bearer` + `X-CSRF-Token` (from `ui_csrf` cookie) + cookie session (`credentials: include`).** Draft mentioned only "cookie session + X-CSRF-Token", omitting the Bearer token. VERDICT: **Corrected.** SOURCE: `src/api/client.ts` (lines setting `Authorization`, `X-CSRF-Token` from `getCookie("ui_csrf")`, `credentials: "include"`).
14. **On `401` for an authenticated user, the client calls `POST /ui/session/refresh` once then retries; a second 401 logs out.** VERDICT: **Verified.** SOURCE: `src/api/client.ts: refreshSession()` + 401 handler.
15. **Public endpoints run on a session-free path (raw `fetch`, no auth/cookie/CSRF).** VERDICT: **Verified.** SOURCE: `src/api/endpoints/fileShareLinks.ts` (public calls use `fetch(...)`, not the `api` client; no `credentials`/`Authorization`).
16. **Web public page route is `/share/:linkId`** (matches the planned deep-link path). VERDICT: **Verified.** SOURCE: `src/App.tsx: <Route path="/share/:linkId" element={<PublicDownloadPage />} />`.
17. **Owner web page route is `/files/share-links`.** VERDICT: **Verified.** SOURCE: `src/App.tsx: <Route path="files/share-links" .../>`.
18. **FastAPI `detail` error shape is `string | [{msg}] | {code,...}` and should map via a shared normalizer.** VERDICT: **Verified.** SOURCE: `src/api/client.ts: normalizeErrorDetail()` + `mapAuthorizationError()`.
19. **`ModalBottomSheet`, typed Navigation Compose routes + `navDeepLink`, and `autoVerify` App Links are the chosen Android frameworks.** VERDICT: **Unverified-assumption (framework choice).** SOURCE: framework ref — Jetpack Compose Material 3 (`developer.android.com/jetpack/compose/components/bottom-sheets`), Navigation-Compose type-safe routes & deep links (`developer.android.com/guide/navigation/design/deep-link`), App Links verification (`developer.android.com/training/app-links/verify-android-applinks`).
20. **Streamed OkHttp download (vs. `DownloadManager`) and `MediaStore` Downloads write.** VERDICT: **Unverified-assumption (framework/design choice driven by claim 10).** SOURCE: framework ref — `DownloadManager` is GET/header-oriented and cannot carry a POST body (`developer.android.com/reference/android/app/DownloadManager`); `MediaStore.Downloads` (`developer.android.com/training/data-storage/shared/media`).

### Corrections made

- §1/§2/§5: owner endpoints corrected to `/ui/files/share-links` (collection-level; `file_node_id` in body, not a `{fileId}` path param); public endpoints corrected to `/public/files/share/{link_id}/info` and `/public/files/share/{link_id}/download`.
- §2/§8: auth model corrected to include the `Authorization: Bearer` token (not only cookie+CSRF); public bypass must also drop the Bearer header.
- §4/§5/§6: DTO field names reconciled to `ShareLinkOut`/`ShareLinkPublicInfoOut`/`CreateShareLinkIn` (`file_node_id`, `file_size_bytes`, `content_type`, `share_url`, `has_password`, `is_revoked`, epoch-int timestamps; `requires_password`/`remaining_downloads`/`is_*` flags). Removed the non-existent `download_url`, `password_ok`, `password_required`, `password_protected`, `url`, `file_id` fields.
- §4: create request expiry corrected from ISO `expires_at` to integer `expiry_hours` (1–720); `max_downloads` 1–100, default 1.
- §5: revoke corrected from `204` to `200 { ok, link_id }`.
- §5/§7/§11: public terminal model corrected from "404/410 status on resolve" to "boolean flags on a `200` `/info` body"; download error codes corrected to `403` (invalid password, was `401`) / `410` (gone).
- §4/§8: password transport corrected from `X-Share-Password` header to JSON request body.
- §4/§13: download mechanism corrected — no `download_url`; recommend streamed OkHttp because the password lives in a POST body that `DownloadManager` can't carry.
- §3 (FR-1): expiry presets reframed as hour counts (≤720) rather than a free-form future timestamp.
- §14 (AC-6/AC-7): updated to the flag-based terminal mechanism and to assert the Bearer header is absent on public requests.

### Open assumptions

- **Exact `detail` payload strings for public errors** (e.g. the body of the `403`/`410` download responses). WHY: OpenAPI declares only `200`/`422` for the public routes; the web client keys off HTTP status, not `detail` text, so the precise `detail` values are not authoritatively documented. Treat status code as the contract; tolerate any `detail` body.
- **Whether `is_used` exclusively means "download limit exhausted"** vs. a single-use semantics distinct from `remaining_downloads == 0`. WHY: schema documents both `is_used` and `remaining_downloads` but not their precise interaction; the web client treats `is_used` as a terminal "already used" state. Confirm during implementation.
- **`Content-Disposition` filename reliability** for the streamed download. WHY: the web client falls back to `"download"` when the header is absent; behavior on the dev host is unverified. Mirror the fallback (prefer `file_name` from `/info`).
- **App Links `autoVerify` on the production host** (requires `assetlinks.json`); the plaintext dev host cannot verify. WHY: deployment-dependent, not testable against the dev environment.
- **All Android framework choices** (Compose Material 3, Navigation-Compose, MediaStore, OkHttp streaming) are standard-practice assumptions, not derived from the backend/web sources (labeled framework refs above).

## 17. Test Plan

Test-target legend: **JVM** = JVM unit/Robolectric (no device); **MWS** = MockWebServer contract; **EMU35** = headless emulator AVD `test35` (API 35, x86_64); **DEV-A15** = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a) on the build host. Use **DEV-A15** where real hardware/OS behavior matters (real Downloads/MediaStore write, real notification tap, ABI/API-34 differences); use **EMU35** for fast UI/instrumented logic.

- **TC-AND-335-01 — Create share link happy path (contract).** Type: contract/MockWebServer (JVM+MWS). Target: `FileShareLinksApi.create` + `ShareRepositoryImpl`. Preconditions: MWS enqueues `201` with a `ShareLinkOut` body. Steps: call `createLink(ShareLinkOptions(fileNodeId="f_123", expiryHours=168, maxDownloads=50, password="hunter2"))`; capture the recorded request. Expected: request is `POST /ui/files/share-links` with body `{file_node_id,expiry_hours,max_downloads,password}`; the request carries `Authorization: Bearer`, `X-CSRF-Token`, and cookies; result is `ApiResult.Success<ShareLink>` with `shareUrl` populated, `hasPassword=true`, epoch `expiresAt` mapped to `Instant`. Traces: AC-1, AC-7.

- **TC-AND-335-02 — List + client-side per-file filter (contract).** Type: contract/MockWebServer (JVM+MWS). Target: `FileShareLinksApi.list` + repo. Preconditions: MWS returns `200 { items: [linkForFileA, linkForFileB] }`. Steps: call `listLinks("fileA")`. Expected: `GET /ui/files/share-links`; both items deserialize; repo returns only the `file_node_id == "fileA"` link (filtering is client-side). Traces: AC-2, AC-7.

- **TC-AND-335-03 — Revoke returns 200 {ok,link_id} (contract).** Type: contract/MockWebServer (JVM+MWS). Target: `FileShareLinksApi.revoke`. Preconditions: MWS returns `200 {"ok":true,"link_id":"lk_1"}`. Steps: call `revokeLink("lk_1")`. Expected: `DELETE /ui/files/share-links/lk_1`; `ApiResult.Success`; mapper does NOT assume a `204` empty body. Traces: AC-2, AC-7.

- **TC-AND-335-04 — Public requests omit auth (security contract).** Type: contract/MockWebServer (JVM+MWS). Target: `resolvePublic`/`downloadPublic` on the `@Tag(PublicRequest::class)` path. Preconditions: a logged-in session exists (cookie jar populated, Bearer set). MWS returns `200` info. Steps: call `resolvePublic("lk_1")` then `downloadPublic("lk_1", null)`; inspect recorded headers. Expected: neither request carries `Cookie`, `X-CSRF-Token`, or `Authorization`; owner calls in the same test DO carry all three. Traces: AC-3, AC-7.

- **TC-AND-335-05 — Public resolve terminal-flag mapping (unit/contract).** Type: contract/MockWebServer (JVM+MWS). Target: repo `resolvePublic` → `UnavailableReason`. Preconditions: MWS returns `200` `ShareLinkPublicInfoOut` bodies with each flag set in turn (`is_revoked`, `is_expired`, `is_used`) and a clean body. Steps: call `resolvePublic` for each. Expected: `is_revoked→Unavailable.Revoked`, `is_expired→Unavailable.Expired`, `is_used→Unavailable.Exhausted`, clean→`Ready` with `requiresPassword` honored; a transport failure (e.g. MWS socket close)→`Unavailable.Generic`. Traces: AC-6.

- **TC-AND-335-06 — Download error codes 403/410 (contract).** Type: contract/MockWebServer (JVM+MWS). Target: `downloadPublic` + mapping. Preconditions: MWS returns `403`, then `410`, then `200` stream. Steps: attempt download with wrong password (403), then on a revoked link (410), then valid (200). Expected: `403→PasswordRequired(attemptError="Invalid password")`; `410→Unavailable/download error "no longer available"`; `200→` bytes streamed and filename parsed from `Content-Disposition` (fallback to `/info` `file_name`). Traces: AC-4, AC-5, AC-6.

- **TC-AND-335-07 — DTO mapping round-trips (unit).** Type: unit (JVM). Target: Moshi adapters for `ShareLinkOut`/`ShareLinkPublicInfoOut`/`CreateShareLinkIn`/`RevokeShareLinkDto`. Preconditions: golden JSON fixtures from §5. Steps: parse → domain → assert; include epoch-int → `Instant` conversion, `requires_password` true/false, all `is_*` flag combos, and `{ok,link_id}`. Expected: exact field mapping; no field name drift (`file_node_id`/`file_size_bytes`/`content_type`/`share_url`). Traces: AC-7.

- **TC-AND-335-08 — ShareSheet create + optimistic revoke rollback (ViewModel unit).** Type: unit (JVM, `core-testing` + Turbine). Target: `ShareSheetViewModel`. Preconditions: fake repo. Steps: emit a links list; call `create(...)` (success appends/refreshes); call `revoke(linkId)` with the fake repo failing the DELETE. Expected: optimistic removal then rollback (row re-inserted) and an inline error on failure; `copy()` emits a clipboard/snackbar effect. Traces: AC-1, AC-2.

- **TC-AND-335-09 — PublicShare password gate + states (ViewModel unit).** Type: unit (JVM, Turbine). Target: `PublicShareViewModel`. Preconditions: fake repo + fake `ShareDownloader`. Steps: resolve a `requiresPassword=true` link → `PasswordRequired`; `submitPassword(wrong)` (repo → 403) → `PasswordRequired(attemptError)`; `submitPassword(correct)` → `Ready`/download dispatched; resolve a revoked link → `Unavailable.Revoked`. Expected: state transitions exactly as above; generic non-leaking error text. Traces: AC-3, AC-4, AC-6.

- **TC-AND-335-10 — Deep link cold + warm start (instrumented).** Type: instrumented (EMU35). Target: NavHost `PublicShare` destination + manifest intent filter. Preconditions: app installed. Steps: `adb shell am start -W -a android.intent.action.VIEW -d "https://<host>/share/lk_test"` from a cold process, then again while the app is foregrounded (warm). Expected: both route to `PublicShareScreen` with `linkId="lk_test"`; the `testlogon://share/lk_test` scheme also resolves. Expected on EMU35 (no real network needed if the resolve call is stubbed/over MWS). Traces: AC-3.

- **TC-AND-335-11 — ShareSheet & PublicScreen UI (Compose-UI).** Type: Compose-UI (EMU35). Target: `ShareSheet`, `PublicShareScreen`. Preconditions: fake VM states. Steps: render `Ready` links list (assert revoke removes a row); render `PasswordRequired` (assert download disabled until a password is entered); render each `Unavailable.*` (assert distinct terminal copy from `strings.xml`). Expected: correct widgets/text; download button disabled when `requiresPassword && password.isBlank()`. Traces: AC-2, AC-4, AC-6.

- **TC-AND-335-12 — Accessibility checks (Compose-UI/instrumented).** Type: Compose-UI + a11y (EMU35). Target: both screens. Preconditions: TalkBack/`AccessibilityChecks` enabled. Steps: run the framework a11y assertions; verify Create/Copy/Revoke/Download have `contentDescription`/semantics; progress exposes `progressSemantics`; touch targets ≥48dp; verify focus order (file name → metadata → password → download) and render at 200% font scale + RTL. Expected: no a11y violations; labeled icon-only buttons. Traces: AC-2, AC-4, AC-5 (a11y aspect; spec §9).

- **TC-AND-335-13 — Real public download to Downloads + flaky/offline host (instrumented, MUST run on DEV-A15).** Type: instrumented/e2e (DEV-A15 — physical device REQUIRED). Target: `ShareDownloader` streamed OkHttp write to `MediaStore.Downloads`. Preconditions: a valid no-password link resolvable against the dev host (or a local stub). Steps: tap Download; observe progress; verify the file lands in the device Downloads with correct name/MIME and opens; then toggle airplane mode mid-resolve and on download start to exercise the ~20s-timeout/offline path. Expected: completed download is visible in the system Downloads UI and openable (real `MediaStore` behavior, which differs from emulator); offline shows the offline/retry state and partial files are cleaned up. Rationale for DEV-A15: real shared-storage/MediaStore and real-network timeout behavior, plus arm64/API-34 path. Traces: AC-5, AC-6.

- **TC-AND-335-14 — E2E fail-closed after revoke (e2e).** Type: instrumented/e2e (DEV-A15 preferred; EMU35 acceptable if device busy). Target: full flow. Preconditions: authenticated owner session. Steps: create a link (owner) → open it on the public screen and download (no session) → revoke (owner) → re-open the public link. Expected: post-revoke, `/info` returns `is_revoked=true` → `Unavailable.Revoked` and any download attempt returns `410`; no logged-in session/cookie ever attaches to the public calls (verify via proxy/log). Traces: AC-1, AC-3, AC-5, AC-6, AC-7.

### Coverage matrix

| AC | Covered by |
| --- | --- |
| AC-1 (create + copyable URL) | TC-01, TC-08, TC-14 |
| AC-2 (list + optimistic revoke) | TC-02, TC-03, TC-08, TC-11 |
| AC-3 (public resolve, no session, deep link cold/warm) | TC-04, TC-09, TC-10, TC-14 |
| AC-4 (password gate, generic wrong-password error) | TC-06, TC-09, TC-11 |
| AC-5 (download with progress/completion) | TC-06, TC-12, TC-13, TC-14 |
| AC-6 (expired/revoked/exhausted terminal + fail-closed) | TC-05, TC-06, TC-09, TC-11, TC-13, TC-14 |
| AC-7 (DTO/error mapping; no cookie/CSRF/Bearer on public) | TC-01, TC-02, TC-03, TC-04, TC-07, TC-14 |
