---
id: AND-335
title: Share links (+ public download)
milestone: M7
epic: E43
priority: P1
size: M
status: draft
depends_on: [AND-331, AND-022]
blocks: []
---

# AND-335 — Share links (+ public download)

## 1. Overview & Goal

Provide the ability to create and revoke shareable links for files in TestLogon, and to open a public, **unauthenticated** download page for a shared file via a deep-linkable route (`/share/:linkId`). This ticket ports the web reference behavior in `frontend/src/api/endpoints/fileShareLinks.ts` to native Android.

Two distinct surfaces are in scope:

1. **Authenticated owner flow** — from a file's detail/row UI an authenticated user creates a share link (optionally with expiry/password/download-limit), sees existing links, copies the link URL, and revokes a link. This runs through the cookie-based session established in earlier auth tickets.
2. **Public consumer flow** — anyone opening `https://<host>/share/<linkId>` (or the app's deep link) lands on a public screen that resolves link metadata and downloads the underlying file **without** a logged-in session. The public endpoints accept the link token only; no `ui_csrf` cookie or `/ui/me` session is assumed.

The deliverable is a self-contained `feature-share` module plus the `FileShareLinksApi` Retrofit service and DTOs in `core-network`/`core-model`, wired into the typed `NavHost` from AND-022. Goal: a creator can mint a link, hand it off, and a recipient with no account can download the file; revoking the link makes the public page fail closed.

## 2. Context & References

- **Web reference:** `frontend/src/api/endpoints/fileShareLinks.ts` (create/list/revoke + public resolve/download), shared types in `frontend/src/api/types.ts`.
- **Backend:** FastAPI + DynamoDB; OpenAPI at `/openapi.json`. Dev host `http://18.222.237.167:8000` is plaintext HTTP and unreliable — design for ~20s timeouts, bounded retry for idempotent GETs only, offline/stale states.
- **Dependencies:**
  - **AND-331 (Files API + DTOs, P0):** provides `FilesApi`, `FileDto`, and the `core-model` file identity (`fileId`) this ticket links against. Share creation references a `fileId` produced by AND-331.
  - **AND-022 (Navigation host & routes, P0):** provides the single-Activity typed `NavHost`. This ticket registers the `Share` (owner sheet) and `PublicShare` (deep-link) destinations.
- **Auth model:** Owner endpoints ride the cookie session + `X-CSRF-Token` header (see auth tickets); on 401 the network layer calls `POST /ui/session/refresh` once then retries. **Public endpoints are exempt** and must run on a cookie/CSRF-free request path.
- **Package base:** `com.testlogon.android` (namespace `com.testlogon.android.feature.share`, `com.testlogon.android.core.*`).

## 3. Functional Requirements

FR-1. **Create link.** From a file UI affordance, the user opens a "Share" bottom sheet. They may optionally set: expiry (none / 1h / 24h / 7d / custom timestamp), a password, and a max-download count. Submitting calls create and shows the resulting absolute URL.

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

```kotlin
interface FileShareLinksApi {
    @GET("files/{fileId}/share-links")
    suspend fun list(@Path("fileId") fileId: String): Response<ShareLinkListDto>

    @POST("files/{fileId}/share-links")
    suspend fun create(
        @Path("fileId") fileId: String,
        @Body body: CreateShareLinkRequest,
    ): Response<ShareLinkDto>

    @DELETE("files/{fileId}/share-links/{linkId}")
    suspend fun revoke(
        @Path("fileId") fileId: String,
        @Path("linkId") linkId: String,
    ): Response<Unit>

    // Public, session-free. Tagged so the auth/CSRF interceptors skip it.
    @GET("share/{linkId}")
    @Tag(PublicRequest::class) // or @Headers("X-TL-Public: 1")
    suspend fun resolvePublic(
        @Path("linkId") linkId: String,
        @Header("X-Share-Password") password: String?,
    ): Response<PublicShareDto>
}
```

**Public download URL.** Resolve returns a `downloadUrl` (absolute) which the public screen passes to a `core-data` `ShareDownloader` wrapping Android `DownloadManager`. The download request must **not** carry session cookies; it uses a separate, cookie-jar-free request (or an unauthenticated `DownloadManager.Request`).

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

Base path under the FastAPI host. Owner endpoints require the cookie session + `X-CSRF-Token`; public endpoints do not.

**Create** — `POST /files/{fileId}/share-links`
Request:
```json
{ "expires_at": "2026-06-12T00:00:00Z", "password": "hunter2", "max_downloads": 50 }
```
All fields optional/nullable. Response `201`:
```json
{
  "link_id": "lk_8fa3...",
  "file_id": "f_123",
  "url": "http://18.222.237.167:8000/share/lk_8fa3...",
  "expires_at": "2026-06-12T00:00:00Z",
  "password_protected": true,
  "max_downloads": 50,
  "download_count": 0,
  "revoked": false,
  "created_at": "2026-06-05T10:00:00Z"
}
```

**List** — `GET /files/{fileId}/share-links` → `200 { "items": [ShareLinkDto, ...] }`.

**Revoke** — `DELETE /files/{fileId}/share-links/{linkId}` → `204` (or `200 {}`).

**Public resolve** — `GET /share/{linkId}` (optional `X-Share-Password` header) → `200`:
```json
{
  "link_id": "lk_8fa3...",
  "file_name": "report.pdf",
  "size_bytes": 482133,
  "mime_type": "application/pdf",
  "expires_at": "2026-06-12T00:00:00Z",
  "password_required": true,
  "password_ok": true,
  "download_url": "http://18.222.237.167:8000/share/lk_8fa3.../download"
}
```
Terminal/error responses (FastAPI `detail`):
- `401` `{ "detail": "invalid_password" }` — wrong/missing password.
- `404` `{ "detail": "not_found" }` — unknown or revoked link.
- `410` `{ "detail": "expired" }` or `{ "detail": "download_limit_reached" }`.

**Public download** — `GET /share/{linkId}/download` (header `X-Share-Password` when required) streams bytes (`Content-Disposition`, `Content-Type`). Handled by `DownloadManager`, not Retrofit.

DTO field names not confirmed against OpenAPI are treated as the contract of record here; reconcile against `/openapi.json` and `fileShareLinks.ts` during implementation, keep Moshi `@Json(name=...)` mappings centralized.

## 6. Data & State Management

Domain models in `core-model`:

```kotlin
data class ShareLink(
    val linkId: String, val fileId: String, val url: String,
    val expiresAt: Instant?, val passwordProtected: Boolean,
    val maxDownloads: Int?, val downloadCount: Int, val revoked: Boolean,
)
data class ShareLinkOptions(val expiresAt: Instant?, val password: String?, val maxDownloads: Int?)
data class PublicShare(
    val linkId: String, val fileName: String, val sizeBytes: Long,
    val mimeType: String, val expiresAt: Instant?, val passwordRequired: Boolean,
    val downloadUrl: String,
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
- **401 on owner endpoints** triggers the single `POST /ui/session/refresh` + retry in the network layer (existing behavior); public endpoints never hit this path.
- **Public terminal mapping:** `404 → Unavailable.Revoked` (link gone), `410 expired → Unavailable.Expired`, `410 download_limit_reached → Unavailable.Exhausted`, `401 invalid_password → PasswordRequired(attemptError)`, network/timeout → `Unavailable.Generic` with retry.
- **Download failures** (DownloadManager `STATUS_FAILED`, no network, insufficient storage) show a snackbar with retry; partial downloads are cleaned up.
- **Optimistic revoke** rolls back (re-inserts the row) if the DELETE fails.
- **Offline:** owner sheet shows a stale/offline banner; public screen shows offline state with retry.

## 8. Security & Privacy

- Public endpoints must execute on a **session-free request path**: a dedicated OkHttp call (or `@Tag(PublicRequest::class)`) that bypasses the persistent cookie jar and the CSRF interceptor, so a logged-in user's session never leaks into a public download and the flow works for unauthenticated recipients.
- `linkId` is an unguessable, capability-bearing token: never logged in full (log a redacted prefix only), never echoed into telemetry, never placed in a screenshot-eligible widget without care.
- Entered link passwords are kept in memory only (`SavedStateHandle`), sent via the `X-Share-Password` header, and never persisted. Password fields use `PasswordVisualTransformation` and `KeyboardType.Password`.
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

- **DTO mapping (unit):** `ShareLinkDto`/`PublicShareDto` ↔ domain round-trips, including null expiry, `password_required` true/false, and each `detail` error shape — mirrors the AND-331 "payloads map (tested)" standard.
- **Repository (unit):** MockWebServer drives create (201), list, revoke (204), and public resolve for `200/401/404/410(expired)/410(limit)`; assert correct `ApiResult`/`UnavailableReason` mapping and that the public call carries **no** cookie/CSRF headers and the owner calls **do**.
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

- **OpenAPI field names unverified.** Exact paths/fields for share links (`expires_at` vs `ttl`, `max_downloads` vs `download_limit`, response envelope `items` vs bare array) must be confirmed against `/openapi.json` and `fileShareLinks.ts`. Risk: rework of Moshi mappings (contained to DTO layer).
- **Public auth bypass.** Whether the backend truly serves `/share/{linkId}` without any cookie is an assumption; if it still expects some token cookie, the session-free path needs adjustment.
- **Download authorization.** Does `download_url` embed the link token (self-authorizing) or rely on the header? Affects whether `DownloadManager` (which can't easily add per-request headers in all OS versions) is viable vs. a streamed OkHttp download. Open question to resolve before implementing FR-7.
- **App Links verification** requires a `assetlinks.json` on the production host; dev plaintext host cannot autoVerify. Tracked as a deployment dependency.
- **Password transport over plaintext dev HTTP** is insecure by nature of the dev environment; acceptable for dev only.

## 14. Acceptance Criteria

AC-1. An authenticated user can create a share link for a file; the returned absolute URL is displayed and copyable. *(Backlog: "Share link works.")*
AC-2. The share sheet lists existing links with expiry and download-count, and revoke removes a link (optimistic, rolled back on failure).
AC-3. Opening `/share/:linkId` (deep link, cold and warm start) renders `PublicShareScreen` resolving metadata **without** an authenticated session.
AC-4. A password-protected link prompts for the password and rejects wrong passwords with a generic error; a correct password enables download.
AC-5. The public page downloads the file to the device, showing progress and completion. *(Backlog: "public page downloads.")*
AC-6. Expired, revoked, and download-limit-exhausted links each render a distinct terminal state; a revoked link's public page fails closed (404/410).
AC-7. DTO/error mapping is covered by passing unit tests; public requests carry no session cookie/CSRF header (asserted in test).

## 15. Definition of Done

- `:feature:share` module + `FileShareLinksApi`/DTOs/domain models merged on `android-port`, namespaced `com.testlogon.android.*`.
- Owner share sheet (create/list/copy/revoke) and `PublicShareScreen` (resolve/password/download/terminal states) implemented per FRs.
- `Share`/`PublicShare` routes and `https`/`testlogon` deep links registered in the AND-022 NavHost and manifest; cold-start deep link verified.
- Unit + ViewModel + Compose + deep-link instrumented tests pass in CI; E2E happy path (create → public download → revoke → fail-closed) green.
- No hardcoded strings; a11y semantics and 200%/RTL checks pass; no PII/tokens/passwords in logs (verified).
- Code review approved; OpenAPI/`fileShareLinks.ts` field reconciliation completed or open questions explicitly ticketed.
