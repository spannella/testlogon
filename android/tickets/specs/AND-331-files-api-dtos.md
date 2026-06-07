---
id: AND-331
title: Files API + DTOs
milestone: M7
epic: E43
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-027]
blocks: [AND-332, AND-333]
---

> **REVIEW NOTE (2026-06-06):** This spec was drafted against an assumed
> `/ui/files/*`, ID-addressed, cursor-paginated REST surface. The authoritative
> sources (OpenAPI index + `frontend/src/api/endpoints/files.ts` /
> `types.ts`) show the real contract is **`/v1/fs/*`, path-addressed** (every
> node is identified by its `path` string, not an opaque `id`), with verbs and
> field names that differ substantially. All affected sections have been
> corrected inline; see §16 for the full audit and §17 for the test plan.

# AND-331 — Files API + DTOs

## 1. Overview & Goal

This ticket delivers the data-layer contract for the TestLogon file manager on
Android: a Retrofit `FilesApi` interface plus the Moshi DTOs that model the
backend's file/folder browse, CRUD, and search payloads. It is a pure
network/serialization slice — no UI, no ViewModel, no repository business logic.
The deliverable is a typed, tested mapping between the FastAPI `/v1/fs/*`
endpoints (mirrored from the web reference `src/api/endpoints/files.ts`)
and Kotlin DTOs/domain models, exposed through the project's `ApiResult<T>`
envelope.

> CORRECTION: the endpoints live under **`/v1/fs/*`**, not `/ui/files/*`. There
> is no `/ui/files` namespace in the backend (verified against OpenAPI index;
> the only `/ui/files/*` paths are `share-links` CRUD, unrelated to browse/CRUD).
> Nodes are addressed by **`path`** (a string like `/docs/a.txt`), not by an
> opaque `id`. (Source: `src/api/endpoints/files.ts`; OpenAPI `GET /v1/fs/list`.)

The single acceptance bar from the backlog is: **file payloads map (tested)** —
every documented request/response JSON shape round-trips through Moshi without
loss, and every endpoint is callable with the correct path, verb, body, query
params, and headers, verified against `MockWebServer`.

Goal in one sentence: ship `FilesApi` + `*Dto` + DTO→domain mappers in
`core-network` / `core-model` so that AND-332 (browse) and AND-333 (upload) can
build features on a stable, verified contract.

## 2. Context & References

- **Module placement:** Retrofit interface and DTOs land in `core-network`
  (package `com.testlogon.android.core.network.files`); domain models in
  `core-model` (`com.testlogon.android.core.model.files`); mappers in
  `core-network` adjacent to the DTOs. Layering rule `app -> feature-* -> core-*`
  is respected; nothing here depends on a feature module.
- **Web reference:** `src/api/endpoints/files.ts` (endpoint set, query
  params, verbs) and `src/api/types.ts` (field names, optionality).
  These are the source of truth for naming; field nullability is confirmed
  against the bundled `reference/openapi.pretty.json`.
  > CORRECTION: the real surface is path-addressed. Browse is
  > `GET /v1/fs/list?path=&limit=&cursor=&sort_by=&sort_dir=`; single node is
  > `GET /v1/fs/info?path=`; filename search is `GET /v1/fs/search?prefix=&limit=`
  > and full-text is `GET /v1/fs/search-text?q=&limit=`. There is no
  > `folder_id`, `id`, `node_type`, `sort`/`order`, or `q`-on-search param.
- **Dependency AND-027 (AuthApi):** establishes the shared Retrofit/OkHttp stack
  — persistent cookie jar, the `Authorization: Bearer <accessToken>` header,
  `X-CSRF-Token` echo interceptor, single 401 → `POST /ui/session/refresh` →
  retry behavior, and the `ApiResult<T>` + FastAPI `detail` error mapping.
  `FilesApi` reuses that exact `Retrofit` instance and `Moshi` builder; this
  ticket adds no new client wiring.
  > CORRECTION: the web client (`src/api/client.ts`) sends **both** an
  > `Authorization: Bearer` header (from the auth store) **and** the
  > `X-CSRF-Token` header read from the `ui_csrf` cookie, and it sets
  > `X-CSRF-Token` on **every** request (GET included), not only mutations —
  > the server simply ignores it on safe verbs. The Android stack should follow
  > the same "always attach if present" rule via interceptor. Cookie auth alone
  > is therefore not the whole story; the Bearer token is the primary
  > credential. (Source: `src/api/client.ts` lines 156-171.) The OpenAPI also
  > documents an alternative `X-API-Key` param on some `/v1/fs/*` routes
  > (`list`, `folder`, `upload`); the web app does not use it — treat it as an
  > unverified server-to-server affordance, not part of this client contract.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). All file metadata calls are cookie-authenticated
  and CSRF-protected for mutating verbs.
- **Downstream:** AND-332 consumes browse/search; AND-333 consumes the presign
  upload DTOs and the create/move endpoints for folder placement.

## 3. Functional Requirements

FR-1. Expose a `FilesApi` Retrofit interface covering the file-manager surface.
The verified endpoint set (all path-addressed, under `/v1/fs/*`):
`list` (browse), `info` (single node), `search` (filename prefix), `searchText`
(full-text), `createFolder`, `renameFile`, `renameFolder`, `move`, `deleteFile`,
`deleteFolder`, `presignUpload`, and `completeUpload`.
> CORRECTION: rename and move are **separate POST endpoints with bodies**, not
> a PATCH/`{id}/move`. Rename is split into `rename-file` vs `rename-folder`
> (web has both). There is **no batch delete**; delete is per-path and split
> into `deleteFile` (`DELETE /v1/fs/file?path=`) and `deleteFolder`
> (`DELETE /v1/fs/folder?path=`). The "finalize" step is `complete-upload`.
> (Source: `src/api/endpoints/files.ts`; OpenAPI `/v1/fs/*` index.)

FR-2. Provide Moshi DTOs for every request body and response shape, with
`@Json(name=...)` on any field whose JSON key differs from idiomatic Kotlin
camelCase, matching `src/api/types.ts` (`FileEntry`, `FileListResp`).

FR-3. Provide pure DTO→domain mappers (`FileEntryDto.toDomain(): FileNode`, etc.)
so feature modules never touch DTOs directly. Unknown/forward-compatible enum
values (e.g. a new `type` discriminator) map to a safe `UNKNOWN` variant rather
than throwing.

FR-4. Browse returns a paginated response compatible with Paging 3; the DTO
must surface the continuation token so AND-332 can wire a `PagingSource`.
> CORRECTION: the browse response is `FileListResp = { path, items, cursor? }`
> — the continuation field is **`cursor`** (optional), there is **no
> `next_cursor` and no `total_count`**. Search (`/v1/fs/search`,
> `/v1/fs/search-text`) is **not paginated**: it returns
> `{ prefix|query, results: FileEntry[] }` bounded by a `limit` (default 50),
> with no cursor. AND-332 should treat search as a single-shot bounded list.
> (Source: `src/api/types.ts: FileListResp`; `src/api/endpoints/files.ts:
> searchFiles/searchText`.)

FR-5. All methods are `suspend` and return either the raw deserialized type or a
`Response<T>`; the calling layer wraps them in `ApiResult<T>`. Mutating calls
(POST/PATCH/DELETE) rely on the shared CSRF interceptor — no per-call header is
declared in the interface.

FR-6. Idempotent GETs (`browse`, `get node`, `search`) are eligible for the
shared bounded-backoff retry; mutating verbs are not.

This ticket explicitly does **not** implement: UI, repositories with caching,
the actual byte upload to the presigned URL (AND-333 owns the PUT-to-storage and
progress), or Room persistence of file metadata.

## 4. Technical Design

Package: `com.testlogon.android.core.network.files`.

> CORRECTION: the entire interface below was rewritten to match the verified
> `/v1/fs/*` contract. Nodes are addressed by a `path` query/body param, not a
> path-segment `{id}`. Relative Retrofit paths must NOT have a leading slash
> (`"v1/fs/list"`), since the base URL ends in `/`.

```kotlin
interface FilesApi {

    // Browse a folder. path defaults to "/" (root). Paginated via `cursor`.
    @GET("v1/fs/list")
    suspend fun list(
        @Query("path") path: String = "/",
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
        @Query("sort_by") sortBy: String? = null,    // e.g. "name" | "size" | "modified"
        @Query("sort_dir") sortDir: String? = null,  // "asc" | "desc"
    ): FileListDto

    // Single node metadata.
    @GET("v1/fs/info")
    suspend fun info(@Query("path") path: String): FileEntryDto

    // Filename prefix search (NOT paginated; bounded by limit).
    @GET("v1/fs/search")
    suspend fun search(
        @Query("prefix") prefix: String,
        @Query("limit") limit: Int = 50,
    ): FileSearchDto            // { prefix, results: [FileEntry] }

    // Full-text content search (NOT paginated).
    @GET("v1/fs/search-text")
    suspend fun searchText(
        @Query("q") query: String,
        @Query("limit") limit: Int = 50,
    ): FileTextSearchDto        // { query, results: [FileEntry] }

    @POST("v1/fs/folder")
    suspend fun createFolder(@Body body: CreateFolderRequest): OkRespDto   // { path }

    @POST("v1/fs/rename-file")
    suspend fun renameFile(@Body body: RenameRequest): MoveResultDto       // { path, new_name }

    @POST("v1/fs/rename-folder")
    suspend fun renameFolder(@Body body: RenameRequest): MoveResultDto     // { path, new_name }

    @POST("v1/fs/move")
    suspend fun move(@Body body: MoveRequest): MoveResultDto               // { src, dst }

    // Delete is per-path with a query param + body-less DELETE.
    @DELETE("v1/fs/file")
    suspend fun deleteFile(@Query("path") path: String): OkRespDto

    @DELETE("v1/fs/folder")
    suspend fun deleteFolder(@Query("path") path: String): DeleteFolderDto // { ok, deleted_count }

    @POST("v1/fs/presign-upload")
    suspend fun presignUpload(@Body body: PresignRequest): PresignResponse

    @POST("v1/fs/complete-upload")
    suspend fun completeUpload(@Body body: CompleteUploadRequest): FileEntryDto
}
```

Request bodies (all snake_case on the wire, matching the OpenAPI `Body_*`
schemas):

```kotlin
data class CreateFolderRequest(val path: String)
data class RenameRequest(val path: String, @Json(name = "new_name") val newName: String)
data class MoveRequest(val src: String, val dst: String)
data class PresignRequest(
    val path: String,
    @Json(name = "content_type") val contentType: String? = null,
)
data class CompleteUploadRequest(
    val path: String,
    val key: String,
    @Json(name = "ticket_id") val ticketId: String,
    @Json(name = "content_type") val contentType: String? = null,
    val encrypted: Boolean = false,
    @Json(name = "enc_meta") val encMeta: Map<String, Any?>? = null,
)
```

Domain model (`com.testlogon.android.core.model.files`):

> CORRECTION: there is no `id`, `parent_id`, `owner_id`, `mime_type`, or
> `download_url` on the wire node. The real `FileEntry` keys are `name`, `path`,
> `type` ("file"|"folder"), `size`, `content_type`, `updated_at`, `created_at`,
> plus a large set of encryption (`enc_*`) and preview (`preview_*`) fields. The
> stable node identifier is `path`. Download/preview URLs are constructed
> client-side (e.g. `/v1/fs/download?path=...`), not returned in the node.

```kotlin
enum class FileNodeType { FILE, FOLDER, UNKNOWN }

data class FileNode(
    val path: String,            // stable identifier
    val name: String,
    val type: FileNodeType,
    val sizeBytes: Long?,        // null/absent for folders ("size")
    val contentType: String?,    // "content_type"
    val updatedAt: Instant?,     // "updated_at" (optional on wire)
    val createdAt: Instant?,     // "created_at" (optional on wire)
    val isEncrypted: Boolean,    // "is_encrypted"
    // Preview affordances (optional, forwarded for AND-332):
    val previewKind: String?,    // "preview_kind"
    val posterUrl: String?,      // "poster_url"
)

data class FilePage(
    val path: String,            // echoed folder path
    val items: List<FileNode>,
    val cursor: String?,         // null/absent = last page
)
```

Mappers are top-level extension functions in `FileDtoMappers.kt`:

```kotlin
internal fun FileEntryDto.toDomain(): FileNode
internal fun FileListDto.toDomain(): FilePage
internal fun String?.toFileNodeType(): FileNodeType =
    when (this?.lowercase()) {
        "file" -> FileNodeType.FILE
        "folder" -> FileNodeType.FOLDER   // backend uses "folder"; not "directory"
        else -> FileNodeType.UNKNOWN
    }
```

Timestamps are parsed from optional ISO-8601 strings via a shared `Instant`
Moshi adapter (reused from the `core-network` adapter set established under
AND-027); the DTO holds the raw nullable `String` and the mapper converts. A
malformed (non-null) timestamp degrades to a mapper-level failure rather than a
deserialization crash; an absent timestamp maps to `null`.

DI: a `@Provides fun provideFilesApi(retrofit: Retrofit): FilesApi =
retrofit.create(FilesApi::class.java)` is added to the existing
`NetworkModule` (`@InstallIn(SingletonComponent::class)`), reusing the
authenticated `Retrofit` from AND-027.

## 5. API Contract

Base URL: `http://18.222.237.167:8000/`. All calls send the session cookies, the
`Authorization: Bearer` header, and the `X-CSRF-Token` header (on every request
when the `ui_csrf` cookie is present) via shared interceptors.

> CORRECTION: every shape in this section was wrong in the original draft. The
> verified contract follows. Wire bodies use snake_case; success bodies are
> small `{ ok, ... }` envelopes (FastAPI `OkResp`), not the full node — except
> `info` and `complete-upload`, which return a `FileEntry`.

**GET `/v1/fs/list?path=/&limit=50&cursor=&sort_by=name&sort_dir=asc`** →
`FileListResp`:

```json
{
  "path": "/",
  "items": [
    {
      "name": "report.pdf",
      "path": "/report.pdf",
      "type": "file",
      "size": 184320,
      "content_type": "application/pdf",
      "updated_at": "2026-05-30T12:04:11Z",
      "created_at": "2026-05-29T09:00:00Z",
      "is_encrypted": false,
      "preview_kind": "pdf",
      "preview_status": "ready"
    }
  ],
  "cursor": "eyJrIjoi..."
}
```
Note: `cursor` is **omitted** on the last page (not `null` by contract, though
the DTO should tolerate both absent and null). There is no `total_count`.

**GET `/v1/fs/info?path=/report.pdf`** → single `FileEntry` (same node shape).

**GET `/v1/fs/search?prefix=invoice&limit=50`** → `{ "prefix": "invoice",
"results": [FileEntry] }` (not paginated).

**GET `/v1/fs/search-text?q=invoice&limit=50`** → `{ "query": "invoice",
"results": [FileEntry] }` (not paginated).

**POST `/v1/fs/folder`** body `{ "path": "/Q2" }` → `OkResp` (e.g. `{ "ok":
true, ... }`). The new folder's path is the one you sent.

**POST `/v1/fs/rename-file`** body `{ "path": "/old.pdf", "new_name":
"new.pdf" }` → `{ "ok": true, "src": "/old.pdf", "dst": "/new.pdf" }`.

**POST `/v1/fs/rename-folder`** body `{ "path": "/Old", "new_name": "New" }` →
`{ "ok": true, "src": "/Old", "dst": "/New" }`.

**POST `/v1/fs/move`** body `{ "src": "/a.pdf", "dst": "/archive/a.pdf" }` →
`{ "ok": true, "src": "/a.pdf", "dst": "/archive/a.pdf" }`.

**DELETE `/v1/fs/file?path=/a.pdf`** → `OkResp` (`{ "ok": true }`). No request
body; the path is a query param.

**DELETE `/v1/fs/folder?path=/Old`** → `{ "ok": true, "deleted_count": N }`.

**POST `/v1/fs/presign-upload`** body `PresignUploadIn`
`{ "path": "/clip.mp4", "content_type": "video/mp4" }` → `PresignUploadOut`:

```json
{
  "upload_url": "https://storage.../put?sig=...",
  "bucket": "tl-fs",
  "key": "u/123/clip.mp4",
  "ticket_id": "tkt_01HX...",
  "path": "/clip.mp4",
  "content_type": "video/mp4"
}
```
All six fields are required. There is no `method`, `headers`, `expires_at`, or
`upload_id` — the PUT is implicitly `Content-Type: <content_type>` (the byte PUT
itself is **out of scope**, AND-333).

**POST `/v1/fs/complete-upload`** body `CompleteUploadIn`
`{ "path": "/clip.mp4", "key": "u/123/clip.mp4", "ticket_id": "tkt_01HX...",
"content_type": "video/mp4", "encrypted": false, "enc_meta": null }` →
`{ "ok": true, "path": "/clip.mp4", "size": 10485760, "content_type":
"video/mp4" }` (`size` may be `null`). Required body fields: `path`, `key`,
`ticket_id`.

DTOs mirror these keys exactly (e.g. `@Json(name = "content_type") val
contentType: String?`, `@Json(name = "is_encrypted") val isEncrypted: Boolean?`).

## 6. Data & State Management

This ticket introduces no persistent state — no Room entities, no DataStore keys,
no StateFlow. It produces immutable DTOs and domain models only. Pagination state
(`cursor`) is surfaced through `FilePage.cursor` for AND-332's
`PagingSource` to manage (browse only; search is single-shot). Caching of file metadata in Room is deferred to the
file-manager feature ticket (AND-332) and is not specified here. The mappers are
pure functions with no side effects, which is what makes them unit-testable in
`core-testing` without a dispatcher or coroutine scope.

## 7. Error Handling & Resilience

- Calls return raw types; the repository layer (AND-332/333) wraps invocations in
  the shared `apiCall { }` helper producing `ApiResult<T>` (`Success`,
  `Error(code, message)`, `NetworkError`, `Unauthorized`).
- **FastAPI `detail` mapping** is reused verbatim from AND-027: `detail` may be a
  string, a list of `{msg}` validation objects, or a `{code, ...}` object; the
  shared `ErrorBodyParser` normalizes all three. This ticket adds no new parser,
  only confirms file endpoints route through it.
- **Timeouts:** the shared OkHttp client uses ~20s call timeout for the unreliable
  dev host. list/info/search/searchText (idempotent GETs) participate in the shared
  bounded-backoff retry (e.g. 2 retries, jittered); all mutating verbs and the
  presign/complete-upload POSTs do **not** retry to avoid duplicate folders/moves.
- **401 handling:** the shared authenticator performs a single
  `POST /ui/session/refresh` then one retry; on repeated 401 the call surfaces
  `ApiResult.Unauthorized`. No file-specific logic.
- **422 (validation):** FastAPI returns `HTTPValidationError =
  { detail: [ { loc, msg, type } ] }` for malformed query params/bodies (e.g.
  missing `path`). This is the canonical error shape for `/v1/fs/*` (every
  endpoint lists `422:HTTPValidationError`). The shared `ErrorBodyParser` reads
  the list-form `detail` and joins the `msg` strings, matching the web client's
  `normalizeErrorDetail`.
- **404/409:** `info`/`rename*`/`move`/`delete*` on a missing or conflicting
  path return the FastAPI error body, mapped to `ApiResult.Error` with the
  server `detail`. These are not retried.
- **Mapper robustness:** unknown `type` → `FileNodeType.UNKNOWN`; absent/null
  `size` on folders is expected and allowed; absent `updated_at`/`created_at` map
  to `null`; a malformed (non-null) timestamp throws inside the mapper and is
  caught by `apiCall` as a parse error rather than crashing.

## 8. Security & Privacy

- All endpoints are cookie-authenticated; the persistent cookie jar and CSRF
  echo (`ui_csrf` cookie → `X-CSRF-Token` header) from AND-027 are mandatory for
  mutating verbs. The `FilesApi` interface deliberately declares no `@Header`,
  delegating to interceptors so credentials are never hand-assembled per call.
- The presign `upload_url` (and the client-constructed `download`/`preview`/
  `thumbnail` URLs) are short-lived/signed; DTOs must not be logged at body level
  (see §10) and these URLs must never be persisted to disk or DataStore in this
  layer. (Note: the node DTO itself carries no `download_url`; download URLs are
  derived from `path` at the feature layer.)
- The dev host is plaintext HTTP; the network security config (owned by the build
  baseline) permits cleartext only for the dev host. No file payloads are cached
  by this ticket, so no at-rest exposure is introduced here.
- No PII beyond `owner_id` (an opaque id) and user-chosen file names is handled;
  file names are user content and are not sanitized client-side beyond
  trim/empty validation deferred to the feature layer.

## 9. Accessibility & i18n

Not applicable at this layer — there is no UI. Two forward-looking constraints:
(1) DTOs carry server-provided strings (file names, MIME types) verbatim and do
not embed any user-facing English copy, so localization remains a feature-layer
concern (AND-332); (2) `size` is exposed as a raw `Long` (mapped to
`FileNode.sizeBytes`) so the feature
layer can format with a locale-aware formatter rather than receiving
pre-formatted text. Any error copy shown to users is produced from `ApiResult`
mapping in the feature module, not here.

## 10. Telemetry & Logging

- Reuse the shared OkHttp `HttpLoggingInterceptor` configured at `BASIC` in
  release and `HEADERS` in debug; **never `BODY`** for file endpoints, to avoid
  logging signed presign/derived URLs and file paths/names.
- Add lightweight breadcrumbs via the shared telemetry facade (no new
  dependency): event names `files.list`, `files.info`, `files.search`,
  `files.search_text`, `files.create_folder`, `files.rename_file`,
  `files.rename_folder`, `files.move`, `files.delete_file`,
  `files.delete_folder`, `files.presign`, `files.complete_upload`, each tagged
  with outcome (`success`/`error`) and HTTP status bucket — never the file
  path/name or URL.
- Mapper failures emit a `files.map_error` event with the DTO field that failed
  (field name only, no value) to aid contract-drift diagnosis.

## 11. Testing Strategy

This is the acceptance core — "file payloads map (tested)".

- **Moshi round-trip unit tests** (`core-testing`, JVM, no Android): for each DTO,
  load a canonical JSON fixture (captured from `reference/openapi.pretty.json`
  examples or the web reference), deserialize, assert all fields, re-serialize,
  and assert key equality. Cover null/absent cases: folder with absent `size`/
  `content_type`, list response with **omitted** `cursor` (last page), node with
  absent `updated_at`/`created_at`, `complete-upload` with `size: null`.
- **Mapper unit tests:** `FileEntryDto.toDomain()` for file vs folder; unknown
  `type` → `UNKNOWN`; timestamp parsing (present, absent → null);
  `FileListDto.toDomain()` empty list and populated list.
- **`MockWebServer` contract tests** (mirrors AND-027 style): enqueue fixture
  responses and assert each `FilesApi` method issues the correct path, query
  string, HTTP verb, and request body JSON. Specifically verify `deleteFile`/
  `deleteFolder` issue a body-less `DELETE` with the `path` query param, `move`
  POSTs `{src,dst}` to `/v1/fs/move`, `renameFile`/`renameFolder` POST `{path,
  new_name}`, and `presignUpload`/`completeUpload` POST their snake_case bodies.
  Assert the `Authorization: Bearer` and `X-CSRF-Token` headers are present on
  every request when configured (interceptor integration).
- **Error-path tests:** enqueue a 422 with a list-form `HTTPValidationError`
  `detail`, plus 401, 404, and 409; assert the shared parser yields the expected
  `ApiResult.Error`/`Unauthorized`.
- **Idempotent retry test:** enqueue one 503 then a 200 for `list`; assert it
  retries and succeeds. Enqueue a 503 for `createFolder`; assert it does **not**
  retry.
- Target: 100% of DTO fields exercised; all twelve endpoints covered by at least
  one MockWebServer test. No instrumented (device) tests required for this slice.

## 12. Dependencies & Sequencing

- **Depends on AND-027** (AuthApi/session endpoints): supplies the authenticated
  `Retrofit`, cookie jar, CSRF interceptor, `Instant` Moshi adapter, `ApiResult`,
  and FastAPI `detail` parser. This ticket must not re-implement any of those.
- **Blocks AND-332** (File manager browse — consumes `list`/`search`/`searchText`
  + `FilePage` pagination) and **AND-333** (Upload via presign — consumes
  `presignUpload`/`completeUpload` + `createFolder`/`move` for folder placement).
- Sequencing: land DTOs + mappers + tests first, then the `FilesApi` interface +
  MockWebServer tests, then wire the `@Provides` into `NetworkModule`. No build
  baseline changes beyond Hilt module edits.

## 13. Risks & Open Questions

- **Contract drift vs. web reference:** field names/optionality in
  `src/api/types.ts` may lag the live backend. Mitigation: capture fixtures from
  `reference/openapi.pretty.json` and treat OpenAPI as tiebreaker. RESOLVED for
  this slice — the bundled OpenAPI and the web reference agree on all `/v1/fs/*`
  shapes used here.
- **Pagination shape:** RESOLVED — browse (`/v1/fs/list`) is cursor-paginated
  via an optional `cursor` field (omitted on last page); there is no
  `total_count`. Search is **not** paginated (single bounded `results` list).
  `FilePage.cursor` is the continuation token for AND-332.
- **Delete shape:** RESOLVED — there is no batch delete and no DELETE-with-body.
  Delete is per-path via a body-less `DELETE /v1/fs/{file,folder}?path=`. AND-332
  must loop for multi-select delete (no atomic batch endpoint exists).
- **Presign host/headers:** RESOLVED for the DTO — `PresignUploadOut` carries
  `upload_url`, `bucket`, `key`, `ticket_id`, `path`, `content_type` (all
  required). There is **no `headers` map** and **no `expires_at`**; the byte PUT
  uses `Content-Type: <content_type>`. The PUT + `complete-upload` orchestration
  is owned by AND-333.
- **`type` vocabulary:** RESOLVED — the backend uses `"file"` and `"folder"`
  (no `"directory"`); the mapper still falls through to `UNKNOWN` for any other
  value for forward-compat.
- **Open:** the `sort_by`/`sort_dir` accepted vocabularies are not enumerated in
  the OpenAPI (free-form strings); the exact accepted values are an unverified
  assumption (see §16 Open assumptions).

## 14. Acceptance Criteria

AC-1. `FilesApi` exposes all twelve methods (`list`, `info`, `search`,
`searchText`, `createFolder`, `renameFile`, `renameFolder`, `move`,
`deleteFile`, `deleteFolder`, `presignUpload`, `completeUpload`) with
paths/verbs/bodies/query params matching the verified `/v1/fs/*` contract; each
is covered by a passing `MockWebServer` test (asserting request line, query, and
body JSON).

AC-2. Every DTO round-trips through Moshi: deserialize→serialize preserves all
documented keys; null/absent-optional fields (`size`, `content_type`,
`updated_at`, `created_at`, and an omitted `cursor` on the last page) are handled
without error. (Directly satisfies the backlog "file payloads map (tested)".)

AC-3. DTO→domain mappers produce correct `FileNode`/`FilePage`; unknown `type`
maps to `FileNodeType.UNKNOWN`; ISO-8601 timestamps parse to `Instant` and
absent timestamps map to `null`.

AC-4. Mutating calls route through the shared interceptors (verified: both
`Authorization: Bearer` and `X-CSRF-Token` headers present on POST/DELETE in
MockWebServer when configured); idempotent GETs participate in bounded retry
while mutations do not (verified with 503-then-200 vs. 503).

AC-5. FastAPI `detail` (string / list-form `HTTPValidationError` / object) maps
to the correct `ApiResult.Error`; repeated 401 yields `ApiResult.Unauthorized`.

AC-6. `provideFilesApi` is wired in `NetworkModule` and resolvable via Hilt; no
new Retrofit/OkHttp instance is created.

## 15. Definition of Done

- All ACs met; `FilesApi`, DTOs (`core-network.files`), domain models
  (`core-model.files`), and mappers merged on branch `android-port`.
- Unit + MockWebServer tests green in CI; DTO field coverage complete; no
  `BODY`-level logging of file endpoints.
- `@Provides fun provideFilesApi` added to `NetworkModule`; KSP/Hilt graph
  compiles.
- `ktlint`/`detekt` clean; no new lint baselines suppressing file-layer code.
- Open questions in §13 (pagination shape, delete shape, `type` vocabulary)
  resolved against the bundled OpenAPI and reflected in the DTOs/tests before
  AND-332 begins (now RESOLVED — see §13/§16), with any residual assumption
  (sort vocabularies) flagged in the PR description.
- PR references AND-331, lists AND-332/AND-333 as downstream consumers, and links
  the captured JSON fixtures.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. "OpenAPI"
refers to `reference/openapi.pretty.json` / `reference/openapi.index.txt`;
frontend paths are under `reference/src/`.

1. **Endpoints live under `/v1/fs/*`, not `/ui/files/*`.** VERDICT: Corrected.
   SOURCE: `src/api/endpoints/files.ts` (all calls target `/v1/fs/...`); OpenAPI
   index — no `/ui/files` browse/CRUD paths exist (only `/ui/files/share-links`).

2. **Nodes are addressed by `path` (string), not an opaque `id`.** VERDICT:
   Corrected. SOURCE: `src/api/types.ts: FileEntry` (`path`); every endpoint
   takes `path`/`src`/`dst` (`src/api/endpoints/files.ts`).

3. **Browse = `GET /v1/fs/list?path=&limit=&cursor=&sort_by=&sort_dir=`.**
   VERDICT: Corrected (was `GET /ui/files?folder_id=...&sort=&order=`). SOURCE:
   `src/api/endpoints/files.ts: listFiles`; OpenAPI `GET /v1/fs/list`
   (params=`path,limit,cursor,sort_by,sort_dir`).

4. **Browse response = `FileListResp { path, items, cursor? }`; no
   `next_cursor`, no `total_count`.** VERDICT: Corrected. SOURCE:
   `src/api/types.ts: FileListResp`.

5. **Single node = `GET /v1/fs/info?path=` → `FileEntry`.** VERDICT: Corrected
   (was `GET /ui/files/{id}`). SOURCE: `src/api/endpoints/files.ts: getFileInfo`;
   OpenAPI `GET /v1/fs/info` (params=`path`).

6. **Filename search = `GET /v1/fs/search?prefix=&limit=` → `{prefix,results}`;
   full-text = `GET /v1/fs/search-text?q=&limit=` → `{query,results}`; neither is
   paginated.** VERDICT: Corrected (was `GET /ui/files/search?q=...` paginated).
   SOURCE: `src/api/endpoints/files.ts: searchFiles/searchText`; OpenAPI
   `GET /v1/fs/search` (params=`prefix,limit`), `GET /v1/fs/search-text`
   (params=`q,limit`).

7. **Create folder = `POST /v1/fs/folder` body `{path}`.** VERDICT: Corrected
   (was `POST /ui/files/folders` body `{parent_id,name}`). SOURCE:
   `src/api/endpoints/files.ts: createFolder`; OpenAPI schema
   `Body_create_folder_v1_fs_folder_post` (`{path}`).

8. **Rename = `POST /v1/fs/rename-file` and `POST /v1/fs/rename-folder`, body
   `{path,new_name}`.** VERDICT: Corrected (was a single `PATCH /ui/files/{id}`
   with `{name}`). SOURCE: `src/api/endpoints/files.ts: renameFile/renameFolder`;
   OpenAPI `Body_rename_file_v1_fs_rename_file_post` (`{path,new_name}`).

9. **Move = `POST /v1/fs/move` body `{src,dst}`.** VERDICT: Corrected (was
   `POST /ui/files/{id}/move` body `{target_parent_id}`). SOURCE:
   `src/api/endpoints/files.ts: moveFile`; OpenAPI
   `Body_move_fs_node_v1_fs_move_post` (`{src,dst}`).

10. **Delete = per-path body-less `DELETE /v1/fs/file?path=` and
    `DELETE /v1/fs/folder?path=`; no batch delete, no DELETE body.** VERDICT:
    Corrected (was `DELETE /ui/files` with `{ids:[...]}` body → 204). SOURCE:
    `src/api/endpoints/files.ts: deleteFile/deleteFolder`; OpenAPI
    `DELETE /v1/fs/file` & `DELETE /v1/fs/folder` (params=`path`, req empty).

11. **Presign = `POST /v1/fs/presign-upload` body `PresignUploadIn {path,
    content_type?}` → `PresignUploadOut {upload_url,bucket,key,ticket_id,path,
    content_type}` (all 6 required).** VERDICT: Corrected (draft invented
    `upload_id/url/method/headers/expires_at`). SOURCE:
    `src/api/endpoints/files.ts: fsPresignUpload`; OpenAPI schemas
    `PresignUploadIn`, `PresignUploadOut`.

12. **Finalize = `POST /v1/fs/complete-upload` body `CompleteUploadIn
    {path,key,ticket_id,content_type?,encrypted?,enc_meta?}`; required:
    path/key/ticket_id.** VERDICT: Corrected (was `POST /ui/files/upload/finalize`
    body `{upload_id,parent_id}`). SOURCE: `src/api/endpoints/files.ts:
    completeUpload`; OpenAPI schema `CompleteUploadIn`.

13. **Node shape keys: `name,path,type,size,content_type,updated_at,created_at,
    is_encrypted` (+ `enc_*`/`preview_*`), `type ∈ {file,folder}`.** VERDICT:
    Corrected (draft used `id,parent_id,node_type,size_bytes,mime_type,
    modified_at,owner_id,download_url`). SOURCE: `src/api/types.ts: FileEntry`.

14. **Folder discriminator is `"folder"` (not `"directory"`).** VERDICT:
    Corrected (draft mapper accepted `"directory"`). SOURCE:
    `src/api/types.ts: FileEntry` (`type: "file" | "folder"`).

15. **Node carries no `download_url`; download/preview URLs are built
    client-side from `path` (`/v1/fs/download?path=`, `/v1/fs/preview?path=`,
    `/v1/fs/thumbnail?path=`).** VERDICT: Corrected. SOURCE:
    `src/api/endpoints/files.ts: downloadUrl/previewUrl/thumbnailUrl`.

16. **Auth: client sends `Authorization: Bearer <accessToken>` AND
    `X-CSRF-Token` (from `ui_csrf` cookie) on EVERY request, plus cookies via
    `credentials: include`.** VERDICT: Corrected (draft said cookie-only and CSRF
    on mutations only). SOURCE: `src/api/client.ts` lines 156-171, 183.

17. **401 handling: single `POST /ui/session/refresh` then one retry; repeated
    401 logs out.** VERDICT: Verified. SOURCE: `src/api/client.ts:
    refreshSession` (line 122) + 401 branch (lines 194-237).

18. **Error body: FastAPI `detail` may be string / list-of-`{msg}` / object;
    422 validation errors are `HTTPValidationError {detail:[ValidationError]}`
    where `ValidationError = {loc,msg,type}`.** VERDICT: Verified. SOURCE:
    `src/api/client.ts: normalizeErrorDetail` (lines 66-102); OpenAPI schemas
    `HTTPValidationError`, `ValidationError`.

19. **DI: `@Provides fun provideFilesApi(retrofit) = retrofit.create(...)` in
    `NetworkModule`, reusing AND-027's authenticated Retrofit.** VERDICT:
    Unverified-assumption (Android module conventions; no source to verify
    against — internal to this port). framework ref: Hilt provides pattern —
    https://developer.android.com/training/dependency-injection/hilt-android

20. **Paging 3 `PagingSource` consumes `cursor` for browse.** VERDICT:
    Unverified-assumption for the page mechanics (downstream AND-332), but the
    `cursor` field it relies on is Verified (claim 4). framework ref:
    https://developer.android.com/topic/libraries/architecture/paging/v3-overview

21. **`X-API-Key` is an alternative auth on some `/v1/fs/*` routes
    (`list`,`folder`,`upload`).** VERDICT: Verified (documented) but
    Unverified-as-used — the web client never sends it; treated as out of
    contract. SOURCE: OpenAPI index `GET /v1/fs/list` (params include
    `X-API-Key`); absence in `src/api/client.ts`.

### Corrections made

- Path namespace `/ui/files/*` → `/v1/fs/*` (claims 1, 3, 5-12).
- Addressing model `{id}` path-segments → `path` query/body params (claims 2, 5,
  10).
- Verbs/shape: `PATCH {id}` rename → `POST rename-file`/`rename-folder`;
  `POST {id}/move {target_parent_id}` → `POST move {src,dst}`; batch
  `DELETE {ids}` → per-path body-less `DELETE ?path=` (claims 8, 9, 10).
- Pagination: `next_cursor`+`total_count` → single optional `cursor`; search
  de-paginated (claims 4, 6).
- Node DTO field set rewritten to real `FileEntry` keys; dropped invented
  `id/parent_id/owner_id/mime_type/download_url/node_type`; `FileNode` re-keyed
  on `path` (claims 13, 14, 15).
- Presign/finalize request+response schemas rewritten to `PresignUploadIn/Out`
  and `CompleteUploadIn` (claims 11, 12).
- Auth corrected to Bearer + always-on CSRF (claim 16); error section updated to
  cite `HTTPValidationError` 422 as canonical (claim 18).
- Endpoint count updated 8 → 12 throughout (interface, §11, AC-1); telemetry
  event names and retry/idempotent lists updated to real method names.

### Open assumptions

- **`sort_by`/`sort_dir` accepted values** — OpenAPI types them as free-form
  strings with no enum; the suggested `name|size|modified` / `asc|desc` are an
  assumption pending live verification. No fixture documents them.
- **Success-envelope exact keys for `OkResp`** — `src/api/types.ts: OkResp` and
  the `createFolder`/`deleteFile` responses are typed loosely (`{ok:boolean,
  ...}`); the mapper should only depend on `ok`. Extra keys are assumed
  ignorable.
- **Hilt/Retrofit/Paging wiring** — Android-port-internal, no backend/web source
  to verify (claims 19, 20); framework refs cited instead.
- **`X-API-Key` server-to-server auth** — documented but unused by the client;
  intentionally out of this contract (claim 21).

## 17. Test Plan

IDs `TC-AND-331-NN`. "MockWebServer" cases are JVM/Robolectric (no device).
DTO/mapper round-trip and contract tests are device-independent and run on the
JVM unit target; the few instrumented cases run on emulator AVD `test35`
(API 35) unless ABI/API parity is in question (then the physical Samsung
A15, SM-A156U / R5CX821TA9R, API 34 arm64-v8a). This is a pure
network/serialization slice, so no camera/biometrics/WebRTC hardware is in
scope.

- **TC-AND-331-01** — Type: contract/MockWebServer. Target: `FilesApi.list`.
  Preconditions: MockWebServer enqueues a 200 `FileListResp` fixture with one
  file + one folder and a `cursor`. Steps: call `list(path="/sub", limit=50,
  sortBy="name", sortDir="asc")`; capture `RecordedRequest`. Expected: request
  line is `GET /v1/fs/list?path=/sub&limit=50&sort_by=name&sort_dir=asc`;
  response maps to `FilePage(path, items.size==2, cursor!=null)`. Traces: AC-1,
  AC-2.

- **TC-AND-331-02** — Type: unit (Moshi round-trip). Target: `FileEntryDto`.
  Preconditions: canonical `FileEntry` JSON fixture (file, with `enc_*`/
  `preview_*`). Steps: deserialize → assert all keys → re-serialize → compare
  key set. Expected: lossless round-trip; snake_case keys preserved
  (`content_type`, `is_encrypted`, `updated_at`). Traces: AC-2.

- **TC-AND-331-03** — Type: unit (Moshi + mapper). Target: `FileEntryDto.toDomain`
  null/absent handling. Preconditions: folder JSON with `type:"folder"`, no
  `size`, no `content_type`, no `updated_at`/`created_at`. Steps: deserialize,
  map. Expected: `FileNode(type=FOLDER, sizeBytes=null, contentType=null,
  updatedAt=null, createdAt=null)`; no exception. Traces: AC-2, AC-3.

- **TC-AND-331-04** — Type: unit (mapper). Target: `String?.toFileNodeType`.
  Preconditions: inputs `"file"`, `"folder"`, `"FOLDER"`, `"directory"`,
  `"symlink"`, null. Steps: map each. Expected: FILE, FOLDER, FOLDER, UNKNOWN,
  UNKNOWN, UNKNOWN (i.e. `"directory"` is NOT folder; unknown→UNKNOWN). Traces:
  AC-3.

- **TC-AND-331-05** — Type: unit (mapper). Target: `FileListDto.toDomain`
  last-page. Preconditions: `FileListResp` JSON with `items:[]` and `cursor`
  omitted. Steps: deserialize, map. Expected: `FilePage(items==[], cursor==null)`
  — omitted and explicit-null both yield null. Traces: AC-2, AC-3.

- **TC-AND-331-06** — Type: contract/MockWebServer. Target: `move`, `renameFile`,
  `renameFolder`, `createFolder`. Preconditions: enqueue matching success
  envelopes. Steps: call each; inspect method/path/body. Expected:
  `POST /v1/fs/move` body `{"src":...,"dst":...}`; `POST /v1/fs/rename-file` body
  `{"path":...,"new_name":...}`; `POST /v1/fs/rename-folder` likewise;
  `POST /v1/fs/folder` body `{"path":...}`. Traces: AC-1.

- **TC-AND-331-07** — Type: contract/MockWebServer. Target: `deleteFile`,
  `deleteFolder`. Preconditions: enqueue `{"ok":true}` and `{"ok":true,
  "deleted_count":3}`. Steps: call `deleteFile("/a.pdf")`,
  `deleteFolder("/Old")`. Expected: `DELETE /v1/fs/file?path=/a.pdf` and
  `DELETE /v1/fs/folder?path=/Old`, each with an **empty request body** (no
  DELETE body); `deleteFolder` maps `deleted_count==3`. Traces: AC-1.

- **TC-AND-331-08** — Type: contract/MockWebServer. Target: `presignUpload`,
  `completeUpload`. Preconditions: enqueue `PresignUploadOut` then
  complete-upload success. Steps: call both. Expected: `POST /v1/fs/presign-upload`
  body `{"path":...,"content_type":...}` → all six required out-fields present;
  `POST /v1/fs/complete-upload` body includes `path`,`key`,`ticket_id`,
  `content_type`,`encrypted`,`enc_meta`; response maps to `FileNode`. Traces:
  AC-1, AC-2.

- **TC-AND-331-09** — Type: contract/MockWebServer. Target: shared interceptors
  on `move`. Preconditions: configure auth store with an access token and a
  `ui_csrf` cookie in the jar. Steps: call `move(...)`; inspect headers. Expected:
  request carries both `Authorization: Bearer <token>` and `X-CSRF-Token:
  <csrf>`. (Repeat assertion that `GET list` also carries both — CSRF is always
  attached.) Traces: AC-4.

- **TC-AND-331-10** — Type: contract/MockWebServer (error path). Target:
  `info` 422. Preconditions: enqueue 422 with
  `{"detail":[{"loc":["query","path"],"msg":"field required","type":"missing"}]}`.
  Steps: call `info("")` through `apiCall`. Expected: `ApiResult.Error` whose
  message is the joined `msg` ("field required"); not retried. Traces: AC-5.

- **TC-AND-331-11** — Type: contract/MockWebServer (error path). Target: 401
  refresh+retry. Preconditions: authenticated; enqueue 401, then a 200 for
  `POST /ui/session/refresh`, then a 200 for the retried `list`. Steps: call
  `list`. Expected: one refresh call to `/ui/session/refresh`, original request
  retried once, success returned. Enqueue 401→refresh-401: expect
  `ApiResult.Unauthorized`. Traces: AC-5.

- **TC-AND-331-12** — Type: contract/MockWebServer (resilience / flaky dev host).
  Target: idempotent retry vs. mutation no-retry. Preconditions: enqueue 503
  then 200 for `list`; separately enqueue a single 503 for `createFolder`. Steps:
  call each. Expected: `list` retries and succeeds; `createFolder` surfaces the
  503 as `ApiResult.Error` with **no** retry (exactly one recorded request) — no
  duplicate folder. Traces: AC-1, AC-4.

- **TC-AND-331-13** — Type: integration (instrumented). Target: Hilt graph
  resolves `FilesApi`. Preconditions: emulator `test35`; Hilt test app. Steps:
  inject `FilesApi` (and confirm same `Retrofit`/`OkHttp` singleton as
  `AuthApi`). Expected: `provideFilesApi` resolves; no second Retrofit instance
  created (assert identity of underlying client). MUST run on a device/emulator
  (Hilt/KSP graph). Traces: AC-6.

- **TC-AND-331-14** — Type: integration (instrumented, ABI/API parity). Target:
  `Instant` adapter + Moshi codegen on real runtime. Preconditions: run the DTO
  round-trip + timestamp-parse suite once on emulator `test35` (API 35 x86_64)
  AND once on the physical Samsung A15 (API 34 arm64-v8a, serial R5CX821TA9R).
  Steps: deserialize `updated_at`/`created_at` ISO-8601, parse to `Instant`,
  assert equality across both targets. Expected: identical parsing/serialization
  on arm64/API-34 and x86_64/API-35 (guards R8/codegen ABI drift). MUST include
  the physical device for arm64-vs-x86 confirmation. Traces: AC-2, AC-3.

Accessibility note: this slice has no UI, so no Compose-UI/a11y cases apply;
a11y of file names/sizes is deferred to AND-332 (raw `size`/strings are exposed
unformatted, per §9, to enable locale-aware/TalkBack-friendly formatting there).

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (all 12 methods: path/verb/body/query) | TC-01, TC-06, TC-07, TC-08, TC-12 |
| AC-2 (Moshi round-trip; null/absent optionals) | TC-01, TC-02, TC-03, TC-05, TC-08, TC-14 |
| AC-3 (DTO→domain mappers; UNKNOWN; timestamps) | TC-03, TC-04, TC-05, TC-14 |
| AC-4 (Bearer+CSRF on mutations; idempotent retry vs mutation no-retry) | TC-09, TC-12 |
| AC-5 (FastAPI `detail`/422 mapping; repeated 401 → Unauthorized) | TC-10, TC-11 |
| AC-6 (`provideFilesApi` wired in Hilt; no new Retrofit) | TC-13 |
