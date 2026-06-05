---
id: AND-331
title: Files API + DTOs
milestone: M7
epic: E43
priority: P0
size: M
status: draft
depends_on: [AND-027]
blocks: [AND-332, AND-333]
---

# AND-331 — Files API + DTOs

## 1. Overview & Goal

This ticket delivers the data-layer contract for the TestLogon file manager on
Android: a Retrofit `FilesApi` interface plus the Moshi DTOs that model the
backend's file/folder browse, CRUD, and search payloads. It is a pure
network/serialization slice — no UI, no ViewModel, no repository business logic.
The deliverable is a typed, tested mapping between the FastAPI `/ui/files/*`
endpoints (mirrored from the web reference `frontend/src/api/endpoints/files.ts`)
and Kotlin DTOs/domain models, exposed through the project's `ApiResult<T>`
envelope.

The single acceptance bar from the backlog is: **file payloads map (tested)** —
every documented request/response JSON shape round-trips through Moshi without
loss, and every endpoint is callable with the correct path, verb, body, and
headers, verified against `MockWebServer`.

Goal in one sentence: ship `FilesApi` + `*Dto` + DTO→domain mappers in
`core-network` / `core-model` so that AND-332 (browse) and AND-333 (upload) can
build features on a stable, verified contract.

## 2. Context & References

- **Module placement:** Retrofit interface and DTOs land in `core-network`
  (package `com.testlogon.android.core.network.files`); domain models in
  `core-model` (`com.testlogon.android.core.model.files`); mappers in
  `core-network` adjacent to the DTOs. Layering rule `app -> feature-* -> core-*`
  is respected; nothing here depends on a feature module.
- **Web reference:** `frontend/src/api/endpoints/files.ts` (endpoint set, query
  params, verbs) and `frontend/src/api/types.ts` (field names, optionality).
  These are the source of truth for naming; confirm field nullability against the
  live `/openapi.json` on the dev host.
- **Dependency AND-027 (AuthApi):** establishes the shared Retrofit/OkHttp stack
  — persistent cookie jar, `X-CSRF-Token` echo interceptor, single 401 →
  `POST /ui/session/refresh` → retry behavior, and the `ApiResult<T>` + FastAPI
  `detail` error mapping. `FilesApi` reuses that exact `Retrofit` instance and
  `Moshi` builder; this ticket adds no new client wiring.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). All file metadata calls are cookie-authenticated
  and CSRF-protected for mutating verbs.
- **Downstream:** AND-332 consumes browse/search; AND-333 consumes the presign
  upload DTOs and the create/move endpoints for folder placement.

## 3. Functional Requirements

FR-1. Expose a `FilesApi` Retrofit interface covering the file-manager surface:
browse a folder, get a single node, create folder, rename, move, delete (single
and batch), search, and request an upload presign URL + finalize.

FR-2. Provide Moshi DTOs for every request body and response shape, with
`@Json(name=...)` on any field whose JSON key differs from idiomatic Kotlin
camelCase, matching `frontend/src/api/types.ts`.

FR-3. Provide pure DTO→domain mappers (`FileNodeDto.toDomain(): FileNode`, etc.)
so feature modules never touch DTOs directly. Unknown/forward-compatible enum
values (e.g. a new `node_type`) map to a safe `UNKNOWN` variant rather than
throwing.

FR-4. Browse and search return paginated responses compatible with Paging 3
(cursor or page/offset per the contract); the DTO must surface the
continuation token so AND-332 can wire a `PagingSource`.

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

```kotlin
interface FilesApi {

    @GET("ui/files")
    suspend fun browse(
        @Query("folder_id") folderId: String?,      // null = root
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 50,
        @Query("sort") sort: String? = null,          // "name" | "size" | "modified"
        @Query("order") order: String? = null,        // "asc" | "desc"
    ): FilePageDto

    @GET("ui/files/{id}")
    suspend fun getNode(@Path("id") id: String): FileNodeDto

    @GET("ui/files/search")
    suspend fun search(
        @Query("q") query: String,
        @Query("folder_id") folderId: String? = null,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 50,
    ): FilePageDto

    @POST("ui/files/folders")
    suspend fun createFolder(@Body body: CreateFolderRequest): FileNodeDto

    @PATCH("ui/files/{id}")
    suspend fun rename(
        @Path("id") id: String,
        @Body body: RenameRequest,
    ): FileNodeDto

    @POST("ui/files/{id}/move")
    suspend fun move(
        @Path("id") id: String,
        @Body body: MoveRequest,
    ): FileNodeDto

    @HTTP(method = "DELETE", path = "ui/files", hasBody = true)
    suspend fun deleteBatch(@Body body: DeleteRequest): Response<Unit>

    @POST("ui/files/upload/presign")
    suspend fun presignUpload(@Body body: PresignRequest): PresignResponse

    @POST("ui/files/upload/finalize")
    suspend fun finalizeUpload(@Body body: FinalizeUploadRequest): FileNodeDto
}
```

Domain model (`com.testlogon.android.core.model.files`):

```kotlin
enum class FileNodeType { FILE, FOLDER, UNKNOWN }

data class FileNode(
    val id: String,
    val parentId: String?,
    val name: String,
    val type: FileNodeType,
    val sizeBytes: Long?,        // null for folders
    val mimeType: String?,
    val modifiedAt: Instant,
    val createdAt: Instant,
    val ownerId: String?,
    val downloadUrl: String?,    // short-lived; nullable for folders
)

data class FilePage(
    val items: List<FileNode>,
    val nextCursor: String?,     // null = last page
    val totalCount: Int?,
)
```

Mappers are top-level extension functions in `FileDtoMappers.kt`:

```kotlin
internal fun FileNodeDto.toDomain(): FileNode
internal fun FilePageDto.toDomain(): FilePage
internal fun String?.toFileNodeType(): FileNodeType =
    when (this?.lowercase()) {
        "file" -> FileNodeType.FILE
        "folder", "directory" -> FileNodeType.FOLDER
        else -> FileNodeType.UNKNOWN
    }
```

Timestamps are parsed from ISO-8601 strings via a shared `Instant` Moshi adapter
(reused from the `core-network` adapter set established under AND-027); the DTO
holds the raw `String` and the mapper converts, so a malformed timestamp degrades
to a mapper-level failure rather than a deserialization crash.

DI: a `@Provides fun provideFilesApi(retrofit: Retrofit): FilesApi =
retrofit.create(FilesApi::class.java)` is added to the existing
`NetworkModule` (`@InstallIn(SingletonComponent::class)`), reusing the
authenticated `Retrofit` from AND-027.

## 5. API Contract

Base URL: `http://18.222.237.167:8000/`. All calls send the session cookies and
the `X-CSRF-Token` header (mutations) via shared interceptors.

**GET `/ui/files?folder_id=&cursor=&limit=50&sort=name&order=asc`** →
`FilePageDto`:

```json
{
  "items": [
    {
      "id": "f_01HX...",
      "parent_id": "f_root",
      "name": "report.pdf",
      "node_type": "file",
      "size_bytes": 184320,
      "mime_type": "application/pdf",
      "modified_at": "2026-05-30T12:04:11Z",
      "created_at": "2026-05-29T09:00:00Z",
      "owner_id": "u_123",
      "download_url": "https://.../report.pdf?sig=..."
    }
  ],
  "next_cursor": "eyJrIjoi...",
  "total_count": 137
}
```

**GET `/ui/files/{id}`** → single `FileNodeDto` (same node shape).

**GET `/ui/files/search?q=invoice&folder_id=&cursor=&limit=50`** → `FilePageDto`.

**POST `/ui/files/folders`** body `CreateFolderRequest`
`{ "parent_id": "f_root", "name": "Q2" }` → `FileNodeDto` (the new folder).

**PATCH `/ui/files/{id}`** body `RenameRequest` `{ "name": "new-name.pdf" }` →
updated `FileNodeDto`.

**POST `/ui/files/{id}/move`** body `MoveRequest`
`{ "target_parent_id": "f_archive" }` → moved `FileNodeDto`.

**DELETE `/ui/files`** body `DeleteRequest`
`{ "ids": ["f_a", "f_b"] }` → `204 No Content`.

**POST `/ui/files/upload/presign`** body `PresignRequest`
`{ "parent_id": "f_root", "name": "clip.mp4", "size_bytes": 10485760, "mime_type": "video/mp4" }`
→ `PresignResponse`:

```json
{
  "upload_id": "up_01HX...",
  "url": "https://storage.../put?sig=...",
  "method": "PUT",
  "headers": { "Content-Type": "video/mp4" },
  "expires_at": "2026-06-05T13:00:00Z"
}
```

**POST `/ui/files/upload/finalize`** body
`{ "upload_id": "up_01HX...", "parent_id": "f_root" }` → finalized `FileNodeDto`.

DTOs mirror these keys exactly (e.g. `@Json(name = "node_type") val nodeType: String?`,
`@Json(name = "size_bytes") val sizeBytes: Long?`). The presign `url` may be an
off-host storage endpoint; the actual byte PUT is **out of scope** (AND-333).

## 6. Data & State Management

This ticket introduces no persistent state — no Room entities, no DataStore keys,
no StateFlow. It produces immutable DTOs and domain models only. Pagination state
(`nextCursor`) is surfaced through `FilePage.nextCursor` for AND-332's
`PagingSource` to manage. Caching of file metadata in Room is deferred to the
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
  dev host. Browse/getNode/search (idempotent GETs) participate in the shared
  bounded-backoff retry (e.g. 2 retries, jittered); all mutating verbs and the
  presign/finalize POSTs do **not** retry to avoid duplicate folders/moves.
- **401 handling:** the shared authenticator performs a single
  `POST /ui/session/refresh` then one retry; on repeated 401 the call surfaces
  `ApiResult.Unauthorized`. No file-specific logic.
- **404/409:** `getNode`/`rename`/`move` on a deleted or conflicting node return
  the FastAPI error body, mapped to `ApiResult.Error` with the server `detail`.
  These are not retried.
- **Mapper robustness:** unknown `node_type` → `FileNodeType.UNKNOWN`; null
  `size_bytes` on folders is expected and allowed; a malformed timestamp throws
  inside the mapper and is caught by `apiCall` as a parse error rather than
  crashing.

## 8. Security & Privacy

- All endpoints are cookie-authenticated; the persistent cookie jar and CSRF
  echo (`ui_csrf` cookie → `X-CSRF-Token` header) from AND-027 are mandatory for
  mutating verbs. The `FilesApi` interface deliberately declares no `@Header`,
  delegating to interceptors so credentials are never hand-assembled per call.
- `download_url` and presign `url` are short-lived signed URLs; DTOs must not be
  logged at body level (see §10) and these URLs must never be persisted to disk
  or DataStore in this layer.
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
concern (AND-332); (2) `size_bytes` is exposed as a raw `Long` so the feature
layer can format with a locale-aware formatter rather than receiving
pre-formatted text. Any error copy shown to users is produced from `ApiResult`
mapping in the feature module, not here.

## 10. Telemetry & Logging

- Reuse the shared OkHttp `HttpLoggingInterceptor` configured at `BASIC` in
  release and `HEADERS` in debug; **never `BODY`** for file endpoints, to avoid
  logging signed `download_url`/presign URLs and file names.
- Add lightweight breadcrumbs via the shared telemetry facade (no new
  dependency): event names `files.browse`, `files.search`, `files.create_folder`,
  `files.rename`, `files.move`, `files.delete`, `files.presign`,
  `files.finalize`, each tagged with outcome (`success`/`error`) and HTTP status
  bucket — never the file name or URL.
- Mapper failures emit a `files.map_error` event with the DTO field that failed
  (field name only, no value) to aid contract-drift diagnosis.

## 11. Testing Strategy

This is the acceptance core — "file payloads map (tested)".

- **Moshi round-trip unit tests** (`core-testing`, JVM, no Android): for each DTO,
  load a canonical JSON fixture (captured from `/openapi.json` examples or the
  web reference), deserialize, assert all fields, re-serialize, and assert key
  equality. Cover null cases: folder with null `size_bytes`/`mime_type`/
  `download_url`, root browse with null `parent_id`, last page with null
  `next_cursor`.
- **Mapper unit tests:** `FileNodeDto.toDomain()` for file vs folder; unknown
  `node_type` → `UNKNOWN`; timestamp parsing; `FilePageDto.toDomain()` empty
  list and populated list.
- **`MockWebServer` contract tests** (mirrors AND-027 style): enqueue fixture
  responses and assert each `FilesApi` method issues the correct path, query
  string, HTTP verb, and request body JSON. Specifically verify
  `deleteBatch` sends a DELETE with a body, `move` posts to `/{id}/move`, and
  `rename` uses PATCH. Assert the `X-CSRF-Token` header is present on mutating
  requests (interceptor integration) and absent-by-omission concerns are covered.
- **Error-path tests:** enqueue 400 with a list-form `detail`, 401, 404, and 409;
  assert the shared parser yields the expected `ApiResult.Error`/`Unauthorized`.
- **Idempotent retry test:** enqueue one 503 then a 200 for `browse`; assert it
  retries and succeeds. Enqueue a 503 for `createFolder`; assert it does **not**
  retry.
- Target: 100% of DTO fields exercised; all eight endpoints covered by at least
  one MockWebServer test. No instrumented (device) tests required.

## 12. Dependencies & Sequencing

- **Depends on AND-027** (AuthApi/session endpoints): supplies the authenticated
  `Retrofit`, cookie jar, CSRF interceptor, `Instant` Moshi adapter, `ApiResult`,
  and FastAPI `detail` parser. This ticket must not re-implement any of those.
- **Blocks AND-332** (File manager browse — consumes `browse`/`search` +
  `FilePage` pagination) and **AND-333** (Upload via presign — consumes
  `presignUpload`/`finalizeUpload` + `createFolder`/`move` for folder placement).
- Sequencing: land DTOs + mappers + tests first, then the `FilesApi` interface +
  MockWebServer tests, then wire the `@Provides` into `NetworkModule`. No build
  baseline changes beyond Hilt module edits.

## 13. Risks & Open Questions

- **Contract drift vs. web reference:** field names/optionality in
  `frontend/src/api/types.ts` may lag the live backend. Mitigation: capture
  fixtures from the live `/openapi.json` and treat OpenAPI as tiebreaker.
- **Pagination shape unknown:** the contract may use `cursor` (assumed here) or
  page/offset. Open question — confirm against `/openapi.json`; `FilePage`
  exposes a single nullable `nextCursor` which can be adapted to an offset
  trivially. **Resolve before AND-332 starts.**
- **Delete-with-body:** some proxies strip DELETE bodies. If the backend expects
  `POST /ui/files/batch-delete` instead, switch `deleteBatch` accordingly; verify
  against OpenAPI.
- **Presign host/headers:** the presign `url` and required headers may target an
  off-host object store; exact header set is owned by AND-333 but the DTO must
  carry an arbitrary `headers` map (modeled as `Map<String, String>`).
- **`node_type` vocabulary:** confirm whether folders are `"folder"` or
  `"directory"`; the mapper accepts both defensively.

## 14. Acceptance Criteria

AC-1. `FilesApi` exposes all eight methods with paths/verbs/bodies/query params
matching the contract; each is covered by a passing `MockWebServer` test
(asserting request line, query, and body JSON).

AC-2. Every DTO round-trips through Moshi: deserialize→serialize preserves all
documented keys; null-optional fields (`size_bytes`, `mime_type`,
`download_url`, `parent_id`, `next_cursor`) are handled without error.
(Directly satisfies the backlog "file payloads map (tested)".)

AC-3. DTO→domain mappers produce correct `FileNode`/`FilePage`; unknown
`node_type` maps to `FileNodeType.UNKNOWN`; ISO-8601 timestamps parse to
`Instant`.

AC-4. Mutating calls route through the shared CSRF interceptor (verified: header
present on POST/PATCH/DELETE in MockWebServer); idempotent GETs participate in
bounded retry while mutations do not (verified with 503-then-200 vs. 503).

AC-5. FastAPI `detail` (string / list / object) maps to the correct
`ApiResult.Error`; repeated 401 yields `ApiResult.Unauthorized`.

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
- Open questions in §13 (pagination shape, delete-with-body, `node_type`
  vocabulary) resolved against `/openapi.json` and reflected in the DTOs/tests
  before AND-332 begins, OR explicitly flagged in the PR description with the
  defensive defaults documented.
- PR references AND-331, lists AND-332/AND-333 as downstream consumers, and links
  the captured JSON fixtures.
