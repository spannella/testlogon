package com.testlogon.android.core.model.files

/**
 * AND-331 - transport DTOs for the path-addressed file-manager surface (`v1/fs` ...).
 *
 * RECONCILIATION NOTE (identical to AND-319's Kyc.kt and the rest of the KYC DTOs): core-model has NO
 * Moshi dependency and NO Moshi codegen, so these DTOs carry NO annotations. The production Moshi
 * (core-network NetworkModule.provideMoshi) decodes them via the reflective KotlinJsonAdapterFactory,
 * which maps Kotlin property names to JSON keys VERBATIM. Every property below is therefore named EXACTLY
 * as the snake_case wire key (content_type, updated_at, is_encrypted, new_name, ticket_id, deleted_count,
 * upload_url, enc_meta, ...). Zero annotations, zero new dependencies. Required wire fields have NO default
 * so the reflective adapter throws JsonDataException when absent; optional wire fields are nullable (or
 * boolean-with-default) so they decode leniently. Unknown extra wire keys (the tolerated enc_ and
 * preview_ family) are ignored by the reflective adapter by default.
 *
 * PRESIGN RECONCILIATION: an existing presign/confirm pair already lives in :app
 * (data/upload/AttachmentDtos.kt: PresignBody / PresignResponse / ConfirmBody). core-network MUST NOT
 * depend on :app, so this ticket REDEFINES its own typed Presign DTOs here in core-model
 * ([PresignRequest] / [PresignResponse] / [CompleteUploadRequest]) shaped to the verified v1 fs presign
 * wire contract. The actual byte PUT + any reuse/unification with the :app uploader is AND-333's job;
 * this ticket only declares the typed endpoints.
 *
 * Timestamps (updated_at / created_at) are nullable ISO-8601 Strings on the wire (NOT epoch Longs); the
 * core-network FileDtoMappers convert them via Instant.parse (wrapped in runCatching so a malformed or
 * absent value maps to null and never crashes). `type` is a plain String on the wire ("file" or
 * "folder"); the typed FileNodeType + UNKNOWN fallback lives in the mapper.
 */

/**
 * A single file-system entry (file or folder). Required wire fields: name, path, type (NO default ->
 * JsonDataException when absent). `size` is present for files. The tolerated extra enc_ and preview_
 * keys beyond [isEncrypted] / [previewKind] / [posterUrl] are ignored by the reflective adapter.
 */
data class FileEntryDto(
    val name: String,
    val path: String,
    val type: String,
    val size: Long? = null,
    val content_type: String? = null,
    val updated_at: String? = null,
    val created_at: String? = null,
    val is_encrypted: Boolean = false,
    val preview_kind: String? = null,
    val poster_url: String? = null,
)

/** GET v1/fs/list response: the listed [path], its [items], and an optional pagination [cursor]. */
data class FileListDto(
    val path: String,
    val items: List<FileEntryDto> = emptyList(),
    val cursor: String? = null,
)

/** GET v1/fs/search response (prefix / name search). */
data class FileSearchDto(
    val prefix: String,
    val results: List<FileEntryDto> = emptyList(),
)

/** GET v1/fs/search-text response (full-text search). */
data class FileTextSearchDto(
    val query: String,
    val results: List<FileEntryDto> = emptyList(),
)

/** Generic success envelope: { ok, path? } (e.g. create-folder, delete-file). */
data class OkRespDto(
    val ok: Boolean,
    val path: String? = null,
)

/**
 * Result of a rename / move. Modelled LENIENTLY: the backend may echo any subset of these keys, so all
 * are optional and `ok` defaults to false rather than being required.
 */
data class MoveResultDto(
    val ok: Boolean = false,
    val path: String? = null,
    val new_name: String? = null,
    val src: String? = null,
    val dst: String? = null,
)

/** DELETE v1/fs/folder response: { ok, deleted_count? }. */
data class DeleteFolderDto(
    val ok: Boolean,
    val deleted_count: Int? = null,
)

/** Body for POST v1/fs/folder. */
data class CreateFolderRequest(
    val path: String,
)

/** Body for POST v1/fs/rename-file and v1/fs/rename-folder. */
data class RenameRequest(
    val path: String,
    val new_name: String,
)

/** Body for POST v1/fs/move. */
data class MoveRequest(
    val src: String,
    val dst: String,
)

/**
 * Body for POST v1/fs/presign-upload (this ticket's own DTO; see PRESIGN RECONCILIATION above).
 * `content_type` is optional (the backend infers it when absent).
 */
data class PresignRequest(
    val path: String,
    val content_type: String? = null,
)

/**
 * Response of POST v1/fs/presign-upload. Required: upload_url, key, ticket_id, path. `bucket` and
 * `content_type` are echoed only on some flows so they are optional. (This ticket's own DTO; see
 * PRESIGN RECONCILIATION above.)
 */
data class PresignResponse(
    val upload_url: String,
    val key: String,
    val ticket_id: String,
    val path: String,
    val bucket: String? = null,
    val content_type: String? = null,
)

/**
 * Body for POST v1/fs/complete-upload. Required: path, key, ticket_id. `encrypted` defaults to false;
 * `enc_meta` is a loosely-typed map (@JvmSuppressWildcards keeps the reflective adapter from generating
 * a wildcard-typed value adapter it cannot resolve).
 */
data class CompleteUploadRequest(
    val path: String,
    val key: String,
    val ticket_id: String,
    val content_type: String? = null,
    val encrypted: Boolean = false,
    val enc_meta: Map<String, @JvmSuppressWildcards Any?>? = null,
)
