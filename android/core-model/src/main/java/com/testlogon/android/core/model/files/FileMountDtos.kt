package com.testlogon.android.core.model.files

/**
 * FM-MOUNTS - transport DTOs for the file-manager S3 mount CRUD surface (`v1/fs/mounts` ...).
 *
 * RECONCILIATION NOTE (identical to the AND-331 FilesDtos): core-model has NO Moshi dependency and NO
 * Moshi codegen, so these DTOs carry NO annotations. The production Moshi (core-network
 * NetworkModule.provideMoshi) decodes them via the reflective KotlinJsonAdapterFactory, which maps Kotlin
 * property names to JSON keys VERBATIM. Every property below is therefore named EXACTLY as the snake_case
 * wire key (mount_path, auth_ref, created_at, updated_at, last_check_at, last_error, mount_id, ...). Zero
 * annotations, zero new dependencies. Required wire fields have NO default so the reflective adapter
 * throws JsonDataException when absent; optional wire fields are nullable (or default) so they decode
 * leniently. Unknown extra wire keys are ignored by the reflective adapter by default.
 *
 * WIRE CONTRACT (backend app/routers/filemanager.py FileMountOut / FileMountCreateIn / FileMountUpdateIn,
 * mirrored by the web frontend/src/api/endpoints/files.ts). The list envelope is `{ items: [...] }`
 * (FileMountsListOut); create returns a single FileMountOut; delete returns `{ ok, deleted }`; validate
 * returns `{ ok, mount_id, status }`.
 */

/**
 * A single S3 file-mount record. Required wire fields: id, owner, provider, mount_path, bucket, mode,
 * auth_ref, status, created_at, updated_at (NO default -> JsonDataException when absent). `prefix`,
 * `last_check_at` and `last_error` are optional/nullable.
 */
data class FileMountDto(
    val id: String,
    val owner: String,
    val provider: String,
    val mount_path: String,
    val bucket: String,
    val prefix: String? = null,
    val mode: String,
    val auth_ref: String,
    val status: String,
    val created_at: String,
    val updated_at: String,
    val last_check_at: String? = null,
    val last_error: String? = null,
)

/** GET v1/fs/mounts response envelope: { items: [FileMountDto] }. */
data class FileMountsListDto(
    val items: List<FileMountDto> = emptyList(),
)

/**
 * Body for POST v1/fs/mounts. `mode` is one of "read_only" / "read_write" (default read_only);
 * `status` is one of "active" / "degraded" / "error" / "disabled" (default active).
 */
data class FileMountCreateRequest(
    val mount_path: String,
    val bucket: String,
    val prefix: String? = null,
    val mode: String = "read_only",
    val auth_ref: String,
    val status: String = "active",
)

/** Body for PATCH v1/fs/mounts/{id}. Every field is optional (null = leave unchanged). */
data class FileMountUpdateRequest(
    val mount_path: String? = null,
    val bucket: String? = null,
    val prefix: String? = null,
    val mode: String? = null,
    val auth_ref: String? = null,
    val status: String? = null,
)

/** DELETE v1/fs/mounts/{id} response: { ok, deleted }. */
data class DeleteFileMountDto(
    val ok: Boolean = false,
    val deleted: Boolean = false,
)

/** POST v1/fs/mounts/{id}/validate response: { ok, mount_id, status }. */
data class ValidateFileMountDto(
    val ok: Boolean = false,
    val mount_id: String? = null,
    val status: String? = null,
)
