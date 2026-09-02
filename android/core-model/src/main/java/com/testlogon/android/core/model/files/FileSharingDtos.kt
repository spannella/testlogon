package com.testlogon.android.core.model.files

/**
 * FM-SHARE - transport DTOs for the USER-TO-USER file sharing, archive (zip) and storage-usage surfaces
 * of the `v1/fs` file-manager router (share / unshare / shared-with / shared-with-me / shared-list /
 * shared-info / usage-daily / usage-storage / upload-archive / download-zip).
 *
 * These mirror the SAME conventions as [FilesDtos] (see that file's header): core-model has NO Moshi
 * dependency and NO codegen, so these DTOs carry NO annotations and every property is named EXACTLY as
 * the snake_case wire key. The production Moshi (core-network) decodes them via the reflective
 * KotlinJsonAdapterFactory (verbatim name mapping). Required wire fields have NO default (a missing key
 * throws JsonDataException); optional/echoed fields are nullable or boolean-with-default. Unknown extra
 * wire keys (the tolerated enc_ / preview_ / signature_packet_ families) are ignored by the reflective
 * adapter. This is the direct-share sibling of the public share-LINK DTOs in [ShareDtos].
 */

/**
 * Body for POST v1/fs/share (all fields `embed=true` on the backend, so they are top-level JSON keys).
 * `permission` is "read" or "write" (defaulted to "read" by the backend when absent, but always sent
 * here). `expires_at` is an optional ISO-8601 string; `signature_packet_id` links a signing packet.
 */
data class ShareFileRequest(
    val path: String,
    val to_user: String,
    val permission: String = "read",
    val expires_at: String? = null,
    val signature_packet_id: String? = null,
)

/** Body for POST v1/fs/unshare: revoke [to_user]'s access to [path]. */
data class UnshareFileRequest(
    val path: String,
    val to_user: String,
)

/**
 * One recipient entry from GET v1/fs/shared-with. `to_user` is the recipient user id; `permission` is
 * "read"/"write"; `expires_at` / `shared_at` are ISO-8601 strings; signature-packet progress keys are
 * echoed only when a packet is attached (tolerated, all optional).
 */
data class SharedRecipientDto(
    val to_user: String,
    val permission: String = "read",
    val expires_at: String? = null,
    val shared_at: String? = null,
    val signature_packet_id: String? = null,
)

/** GET v1/fs/shared-with response: the normalised [path] and who it is [shared_with]. */
data class SharedWithDto(
    val path: String,
    val shared_with: List<SharedRecipientDto> = emptyList(),
)

/**
 * One entry from GET v1/fs/shared-with-me: a node another user ([owner]) shared with the caller. `type`
 * / `name` / `size` / `content_type` are enriched from the node when reachable (all optional). The
 * signature_packet_ family is tolerated and optional.
 */
data class SharedWithMeItemDto(
    val owner: String,
    val path: String,
    val permission: String = "read",
    val shared_at: String? = null,
    val expires_at: String? = null,
    val signature_packet_id: String? = null,
    val type: String? = null,
    val name: String? = null,
    val size: Long? = null,
    val content_type: String? = null,
    val is_encrypted: Boolean = false,
)

/** GET v1/fs/shared-with-me response: the caller's inbound shares. */
data class SharedWithMeDto(
    val items: List<SharedWithMeItemDto> = emptyList(),
)

/** GET v1/fs/shared-list response: the shared folder [path], its [items] and an optional [cursor]. */
data class SharedListDto(
    val path: String,
    val items: List<FileEntryDto> = emptyList(),
    val cursor: String? = null,
)

// ---- Storage-usage DTOs -------------------------------------------------------------------------

/** One day's transfer/storage row from GET v1/fs/usage/daily. */
data class UsageDailyItemDto(
    val day_utc: String,
    val upload_bytes_total: Long = 0,
    val download_bytes_total: Long = 0,
    val storage_bytes_end_of_day: Long = 0,
)

/** GET v1/fs/usage/daily response: the resolved [from]/[to] range and the per-day [items]. */
data class UsageDailyDto(
    val from: String,
    val to: String,
    val items: List<UsageDailyItemDto> = emptyList(),
)

/** One heaviest-file row from GET v1/fs/usage/storage. */
data class UsageStorageFileDto(
    val path: String,
    val size: Long = 0,
)

/** GET v1/fs/usage/storage response: current total storage and the [top_files] by size. */
data class UsageStorageDto(
    val storage_bytes_current: Long = 0,
    val top_files: List<UsageStorageFileDto> = emptyList(),
)

// ---- Archive (zip) DTOs -------------------------------------------------------------------------

/**
 * Response of POST v1/fs/upload-archive (and v1/fs/upload-zip): `{ ok, created: [paths], count }`. The
 * archive is extracted server-side into the destination folder; [created] lists the extracted node
 * paths.
 */
data class UploadArchiveResultDto(
    val ok: Boolean = false,
    val created: List<String> = emptyList(),
    val count: Int = 0,
)
