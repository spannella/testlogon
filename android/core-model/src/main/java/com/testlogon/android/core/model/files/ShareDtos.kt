package com.testlogon.android.core.model.files

/**
 * AND-335 - transport DTOs for shareable file links (owner + public surfaces).
 *
 * RECONCILIATION NOTE (identical to AND-331's FilesDtos.kt and the KYC DTOs): core-model has NO Moshi
 * dependency and NO Moshi codegen, so these DTOs carry NO annotations. The production Moshi
 * (core-network NetworkModule.provideMoshi) decodes them via the reflective KotlinJsonAdapterFactory,
 * which maps Kotlin property names to JSON keys VERBATIM. Every property below is therefore named EXACTLY
 * as the snake_case wire key (link_id, file_node_id, share_url, expiry_hours, max_downloads,
 * download_count, password_protected, created_at, expires_at, file_name, content_type,
 * password_required, ...). Zero annotations, zero new dependencies. Required wire fields have NO default
 * so the reflective adapter throws JsonDataException when absent; optional wire fields are nullable (or
 * boolean-with-default) so they decode leniently. Unknown extra wire keys are ignored by default.
 *
 * Timestamps here are epoch milliseconds (Longs) on the wire (NOT ISO Strings), per the verified AND-335
 * contract; the epoch -> Instant conversion happens in the feature-side ShareDtoMappers, never in Moshi.
 *
 * OWNER surface (authenticated, ui/files/share-links): [ShareLinkListDto], [ShareLinkOutDto],
 * [CreateShareLinkRequest], [RevokeShareLinkDto].
 * PUBLIC surface (session-free, public/files/share): [PublicShareDto], [PublicDownloadRequest].
 */

/** GET ui/files/share-links response: ALL of the caller's links (filtered by file client-side). */
data class ShareLinkListDto(
    val links: List<ShareLinkOutDto> = emptyList(),
)

/**
 * A single owner-visible share link. Required wire fields: link_id, share_url (NO default ->
 * JsonDataException when absent). All other fields are modelled leniently (nullable / boolean-default)
 * because the backend may omit them depending on the link's state. `share_url` is an absolute URL.
 * `expires_at` / `created_at` are epoch millis.
 */
data class ShareLinkOutDto(
    val link_id: String,
    val share_url: String,
    val file_node_id: String? = null,
    val expiry_hours: Int? = null,
    val expires_at: Long? = null,
    val max_downloads: Int? = null,
    val download_count: Int? = null,
    val password_protected: Boolean = false,
    val created_at: Long? = null,
    val revoked: Boolean? = null,
)

/**
 * Body for POST ui/files/share-links. `file_node_id` identifies the file to share; `expiry_hours`
 * (1..720), `max_downloads` (1..100) and the optional `password` (4..128 when set) are validated in the
 * domain layer before the request is built.
 */
data class CreateShareLinkRequest(
    val file_node_id: String,
    val expiry_hours: Int,
    val max_downloads: Int,
    val password: String? = null,
)

/** DELETE ui/files/share-links/{link_id} response: { ok, link_id } (a 200, NOT a 204). */
data class RevokeShareLinkDto(
    val ok: Boolean = false,
    val link_id: String? = null,
)

/**
 * GET public/files/share/{link_id}/info response (session-free) - the verified `ShareLinkPublicInfoOut`
 * schema (OpenAPI tag `public-file-share`; web `src/api/types.ts: ShareLinkPublicInfo`).
 *
 * AND-392 CORRECTED CONTRACT: the authoritative public-info wire keys are `file_name`, `file_size_bytes`,
 * `content_type` (the three REQUIRED fields on the wire), `requires_password`, `is_expired`, `is_revoked`,
 * `is_used` and `remaining_downloads`. The public payload has NO `link_id`, `owner_display_name`,
 * `expires_at`, `preview_url` or `downloads_remaining` - the earlier AND-335 draft modelled
 * `size`/`revoked`/`expired`/`exhausted`/`password_required`/`download_count`/`max_downloads`, which the
 * OpenAPI does not expose. To stay ADDITIVE and not break AND-335's already-green tests/behaviour, BOTH
 * name sets are kept: the reflective Moshi only binds keys actually present on the wire, and the AND-392
 * mapper (ShareDomain.toDomain) prefers the corrected names with the legacy names as a fallback. State is
 * carried via the boolean flags (`is_revoked` / `is_expired` / `is_used`, falling back to the legacy
 * `revoked` / `expired` / `exhausted`) plus `requires_password`; there is NO download URL in this payload
 * (the bytes come from the separate download endpoint). Every field is nullable / boolean-default so a
 * partial payload decodes leniently; `link_id` is kept (nullable) only for the AND-335 fakes that set it.
 */
data class PublicShareDto(
    // AND-392 corrected (verified ShareLinkPublicInfoOut) wire keys.
    val file_name: String? = null,
    val file_size_bytes: Long? = null,
    val content_type: String? = null,
    val requires_password: Boolean = false,
    val is_expired: Boolean = false,
    val is_revoked: Boolean = false,
    val is_used: Boolean = false,
    val remaining_downloads: Int = 0,
    // AND-335 legacy keys, tolerated as a fallback (older drafts / older backends / existing fakes).
    val link_id: String? = null,
    val size: Long? = null,
    val expires_at: Long? = null,
    val password_required: Boolean = false,
    val revoked: Boolean? = null,
    val expired: Boolean? = null,
    val exhausted: Boolean? = null,
    val download_count: Int? = null,
    val max_downloads: Int? = null,
)

/** Body for POST public/files/share/{link_id}/download. `password` is null for unprotected links. */
data class PublicDownloadRequest(
    val password: String? = null,
)
