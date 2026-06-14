package com.testlogon.android.core.model.files

/**
 * AND-336 - transport DTOs for the BACKEND-MEDIATED Google Drive import surface
 * (ui/integrations/google-drive/...).
 *
 * RECONCILIATION NOTE (identical to AND-331's FilesDtos.kt and the KYC DTOs): core-model has NO Moshi
 * dependency and NO Moshi codegen, so these DTOs carry NO annotations. The production Moshi
 * (core-network NetworkModule.provideMoshi) decodes them via the reflective KotlinJsonAdapterFactory,
 * which maps Kotlin property names to JSON keys VERBATIM. Every property below is therefore named EXACTLY
 * as the snake_case wire key (auth_url, mime_type, is_folder, modified_time, next_page_token, file_id,
 * folder_id, page_token, page_size). Required wire fields have NO default so the reflective adapter throws
 * JsonDataException when absent; optional wire fields are nullable (or list-with-default) so they decode
 * leniently. Unknown extra wire keys are ignored by the reflective adapter by default.
 *
 * BACKEND-MEDIATED: the backend performs the OAuth dance and proxies Drive server-side; the client never
 * touches the Google SDK / Play Services. The byte transfer Drive to TestLogon also happens server-side,
 * so there is NO download / re-upload DTO here - the import endpoint just names the source Drive file and
 * the optional TestLogon target folder.
 */

/**
 * GET ui/integrations/google-drive/status response. Modelled LENIENTLY: only the connected flag is
 * meaningful; the email is present once connected, and mock flags a dev/stub backend. `connected`
 * defaults to false so a sparse body decodes safely.
 */
data class DriveStatusRespDto(
    val connected: Boolean = false,
    val email: String? = null,
    val mock: Boolean? = null,
)

/**
 * GET ui/integrations/google-drive/connect response: the OAuth consent [auth_url] the client opens
 * externally (required - NO default). `mock` flags a dev/stub backend.
 */
data class DriveConnectRespDto(
    val auth_url: String,
    val mock: Boolean? = null,
)

/**
 * Body for POST ui/integrations/google-drive/callback. The backend's own redirect normally completes
 * OAuth server-side; this DTO exists for the SECONDARY case where the client forwards a captured code.
 * `state` is optional.
 */
data class DriveCallbackReqDto(
    val code: String,
    val state: String? = null,
)

/**
 * GET ui/integrations/google-drive/files response: the listed Drive [files] plus an optional
 * [next_page_token]. `files` defaults to empty so a sparse body decodes safely.
 */
data class DriveFilesRespDto(
    val files: List<DriveFileDto> = emptyList(),
    val next_page_token: String? = null,
)

/**
 * A single Drive entry. Required wire fields: id, name (NO default -> JsonDataException when absent).
 * Folder detection is lenient: either the explicit [is_folder] flag OR a [mime_type] of
 * "application/vnd.google-apps.folder" identifies a folder. `size` and `modified_time` are present only
 * for some entries.
 */
data class DriveFileDto(
    val id: String,
    val name: String,
    val mime_type: String? = null,
    val is_folder: Boolean? = null,
    val size: Long? = null,
    val modified_time: String? = null,
)

/**
 * Body for POST ui/integrations/google-drive/import. [file_id] names the source Drive file; [folder_id]
 * is the OPTIONAL TestLogon target path / folder; [name] optionally overrides the imported file name.
 */
data class DriveImportReqDto(
    val file_id: String,
    val folder_id: String? = null,
    val name: String? = null,
)

/**
 * POST ui/integrations/google-drive/import response. Modelled LENIENTLY: the backend may echo any
 * subset, so all are optional and `ok` defaults to false. `path` is the resulting TestLogon path when
 * the backend reports one.
 */
data class DriveImportRespDto(
    val ok: Boolean = false,
    val path: String? = null,
)
