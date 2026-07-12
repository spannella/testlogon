package com.testlogon.android.core.network.projects

import com.squareup.moshi.Json

/**
 * AND-374 - transport DTOs for the PROJECTS read surface + the account-scoped Google Drive provider OAuth
 * handshake (start / callback) and the connected-provider credential read.
 *
 * CODEGEN NOTE (identical to AND-371 TicketDtos / AND-353 OrgDtos): core-network does NOT apply the Moshi KSP
 * codegen plugin, so these DTOs decode via the reflective KotlinJsonAdapterFactory registered on the shared
 * Moshi in NetworkModule.provideMoshi. The reflective factory maps Kotlin property names to JSON keys VERBATIM
 * (Moshi does NOT auto snake_case), so every snake_case wire key is pinned with an explicit @Json(name = ...).
 * @JsonClass(generateAdapter = true) is intentionally OMITTED.
 *
 * REQUIRED wire keys (id, owner, name, created_at, updated_at on ProjectOut; provider/authorization_url/state/
 * expires_at on the start response; provider on the credential) have NO default, so a missing key surfaces a
 * JsonDataException. Everything else is nullable / defaulted; extra / unknown wire keys are tolerated leniently.
 *
 * CONTRACT (CORRECTED per spec §5/§16; relative paths, NO leading slash):
 *   GET  v1/projects?cursor=&limit=20                                   -> ProjectListEnvelope { items, cursor }
 *   GET  v1/projects/{projectId}                                        -> ProjectOut (bare)
 *   GET  v1/projects/{projectId}/detail?limit=&cursor=                  -> ProjectDetailEnvelope { project, files, cursor }
 *   POST v1/projects/providers/google_drive/oauth/start  (EMPTY body)   -> ProviderOAuthStartOut
 *   POST v1/projects/providers/google_drive/oauth/callback {code,state} -> ProviderCredentialOut
 *   GET  v1/projects/providers/{provider}/credentials?org=             -> ProviderCredentialOut (404 = not connected)
 *
 * The list cursor field is `cursor` (NOT next_cursor). ProjectOut has NO `status` and NO embedded `providers[]`
 * (connection state is read separately via the credentials GET). The callback returns a CREDENTIAL, not a project.
 */

/**
 * One project. `id`, `owner`, `name`, `created_at` and `updated_at` are REQUIRED by the schema (no default).
 * `description` is optional; `tags` / `settings` default to empty. There is NO `status` and NO `providers[]`
 * (see spec §16 items 4/5). `created_at` / `updated_at` are ISO-8601 strings on this surface (NOT epoch).
 */
data class ProjectOut(
    @Json(name = "id") val id: String,
    @Json(name = "owner") val owner: String,
    @Json(name = "name") val name: String,
    @Json(name = "description") val description: String? = null,
    @Json(name = "tags") val tags: List<String> = emptyList(),
    @Json(name = "settings") val settings: Map<String, Any?> = emptyMap(),
    @Json(name = "created_at") val createdAt: String,
    @Json(name = "updated_at") val updatedAt: String,
)

/**
 * Batch-8 (#9) - request body for POST v1/projects. `name` is required (server-validated 1..120); `description`
 * is optional (max 2000); `tags` defaults to empty. Mirrors the backend ProjectCreateIn.
 */
data class ProjectCreateIn(
    @Json(name = "name") val name: String,
    @Json(name = "description") val description: String? = null,
    @Json(name = "tags") val tags: List<String> = emptyList(),
)

/**
 * Paginated envelope for GET v1/projects. The continuation field is `cursor` (CORRECTED from next_cursor); a
 * null / absent / blank cursor means there is no further page.
 */
data class ProjectListEnvelope(
    @Json(name = "items") val items: List<ProjectOut> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
)

/**
 * Envelope for GET v1/projects/{projectId}/detail = { project, files[], cursor }. `files[]` is the AND-336
 * Files-epic surface and is OUT OF SCOPE here (decoded leniently as raw maps so an unexpected file shape never
 * fails the project read; the domain mapper ignores it).
 */
data class ProjectDetailEnvelope(
    @Json(name = "project") val project: ProjectOut,
    @Json(name = "files") val files: List<Map<String, Any?>> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
)

/**
 * Response of POST v1/projects/providers/google_drive/oauth/start (ProviderOAuthStartOut). All four fields are
 * REQUIRED. `authorizationUrl` is opened in a Custom Tab; `state` is held in SavedStateHandle for the callback
 * CSRF/replay check. `expiresAt` is an ISO-8601 string.
 */
data class ProviderOAuthStartOut(
    @Json(name = "provider") val provider: String,
    @Json(name = "authorization_url") val authorizationUrl: String,
    @Json(name = "state") val state: String,
    @Json(name = "expires_at") val expiresAt: String,
)

/**
 * Request body for POST v1/projects/providers/google_drive/oauth/callback (ProviderOAuthCallbackIn). Both
 * fields are REQUIRED (server-validated 1..8192 chars).
 */
data class ProviderOAuthCallbackIn(
    @Json(name = "code") val code: String,
    @Json(name = "state") val state: String,
)

/**
 * A connected provider credential (ProviderCredentialOut) - returned by the callback POST and by the
 * credentials GET. There is NO `account_email` and NO `folder_id` (spec §16 item 10). `provider` is required;
 * `org` is optional; `scopes` / `metadata` default to empty. `created_at` / `updated_at` are ISO-8601 strings.
 */
data class ProviderCredentialOut(
    @Json(name = "provider") val provider: String,
    @Json(name = "org") val org: String? = null,
    @Json(name = "scopes") val scopes: List<String> = emptyList(),
    @Json(name = "metadata") val metadata: Map<String, Any?> = emptyMap(),
    @Json(name = "created_at") val createdAt: String? = null,
    @Json(name = "updated_at") val updatedAt: String? = null,
)

/**
 * AND-374 - documented constants for the provider-key wire value. Plain String constants (NOT a Kotlin enum) so
 * an unexpected server value never fails deserialization. Google Drive is the only provider in scope.
 */
object ProjectProviders {
    const val GOOGLE_DRIVE = "google_drive"
}
