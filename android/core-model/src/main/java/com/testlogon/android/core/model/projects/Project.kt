package com.testlogon.android.core.model.projects

/**
 * AND-374 - domain models for the PROJECTS surface.
 *
 * core-model has NO Moshi / core-network dependency: these are plain domain types. The DTO -> domain bridge
 * lives in the :app feature (ProjectMappers) since core-model cannot depend on core-network.
 *
 * TIME: [createdAt] / [updatedAt] are the RAW ISO-8601 strings from the wire (this surface sends ISO strings,
 * NOT epoch - spec §5); the UI parses / relative-formats them, falling back to the raw string if unparseable.
 * Identity [id] / [owner] are opaque, required Strings; [name] is required. [description] is optional;
 * [tags] / [settings] default to empty. There is NO `status` and NO embedded provider list (connection state
 * is a separate account-scoped read - see [DriveConnection]).
 */
data class Project(
    val id: String,
    val owner: String,
    val name: String,
    val description: String? = null,
    val tags: List<String> = emptyList(),
    val settings: Map<String, Any?> = emptyMap(),
    val createdAt: String? = null,
    val updatedAt: String? = null,
)

/**
 * AND-374 - the account-scoped Google Drive connection state surfaced on the project detail screen (read via
 * the provider-credentials GET, since the project object carries no provider list). [connected] is derived: a
 * successful credential read -> true; a 404 / error -> false. [scopes] is best-effort metadata for display;
 * there is NO account_email / folder_id on the wire (spec §16 item 10), so none is modeled or rendered.
 */
data class DriveConnection(
    val connected: Boolean,
    val scopes: List<String> = emptyList(),
)

/**
 * AND-374 - the parsed result of the account-scoped Google Drive OAuth `start` response. [authorizationUrl] is
 * opened in a Custom Tab; [state] is held in SavedStateHandle and matched against the callback `state` for
 * CSRF/replay protection before the callback POST.
 */
data class ProviderStart(
    val provider: String,
    val authorizationUrl: String,
    val state: String,
    val expiresAt: String? = null,
)

/**
 * AND-374 - the captured deep-link callback parameters forwarded to the provider `callback` endpoint. A
 * present [error] (e.g. "access_denied") means the user canceled / denied - the app does NOT call the callback
 * endpoint and surfaces a neutral canceled message. [code] / [state] are present on a successful authorization.
 */
data class ProviderCallbackParams(
    val code: String? = null,
    val state: String? = null,
    val error: String? = null,
)
