package com.testlogon.android.core.network.jira

import com.squareup.moshi.Json

/**
 * JIRA-AND-1 - transport DTOs for the Jira integration surface (connection status / OAuth connect + callback /
 * project discovery + preferences / per-ticket external link + sync-status + conflict resolution). Mirrors the
 * verified web contract in frontend/src/api/endpoints/jira.ts.
 *
 * CODEGEN NOTE (identical to the AND-371 TicketDtos): core-network does NOT apply the Moshi KSP codegen plugin,
 * so these DTOs decode via the reflective KotlinJsonAdapterFactory registered on the shared Moshi. Every wire
 * key is pinned with an explicit @Json(name = ...); @JsonClass(generateAdapter = true) is intentionally OMITTED.
 *
 * ENUM-LIKE FIELDS: status / sync_state / provider / link_mode are decoded as RAW Strings (see [JiraConstants]),
 * so an unknown server token never fails deserialization. Unknown wire keys are tolerated leniently.
 *
 * DEGRADE-ON-404: when the Jira feature is not enabled / the caller is not connected the server may 404; the
 * repository maps that to an honest not-connected empty result (never a crash).
 */

/** One connected Jira workspace connection (embedded in [JiraStatusResp.items]). */
data class JiraConnectionDto(
    @Json(name = "connection_id") val connectionId: String,
    @Json(name = "workspace_id") val workspaceId: String? = null,
    @Json(name = "cloud_id") val cloudId: String? = null,
    @Json(name = "site_url") val siteUrl: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "scopes") val scopes: List<String> = emptyList(),
    @Json(name = "updated_at") val updatedAt: Long? = null,
)

/** GET /integrations/jira/status -> connection status envelope. */
data class JiraStatusResp(
    @Json(name = "connected") val connected: Boolean = false,
    @Json(name = "items") val items: List<JiraConnectionDto> = emptyList(),
)

/** POST /integrations/jira/connect body. */
data class JiraConnectReq(
    @Json(name = "workspace_id") val workspaceId: String,
    @Json(name = "redirect_uri") val redirectUri: String,
)

/** POST /integrations/jira/connect -> the OAuth authorize URL + the opaque state to echo back. */
data class JiraConnectResp(
    @Json(name = "connect_url") val connectUrl: String,
    @Json(name = "state") val state: String,
)

/** GET /integrations/jira/callback -> connected / failed. */
data class JiraCallbackResp(
    @Json(name = "status") val status: String,
    @Json(name = "connection_id") val connectionId: String? = null,
    @Json(name = "error_code") val errorCode: String? = null,
)

/** POST /integrations/jira/disconnect body. */
data class JiraDisconnectReq(
    @Json(name = "workspace_id") val workspaceId: String,
    @Json(name = "connection_id") val connectionId: String,
)

/** One discoverable Jira project (embedded in [JiraProjectsResp.items]). */
data class JiraProjectDto(
    @Json(name = "cloud_id") val cloudId: String? = null,
    @Json(name = "project_id") val projectId: String? = null,
    @Json(name = "project_key") val projectKey: String,
    @Json(name = "name") val name: String? = null,
    @Json(name = "is_private") val isPrivate: Boolean = false,
)

/** GET /integrations/jira/projects -> paginated project envelope. */
data class JiraProjectsResp(
    @Json(name = "items") val items: List<JiraProjectDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

/** GET/PUT /integrations/jira/preferences -> the selected project keys for a cloud. */
data class JiraPreferencesResp(
    @Json(name = "workspace_id") val workspaceId: String? = null,
    @Json(name = "cloud_id") val cloudId: String? = null,
    @Json(name = "project_keys") val projectKeys: List<String> = emptyList(),
    @Json(name = "updated_at") val updatedAt: Long? = null,
)

/** PUT /integrations/jira/preferences body. */
data class JiraPreferencesReq(
    @Json(name = "workspace_id") val workspaceId: String,
    @Json(name = "cloud_id") val cloudId: String,
    @Json(name = "project_keys") val projectKeys: List<String>,
)

/** POST .../external-links/jira/link-existing body. */
data class JiraLinkExistingReq(
    @Json(name = "workspace_id") val workspaceId: String,
    @Json(name = "external_issue_key") val externalIssueKey: String? = null,
    @Json(name = "external_issue_id") val externalIssueId: String? = null,
    @Json(name = "link_mode") val linkMode: String = "bidirectional",
)

/** POST .../external-links/jira/link-existing (and create) -> the created link. */
data class JiraLinkResp(
    @Json(name = "ticket_id") val ticketId: String? = null,
    @Json(name = "link_id") val linkId: String? = null,
    @Json(name = "provider") val provider: String? = null,
    @Json(name = "external_issue_id") val externalIssueId: String? = null,
    @Json(name = "external_issue_key") val externalIssueKey: String? = null,
    @Json(name = "link_mode") val linkMode: String? = null,
    @Json(name = "sync_state") val syncState: String? = null,
)

/** DELETE .../external-links/{link_id} -> unlink confirmation. */
data class JiraUnlinkResp(
    @Json(name = "ticket_id") val ticketId: String? = null,
    @Json(name = "link_id") val linkId: String? = null,
    @Json(name = "sync_state") val syncState: String? = null,
)

/** GET /tickets/{id}/sync-status -> the current external-link sync status. */
data class TicketSyncStatusResp(
    @Json(name = "ticket_id") val ticketId: String,
    @Json(name = "linked") val linked: Boolean = false,
    @Json(name = "provider") val provider: String? = null,
    @Json(name = "sync_state") val syncState: String = "not_linked",
    @Json(name = "link_id") val linkId: String? = null,
    @Json(name = "external_issue_id") val externalIssueId: String? = null,
    @Json(name = "external_issue_key") val externalIssueKey: String? = null,
    @Json(name = "jira_status") val jiraStatus: String? = null,
    @Json(name = "last_synced_at") val lastSyncedAt: Long? = null,
    @Json(name = "conflict_fields") val conflictFields: List<String> = emptyList(),
    @Json(name = "conflict_local_values") val conflictLocalValues: Map<String, Any?> = emptyMap(),
    @Json(name = "conflict_remote_values") val conflictRemoteValues: Map<String, Any?> = emptyMap(),
)

/** POST .../external-links/{link_id}/resolve-conflict body. */
data class JiraConflictResolveReq(
    @Json(name = "workspace_id") val workspaceId: String,
    @Json(name = "action") val action: String,
    @Json(name = "current_ticket") val currentTicket: Map<String, Any?> = emptyMap(),
)

/** POST .../resolve-conflict -> the resolved link (sync_state is always "in_sync"). */
data class JiraConflictResolveResp(
    @Json(name = "ticket_id") val ticketId: String? = null,
    @Json(name = "link_id") val linkId: String? = null,
    @Json(name = "action") val action: String? = null,
    @Json(name = "resolved_fields") val resolvedFields: List<String> = emptyList(),
    @Json(name = "sync_state") val syncState: String? = null,
    @Json(name = "follow_up_tasks") val followUpTasks: Int = 0,
)

/**
 * JIRA-AND-1 - the documented RAW-String constants for the enum-like wire fields. These are NOT Kotlin enums
 * (unknown-safe): a value not listed here still decodes fine and the UI falls back to the raw token.
 */
object JiraConstants {
    object SyncState {
        const val NOT_LINKED = "not_linked"
        const val QUEUED = "queued"
        const val IN_SYNC = "in_sync"
        const val CONFLICT = "conflict"
        const val FAILED = "failed"
    }

    object LinkMode {
        const val PUSH_ONLY = "push_only"
        const val PULL_ONLY = "pull_only"
        const val BIDIRECTIONAL = "bidirectional"
    }

    object ConnectionStatus {
        const val ACTIVE = "active"
    }

    object ResolveAction {
        const val KEEP_INTERNAL = "keep_internal"
        const val KEEP_JIRA = "keep_jira"
    }

    /** The OAuth callback result tokens. */
    object CallbackStatus {
        const val CONNECTED = "connected"
        const val FAILED = "failed"
    }
}
