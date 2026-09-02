package com.testlogon.android.core.network.jira

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.PUT
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * JIRA-AND-1 - Retrofit interface for the Jira integration surface. Transport only; the repository layer wraps
 * these RAW DTO returns into ApiResult and maps 404 to an honest not-connected empty. Mirrors the verified web
 * contract in frontend/src/api/endpoints/jira.ts.
 *
 * Paths have NO leading slash (relative to the shared authenticated Retrofit base URL, matching the rest of the
 * codebase). @Path token is EXACTLY {ticketId} / {linkId}. Retrofit drops a null @Query, so optional queries
 * (cursor / q) are sent only when non-null.
 *
 * The link / link-existing POSTs require an Idempotency-Key header (the web sends one per attempt); the caller
 * generates it. NON-idempotent POSTs / DELETE are excluded from the global GET-only retry backoff.
 */
interface JiraApi {

    /** GET the caller's Jira connections for a workspace. */
    @GET("integrations/jira/status")
    suspend fun status(
        @Query("workspace_id") workspaceId: String,
    ): JiraStatusResp

    /** POST begin an OAuth connect; returns the authorize URL + opaque state. */
    @POST("integrations/jira/connect")
    suspend fun connect(
        @Body body: JiraConnectReq,
    ): JiraConnectResp

    /** GET complete the OAuth callback (code + state echoed from the redirect). */
    @GET("integrations/jira/callback")
    suspend fun callback(
        @Query("code") code: String,
        @Query("state") state: String,
    ): JiraCallbackResp

    /** POST disconnect a connection. */
    @POST("integrations/jira/disconnect")
    suspend fun disconnect(
        @Body body: JiraDisconnectReq,
    ): Map<String, Any?>

    /** GET discover projects for a connected cloud. */
    @GET("integrations/jira/projects")
    suspend fun projects(
        @Query("workspace_id") workspaceId: String,
        @Query("cloud_id") cloudId: String,
        @Query("limit") limit: Int = 100,
        @Query("cursor") cursor: String? = null,
    ): JiraProjectsResp

    /** GET the saved project-key preferences for a cloud. */
    @GET("integrations/jira/preferences")
    suspend fun getPreferences(
        @Query("workspace_id") workspaceId: String,
        @Query("cloud_id") cloudId: String,
    ): JiraPreferencesResp

    /** PUT the project-key preferences for a cloud. */
    @PUT("integrations/jira/preferences")
    suspend fun putPreferences(
        @Body body: JiraPreferencesReq,
    ): JiraPreferencesResp

    /** GET the current sync status for a ticket (not_linked when unlinked). */
    @GET("tickets/{ticketId}/sync-status")
    suspend fun ticketSyncStatus(
        @Path("ticketId") ticketId: String,
    ): TicketSyncStatusResp

    /** POST link an EXISTING Jira issue to a ticket (requires an Idempotency-Key). */
    @POST("tickets/{ticketId}/external-links/jira/link-existing")
    suspend fun linkExisting(
        @Path("ticketId") ticketId: String,
        @Header("Idempotency-Key") idempotencyKey: String,
        @Body body: JiraLinkExistingReq,
    ): JiraLinkResp

    /** DELETE unlink an external link from a ticket. */
    @DELETE("tickets/{ticketId}/external-links/{linkId}")
    suspend fun unlink(
        @Path("ticketId") ticketId: String,
        @Path("linkId") linkId: String,
    ): JiraUnlinkResp

    /** POST resolve a sync conflict (keep_internal / keep_jira). */
    @POST("tickets/{ticketId}/external-links/{linkId}/resolve-conflict")
    suspend fun resolveConflict(
        @Path("ticketId") ticketId: String,
        @Path("linkId") linkId: String,
        @Body body: JiraConflictResolveReq,
    ): JiraConflictResolveResp
}
