package com.testlogon.android.core.network.projects

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-374 - Retrofit interface for the PROJECTS read surface + the account-scoped Google Drive provider OAuth
 * handshake. Transport only; the AND-374 ProjectsRepository (in :app) wraps these RAW DTO returns into
 * ApiResult via the established call{} pattern.
 *
 * Paths have NO leading slash (relative to the shared Retrofit base URL). @Path tokens are EXACTLY
 * {projectId} / {provider}. The shared authenticated client attaches the session cookie + X-CSRF-Token via the
 * global interceptors (AND-027). listProjects / getProject / getProjectDetail / getProviderCredential are
 * idempotent GETs (eligible for the global GET-only retry backoff); the start / callback POSTs are
 * NON-idempotent (the global retry intentionally excludes them - retry is user-driven only).
 *
 * CORRECTED contract (spec §5 / §16): paths are /v1/projects (NOT /ui/projects); the Drive OAuth start/callback
 * are ACCOUNT-scoped (no {projectId} segment) under v1/projects/providers/google_drive/oauth/{start,callback};
 * `start` has an EMPTY request body; the callback returns a ProviderCredentialOut (NOT a project); the list
 * cursor field is `cursor` (NOT next_cursor).
 */
interface ProjectsApi {

    /** GET the caller's projects (paginated envelope { items, cursor }). Pass [cursor] for the next page. */
    @GET("v1/projects")
    suspend fun listProjects(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 20,
    ): ProjectListEnvelope

    /** GET one project (bare ProjectOut). Idempotent. */
    @GET("v1/projects/{projectId}")
    suspend fun getProject(
        @Path("projectId") projectId: String,
    ): ProjectOut

    /**
     * GET the project detail used by the web reference ({ project, files[], cursor }). `files[]` is the
     * AND-336 Files-epic surface and is ignored by the domain mapper here. Idempotent.
     */
    @GET("v1/projects/{projectId}/detail")
    suspend fun getProjectDetail(
        @Path("projectId") projectId: String,
        @Query("limit") limit: Int = 20,
        @Query("cursor") cursor: String? = null,
    ): ProjectDetailEnvelope

    /**
     * POST the account-scoped Google Drive OAuth START. The request body is EMPTY (no redirect_uri - spec §16
     * item 6); the response carries the authorization_url to open + the state for the callback CSRF check.
     * NON-idempotent (no auto-retry).
     */
    @POST("v1/projects/providers/google_drive/oauth/start")
    suspend fun startGoogleDrive(): ProviderOAuthStartOut

    /**
     * POST the account-scoped Google Drive OAuth CALLBACK with the captured {code, state}. Returns a
     * ProviderCredentialOut (NOT a project - spec §16 item 8). NON-idempotent (no auto-retry).
     */
    @POST("v1/projects/providers/google_drive/oauth/callback")
    suspend fun completeGoogleDrive(
        @Body body: ProviderOAuthCallbackIn,
    ): ProviderCredentialOut

    /**
     * GET the connected-provider credential (ProviderCredentialOut). Because ProjectOut carries no provider
     * list, the "is Drive connected" state is read here; a 404 / error indicates not connected. Idempotent.
     */
    @GET("v1/projects/providers/{provider}/credentials")
    suspend fun getProviderCredential(
        @Path("provider") provider: String,
        @Query("org") org: String? = null,
    ): ProviderCredentialOut
}
