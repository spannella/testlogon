package com.testlogon.android.data.dashboard

import retrofit2.http.GET
import retrofit2.http.POST

/**
 * AND-065 — Retrofit interface for the creator dashboard surface.
 *
 * Paths are relative (no leading slash) so they resolve against the shared Retrofit base URL;
 * cookies, Authorization and `X-CSRF-Token` are attached by the core-network interceptor chain.
 * All methods are `suspend` and return the typed DTO body; non-2xx surfaces as
 * `retrofit2.HttpException`.
 *
 * Endpoints verified against src/api/endpoints/dashboard.ts and OpenAPI:
 *  - getDashboard -> GET ui/dashboard/summary (op dashboard_summary_ui_dashboard_summary_get)
 *  - refreshDashboard -> POST ui/dashboard/refresh (op dashboard_refresh_ui_dashboard_refresh_post)
 */
interface DashboardApi {

    /** Authenticated creator dashboard summary. Idempotent GET. */
    @GET("ui/dashboard/summary")
    suspend fun getDashboard(): DashboardSummaryDto

    /**
     * Server-side refresh trigger (web calls this then refetches the summary). Non-idempotent,
     * rate-limited; only fired by an explicit user refresh, never auto-retried.
     */
    @POST("ui/dashboard/refresh")
    suspend fun refreshDashboard(): RefreshAckDto
}
