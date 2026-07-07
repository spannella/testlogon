package com.testlogon.android.data.ads

import retrofit2.http.Body
import retrofit2.http.POST

/**
 * ADV-106 — Retrofit client for ad-serving impression/click tracking.
 *
 * Path is relative to the shared Retrofit base URL; the core-network interceptor chain attaches the UI
 * session cookie / Bearer / CSRF (the route is behind require_ui_session). Suspend, returns the typed
 * body; non-2xx surfaces as retrofit2.HttpException.
 */
interface AdTrackApi {

    /** Record one ad event (impression|click|...) for a served sponsored unit. */
    @POST("ui/ads/track")
    suspend fun track(@Body body: AdTrackEventDto): AdTrackResultDto
}
