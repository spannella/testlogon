package com.testlogon.android.data.gcal

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Query

/**
 * AND-273 — Retrofit interface for the backend-mediated Google Calendar integration.
 *
 * Verified against openapi.index.txt lines 1260-1266 and src/api/endpoints/calendar.ts google helpers.
 * Paths are relative (no leading slash); cookies / CSRF (on mutations) / auth are attached by the shared
 * interceptor chain. connect/start, disconnect, mappings and sync/run are POSTs; status, calendars and
 * the OAuth callback are GETs. The callback is normally hit server-side off the provider redirect; the
 * client only drives it when a custom-scheme deep link is wired. `connect/start`/`disconnect`/`sync/run`
 * take empty JSON bodies in the web client; only `mappings` carries a real body.
 */
interface GoogleCalendarApi {

    @POST("ui/calendar/integrations/google/connect/start")
    suspend fun connectStart(): ConnectStartDto

    @GET("ui/calendar/integrations/google/connect/callback")
    suspend fun connectCallback(
        @Query("code") code: String? = null,
        @Query("state") state: String? = null,
        @Query("error") error: String? = null,
    ): ConnectCallbackDto

    @GET("ui/calendar/integrations/google/status")
    suspend fun status(): IntegrationStatusDto

    @GET("ui/calendar/integrations/google/calendars")
    suspend fun listProviderCalendars(): ProviderCalendarsDto

    @Headers("Content-Type: application/json")
    @POST("ui/calendar/integrations/google/mappings")
    suspend fun createMapping(@Body body: MappingCreateDto): MappingDto

    @POST("ui/calendar/integrations/google/disconnect")
    suspend fun disconnect(@Query("connection_id") connectionId: String? = null): DisconnectDto

    @POST("ui/calendar/integrations/google/sync/run")
    suspend fun runSync(@Query("mode") mode: String = "incremental"): SyncRunDto
}
