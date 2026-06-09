package com.testlogon.android.data.preferences

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST

/**
 * AND-080 — Retrofit interface for per-alert-type notification preferences.
 *
 * Verified against OpenAPI:
 *  - GET  ui/alerts/type-preferences  (op get_type_preferences_...; response untyped)
 *  - POST ui/alerts/type-preferences <- AlertTypePreferenceUpdate (op update_type_preferences_...)
 *
 * One alert type per POST. The GET response is untyped server-side; we decode tolerantly.
 */
interface NotificationPreferencesApi {

    @GET("ui/alerts/type-preferences")
    suspend fun getTypePreferences(): AlertTypePreferencesEnvelopeDto

    @POST("ui/alerts/type-preferences")
    suspend fun updateTypePreference(@Body body: AlertTypePreferenceUpdateDto): OkResponseDto
}
