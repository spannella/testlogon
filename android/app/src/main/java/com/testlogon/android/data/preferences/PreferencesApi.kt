package com.testlogon.android.data.preferences

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.PATCH

/**
 * AND-078 — Retrofit interface for UI preferences.
 *
 * Verified against OpenAPI + `src/api/endpoints/preferences.ts`:
 *  - GET   ui/settings/preferences -> {"preferences": {...}}        (op ui_get_preferences_...)
 *  - PATCH ui/settings/preferences <- PreferencesPatchReq -> {"ok"} (op ui_update_preferences_...)
 *
 * Paths are relative; cookies, Authorization and `X-CSRF-Token` are attached by the core-network
 * interceptor chain. Non-2xx surfaces as `retrofit2.HttpException`.
 */
interface PreferencesApi {

    @GET("ui/settings/preferences")
    suspend fun getPreferences(): PreferencesEnvelopeDto

    @PATCH("ui/settings/preferences")
    suspend fun updatePreferences(@Body body: UpdatePreferencesRequestDto): OkResponseDto
}
