package com.testlogon.android.data.preferences

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.PUT

/**
 * AND-079 — Retrofit interface for call media preferences.
 *
 * Verified against OpenAPI + `src/api/endpoints/mediaPreferences.ts`:
 *  - GET ui/media/preferences -> MediaPreferencesOut (op ui_get_media_preferences_...)
 *  - PUT ui/media/preferences <- MediaPreferencesIn -> MediaPreferencesOut (op ui_save_media_...)
 *
 * Note the write verb is PUT (full-state replace), not PATCH.
 */
interface MediaPreferencesApi {

    @GET("ui/media/preferences")
    suspend fun getMediaPreferences(): MediaPreferencesOutDto

    @PUT("ui/media/preferences")
    suspend fun saveMediaPreferences(@Body body: MediaPreferencesInDto): MediaPreferencesOutDto
}
