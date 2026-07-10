package com.testlogon.android.data.preferences

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST

/**
 * D2 - per-event PUSH preferences over the alert opt-in / opt-out model.
 *
 * Backend (LIVE hotfix, ecomd2):
 *   GET  ui/alerts/push_prefs -> { push_event_types, push_opt_out_event_types, default_push_event_types }
 *   POST ui/alerts/push_prefs <- { push_event_types?, push_opt_out_event_types? } -> full alert prefs
 *
 * Semantics:
 *  - default_push_event_types = the transactional events that are PUSH-ON by default (opt-OUT model:
 *    sold / order shipped / out-for-delivery / delivered / tips / subscription).
 *  - push_opt_out_event_types = the default-ON events the user has explicitly turned OFF.
 *  - push_event_types = explicit opt-IN for events that are OFF by default.
 *  A given event is push-enabled iff (default-ON and NOT opted-out) OR (explicitly opted-in).
 */
interface PushEventPrefsApi {
    @GET("ui/alerts/push_prefs")
    suspend fun getPushPrefs(): PushPrefsDto

    @POST("ui/alerts/push_prefs")
    suspend fun setPushPrefs(@Body body: PushPrefsUpdateDto): PushPrefsDto
}

@JsonClass(generateAdapter = true)
data class PushPrefsDto(
    @Json(name = "push_event_types") val pushEventTypes: List<String> = emptyList(),
    @Json(name = "push_opt_out_event_types") val pushOptOutEventTypes: List<String> = emptyList(),
    @Json(name = "default_push_event_types") val defaultPushEventTypes: List<String> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class PushPrefsUpdateDto(
    @Json(name = "push_event_types") val pushEventTypes: List<String>,
    @Json(name = "push_opt_out_event_types") val pushOptOutEventTypes: List<String>,
)
