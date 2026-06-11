package com.testlogon.android.data.broadcast

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.Response
import retrofit2.http.DELETE
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-279 — Retrofit interface for the broadcast remind-me write surface.
 *
 * VERIFIED against reference/openapi.index.txt and reference/src/api/endpoints/broadcastSchedule.ts:
 *  - POST   broadcast/sessions/{session_id}/remind-me  -> 200 (untyped; web types it {ok, remind_at}).
 *  - DELETE broadcast/sessions/{session_id}/remind-me  -> 200 (untyped; web types it {ok}).
 *
 * Kept separate from the AND-278 [BroadcastApi] read surface so the data-only slice stays untouched.
 * These are NON-idempotent writes: the CSRF header + cookies ride the shared interceptor chain; the
 * repository never auto-retries them. The session DTO carries NO `reminder_set` flag (verified), so
 * on-state is client/local only (AND-279 §16).
 */
interface BroadcastReminderApi {

    @POST("broadcast/sessions/{sessionId}/remind-me")
    suspend fun registerReminder(@Path("sessionId") sessionId: String): Response<ReminderResultDto>

    @DELETE("broadcast/sessions/{sessionId}/remind-me")
    suspend fun cancelReminder(@Path("sessionId") sessionId: String): Response<ReminderOkDto>
}

/** POST /remind-me 200 body — `{ ok, remind_at }` (remind_at is epoch SECONDS; both fields optional). */
@JsonClass(generateAdapter = true)
data class ReminderResultDto(
    val ok: Boolean = true,
    @Json(name = "remind_at") val remindAt: Long? = null,
)

/** DELETE /remind-me 200 body — `{ ok }` (also accepts a bare empty body). */
@JsonClass(generateAdapter = true)
data class ReminderOkDto(
    val ok: Boolean = true,
)
