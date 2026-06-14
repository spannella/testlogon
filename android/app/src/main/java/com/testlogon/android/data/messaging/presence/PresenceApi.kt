package com.testlogon.android.data.messaging.presence

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Query

/**
 * AND-145 — Retrofit interface for messaging presence.
 *
 * Relative paths (no leading slash) resolve against the shared Retrofit base URL; cookies +
 * Authorization + X-CSRF-Token are attached by the core-network interceptor chain (no per-method
 * auth headers). Paths verified in openapi.index.txt + reference/src/api/endpoints/messaging.ts.
 */
interface PresenceApi {

    /** Report the local user online. Mutating POST → CSRF attached by the shared interceptor. */
    @Headers("Content-Type: application/json")
    @POST("messaging/presence/heartbeat")
    suspend fun heartbeat(@Body body: HeartbeatReq = HeartbeatReq()): HeartbeatResp

    /** Seed presence for a set of peers (comma-joined ids). Returns a BARE array. Idempotent GET. */
    @GET("messaging/presence")
    suspend fun getPresence(@Query("user_ids") userIds: String): List<PresenceDto>
}
