package com.testlogon.android.data.webrtc

import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-291 — dedicated Retrofit interface for the TURN/STUN credential fetch.
 *
 * VERIFIED: it is a per-call POST with an empty body (openapi.index.txt L407;
 * reference/src/api/endpoints/messaging.ts: fetchTurnCredentials -> api.post(.../turn-credentials, {})).
 * Path is relative (resolves against the shared Retrofit base URL); cookies / Authorization / X-CSRF
 * are attached by the core-network interceptor chain. Because this is a POST (not an idempotent GET) the
 * project's GET-retry/backoff policy does NOT auto-apply.
 */
interface IceServersApi {

    @POST("messaging/messages/calls/{callId}/turn-credentials")
    suspend fun getTurnCredentials(@Path("callId") callId: String): TurnCredentialsDto
}
