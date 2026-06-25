package com.testlogon.android.core.network.apikeys

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST

/**
 * B-APIKEY (batch 7) - Retrofit interface for the developer API-keys management surface. Transport only; the
 * :app repository wraps these RAW DTO returns into ApiResult via the established call{} pattern (mirrors the
 * AND-398 WebhooksApi).
 *
 * Paths have NO leading slash (relative to the shared Retrofit base URL, matching the rest of the codebase). The
 * shared authenticated client (AND-027) attaches the session cookie jar, `Authorization: Bearer <token>` and
 * `X-CSRF-Token` (from the ui_csrf cookie) on EVERY request via the global interceptors - there is NO per-call
 * header wiring here and NO new auth/network plumbing is added.
 *
 * RETRY: [list] is an idempotent suspend GET eligible for the shared GET-only bounded backoff. [create] and
 * [revoke] are NON-idempotent POSTs (no idempotency key) intentionally excluded from auto-retry - a failure
 * surfaces for a user-driven retry.
 */
interface ApiKeysApi {

    /** GET the caller's (non-revoked) API keys. NAMED {keys:[...]} envelope. Idempotent. */
    @GET("ui/api_keys")
    suspend fun list(): ApiKeysListDto

    /**
     * POST a new API key. Returns the created key WITH the one-time `key_secret` (HTTP 200). NON-idempotent ->
     * NO auto-retry. May return 401 "Fresh MFA required" when the caller has MFA factors configured.
     */
    @POST("ui/api_keys")
    suspend fun create(@Body body: CreateApiKeyRequest): CreateApiKeyResultDto

    /** POST a revoke. Returns {"ok":true}. NON-idempotent. May require fresh MFA (401). */
    @POST("ui/api_keys/revoke")
    suspend fun revoke(@Body body: RevokeApiKeyRequest)
}
