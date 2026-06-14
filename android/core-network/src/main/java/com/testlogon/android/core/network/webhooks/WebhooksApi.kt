package com.testlogon.android.core.network.webhooks

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-398 - Retrofit interface for the WEBHOOKS config (light) READ + light-CREATE surface. Transport only; the
 * AND-398 :app repository wraps these RAW DTO returns into ApiResult via the established call{} pattern.
 *
 * Paths have NO leading slash (relative to the shared Retrofit base URL, matching the rest of the codebase).
 * The @Path token is EXACTLY {endpointId} and maps to the wire path param `endpoint_id` (CORRECTED: the draft
 * used {id}). The shared authenticated client (AND-027) attaches the session cookie jar, `Authorization:
 * Bearer <token>` and `X-CSRF-Token` (from the ui_csrf cookie) on EVERY request via the global interceptors -
 * there is NO per-call header wiring here and NO new auth/network plumbing is added by this ticket.
 *
 * RETURN SHAPES (OpenAPI / frontend-verified - see the AND-398 CORRECTED contract):
 *  - list() returns a BARE ARRAY of [WebhookEndpointDto] (NO {webhooks:[...]} envelope).
 *  - get() returns a bare [WebhookEndpointDto] (same shape as a list element).
 *  - create() returns the created [WebhookEndpointDto] on HTTP 201 (the web client deserializes it; the
 *    one-time signing `secret`, if present, appears here).
 *  - eventTypes() returns the NAMED [EventTypesDto] envelope { event_types: [{type, description}] }.
 *
 * RETRY: list() / get() / eventTypes() are idempotent suspend GETs eligible for the shared GET-only bounded
 * backoff. create() is a NON-idempotent POST (no idempotency key) and is intentionally excluded from the
 * GET-only retry - a failed create surfaces inline for a user-driven retry.
 */
interface WebhooksApi {

    /** GET the caller's webhook endpoints (BARE ARRAY, NOT an envelope). Idempotent. */
    @GET("ui/webhooks")
    suspend fun list(): List<WebhookEndpointDto>

    /** GET one webhook endpoint by id (bare object). @Path token maps to the wire `endpoint_id`. Idempotent. */
    @GET("ui/webhooks/{endpointId}")
    suspend fun get(@Path("endpointId") endpointId: String): WebhookEndpointDto

    /**
     * POST a LIGHT create (url + event_types only). Returns the created endpoint (HTTP 201). NON-idempotent ->
     * NO auto-retry (the repo excludes it; the caller decides whether to re-send).
     */
    @POST("ui/webhooks")
    suspend fun create(@Body body: CreateWebhookRequest): WebhookEndpointDto

    /** GET the enumerable subscribable event types (NAMED {event_types} envelope) for the create multi-select. */
    @GET("ui/webhooks/event-types")
    suspend fun eventTypes(): EventTypesDto
}
