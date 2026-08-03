package com.testlogon.android.core.network.webhooks

import com.squareup.moshi.Json

/**
 * AND-398 - transport DTOs for the WEBHOOKS config (light) surface (outbound webhook endpoints).
 *
 * CODEGEN NOTE (identical to AND-371 TicketDtos / AND-353 OrgDtos): core-network does NOT apply the Moshi KSP
 * codegen plugin, so these DTOs decode via the reflective KotlinJsonAdapterFactory registered on the shared
 * Moshi in NetworkModule.provideMoshi. The reflective factory maps Kotlin property names to JSON keys VERBATIM
 * (Moshi does NOT auto snake_case), so every wire key is pinned with an explicit @Json(name = ...).
 * @JsonClass(generateAdapter = true) is intentionally OMITTED.
 *
 * Required wire keys per the OpenAPI WebhookEndpointOut schema are `endpoint_id` and `url` (no default -> a
 * missing key surfaces a JsonDataException). Everything else is nullable with a null / empty-list default;
 * extra / unknown wire keys are tolerated leniently by the reflective adapter (the light feature ignores the
 * optional retry_policy / circuit-breaker fields entirely).
 *
 * TIME: `created_at` / `updated_at` are EPOCH SECONDS typed as Long (NOT ISO-8601 strings - see the AND-398
 * CORRECTED contract; the :app mapper does Instant.ofEpochSecond).
 *
 * SECRET: `secret` is a nullable String (anyOf [string, null]); it is typically null on list / detail and may
 * be populated once on create / rotation. There is NO `secret_set` boolean; secretSet is DERIVED in the mapper
 * (secret != null).
 *
 * WIRE CONTRACT (OpenAPI / frontend-verified; relative paths, NO leading slash):
 *   GET  ui/webhooks                 -> BARE ARRAY of WebhookEndpointDto (NO {webhooks:[...]} envelope)
 *   GET  ui/webhooks/{endpointId}    -> WebhookEndpointDto (bare object, same shape as a list element)
 *   POST ui/webhooks                 -> 201 WebhookEndpointDto (the created endpoint; may carry the secret)
 *   GET  ui/webhooks/event-types     -> EventTypesDto { event_types: [{type, description}] }
 */

/**
 * One outbound webhook endpoint (the OpenAPI WebhookEndpointOut). `endpoint_id` + `url` are required; the rest
 * default so the row renders defensively. `event_types` is the subscribed event-type list (NOT `events`);
 * `enabled` is the active flag (NOT `active`). The light feature ignores the optional retry_policy /
 * signature_version / circuit-breaker fields.
 */
data class WebhookEndpointDto(
    @Json(name = "endpoint_id") val endpointId: String,
    @Json(name = "url") val url: String,
    @Json(name = "description") val description: String? = null,
    @Json(name = "event_types") val eventTypes: List<String> = emptyList(),
    @Json(name = "enabled") val enabled: Boolean = true,
    @Json(name = "secret") val secret: String? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "updated_at") val updatedAt: Long? = null,
)

/**
 * AND-398 - request body for POST ui/webhooks (a LIGHT create). The only fields sent are the required `url`
 * and `event_types` (note the wire key is `event_types`, NOT `events`). "Light" means the optional backend
 * fields (description / retry_policy / signature_version / circuit_failure_threshold / a manual secret) are
 * intentionally left absent so the backend applies its defaults and generates the signing secret.
 */
data class CreateWebhookRequest(
    @Json(name = "url") val url: String,
    @Json(name = "event_types") val eventTypes: List<String>,
)

/**
 * Envelope for GET ui/webhooks/event-types (the body is {"event_types": [...]}, the only NAMED-envelope call in
 * this feature - the endpoint list itself is a bare array). Used to populate the create-screen multi-select.
 */
data class EventTypesDto(
    @Json(name = "event_types") val eventTypes: List<WebhookEventTypeDto> = emptyList(),
)

/**
 * One subscribable event type returned by GET ui/webhooks/event-types. `type` is the wire token sent back in a
 * create body; `description` is human copy. Both are nullable / defaulted so an unexpected metadata shape never
 * fails deserialization.
 */
data class WebhookEventTypeDto(
    @Json(name = "type") val type: String,
    @Json(name = "description") val description: String? = null,
)

/**
 * PAR-26 - result of POST ui/webhooks/{endpointId}/test (a synthetic delivery attempt).
 *
 * The backend records a delivery attempt and reports the outcome WITHOUT throwing on an unreachable host: a
 * delivery to a reserved / unreachable host returns HTTP 200 with `status:"failed"` (response_code / error
 * populated), NOT an HTTP error - so the caller surfaces `status` == "failed" as a failed delivery, not a
 * transport error. All fields except `status` are nullable (response_code is null on a failed attempt).
 */
data class WebhookTestResultDto(
    @Json(name = "delivery_id") val deliveryId: String? = null,
    @Json(name = "status") val status: String,
    @Json(name = "response_code") val responseCode: Int? = null,
    @Json(name = "response_body") val responseBody: String? = null,
    @Json(name = "error") val error: String? = null,
    @Json(name = "duration_ms") val durationMs: Long? = null,
)

/**
 * PAR-26 - result of POST ui/webhooks/{endpointId}/rotate-secret. `secret` is the NEW plaintext signing
 * secret, returned exactly ONCE (it is stored hashed server-side and is NEVER re-fetchable). It is surfaced
 * for a one-time in-session reveal and is NEVER cached / persisted / logged (mirrors the create-secret rule).
 */
data class WebhookRotateSecretDto(
    @Json(name = "secret") val secret: String,
)
