package com.testlogon.android.core.model.webhooks

/**
 * AND-398 - domain models for the WEBHOOKS config (light) surface (outbound webhook endpoints).
 *
 * core-model has NO Moshi / core-network dependency: these are plain domain types. The DTO -> domain bridge
 * lives in the :app feature (WebhookMappers) since core-model cannot depend on core-network.
 *
 * TIME: [createdAt] is an EPOCH-SECONDS [Long] (the wire `created_at` is an epoch integer - see the AND-398
 * CORRECTED contract; relative-time formatting happens at the UI). It is kept a Long (NOT java.time.Instant) to
 * stay minSdk-24-safe and to keep JVM unit tests free of java.time, matching the rest of core-model. The
 * identifier [id] is the opaque, required wire `endpoint_id`.
 *
 * SECRET: [secretSet] is DERIVED at mapping time (dto.secret != null) - there is NO `secret_set` boolean on the
 * wire. [secret] carries the one-time signing secret returned on CREATE (null on list / detail); it is shown
 * once in-session and NEVER persisted or logged (AC-7 / §8).
 */
data class Webhook(
    val id: String,
    val url: String,
    val description: String = "",
    val events: List<String> = emptyList(),
    val enabled: Boolean = true,
    val secretSet: Boolean = false,
    val secret: String? = null,
    val createdAt: Long? = null,
)

/**
 * AND-398 - one subscribable event type (from GET ui/webhooks/event-types), used to populate the create-screen
 * multi-select. [type] is the wire token sent back in a create body; [description] is human copy (defaulted, so
 * a metadata row with no description still renders).
 */
data class WebhookEventType(
    val type: String,
    val description: String = "",
)

/**
 * PAR-26 - the outcome of a webhook test-send (POST ui/webhooks/{id}/test). The backend records a synthetic
 * delivery and reports the result WITHOUT throwing on an unreachable host, so [succeeded] is derived from the
 * wire `status` == "success" (a reserved/unreachable host comes back status="failed" with a populated
 * [error]). [responseCode] is null on a failed attempt; [durationMs] is best-effort.
 */
data class WebhookTestResult(
    val deliveryId: String? = null,
    val status: String,
    val responseCode: Int? = null,
    val error: String? = null,
    val durationMs: Long? = null,
) {
    /** True only when the backend reported a successful delivery (status == "success"). */
    val succeeded: Boolean get() = status.equals(STATUS_SUCCESS, ignoreCase = true)

    companion object {
        const val STATUS_SUCCESS = "success"
    }
}
