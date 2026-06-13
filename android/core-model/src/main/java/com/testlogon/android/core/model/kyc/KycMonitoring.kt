package com.testlogon.android.core.model.kyc

/**
 * AND-329 - transport DTOs for the READ-ONLY KYC ongoing-monitoring surface
 * (the review schedule + recent trigger events that drive the monitoring banner).
 *
 * RECONCILIATION NOTE (identical to AND-319's Kyc.kt / AND-321..328): core-model has NO Moshi dependency and
 * NO Moshi codegen, so these DTOs carry NO annotations. The production Moshi (core-network
 * NetworkModule.provideMoshi) decodes them via the reflective KotlinJsonAdapterFactory, which maps Kotlin
 * property names to JSON keys VERBATIM. Every property below is therefore named EXACTLY as the snake_case wire
 * key (schedule, case_id, status, next_review_date, grace_deadline, last_review_date, events, event_id,
 * trigger_type, created_at, note). Zero annotations, zero new dependencies. Optional wire fields are nullable
 * (or empty-collection) with a default; the only required field is [KycReviewScheduleDto.status] (present iff a
 * schedule object is present). Extra/unknown wire fields are tolerated leniently.
 *
 * Wire contract (verified; cookie + CSRF + Bearer attached globally):
 *   GET v1/kyc/monitoring/schedule -> 200 KycReviewScheduleEnvelopeDto { schedule? }
 *   GET v1/kyc/monitoring/triggers -> 200 KycTriggerEventListEnvelopeDto { events[] }
 *
 * All date fields are epoch-SECOND Longs (NOT Instant/ISO) so JVM unit tests need no java.time; the feature
 * mapper converts them to Instant. Both endpoints are idempotent GETs (READ-ONLY).
 */

/** GET v1/kyc/monitoring/schedule envelope: the optional review schedule (absent key -> null). */
data class KycReviewScheduleEnvelopeDto(
    val schedule: KycReviewScheduleDto? = null,
)

/**
 * The ongoing-monitoring review schedule for a case. Only [status] is REQUIRED (no default) so a present-but-
 * malformed schedule object fails fast with a JsonDataException; everything else is optional. The wire status
 * token is a plain String here (the lenient mapping lives in the feature domain mapper).
 */
data class KycReviewScheduleDto(
    val case_id: String? = null,
    val status: String,
    val next_review_date: Long? = null,
    val grace_deadline: Long? = null,
    val last_review_date: Long? = null,
)

/** GET v1/kyc/monitoring/triggers envelope: the recent trigger events (absent key -> empty list). */
data class KycTriggerEventListEnvelopeDto(
    val events: List<KycTriggerEventDto> = emptyList(),
)

/**
 * A single ongoing-monitoring trigger event (e.g. a periodic-review-due or risk-change event). All fields are
 * optional and leniently typed: the wire shape varies by trigger source and the feature only needs the
 * presence + a best-effort label.
 */
data class KycTriggerEventDto(
    val event_id: String? = null,
    val trigger_type: String? = null,
    val case_id: String? = null,
    val created_at: Long? = null,
    val note: String? = null,
)
