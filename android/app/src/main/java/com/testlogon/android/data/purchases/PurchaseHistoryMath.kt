package com.testlogon.android.data.purchases

/**
 * AND-218-extras — PURE, framework-free logic for the purchase-history extra surfaces (event timeline +
 * receipt link), plus tracking-status/step formatting helpers. No Android / java.time types, so every
 * function here is JVM-unit-testable. DTO -> render-ready model mapping lives here so the ViewModel /
 * screen never see raw DTOs.
 *
 * Design rules (mirrors the rest of the purchases surface):
 *  - Degrade, never throw: an absent event_name maps to an Unknown label; a blank/relative receipt URL
 *    is reported as not-openable rather than crashing the CTA.
 *  - Timestamps are Long epoch SECONDS, passed through unchanged (the presentation layer formats them
 *    with the existing formatEpochSeconds helper). 0/absent is preserved as null.
 *  - Event labels are derived from the raw backend event_name (snake_case) with a small known-name map
 *    and a Title-Cased fallback for anything unrecognized.
 */

// ---- Event timeline ----

/** One render-ready transaction event. [label] is always non-blank (Unknown fallback). */
data class PurchaseEvent(
    /** Human label for the event (e.g. "Order created", "Payment completed"). Never blank. */
    val label: String,
    /** epoch SECONDS, or null when the wire row carried no usable timestamp. */
    val atEpochSec: Long?,
    /** A short one-line detail pulled from the payload (note/reason/...); null when none. */
    val detail: String?,
)

/**
 * Maps a raw backend event_name (snake_case) to a human label. Known names get a curated label; unknown
 * names fall back to a Title-Cased de-underscored form ("shipping_updated" -> "Shipping updated"). A
 * null/blank name maps to "Update" so the row is never dropped or blank.
 */
fun purchaseEventLabel(eventName: String?): String {
    val key = eventName?.trim()?.lowercase().orEmpty()
    if (key.isEmpty()) return "Update"
    return when (key) {
        "created", "transaction_created", "order_created" -> "Order created"
        "completed", "transaction_completed", "confirmed" -> "Payment completed"
        "confirm_received", "delivery_confirmed", "received" -> "Delivery confirmed"
        "reverted", "refunded", "transaction_reverted" -> "Refunded"
        "cancelled", "canceled", "cancel" -> "Cancelled"
        "cancel_requested", "cancel_request" -> "Cancellation requested"
        "cancel_denied" -> "Cancellation denied"
        "shipping_updated", "shipping_update", "shipment_updated" -> "Shipping updated"
        "shipped" -> "Shipped"
        "delivered" -> "Delivered"
        "receipt_generated" -> "Receipt generated"
        else -> titleCaseFromSnake(key)
    }
}

/** "shipping_updated" -> "Shipping updated"; de-underscored, first char of the whole string uppercased. */
internal fun titleCaseFromSnake(raw: String): String {
    val words = raw.split('_', '-', ' ').filter { it.isNotBlank() }
    if (words.isEmpty()) return "Update"
    val joined = words.joinToString(" ")
    return joined.replaceFirstChar { it.uppercase() }
}

/**
 * Extracts a short one-line detail from an event payload. Prefers common human-note keys in priority
 * order (note, reason, message, description, status, processor_ref); returns null when none is a
 * non-blank String. Never renders raw maps / nested objects.
 */
internal fun eventDetailFromPayload(payload: Map<String, Any?>?): String? {
    if (payload.isNullOrEmpty()) return null
    for (key in listOf("note", "reason", "message", "description", "status", "processor_ref")) {
        val v = payload[key]
        if (v is String && v.isNotBlank()) return v.trim()
    }
    return null
}

/** DTO -> render model for a single event. */
internal fun PurchaseEventDto.toDomain(): PurchaseEvent = PurchaseEvent(
    label = purchaseEventLabel(eventName),
    atEpochSec = createdAt?.takeIf { it > 0L },
    detail = eventDetailFromPayload(payload),
)

/**
 * Maps the events envelope to a newest-first list of render models. A null / empty events array yields
 * an empty list (degrade-on-404: the ViewModel treats an empty list as "no timeline" and hides the
 * section). Rows with a null timestamp sort last (they carry no ordering signal).
 */
fun PurchaseEventsResponseDto.toTimeline(): List<PurchaseEvent> =
    events.orEmpty()
        .map { it.toDomain() }
        .sortedByDescending { it.atEpochSec ?: Long.MIN_VALUE }

// ---- Receipt ----

/**
 * Render-ready receipt link. [isOpenable] gates the "Open / Download" CTA — true only when [url] is an
 * absolute http(s) URL that the open-with / Custom-Tabs idiom can actually launch. A blank or relative
 * receipt_url (dev-host / not-yet-generated) is surfaced as not-openable rather than crashing the CTA.
 */
data class PurchaseReceipt(
    val url: String?,
    val generatedAtEpochSec: Long?,
) {
    val isOpenable: Boolean
        get() = url?.let { isOpenableUrl(it) } == true
}

/** True when [url] is an absolute http(s) URL safe to hand to an ACTION_VIEW / Custom Tabs launch. */
internal fun isOpenableUrl(url: String?): Boolean {
    val u = url?.trim().orEmpty()
    return u.startsWith("http://", ignoreCase = true) || u.startsWith("https://", ignoreCase = true)
}

/**
 * DTO -> render model. A response with no usable url yields a receipt whose [PurchaseReceipt.isOpenable]
 * is false. Returns null only when the whole DTO is effectively empty (no url and no timestamp) so the
 * ViewModel can hide the receipt section entirely (degrade-on-404 parity).
 */
fun PurchaseReceiptDto.toReceiptOrNull(): PurchaseReceipt? {
    val cleanUrl = receiptUrl?.trim()?.takeIf { it.isNotBlank() }
    val at = generatedAt?.takeIf { it > 0L }
    if (cleanUrl == null && at == null) return null
    return PurchaseReceipt(url = cleanUrl, generatedAtEpochSec = at)
}

// ---- Tracking status / step formatting (pure; plain strings, not Android resources) ----

/**
 * Canonical tracking step ordering for a linear stepper. The domain ShipmentStatus lives in
 * data/tracking; this helper works off the raw wire status string so it stays dependency-free and
 * JVM-testable. Unknown -> [TrackingStep.UNKNOWN].
 */
enum class TrackingStep {
    PRE_TRANSIT, LABEL_CREATED, IN_TRANSIT, OUT_FOR_DELIVERY, DELIVERED, EXCEPTION, RETURNED, UNKNOWN,
    ;

    /** 0-based index into the happy-path stepper (EXCEPTION/RETURNED/UNKNOWN are off-path -> -1). */
    val stepIndex: Int
        get() = when (this) {
            PRE_TRANSIT -> 0
            LABEL_CREATED -> 1
            IN_TRANSIT -> 2
            OUT_FOR_DELIVERY -> 3
            DELIVERED -> 4
            EXCEPTION, RETURNED, UNKNOWN -> -1
        }
}

/** Number of steps on the happy-path stepper (pre-transit .. delivered). */
const val TRACKING_STEP_COUNT: Int = 5

/** Case-insensitive raw-status -> [TrackingStep]; unrecognized -> [TrackingStep.UNKNOWN]. */
fun trackingStepFromStatus(raw: String?): TrackingStep = when (raw?.lowercase()?.trim()) {
    "pre_transit", "pretransit" -> TrackingStep.PRE_TRANSIT
    "label_created", "labelcreated" -> TrackingStep.LABEL_CREATED
    "in_transit", "intransit" -> TrackingStep.IN_TRANSIT
    "out_for_delivery", "outfordelivery" -> TrackingStep.OUT_FOR_DELIVERY
    "delivered" -> TrackingStep.DELIVERED
    "exception" -> TrackingStep.EXCEPTION
    "returned" -> TrackingStep.RETURNED
    else -> TrackingStep.UNKNOWN
}

/** Human label for a tracking step (used by the timeline / stepper headline). */
fun trackingStepLabel(step: TrackingStep): String = when (step) {
    TrackingStep.PRE_TRANSIT -> "Pre-transit"
    TrackingStep.LABEL_CREATED -> "Label created"
    TrackingStep.IN_TRANSIT -> "In transit"
    TrackingStep.OUT_FOR_DELIVERY -> "Out for delivery"
    TrackingStep.DELIVERED -> "Delivered"
    TrackingStep.EXCEPTION -> "Exception"
    TrackingStep.RETURNED -> "Returned"
    TrackingStep.UNKNOWN -> "Unknown"
}

/**
 * Progress fraction (0f..1f) along the happy-path stepper for a raw status, for a linear progress bar.
 * Off-path states (exception/returned/unknown) report 0f. Delivered is 1f.
 */
fun trackingProgressFraction(raw: String?): Float {
    val idx = trackingStepFromStatus(raw).stepIndex
    if (idx < 0) return 0f
    return idx.toFloat() / (TRACKING_STEP_COUNT - 1).toFloat()
}
