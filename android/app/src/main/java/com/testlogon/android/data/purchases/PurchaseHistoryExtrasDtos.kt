package com.testlogon.android.data.purchases

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-218-extras — wire DTOs for the purchase-history EXTRA surfaces surfaced on the transaction
 * detail screen: the transaction event timeline and the receipt link. (Carrier tracking already has
 * its own dedicated data/tracking layer — AND-215 — and is NOT re-declared here.)
 *
 * Verified backend contract (app/routers/purchase_history.py):
 *  - GET ui/purchase-history/transactions/{txn_id}/events
 *      -> { "txn_id": str, "events": [ <purchase_events item> ] }
 *      each event item (app/services/purchase_history._record_event put_item):
 *        { pk, sk, txn_id, user_sub, event_name (str), payload (obj), created_at (epoch SECONDS) }
 *      Only event_name + created_at + payload are surfaced; the rest are storage keys and ignored.
 *  - GET ui/purchase-history/transactions/{txn_id}/tracking  (already modeled by data/tracking).
 *  - GET ui/purchase-history/transactions/{txn_id}/receipt   (schema ReceiptLinkOut)
 *      -> { txn_id, receipt_path (str), receipt_url (str), generated_at (epoch SECONDS) }
 *
 * All three degrade on 404 (a txn with no events / no receipt yet). Money/timestamps mirror the rest of
 * the purchases surface: epoch SECONDS as Long. Unknown keys are tolerated (Moshi codegen default) so
 * additive backend evolution never throws.
 */

/** One transaction event row (subset of the purchase_events item that the UI renders). */
@JsonClass(generateAdapter = true)
data class PurchaseEventDto(
    // The raw backend event name, e.g. "created" / "completed" / "shipping_updated". May be absent
    // on malformed/legacy rows -> mapped to an Unknown label, never dropped.
    @Json(name = "event_name") val eventName: String? = null,
    // epoch SECONDS.
    @Json(name = "created_at") val createdAt: Long? = null,
    // Free-form event payload (note/reason/processor_ref/...). Kept as a raw map; rendered best-effort.
    @Json(name = "payload") val payload: Map<String, Any?>? = null,
)

/** Response envelope for the events endpoint (a `txn_id` + a bare `events` array). */
@JsonClass(generateAdapter = true)
data class PurchaseEventsResponseDto(
    @Json(name = "txn_id") val txnId: String? = null,
    @Json(name = "events") val events: List<PurchaseEventDto>? = null,
)

/** Response body for the receipt endpoint (schema ReceiptLinkOut). */
@JsonClass(generateAdapter = true)
data class PurchaseReceiptDto(
    @Json(name = "txn_id") val txnId: String? = null,
    @Json(name = "receipt_path") val receiptPath: String? = null,
    @Json(name = "receipt_url") val receiptUrl: String? = null,
    // epoch SECONDS.
    @Json(name = "generated_at") val generatedAt: Long? = null,
)
