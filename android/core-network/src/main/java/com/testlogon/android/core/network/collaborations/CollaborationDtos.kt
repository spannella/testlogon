package com.testlogon.android.core.network.collaborations

import com.squareup.moshi.Json

/**
 * AND-358 - transport DTOs for the READ-ONLY collaborations surface (a two-party revenue-sharing agreement).
 *
 * CODEGEN NOTE (identical to AND-356 SyndicateDtos): core-network does NOT apply the Moshi KSP codegen
 * plugin, so these DTOs decode via the reflective KotlinJsonAdapterFactory registered on the shared Moshi in
 * NetworkModule.provideMoshi. The reflective factory maps Kotlin property names to JSON keys VERBATIM (Moshi
 * does NOT auto snake_case), so every wire key is pinned with an explicit @Json(name = ...).
 * @JsonClass(generateAdapter = true) is intentionally OMITTED.
 *
 * Optional fields are nullable with null defaults; required wire fields have NO default so a missing key
 * surfaces as a JsonDataException. Extra/unknown wire keys are tolerated leniently by the reflective adapter.
 *
 * WIRE CONTRACT (OpenAPI / frontend-verified - a collaboration is a TWO-PARTY agreement):
 *   GET ui/collaborations                       -> CollaborationListOut {items/collaborations[], next_cursor?}
 *   GET ui/collaborations/{collabId}            -> CollaborationOut
 *   GET ui/collaborations/{collabId}/splits     -> CollabSplitHistoryOut {records[]}
 *
 * KEY POINTS:
 *  - `collab_id` is the canonical id; `id` is accepted as a fallback (the resolved id is computed in the
 *    core-model mapper).
 *  - `status` is a FREE string on the wire (kept RAW; the typed CollabStatus + UNKNOWN fallback lives in
 *    core-model). Do NOT assume the value set.
 *  - `split` is a userId -> integer PERCENT map (0-100, NOT basis points). The viewer's share is
 *    split[currentUserId] when present; sum==100 is checked (a non-100 total is a NON-blocking warning).
 *  - `created_at` / `updated_at` are INTEGER epoch-SECONDS (Long).
 *  - The split-history records carry per-distribution `amount_cents` (Int) rendered with MoneyFormat.
 *
 * There is NO participant_count, NO participants[], and NO per-party display_name / role on the wire.
 *
 * ROOM DECISION: there is NO Room cache and NO migration this wave - the list is a network Paging-3
 * PagingSource and the detail keeps an in-memory last-good snapshot with an isStale flag. Room persistence
 * across process death is DEFERRED.
 */

/**
 * One collaboration (a two-party agreement). `collab_id` is canonical; `id` is a tolerated fallback. `status`
 * is a FREE string (kept raw). `split` is a userId -> integer PERCENT (0-100) map. `created_at` /
 * `updated_at` are INTEGER epoch-seconds.
 */
data class CollaborationOut(
    @Json(name = "collab_id") val collabId: String? = null,
    @Json(name = "id") val id: String? = null,
    @Json(name = "title") val title: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "initiator_id") val initiatorId: String? = null,
    @Json(name = "recipient_id") val recipientId: String? = null,
    @Json(name = "split") val split: Map<String, Int>? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "updated_at") val updatedAt: Long? = null,
)

/**
 * The collaboration list envelope. The backend may key the page under `items` OR `collaborations`; both are
 * tolerated (the mapper coalesces them). `next_cursor` is the opaque Paging-3 cursor (null/blank terminates).
 */
data class CollaborationListOut(
    @Json(name = "items") val items: List<CollaborationOut>? = null,
    @Json(name = "collaborations") val collaborations: List<CollaborationOut>? = null,
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

/**
 * The split-history envelope (optional distributions). `records` is the list of historical split records;
 * each record carries the per-party distributions with their `amount_cents`.
 */
data class CollabSplitHistoryOut(
    @Json(name = "records") val records: List<CollabSplitRecord>? = null,
)

/**
 * One split-history record. `distributions` is the per-party breakdown for this record; the optional
 * `record_id` / `created_at` are retained for completeness (relative-time is not required by the screen).
 */
data class CollabSplitRecord(
    @Json(name = "record_id") val recordId: String? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "distributions") val distributions: List<CollabSplitDistribution>? = null,
)

/**
 * One per-party distribution within a split record. `percentage` is the party's integer percent; `amount_cents`
 * is the disbursed amount in minor units (Int), rendered with MoneyFormat.formatCents when present.
 */
data class CollabSplitDistribution(
    @Json(name = "user_id") val userId: String? = null,
    @Json(name = "percentage") val percentage: Int? = null,
    @Json(name = "amount_cents") val amountCents: Int? = null,
)
