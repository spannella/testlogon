package com.testlogon.android.core.network.collaborations

import com.squareup.moshi.Json

/**
 * AND-358 / PAR-04 / FIN-011 - transport DTOs for the collaborations surface (a two-party revenue-sharing
 * agreement + its revenue-splitting / dispute layer).
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
 * WIRE CONTRACT (OpenAPI / frontend-verified - collaborations.ts + collaborationRevenue.ts):
 *   GET    ui/collaborations                                          -> CollaborationListOut
 *   GET    ui/collaborations/{collabId}                               -> CollaborationOut
 *   GET    ui/collaborations/{collabId}/splits                        -> CollabSplitHistoryOut {items[], next_cursor?}
 *   GET    ui/collaborations/{collabId}/revisions                     -> [CollaborationRevisionOut]
 *   GET    ui/collaborations/settings                                 -> CollaborationSettingsOut
 *   PUT    ui/collaborations/settings                                 -> CollaborationSettingsOut
 *   GET    ui/collaborations/{collabId}/content                       -> CollabContentListOut
 *   POST   ui/collaborations/{collabId}/content                       -> {ok, content_id, collaboration_id}
 *   DELETE ui/collaborations/{collabId}/content/{contentId}           -> {ok, ...}
 *   POST   ui/collaborations/{collabId}/content/{contentId}/revenue-event -> {ok, split}
 *   GET    ui/collaborations/{collabId}/disputes                      -> CollabDisputeListOut
 *   POST   ui/collaborations/{collabId}/splits/{splitId}/dispute      -> {ok, dispute_status}
 *   POST   ui/collaborations/{collabId}/disputes/{disputeId}/resolve  -> {ok, status, dispute}
 *
 * KEY POINTS:
 *  - `collab_id` is the canonical id; `id` is accepted as a fallback (resolved id computed in the mapper).
 *  - `status` is a FREE string on the wire (kept RAW; the typed enum + UNKNOWN fallback lives in core-model).
 *  - `split` is a userId -> integer PERCENT map (0-100, NOT basis points).
 *  - `created_at` / `updated_at` are INTEGER epoch-SECONDS (Long).
 *  - split records carry per-distribution `amount_cents` (Int) rendered with formatCents.
 */

/**
 * One collaboration (a two-party agreement). `collab_id` is canonical; `id` is a tolerated fallback. `status`
 * is a FREE string (kept raw). `split` is a userId -> integer PERCENT (0-100) map. `created_at` /
 * `updated_at` are INTEGER epoch-seconds.
 */
data class CollaborationOut(
    @Json(name = "collab_id") val collabId: String? = null,
    @Json(name = "collaboration_id") val collaborationId: String? = null,
    @Json(name = "id") val id: String? = null,
    @Json(name = "title") val title: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "initiator_id") val initiatorId: String? = null,
    @Json(name = "recipient_id") val recipientId: String? = null,
    @Json(name = "split") val split: Map<String, Int>? = null,
    @Json(name = "last_proposed_by") val lastProposedBy: String? = null,
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
 * The split-history envelope. The REAL backend keys the page under `items` with a `next_cursor` (FIN-011); an
 * older/alternate shape keyed it under `records`. BOTH are tolerated (the mapper coalesces `items` then
 * `records`) so a shape change never drops the section.
 */
data class CollabSplitHistoryOut(
    @Json(name = "items") val items: List<CollabSplitRecord>? = null,
    @Json(name = "records") val records: List<CollabSplitRecord>? = null,
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

/**
 * One split-history record. `distributions` is the per-party breakdown. FIN-011 adds the executed-split
 * metadata (`split_id`, `content_id`, `content_type`, `gross_amount_cents`, `source`, `dispute_status`); all
 * are optional/nullable so the older distributions-only shape still decodes. `record_id` is retained as a
 * fallback id when `split_id` is absent.
 */
data class CollabSplitRecord(
    @Json(name = "split_id") val splitId: String? = null,
    @Json(name = "record_id") val recordId: String? = null,
    @Json(name = "content_id") val contentId: String? = null,
    @Json(name = "content_type") val contentType: String? = null,
    @Json(name = "gross_amount_cents") val grossAmountCents: Int? = null,
    @Json(name = "source") val source: String? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "dispute_status") val disputeStatus: String? = null,
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

// ---------------------------------------------------------------------------
// PAR-04 - deal-action request bodies + the revision-history response DTO.
// ---------------------------------------------------------------------------

/**
 * PAR-04 - counter-offer request. `counter_split_pct` is the INITIATOR's proposed integer percent (1..99;
 * the recipient gets the remainder). Matches CollaborationCounterIn (models.py).
 */
data class CollaborationCounterIn(
    @Json(name = "counter_split_pct") val counterSplitPct: Int,
)

/** PAR-04 - terminate request. `reason` is an OPTIONAL free note. Matches CollaborationTerminateIn. */
data class CollaborationTerminateIn(
    @Json(name = "reason") val reason: String? = null,
)

/**
 * PAR-04 - one prior negotiation revision (an element of the GET .../revisions ARRAY). `split` is the proposed
 * userId -> integer percent map at that step; `proposed_by` / `proposed_at` (epoch-seconds) record authorship;
 * `status` is typically "superseded". `terms_text` is an optional note. Matches CollaborationRevisionOut.
 */
data class CollaborationRevisionOut(
    @Json(name = "revision") val revision: Int? = null,
    @Json(name = "split") val split: Map<String, Int>? = null,
    @Json(name = "terms_text") val termsText: String? = null,
    @Json(name = "proposed_by") val proposedBy: String? = null,
    @Json(name = "proposed_at") val proposedAt: Long? = null,
    @Json(name = "status") val status: String? = null,
)

// ---------------------------------------------------------------------------
// FIN-011 - inbound-request settings (GET/PUT ui/collaborations/settings).
// ---------------------------------------------------------------------------

/**
 * The viewer's inbound-collaboration settings. All fields default so a degraded read renders a form.
 * Matches CollaborationSettingsOut (models.py) / CollaborationSettingsOut (types.ts).
 */
data class CollaborationSettingsOut(
    @Json(name = "accepting_requests") val acceptingRequests: Boolean? = null,
    @Json(name = "min_split_pct") val minSplitPct: Int? = null,
    @Json(name = "allowed_content_types") val allowedContentTypes: List<String>? = null,
    @Json(name = "auto_expire_days") val autoExpireDays: Int? = null,
    @Json(name = "updated_at") val updatedAt: Long? = null,
)

/**
 * The settings PUT body. Every field is OPTIONAL (partial update, `exclude_none` on the server) - a null field
 * is omitted by the client so unset fields keep their server value. Matches CollaborationSettingsIn.
 */
data class CollaborationSettingsIn(
    @Json(name = "accepting_requests") val acceptingRequests: Boolean? = null,
    @Json(name = "min_split_pct") val minSplitPct: Int? = null,
    @Json(name = "allowed_content_types") val allowedContentTypes: List<String>? = null,
    @Json(name = "auto_expire_days") val autoExpireDays: Int? = null,
)

// ---------------------------------------------------------------------------
// FIN-011 - content assignment + the auto-split revenue event.
// ---------------------------------------------------------------------------

/**
 * The assigned-content list envelope (GET .../content). `items` is the content assigned to this collaboration;
 * `collaboration_id` echoes the id. Matches CollabContentListOut.
 */
data class CollabContentListOut(
    @Json(name = "items") val items: List<CollabContentItem>? = null,
    @Json(name = "collaboration_id") val collaborationId: String? = null,
)

/**
 * One assigned content item. `total_revenue_cents` is the running gross this content has generated inside the
 * collaboration; `split_count` is how many split records it has produced. Matches CollabContentItem.
 */
data class CollabContentItem(
    @Json(name = "content_id") val contentId: String? = null,
    @Json(name = "content_type") val contentType: String? = null,
    @Json(name = "title") val title: String? = null,
    @Json(name = "assigned_by") val assignedBy: String? = null,
    @Json(name = "assigned_at") val assignedAt: Long? = null,
    @Json(name = "total_revenue_cents") val totalRevenueCents: Int? = null,
    @Json(name = "split_count") val splitCount: Int? = null,
)

/**
 * POST .../content body - assign a piece of owned content to the collaboration. `content_type` is one of
 * vod / post / broadcast. Matches CollabContentAssignIn.
 */
data class CollabContentAssignIn(
    @Json(name = "content_id") val contentId: String,
    @Json(name = "content_type") val contentType: String,
    @Json(name = "title") val title: String? = null,
)

/**
 * POST .../content/{contentId}/revenue-event body - deterministically trigger an auto-split for a revenue
 * event on assigned content. `amount_cents` (>0) is the gross; `source` is one of
 * tip / unlock / vod_purchase / subscription / sale. Matches CollabContentSplitTriggerIn.
 */
data class CollabContentSplitTriggerIn(
    @Json(name = "content_id") val contentId: String,
    @Json(name = "amount_cents") val amountCents: Int,
    @Json(name = "source") val source: String? = null,
    @Json(name = "currency") val currency: String? = null,
)

// ---------------------------------------------------------------------------
// FIN-011 - disputes (file / list / resolve).
// ---------------------------------------------------------------------------

/**
 * The disputes list envelope (GET .../disputes). `items` is the disputes for this collaboration (optionally
 * filtered by `status`). Matches CollabDisputeListOut.
 */
data class CollabDisputeListOut(
    @Json(name = "items") val items: List<CollabDisputeOut>? = null,
)

/**
 * One dispute filed against a split record. `proposed_split` is the re-split the filer proposes (optional);
 * `status` is a FREE string (parsed to DisputeState in core-model). The resolution fields populate on resolve.
 * Matches CollabDisputeOut.
 */
data class CollabDisputeOut(
    @Json(name = "dispute_id") val disputeId: String? = null,
    @Json(name = "split_id") val splitId: String? = null,
    @Json(name = "collaboration_id") val collaborationId: String? = null,
    @Json(name = "filed_by") val filedBy: String? = null,
    @Json(name = "reason") val reason: String? = null,
    @Json(name = "proposed_split") val proposedSplit: Map<String, Int>? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "resolution") val resolution: String? = null,
    @Json(name = "resolved_by") val resolvedBy: String? = null,
    @Json(name = "resolved_at") val resolvedAt: Long? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
)

/**
 * POST .../splits/{splitId}/dispute body - file a dispute on a split record. `reason` is required (10..2000
 * chars server-side); `proposed_split` is an OPTIONAL userId -> integer percent re-split. Matches
 * CollabDisputeIn.
 */
data class CollabDisputeIn(
    @Json(name = "reason") val reason: String,
    @Json(name = "proposed_split") val proposedSplit: Map<String, Int>? = null,
)

/**
 * POST .../disputes/{disputeId}/resolve body - resolve an open dispute. `resolution` is required (5..2000
 * chars); `accept` decides whether the proposed re-split is applied. Matches CollabDisputeResolveIn.
 */
data class CollabDisputeResolveIn(
    @Json(name = "resolution") val resolution: String,
    @Json(name = "accept") val accept: Boolean = true,
)

/**
 * The generic {ok:true, ...} acknowledgement returned by the assign / unassign / dispute-file / resolve
 * mutations. Only the fields the client reads are pinned; extra keys are tolerated. `status` /
 * `dispute_status` surface the resulting state.
 */
data class CollabOkOut(
    @Json(name = "ok") val ok: Boolean? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "dispute_status") val disputeStatus: String? = null,
)
