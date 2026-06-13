package com.testlogon.android.core.network.syndicates

import com.squareup.moshi.Json

/**
 * AND-356 - transport DTOs for the READ-ONLY syndicate overview surface (Feed / Treasury / Revenue-split).
 *
 * CODEGEN NOTE (identical to AND-355 GroupDtos): core-network does NOT apply the Moshi KSP codegen plugin,
 * so these DTOs decode via the reflective KotlinJsonAdapterFactory registered on the shared Moshi in
 * NetworkModule.provideMoshi. The reflective factory maps Kotlin property names to JSON keys VERBATIM
 * (Moshi does NOT auto snake_case), so every wire key is pinned with an explicit @Json(name = ...).
 * @JsonClass(generateAdapter = true) is intentionally OMITTED.
 *
 * Optional fields are nullable with null defaults; required wire fields have NO default so a missing key
 * surfaces as a JsonDataException. Extra/unknown wire keys are tolerated leniently by the reflective
 * adapter.
 *
 * WIRE CONTRACT (OpenAPI section 5 / frontend syndicates.ts - verified):
 *   GET ui/syndicates/{syndicateId}                 -> SyndicateProfileOut (name, member_count,
 *                                                      admin_user_id, currency lowercase ISO, is_member)
 *   GET ui/syndicates/{syndicateId}/feed            -> SyndicateFeedOut {posts[], is_member, + paging}
 *   GET ui/syndicates/{syndicateId}/treasury        -> SyndicateTreasuryOut (balance/totals + ledger page)
 *   GET ui/syndicates/{syndicateId}/revenue-split   -> SplitConfigOut (mode, fee, weights_bps map, ...)
 *
 * ROLE NOTE: there is NO viewer_role field on the wire - the role badge is DERIVED downstream
 * (admin_user_id == current userId -> admin, else member). currency is lowercase ISO on the wire and is
 * upper-cased in the core-model mapper for NumberFormat. created_at / ts are INTEGER epoch (Long). All
 * money is *_cents (Int). The typed SplitMode enum + UNKNOWN fallback lives in core-model.
 *
 * ROOM DECISION: there is NO Room cache and NO migration this wave - the feed + ledger are network
 * Paging-3 PagingSources and the non-paged snapshots are kept in-memory in the ViewModel with an isStale
 * flag. Room persistence across process death is DEFERRED.
 */

/**
 * The syndicate overview / profile. `id` + `name` are required; `currency` is a lowercase ISO code on the
 * wire (upper-cased in the mapper). `is_member` gates the NotMember empty-state; the role badge is derived
 * from `admin_user_id` == the current user (there is NO viewer_role field).
 */
data class SyndicateProfileOut(
    @Json(name = "id") val id: String,
    @Json(name = "name") val name: String,
    @Json(name = "member_count") val memberCount: Int? = null,
    @Json(name = "admin_user_id") val adminUserId: String? = null,
    @Json(name = "currency") val currency: String? = null,
    @Json(name = "is_member") val isMember: Boolean? = null,
)

/**
 * One plain feed post. There is NO post-type discriminator and NO body/actor field - the post carries
 * `author_*`, `created_at` (INTEGER epoch), `text`, an optional `image_url`, and optional non-interactive
 * reaction/comment/tip counts.
 */
data class SyndicatePostOut(
    @Json(name = "post_id") val postId: String,
    @Json(name = "author_name") val authorName: String? = null,
    @Json(name = "author_avatar_url") val authorAvatarUrl: String? = null,
    @Json(name = "created_at") val createdAt: Long,
    @Json(name = "text") val text: String? = null,
    @Json(name = "image_url") val imageUrl: String? = null,
    @Json(name = "reaction_count") val reactionCount: Int? = null,
    @Json(name = "comment_count") val commentCount: Int? = null,
    @Json(name = "tip_count") val tipCount: Int? = null,
)

/**
 * The feed page envelope. `posts` is reverse-chronological; `is_member` mirrors the profile flag; the
 * paging cursor (`next_cursor`) is opaque and a null/blank cursor terminates pagination. `page` is the
 * optional fallback page index when the backend pages by integer index instead of a cursor.
 */
data class SyndicateFeedOut(
    @Json(name = "posts") val posts: List<SyndicatePostOut> = emptyList(),
    @Json(name = "is_member") val isMember: Boolean? = null,
    @Json(name = "next_cursor") val nextCursor: String? = null,
    @Json(name = "page") val page: Int? = null,
)

/**
 * The treasury summary + a page of the ledger. All balances are *_cents (Int); `currency` is lowercase ISO
 * (upper-cased in the mapper). The ledger page carries its own opaque `next_cursor`.
 */
data class SyndicateTreasuryOut(
    @Json(name = "balance_cents") val balanceCents: Int,
    @Json(name = "total_deposited_cents") val totalDepositedCents: Int,
    @Json(name = "total_disbursed_cents") val totalDisbursedCents: Int,
    @Json(name = "currency") val currency: String? = null,
    @Json(name = "ledger") val ledger: List<SyndicateTreasuryLedgerEntryOut> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
    @Json(name = "page") val page: Int? = null,
)

/**
 * One ledger entry. `direction` is "credit" or "debit" (kept raw); `amount_cents` is the magnitude (Int);
 * `ts` is INTEGER epoch; `reason` + `counterparty_user_id` are optional.
 */
data class SyndicateTreasuryLedgerEntryOut(
    @Json(name = "entry_id") val entryId: String? = null,
    @Json(name = "direction") val direction: String? = null,
    @Json(name = "amount_cents") val amountCents: Int,
    @Json(name = "reason") val reason: String? = null,
    @Json(name = "ts") val ts: Long,
    @Json(name = "counterparty_user_id") val counterpartyUserId: String? = null,
)

/**
 * The revenue-split policy. `mode` is one of equal|weighted|performance on the wire (anything else maps to
 * the SplitMode.UNKNOWN fallback in core-model). `platform_fee_bps` is basis points. `weights_bps` is a
 * userId -> basis-points map (10000 = 100%); it may be absent/empty for equal/performance modes. There is
 * NO per-member payout array.
 */
data class SplitConfigOut(
    @Json(name = "mode") val mode: String? = null,
    @Json(name = "platform_fee_bps") val platformFeeBps: Int? = null,
    @Json(name = "performance_metric") val performanceMetric: String? = null,
    @Json(name = "performance_window_days") val performanceWindowDays: Int? = null,
    @Json(name = "updated_at") val updatedAt: Long? = null,
    @Json(name = "updated_by") val updatedBy: String? = null,
    @Json(name = "weights_bps") val weightsBps: Map<String, Int>? = null,
)

/**
 * OPTIONAL viewer-earnings payload (GET ui/syndicates/{syndicateId}/revenue-split/my-earnings). Included
 * for completeness; the overview screen does not require it. All money is *_cents.
 */
data class MemberEarningsOut(
    @Json(name = "user_id") val userId: String? = null,
    @Json(name = "earned_cents") val earnedCents: Int? = null,
    @Json(name = "currency") val currency: String? = null,
    @Json(name = "window_days") val windowDays: Int? = null,
)

// ---- AND-357: open-licensing sub-surface (extends AND-356, same DTO file) ----

/**
 * AND-357 - one open-licensing content row.
 *
 * WIRE: content_id + content_type are required; content_type is one of the fixed 6 values
 * video|music|image|post|broadcast|clip (the typed enum + UNKNOWN fallback lives in core-model). exempt
 * gates the "Exempt" vs "Auto-licensed" label (defaults false when the wire omits it); registered_at is an
 * INTEGER epoch-SECONDS value (relative-time at the UI). There is NO SPDX type, NO open/claimed/expired
 * status and NO registrant_sub / title / notes on this row.
 */
data class SyndicateOpenLicensingContentOut(
    @Json(name = "content_id") val contentId: String,
    @Json(name = "content_type") val contentType: String,
    @Json(name = "creator_id") val creatorId: String? = null,
    @Json(name = "exempt") val exempt: Boolean? = false,
    @Json(name = "registered_at") val registeredAt: Long? = null,
)

/**
 * AND-357 - the open-licensing content list envelope. NOT paginated: a single bounded page carried as
 * {items}. There is NO cursor / page field (no Paging 3 on this surface).
 */
data class OpenLicensingContentListResponse(
    @Json(name = "items") val items: List<SyndicateOpenLicensingContentOut> = emptyList(),
)

/**
 * AND-357 - the register-content request body. content_id is 1..200 chars; content_type is one of the fixed
 * 6 values (validated server-side; a 422 maps back per-field by loc tail). The X-CSRF-Token is attached by
 * the shared authenticated client interceptor (NOT a field here).
 */
data class SyndicateOpenLicensingRegisterIn(
    @Json(name = "content_id") val contentId: String,
    @Json(name = "content_type") val contentType: String,
)

/**
 * AND-357 - the register-content response. This is a registration RECEIPT, NOT a list row: it echoes
 * content_id + syndicate_id and reports licenses_created (the count of licenses minted). On success the UI
 * surfaces licenses_created and REFETCHES the list (it does NOT optimistically prepend this).
 */
data class SyndicateOpenLicensingRegistrationOut(
    @Json(name = "content_id") val contentId: String? = null,
    @Json(name = "syndicate_id") val syndicateId: String? = null,
    @Json(name = "licenses_created") val licensesCreated: Int? = 0,
)
