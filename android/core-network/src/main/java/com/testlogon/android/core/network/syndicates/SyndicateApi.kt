package com.testlogon.android.core.network.syndicates

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-356 - Retrofit interface for the READ-ONLY syndicate overview surface. Transport only; the
 * repository (SyndicateRepository) wraps these RAW DTO returns in ApiResult and exposes the feed + ledger
 * as Paging-3 flows.
 *
 * Paths have NO leading slash (relative to the shared Retrofit base URL, matching the rest of the
 * codebase). All calls are suspend. The shared authenticated client attaches the session cookie, the
 * X-CSRF-Token and the Bearer token via the global interceptors - there is NO cookieless client here.
 *
 * AND-356 was READ-ONLY (Feed / Treasury / Revenue-split). AND-357 EXTENDS this same interface with the
 * open-licensing sub-surface (a non-paged content LIST + a CSRF-protected register mutation) - it is NOT a
 * fork. join / propose / payout remain downstream / OUT OF SCOPE.
 *
 * @Path token is EXACTLY {syndicateId}. The feed + ledger are cursor-paged via the optional `cursor`
 * query (with a `page` fallback for index-paged backends). The open-licensing list is NOT paged.
 */
interface SyndicateApi {

    /** GET the syndicate overview / profile (name, member_count, admin_user_id, currency, is_member). */
    @GET("ui/syndicates/{syndicateId}")
    suspend fun getProfile(@Path("syndicateId") syndicateId: String): SyndicateProfileOut

    /**
     * GET one reverse-chronological page of the feed. `cursor` is the opaque next-page token (null for the
     * first page); `page` is the integer-index fallback. Returns the {posts, is_member, next_cursor}
     * envelope.
     */
    @GET("ui/syndicates/{syndicateId}/feed")
    suspend fun getFeed(
        @Path("syndicateId") syndicateId: String,
        @Query("cursor") cursor: String? = null,
        @Query("page") page: Int? = null,
    ): SyndicateFeedOut

    /**
     * GET the treasury summary + the first (or cursor-anchored) ledger page. The ledger is carried inline
     * on this endpoint; passing a `cursor` / `page` returns the corresponding ledger page (the summary is
     * still echoed).
     */
    @GET("ui/syndicates/{syndicateId}/treasury")
    suspend fun getTreasury(
        @Path("syndicateId") syndicateId: String,
        @Query("cursor") cursor: String? = null,
        @Query("page") page: Int? = null,
    ): SyndicateTreasuryOut

    /** GET the revenue-split policy (mode, platform_fee_bps, weights_bps, ...). */
    @GET("ui/syndicates/{syndicateId}/revenue-split")
    suspend fun getRevenueSplit(@Path("syndicateId") syndicateId: String): SplitConfigOut

    /** OPTIONAL - GET the viewer's own earnings under the current split. Not required by the overview. */
    @GET("ui/syndicates/{syndicateId}/revenue-split/my-earnings")
    suspend fun getMyEarnings(@Path("syndicateId") syndicateId: String): MemberEarningsOut

    // ---- AND-357: open-licensing sub-surface ----

    /**
     * AND-357 - GET the syndicate's open-licensing content. NOT paginated: returns the {items} envelope
     * (a single bounded page). No cursor / page query.
     */
    @GET("ui/syndicates/open-licensing/{syndicateId}/content")
    suspend fun getOpenLicensingContent(
        @Path("syndicateId") syndicateId: String,
    ): OpenLicensingContentListResponse

    /**
     * AND-357 - register a piece of content for open licensing (a mutation). The X-CSRF-Token is attached by
     * the shared authenticated client interceptor. Returns the registration RECEIPT
     * {content_id, syndicate_id, licenses_created} - NOT a list row (the caller REFETCHES the list on
     * success). A 422 carries the FastAPI detail[{loc,msg,type}] for per-field mapping.
     */
    @POST("ui/syndicates/open-licensing/{syndicateId}/register")
    suspend fun registerOpenLicensing(
        @Path("syndicateId") syndicateId: String,
        @Body body: SyndicateOpenLicensingRegisterIn,
    ): SyndicateOpenLicensingRegistrationOut
}
