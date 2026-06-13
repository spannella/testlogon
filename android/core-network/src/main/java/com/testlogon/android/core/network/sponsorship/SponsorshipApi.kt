package com.testlogon.android.core.network.sponsorship

import retrofit2.http.GET

/**
 * AND-365 - Retrofit interface for the READ-ONLY sponsorship inbox (inbound brand deals). Transport only; no
 * repo / VM / UI / domain mapping (those live in the :app feature). This is the platform's OWN REST surface,
 * NOT a third-party SDK.
 *
 * The path has NO leading slash (relative to the shared Retrofit base URL, matching the rest of the
 * codebase). Session cookie / Authorization Bearer are attached globally by the core-network interceptors.
 *
 * WIRE CONTRACT (verified against reference web src/api/endpoints/sponsorshipDeals.ts): a single idempotent
 * suspend GET returning a RAW BARE ARRAY of [SponsorshipDealDto]. The web list endpoint accepts optional
 * status / role query params, but AND-365 filters + sorts CLIENT-SIDE (the inbox loads the full array once),
 * so NO query params are sent. Mutation (accept / reject / counter / complete / cancel) is OUT OF SCOPE
 * (downstream AND-366).
 */
interface SponsorshipApi {

    /** GET the caller's sponsorship deals (BARE ARRAY). No params, no envelope, no paging. */
    @GET("ui/ads/sponsorships")
    suspend fun listDeals(): List<SponsorshipDealDto>
}
