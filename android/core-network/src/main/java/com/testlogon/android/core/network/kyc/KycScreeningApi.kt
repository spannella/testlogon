package com.testlogon.android.core.network.kyc

import com.testlogon.android.core.model.kyc.KycScreeningResultsListResponseDto
import retrofit2.http.GET
import retrofit2.http.Path

/**
 * AND-328 - Retrofit interface for the READ-ONLY KYC screening results surface
 * (sanctions / PEP / adverse-media per-screen results for a case).
 *
 * The screening results live under the `ui/` prefix (mirroring AND-321's KycDocumentsApi / AND-326's
 * KycResidencyApi `ui/` document surfaces). Paths have NO leading slash (relative to the shared Retrofit base
 * URL). Session cookies, Authorization Bearer and X-CSRF-Token are attached by the core-network interceptors.
 *
 * READ-ONLY: the single endpoint is an idempotent GET. There are NO writes / mutations on this surface (no
 * vendor SDK, no flagged seam). The documented error is 422; 401 is handled globally. The case id is obtained
 * by the repository from KycApi.listCases (or supplied as a nav arg).
 */
interface KycScreeningApi {

    @GET("ui/kyc/screening/cases/{case_id}")
    suspend fun screening(@Path("case_id") caseId: String): KycScreeningResultsListResponseDto
}
