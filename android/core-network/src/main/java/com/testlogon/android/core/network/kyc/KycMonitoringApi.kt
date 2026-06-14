package com.testlogon.android.core.network.kyc

import com.testlogon.android.core.model.kyc.KycReviewScheduleEnvelopeDto
import com.testlogon.android.core.model.kyc.KycTriggerEventListEnvelopeDto
import retrofit2.http.GET

/**
 * AND-329 - Retrofit interface for the READ-ONLY KYC ongoing-monitoring surface
 * (the review schedule + recent trigger events that decide whether the monitoring banner shows).
 *
 * Paths have NO leading slash (relative to the shared Retrofit base URL, matching the rest of the codebase).
 * Session cookies, Authorization Bearer and X-CSRF-Token are attached by the core-network interceptors.
 *
 * READ-ONLY: both endpoints are idempotent GETs. There are NO writes / mutations on this surface (no vendor
 * SDK, no flagged seam). The documented error is 422; 401 is handled globally. The case list + per-case detail
 * REUSE AND-319's KycApi.listCases / getCase (no new case endpoints here).
 */
interface KycMonitoringApi {

    @GET("v1/kyc/monitoring/schedule")
    suspend fun schedule(): KycReviewScheduleEnvelopeDto

    @GET("v1/kyc/monitoring/triggers")
    suspend fun triggers(): KycTriggerEventListEnvelopeDto
}
