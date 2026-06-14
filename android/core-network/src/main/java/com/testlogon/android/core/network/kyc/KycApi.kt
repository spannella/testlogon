package com.testlogon.android.core.network.kyc

import com.testlogon.android.core.model.kyc.KycCaseCreateRequest
import com.testlogon.android.core.model.kyc.KycCaseDraftPatchRequest
import com.testlogon.android.core.model.kyc.KycCaseEnvelope
import com.testlogon.android.core.model.kyc.KycCaseListEnvelope
import com.testlogon.android.core.model.kyc.KycEstimatedWaitEnvelope
import com.testlogon.android.core.model.kyc.KycFileAttachmentRequest
import com.testlogon.android.core.model.kyc.KycReadinessEnvelope
import com.testlogon.android.core.model.kyc.KycSubmitCaseRequest
import okhttp3.ResponseBody
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-319 - Retrofit interface for the `v1/kyc` endpoint surface (transport only; no vendor SDK).
 *
 * Paths have NO leading slash (relative to the Retrofit base URL, matching the rest of the codebase).
 * All calls are suspend. Mutations carry an explicit JSON Content-Type. The three tier endpoints have
 * undocumented bodies, so they return okhttp3.ResponseBody rather than an invented DTO. Session
 * cookies, Authorization Bearer and X-CSRF-Token are attached by core-network interceptors.
 *
 * estimated-wait is declared before getCase to keep the static `cases/estimated-wait` segment visually
 * distinct from the `cases/{case_id}` template (Retrofit matches by annotation, not declaration order).
 */
interface KycApi {

    // ---- Tiers (undocumented bodies -> ResponseBody) ----

    @GET("v1/kyc/tiers/me")
    suspend fun tierMe(): ResponseBody

    @POST("v1/kyc/tiers/me/evaluate")
    suspend fun evaluateTier(): ResponseBody

    @GET("v1/kyc/tiers/me/requirements/{target_tier}")
    suspend fun tierRequirements(@Path("target_tier") targetTier: String): ResponseBody

    // ---- Cases ----

    @Headers("Content-Type: application/json")
    @POST("v1/kyc/cases")
    suspend fun createCase(@Body body: KycCaseCreateRequest): KycCaseEnvelope

    @GET("v1/kyc/cases")
    suspend fun listCases(): KycCaseListEnvelope

    @GET("v1/kyc/cases/estimated-wait")
    suspend fun estimatedWait(): KycEstimatedWaitEnvelope

    @GET("v1/kyc/cases/{case_id}")
    suspend fun getCase(@Path("case_id") caseId: String): KycCaseEnvelope

    @Headers("Content-Type: application/json")
    @PATCH("v1/kyc/cases/{case_id}")
    suspend fun patchDraft(
        @Path("case_id") caseId: String,
        @Body body: KycCaseDraftPatchRequest,
    ): KycCaseEnvelope

    @Headers("Content-Type: application/json")
    @POST("v1/kyc/cases/{case_id}/files")
    suspend fun attachFile(
        @Path("case_id") caseId: String,
        @Body body: KycFileAttachmentRequest,
    ): KycCaseEnvelope

    @GET("v1/kyc/cases/{case_id}/readiness")
    suspend fun readiness(@Path("case_id") caseId: String): KycReadinessEnvelope

    @Headers("Content-Type: application/json")
    @POST("v1/kyc/cases/{case_id}/submit")
    suspend fun submitCase(
        @Path("case_id") caseId: String,
        @Body body: KycSubmitCaseRequest,
    ): KycCaseEnvelope
}
