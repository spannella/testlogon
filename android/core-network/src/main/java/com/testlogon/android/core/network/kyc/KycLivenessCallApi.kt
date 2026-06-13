package com.testlogon.android.core.network.kyc

import com.testlogon.android.core.model.kyc.KycLivenessCallCaseStatusEnvelopeDto
import com.testlogon.android.core.model.kyc.KycLivenessCallListDto
import com.testlogon.android.core.model.kyc.KycLivenessCallOutDto
import com.testlogon.android.core.model.kyc.KycLivenessCallScheduleRequestDto
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-324 - Retrofit interface for the KYC scheduled liveness (video-verification) call endpoint.
 *
 * Like AND-321's [KycDocumentsApi] / AND-322's [KycIdScannerApi], these endpoints live under the `ui/`
 * prefix (NOT `v1/`); paths have NO leading slash (relative to the shared Retrofit base URL). Session
 * cookies, Authorization Bearer and X-CSRF-Token are attached by the core-network interceptors.
 *
 * This is a REAL REST scheduling control plane, NOT in-app WebRTC: the user books a video-verification
 * appointment against a KYC case, a human verifier conducts it later, and the resulting opaque
 * [KycLivenessCallOutDto.join_url] is opened EXTERNALLY by the screen (ACTION_VIEW). No WebRTC / camera /
 * vendor SDK is involved here.
 *
 * IDEMPOTENCY: [scheduleCall] and [cancelCall] are NON-IDEMPOTENT mutating POSTs (a retry of a succeeded
 * schedule double-books; a retry of a succeeded cancel is wasted) so they are NOT auto-retried, and the
 * caller (LivenessCallViewModel) debounces the schedule. The GETs are idempotent.
 */
interface KycLivenessCallApi {

    @Headers("Content-Type: application/json")
    @POST("ui/kyc/liveness-call")
    suspend fun scheduleCall(@Body body: KycLivenessCallScheduleRequestDto): KycLivenessCallOutDto

    @GET("ui/kyc/liveness-call")
    suspend fun listCalls(): KycLivenessCallListDto

    @GET("ui/kyc/liveness-call/{callId}")
    suspend fun getCall(@Path("callId") callId: String): KycLivenessCallOutDto

    @GET("ui/kyc/liveness-call/case/{caseId}")
    suspend fun getCaseStatus(@Path("caseId") caseId: String): KycLivenessCallCaseStatusEnvelopeDto

    @POST("ui/kyc/liveness-call/{callId}/cancel")
    suspend fun cancelCall(@Path("callId") callId: String): KycLivenessCallOutDto
}
