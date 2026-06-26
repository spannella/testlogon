package com.testlogon.android.core.network.kyc

import com.testlogon.android.core.model.kyc.KycVerifyConfirmOutDto
import com.testlogon.android.core.model.kyc.KycVerifyConfirmRequestDto
import com.testlogon.android.core.model.kyc.KycVerifyEmailStartRequestDto
import com.testlogon.android.core.model.kyc.KycVerifyPhoneStartRequestDto
import com.testlogon.android.core.model.kyc.KycVerifyStartOutDto
import retrofit2.http.Body
import retrofit2.http.Headers
import retrofit2.http.POST

/**
 * Batch-9 (#18) - Retrofit interface for the Tier-1 email/phone verification control plane.
 *
 * Paths have NO leading slash (relative to the shared Retrofit base URL, matching the rest of the codebase).
 * All calls are suspend mutating POSTs carrying an explicit JSON Content-Type; session cookies, Authorization
 * Bearer and X-CSRF-Token are attached by the core-network interceptors. The two start calls return a code
 * envelope (with a dev_code in dev_mode); the two confirm calls return the updated verified flag.
 */
interface KycVerifyApi {

    @Headers("Content-Type: application/json")
    @POST("v1/kyc/tiers/me/verify/email/start")
    suspend fun startEmail(@Body body: KycVerifyEmailStartRequestDto): KycVerifyStartOutDto

    @Headers("Content-Type: application/json")
    @POST("v1/kyc/tiers/me/verify/email/confirm")
    suspend fun confirmEmail(@Body body: KycVerifyConfirmRequestDto): KycVerifyConfirmOutDto

    @Headers("Content-Type: application/json")
    @POST("v1/kyc/tiers/me/verify/phone/start")
    suspend fun startPhone(@Body body: KycVerifyPhoneStartRequestDto): KycVerifyStartOutDto

    @Headers("Content-Type: application/json")
    @POST("v1/kyc/tiers/me/verify/phone/confirm")
    suspend fun confirmPhone(@Body body: KycVerifyConfirmRequestDto): KycVerifyConfirmOutDto
}
