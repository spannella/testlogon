package com.testlogon.android.core.network.callrate

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.PUT
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * Retrofit interface for the creator paid-calls rate settings (web parity: src/api/endpoints/callBilling.ts).
 *
 * Transport only; the :app repository folds these into ApiResult. Paths have NO leading slash; the shared
 * authenticated client attaches cookies + Authorization + X-CSRF-Token globally.
 *
 * NOTE: the GET takes a `creator_id` (the web passes the signed-in user's id for the "own rate" view). The :app
 * repository resolves the caller's user_sub via the shared CurrentUserRepository before reading. A 404 from GET
 * means "no rate configured yet" and the repository maps it to a clean absence.
 */
interface CallRateApi {

    /** GET a creator's per-minute rate. 404 => not configured. Idempotent. */
    @GET("ui/calls/rates/{creator_id}")
    suspend fun getRate(@Path("creator_id") creatorId: String): CallRateDto

    /** POST to set/create the caller's own rate. */
    @POST("ui/calls/rates")
    suspend fun setRate(@Body body: CallRateInDto): CallRateDto

    /** PUT to update the caller's own rate. */
    @PUT("ui/calls/rates")
    suspend fun updateRate(@Body body: CallRateInDto): CallRateDto

    /** DELETE to disable paid calls (remove the caller's rate). */
    @DELETE("ui/calls/rates")
    suspend fun deleteRate()
}
