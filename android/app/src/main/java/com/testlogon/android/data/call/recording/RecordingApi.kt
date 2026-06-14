package com.testlogon.android.data.call.recording

import retrofit2.http.Body
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-302 — dedicated Retrofit interface for the call-recording consent + upload control plane.
 *
 * Paths are relative (no leading slash) so they resolve against the shared Retrofit base URL; cookies /
 * X-CSRF-Token on these POST mutations are attached by the core-network interceptor chain — this interface
 * stays header-agnostic (mirroring [com.testlogon.android.data.call.CallApi]).
 *
 * Each method returns the raw success DTO body and throws retrofit2.HttpException on non-2xx; the wrapping
 * into ApiResult (catching HttpException / JsonDataException / JsonEncodingException / IOException) is done
 * in [RecordingRepository], mirroring CallRepository.
 *
 * The storage PUT to the presigned upload_url is NOT modeled here: it is a SEPARATE cookieless call handled
 * by the reused AND-129 [com.testlogon.android.data.upload.StorageUploadClient].
 */
interface RecordingApi {

    /** POST messages/calls/{call_id}/recording/request — open a consent prompt (no body). */
    @POST("messages/calls/{callId}/recording/request")
    suspend fun request(@Path("callId") callId: String): RecordingRequestOutDto

    /** POST messages/calls/{call_id}/recording/consent — accept (no body); means capture may begin. */
    @POST("messages/calls/{callId}/recording/consent")
    suspend fun consent(@Path("callId") callId: String): RecordingConsentOutDto

    /** POST messages/calls/{call_id}/recording/decline — decline (no body). */
    @POST("messages/calls/{callId}/recording/decline")
    suspend fun decline(@Path("callId") callId: String): RecordingDeclineOutDto

    /** POST messages/calls/{call_id}/recording/upload/presign — presigned PUT target for the artifact. */
    @POST("messages/calls/{callId}/recording/upload/presign")
    suspend fun presign(
        @Path("callId") callId: String,
        @Body body: RecordingUploadPresignInDto,
    ): RecordingUploadPresignOutDto

    /** POST messages/calls/{call_id}/recording/upload/complete — finalize after the PUT succeeds. */
    @POST("messages/calls/{callId}/recording/upload/complete")
    suspend fun complete(
        @Path("callId") callId: String,
        @Body body: RecordingUploadCompleteInDto,
    ): RecordingUploadCompleteOutDto
}
