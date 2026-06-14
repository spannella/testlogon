package com.testlogon.android.data.call.recording

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-302 — data layer over [RecordingApi] for the call-recording consent + upload control plane.
 *
 * These are REAL backend endpoints (consent protocol + presign/complete), so this is fully implemented +
 * testable independent of the FLAGGED capture seam. Each op is wrapped in [ApiResult] (Failure for HTTP
 * errors via [ApiErrorParser], NetworkError for transport failures, Failure(parse) for malformed JSON),
 * mapping wire DTOs -> domain before returning. Never throws (CancellationException re-thrown). The
 * JsonEncodingException catch precedes IOException (it is an IOException subtype) — matching CallRepository.
 *
 * The storage PUT (presign -> PUT -> complete) reuses the AND-129 transport
 * ([com.testlogon.android.data.upload.StorageUploadClient]); this repository owns only the typed
 * presign/complete REST, NOT the PUT.
 */
interface RecordingRepository {

    /** POST .../recording/request — open a consent prompt for [callId]. */
    suspend fun request(callId: String): ApiResult<RecordingRequest>

    /** POST .../recording/consent — accept (the server consent GATE; capture may begin after this). */
    suspend fun consent(callId: String): ApiResult<RecordingConsent>

    /** POST .../recording/decline — decline (capture must NOT begin). */
    suspend fun decline(callId: String): ApiResult<Boolean>

    /** POST .../recording/upload/presign — presigned PUT target for the captured artifact. */
    suspend fun presign(
        callId: String,
        contentType: String,
        fileSizeBytes: Long,
    ): ApiResult<RecordingPresign>

    /** POST .../recording/upload/complete — finalize after the PUT succeeds. */
    suspend fun complete(
        callId: String,
        recordingId: String,
        durationSeconds: Float,
    ): ApiResult<RecordingComplete>
}

@Singleton
class RecordingRepositoryImpl @Inject constructor(
    private val api: RecordingApi,
    private val errorParser: ApiErrorParser,
) : RecordingRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun request(callId: String): ApiResult<RecordingRequest> = withContext(io) {
        call { api.request(callId) }.map { it.toDomain() }
    }

    override suspend fun consent(callId: String): ApiResult<RecordingConsent> = withContext(io) {
        call { api.consent(callId) }.map { it.toDomain() }
    }

    override suspend fun decline(callId: String): ApiResult<Boolean> = withContext(io) {
        call { api.decline(callId) }.map { it.ok }
    }

    override suspend fun presign(
        callId: String,
        contentType: String,
        fileSizeBytes: Long,
    ): ApiResult<RecordingPresign> = withContext(io) {
        call {
            api.presign(
                callId,
                RecordingUploadPresignInDto(contentType = contentType, fileSizeBytes = fileSizeBytes),
            )
        }.map { it.toDomain() }
    }

    override suspend fun complete(
        callId: String,
        recordingId: String,
        durationSeconds: Float,
    ): ApiResult<RecordingComplete> = withContext(io) {
        call {
            api.complete(
                callId,
                RecordingUploadCompleteInDto(recordingId = recordingId, durationSeconds = durationSeconds),
            )
        }.map { it.toDomain() }
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonEncodingException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
