package com.testlogon.android.feature.kyc.liveness.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.kyc.KycLivenessCallScheduleRequestDto
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.kyc.KycLivenessCallApi
import com.testlogon.android.feature.kyc.liveness.model.LivenessCall
import com.testlogon.android.feature.kyc.liveness.model.toDomain
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-324 - data layer for the KYC scheduled liveness (video-verification) call flow.
 *
 * Wraps AND-324's [KycLivenessCallApi] (provided by core-network's KycNetworkModule). DTOs are mapped to
 * the domain [LivenessCall] BEFORE the typed [ApiResult] (mirrors AND-320 / AND-321 / AND-322 / AND-323).
 *
 * This is a REAL REST scheduling control plane, NOT in-app WebRTC: schedule books an appointment, the
 * verifier joins later, and the call's opaque join_url is opened EXTERNALLY by the screen. [schedule] and
 * [cancel] are NON-IDEMPOTENT POSTs and are NOT auto-retried (the VM debounces schedule); [list] /
 * [getCall] / [getCaseStatus] are idempotent GETs.
 */
interface LivenessCallRepository {

    /** Books a video-verification appointment for [caseId] at [scheduledAtEpochSec] (epoch seconds). */
    suspend fun schedule(
        caseId: String,
        scheduledAtEpochSec: Long,
        durationMinutes: Int,
        note: String? = null,
    ): ApiResult<LivenessCall>

    /** Lists the signed-in user's scheduled / past liveness calls. */
    suspend fun list(): ApiResult<List<LivenessCall>>

    /** Reads one call by id (manual status refresh). */
    suspend fun getCall(callId: String): ApiResult<LivenessCall>

    /** Cancels a still-cancellable call; returns the updated (cancelled) call. */
    suspend fun cancel(callId: String): ApiResult<LivenessCall>
}

@Singleton
class LivenessCallRepositoryImpl @Inject constructor(
    private val api: KycLivenessCallApi,
    private val errorParser: ApiErrorParser,
) : LivenessCallRepository {

    override suspend fun schedule(
        caseId: String,
        scheduledAtEpochSec: Long,
        durationMinutes: Int,
        note: String?,
    ): ApiResult<LivenessCall> = withContext(Dispatchers.IO) {
        call {
            api.scheduleCall(
                KycLivenessCallScheduleRequestDto(
                    case_id = caseId,
                    scheduled_at = scheduledAtEpochSec,
                    duration_minutes = durationMinutes,
                    note = note,
                ),
            ).toDomain()
        }
    }

    override suspend fun list(): ApiResult<List<LivenessCall>> = withContext(Dispatchers.IO) {
        call { api.listCalls().calls.map { it.toDomain() } }
    }

    override suspend fun getCall(callId: String): ApiResult<LivenessCall> = withContext(Dispatchers.IO) {
        call { api.getCall(callId).toDomain() }
    }

    override suspend fun cancel(callId: String): ApiResult<LivenessCall> = withContext(Dispatchers.IO) {
        call { api.cancelCall(callId).toDomain() }
    }

    /**
     * Folds a block into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser], preserving the
     * status); malformed JSON -> Failure(parse); transport failures -> NetworkError. The
     * JsonEncodingException catch precedes the IOException catch (it is an IOException subtype).
     * Cancellation is re-thrown. Mirrors AND-321 / AND-322 / AND-323.
     */
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
