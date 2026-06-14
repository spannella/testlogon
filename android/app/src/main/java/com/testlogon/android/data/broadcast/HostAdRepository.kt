package com.testlogon.android.data.broadcast

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Response
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-316 — data layer over [HostAdApi] for the host AD-BREAK / AD-CONFIG control plane.
 *
 * Kept DELIBERATELY SEPARATE from [HostControlRepository] / [BroadcastRepository] /
 * [BroadcastMonetizationRepository] so the shared broadcast fakes are NOT touched. Each call is wrapped in
 * [ApiResult]; the wire DTO is mapped to the domain BEFORE the typed result. HTTP errors fold to Failure (via
 * [ApiErrorParser]); transport failures to NetworkError; CancellationException is re-thrown. Mutations
 * (PATCH / POST) are NEVER auto-retried.
 *
 * [updateAdConfig] builds a [BroadcastAdConfigInDto] with ONLY the provided (non-null) fields so Moshi omits
 * the untouched keys from the wire body (partial update). [endAdBreak] is typed [Response]<[Unit]> and
 * treated as success-by-isSuccessful (the empty / {ok} body is ignored; the ViewModel re-reads ad-config to
 * reconcile total_ad_breaks).
 */
interface HostAdRepository {

    /** Read the current ad-config + ad-break state for [sessionId]. */
    suspend fun getAdConfig(sessionId: String): ApiResult<AdConfig>

    /**
     * PATCH the ad-config with ONLY the provided fields (nulls are omitted). Returns the reconciled config
     * from the server response.
     */
    suspend fun updateAdConfig(
        sessionId: String,
        preRollEnabled: Boolean?,
        durationSeconds: Int?,
        skipAfterSeconds: Int?,
    ): ApiResult<AdConfig>

    /** Trigger a mid-roll ad break for [sessionId] (no body). */
    suspend fun triggerAdBreak(sessionId: String): ApiResult<AdBreak>

    /** End the active ad break early for [sessionId] (empty / {ok} body -> success-by-isSuccessful). */
    suspend fun endAdBreak(sessionId: String): ApiResult<Unit>
}

@Singleton
class HostAdRepositoryImpl @Inject constructor(
    private val api: HostAdApi,
    private val errorParser: ApiErrorParser,
) : HostAdRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun getAdConfig(sessionId: String): ApiResult<AdConfig> = withContext(io) {
        call { api.getAdConfig(sessionId).bodyOrThrow() }.map { it.toDomain() }
    }

    override suspend fun updateAdConfig(
        sessionId: String,
        preRollEnabled: Boolean?,
        durationSeconds: Int?,
        skipAfterSeconds: Int?,
    ): ApiResult<AdConfig> = withContext(io) {
        // Only the provided (non-null) fields are set; Moshi omits the untouched keys from the wire body.
        val body = BroadcastAdConfigInDto(
            preRollEnabled = preRollEnabled,
            midRollAdBreakDurationSeconds = durationSeconds,
            midRollSkipAfterSeconds = skipAfterSeconds,
        )
        call { api.updateAdConfig(sessionId, body).bodyOrThrow() }.map { it.toDomain() }
    }

    override suspend fun triggerAdBreak(sessionId: String): ApiResult<AdBreak> = withContext(io) {
        call { api.triggerAdBreak(sessionId).bodyOrThrow() }.map { it.toDomain() }
    }

    override suspend fun endAdBreak(sessionId: String): ApiResult<Unit> = withContext(io) {
        call { api.endAdBreak(sessionId).unitOrThrow() }
    }

    /** Extracts a 2xx body (throwing on a null body) or throws an [HttpException] for a non-2xx response. */
    private fun <T> Response<T>.bodyOrThrow(): T {
        if (!isSuccessful) throw HttpException(this)
        return requireNotNull(body()) { "Expected a response body but none was present." }
    }

    /** Treats any 2xx (incl. an empty body) as success; any other code throws an [HttpException]. */
    private fun Response<Unit>.unitOrThrow() {
        if (!isSuccessful) throw HttpException(this)
    }

    /**
     * Folds a single call into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser]); transport
     * failures -> NetworkError; cancellation is re-thrown. Mutations are never auto-retried.
     */
    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
