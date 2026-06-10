package com.testlogon.android.data.vod.adsupported

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
 * AND-194 — ad-supported (AVOD) data layer over [VodAdSupportedApi].
 *
 * `getSession` (GET) is idempotent; `start`/`reportBreak` are POSTs and are not auto-retried by the
 * network layer (start re-issues only on explicit user retry; mandatory-break report failure keeps the
 * gate closed). No payment is involved — AVOD is the free-with-ads path; ads are removed when the user
 * holds an entitlement (gated upstream).
 */
interface VodAdSupportedRepository {

    /** Read current session state (no playback grant). */
    suspend fun getSession(videoId: String): ApiResult<AdSupportedSession>

    /** Start (or resume) the session; returns playback_url + ad_schedule. */
    suspend fun start(videoId: String, resumePositionSeconds: Int = 0): ApiResult<AdSupportedSession>

    /** Report a break impression|complete|skip; returns the updated gating state. */
    suspend fun reportBreak(
        videoId: String,
        breakId: String,
        eventType: String = VodAdSupportedApi.EVENT_COMPLETE,
    ): ApiResult<AdBreakReport>
}

@Singleton
class VodAdSupportedRepositoryImpl @Inject constructor(
    private val api: VodAdSupportedApi,
    private val errorParser: ApiErrorParser,
) : VodAdSupportedRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun getSession(videoId: String): ApiResult<AdSupportedSession> = withContext(io) {
        call { api.getSession(videoId) }.map { it.toDomain() }
    }

    override suspend fun start(videoId: String, resumePositionSeconds: Int): ApiResult<AdSupportedSession> =
        withContext(io) {
            call { api.start(videoId, VodAdSupportedStartInDto(resumePositionSeconds)) }
                .map { it.toDomain() }
        }

    override suspend fun reportBreak(
        videoId: String,
        breakId: String,
        eventType: String,
    ): ApiResult<AdBreakReport> = withContext(io) {
        call { api.reportBreak(videoId, VodAdBreakReportInDto(breakId, eventType)) }.map { it.toDomain() }
    }

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
