package com.testlogon.android.feature.files.data

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.files.ShareFileRequest
import com.testlogon.android.core.model.files.SharedWithMeItemDto
import com.testlogon.android.core.model.files.UnshareFileRequest
import com.testlogon.android.core.model.files.UsageDailyDto
import com.testlogon.android.core.model.files.UsageStorageDto
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.files.FileSharingApi
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
 * FM-SHARE - data layer for the user-to-user file sharing, archive and storage-usage surfaces, over the
 * [FileSharingApi].
 *
 * DEGRADE-ON-404 (and the backend feature-gate 403): these surfaces may be disabled per-deployment. The
 * READ entry points ([sharedWithMe], [usageDaily], [usageStorage]) fold a 404 (route absent) or 403
 * (feature disabled) into a graceful "unavailable" success ([available] = false) so the UI shows an
 * honest "not available here" state instead of an error. Genuine failures (422/5xx/network) still
 * surface as Failure / NetworkError. The MUTATING verbs (share/unshare/upload-archive) surface their
 * errors normally (they are only offered once a read reports the surface available).
 *
 * Distinct from [FilesRepository] (path-addressed CRUD) so the existing FilesRepository / FilesApi fakes
 * are untouched. No Room, no new dependency.
 */
interface FileSharingRepository {

    /** Grant [ShareFileRequest.to_user] access to a node the caller owns. */
    suspend fun share(body: ShareFileRequest): ApiResult<Unit>

    /** Revoke [toUser]'s access to [path]. */
    suspend fun unshare(path: String, toUser: String): ApiResult<Unit>

    /** List nodes OTHER users have shared with the caller (degrade-on-404/403 -> unavailable). */
    suspend fun sharedWithMe(): ApiResult<SharedWithMeResult>

    /** Per-day upload/download/storage rows in an optional [from]/[to] range (degrade-on-404/403). */
    suspend fun usageDaily(from: String? = null, to: String? = null): ApiResult<UsageDailyResult>

    /** Current total storage + heaviest [topN] files (degrade-on-404/403 -> unavailable). */
    suspend fun usageStorage(topN: Int? = null): ApiResult<UsageStorageResult>
}

/** Inbound shares plus whether the surface is available in this environment (degrade-on-404/403). */
data class SharedWithMeResult(
    val items: List<SharedWithMeItemDto>,
    val available: Boolean,
)

/** Daily usage rows plus surface availability. */
data class UsageDailyResult(
    val daily: UsageDailyDto?,
    val available: Boolean,
)

/** Storage-usage snapshot plus surface availability. */
data class UsageStorageResult(
    val storage: UsageStorageDto?,
    val available: Boolean,
)

@Singleton
class FileSharingRepositoryImpl @Inject constructor(
    private val api: FileSharingApi,
    private val errorParser: ApiErrorParser,
) : FileSharingRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun share(body: ShareFileRequest): ApiResult<Unit> =
        withContext(io) { call { api.share(body); Unit } }

    override suspend fun unshare(path: String, toUser: String): ApiResult<Unit> =
        withContext(io) {
            call { api.unshare(UnshareFileRequest(path = path, to_user = toUser)); Unit }
        }

    override suspend fun sharedWithMe(): ApiResult<SharedWithMeResult> = withContext(io) {
        degrade(
            onUnavailable = { SharedWithMeResult(items = emptyList(), available = false) },
        ) {
            SharedWithMeResult(items = api.sharedWithMe().items, available = true)
        }
    }

    override suspend fun usageDaily(from: String?, to: String?): ApiResult<UsageDailyResult> =
        withContext(io) {
            degrade(
                onUnavailable = { UsageDailyResult(daily = null, available = false) },
            ) {
                UsageDailyResult(daily = api.usageDaily(from = from, to = to), available = true)
            }
        }

    override suspend fun usageStorage(topN: Int?): ApiResult<UsageStorageResult> = withContext(io) {
        degrade(
            onUnavailable = { UsageStorageResult(storage = null, available = false) },
        ) {
            UsageStorageResult(storage = api.usageStorage(topN = topN), available = true)
        }
    }

    /**
     * Run [block]; on a 404 (route absent) or 403 (feature disabled) return [onUnavailable] wrapped as a
     * Success (the surface is not enabled here). Other HTTP errors -> Failure; IO -> NetworkError.
     */
    private suspend fun <T> degrade(
        onUnavailable: () -> T,
        block: suspend () -> T,
    ): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        val error = errorParser.from(e)
        if (error.status == HTTP_NOT_FOUND || error.status == HTTP_FORBIDDEN) {
            ApiResult.Success(onUnavailable())
        } else {
            ApiResult.Failure(error)
        }
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
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

    private companion object {
        const val HTTP_NOT_FOUND = 404
        const val HTTP_FORBIDDEN = 403
    }
}
