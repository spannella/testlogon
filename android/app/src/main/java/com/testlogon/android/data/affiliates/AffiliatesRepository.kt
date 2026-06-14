package com.testlogon.android.data.affiliates

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.referrals.DEFAULT_CURRENCY_USD
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
 * AND-265 — affiliates dashboard data layer over [AffiliatesApi].
 *
 * Thin orchestration: loadDashboard() issues the single idempotent GET ui/affiliates/links, maps to
 * domain, and computes the aggregated earnings client-side. Wrapped in [ApiResult] (CancellationException
 * re-thrown, HTTP -> Failure, JsonDataException -> Failure, transport -> NetworkError). DTOs map to
 * domain before returning. A last-known-good snapshot is held in memory for the offline/stale UI; [clear]
 * empties it (logout cleanup).
 */
interface AffiliatesRepository {

    suspend fun loadDashboard(): ApiResult<AffiliateDashboard>

    fun cached(): AffiliateDashboard?

    fun clear()
}

@Singleton
class AffiliatesRepositoryImpl @Inject constructor(
    private val api: AffiliatesApi,
    private val errorParser: ApiErrorParser,
) : AffiliatesRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    @Volatile
    private var snapshot: AffiliateDashboard? = null

    override suspend fun loadDashboard(): ApiResult<AffiliateDashboard> = withContext(io) {
        call { api.getLinks().toDomain(DEFAULT_CURRENCY_USD) }
            .also { if (it is ApiResult.Success) snapshot = it.data }
    }

    override fun cached(): AffiliateDashboard? = snapshot

    override fun clear() {
        snapshot = null
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: com.squareup.moshi.JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
