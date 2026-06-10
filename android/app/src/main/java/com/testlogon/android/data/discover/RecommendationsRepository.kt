package com.testlogon.android.data.discover

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
 * AND-184 — recommendations ("for you") data layer over [DiscoverApi.getForYou].
 *
 * Maps the flat ForYouResponse to [Recommendations]. An in-memory last-success cache (held in this
 * @Singleton) backs the stale path after a transient failure; [clearCache] is wired to logout. No Room
 * cache in this slice (the spec's 6h Room TTL is deferred — noted in the report). Not-interested
 * feedback reuses AND-175 [com.testlogon.android.data.feed.PostActionsRepository] from the ViewModel,
 * so there is no negative-signal call here.
 */
interface RecommendationsRepository {

    suspend fun getRecommendations(): ApiResult<Recommendations>

    fun cached(): Recommendations?

    fun clearCache()
}

@Singleton
class RecommendationsRepositoryImpl @Inject constructor(
    private val api: DiscoverApi,
    private val errorParser: ApiErrorParser,
) : RecommendationsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    @Volatile
    private var lastSuccess: Recommendations? = null

    override fun cached(): Recommendations? = lastSuccess

    override fun clearCache() {
        lastSuccess = null
    }

    override suspend fun getRecommendations(): ApiResult<Recommendations> = withContext(io) {
        val result = call { api.getForYou() }.map { it.toDomain() }
        if (result is ApiResult.Success) lastSuccess = result.data
        result
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
