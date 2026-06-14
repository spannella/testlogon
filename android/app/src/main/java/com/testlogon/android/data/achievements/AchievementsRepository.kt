package com.testlogon.android.data.achievements

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.auth.AuthStateStore
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-093 / AND-094 — achievements + leaderboard data layer over [AchievementsApi].
 *
 * The achievements catalog fans out to three concurrent GETs and composes the partitioned
 * [AchievementCatalog] in the mapper. The primary `/ui/achievements` (earned) call decides
 * success/failure; `/progress` and `/definitions` are best-effort (degraded mode renders earned-only
 * if they fail). The leaderboard merges the ranked list with the separate `/me` rank; a `/me` failure
 * degrades gracefully (list renders, own-rank hidden). Mutations: none. CancellationException is
 * re-thrown so structured concurrency works.
 */
interface AchievementsRepository {

    suspend fun getCatalog(): ApiResult<AchievementCatalog>

    suspend fun getLeaderboard(period: String, limit: Int = 50): ApiResult<Leaderboard>
}

@Singleton
class AchievementsRepositoryImpl @Inject constructor(
    private val api: AchievementsApi,
    private val authStateStore: AuthStateStore,
    private val errorParser: ApiErrorParser,
) : AchievementsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun getCatalog(): ApiResult<AchievementCatalog> = withContext(io) {
        coroutineScope {
            val earnedDeferred = async { apiCall { api.getMyAchievements() } }
            val progressDeferred = async { apiCall { api.getProgress() } }
            val definitionsDeferred = async { apiCall { api.listDefinitions(activeOnly = true) } }

            when (val earned = earnedDeferred.await()) {
                is ApiResult.Success -> {
                    // Best-effort: failed side calls degrade to empty rather than failing the screen.
                    val progress = (progressDeferred.await() as? ApiResult.Success)?.data
                        ?: AchievementProgressResponseDto()
                    val definitions = (definitionsDeferred.await() as? ApiResult.Success)?.data
                        ?: AchievementDefinitionsResponseDto()
                    ApiResult.Success(buildCatalog(earned.data, progress, definitions))
                }
                is ApiResult.Failure -> earned
                is ApiResult.NetworkError -> earned
            }
        }
    }

    override suspend fun getLeaderboard(period: String, limit: Int): ApiResult<Leaderboard> =
        withContext(io) {
            val currentSub = authStateStore.userSub.value
            coroutineScope {
                val listDeferred = async { apiCall { api.getLeaderboard(period, limit) } }
                val meDeferred = async { apiCall { api.getMyRank(period) } }

                when (val list = listDeferred.await()) {
                    is ApiResult.Success -> {
                        val me = (meDeferred.await() as? ApiResult.Success)?.data
                            ?.toDomainOrNull(currentSub)
                        ApiResult.Success(
                            Leaderboard(
                                entries = list.data.entries.map { it.toDomain(currentSub) },
                                me = me,
                                nextCursor = list.data.nextCursor,
                                period = list.data.period ?: period,
                            ),
                        )
                    }
                    is ApiResult.Failure -> list
                    is ApiResult.NetworkError -> list
                }
            }
        }

    private suspend fun <T> apiCall(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
