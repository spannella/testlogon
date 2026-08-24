package com.testlogon.android.data.rewards

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Retrofit
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Data layer for the REFERRALS + REWARDS surface over [RewardsApi].
 *
 * READS ([referral], [referralList], [rewards], [rewardsHistory], [rewardsCatalog]) DEGRADE on 404 /
 * HTTP-error to an honest empty/unavailable value so the screens show a truthful "coming soon" empty
 * state rather than an error; a real transport failure surfaces as [ApiResult.NetworkError] so the UI
 * can offer retry. The MUTATION ([redeem]) passes failures through as [ApiResult.Failure] /
 * [ApiResult.NetworkError] — a rejection (or undeployed 404) surfaces as a CLEAR error and NEVER a
 * silent success (no points/cash are ever assumed moved on the client). CancellationException is always
 * re-thrown. Crediting is entirely server-side; the client owns only surfaces + share + redeem.
 */
interface RewardsRepository {
    suspend fun referral(): ApiResult<ReferralSummary>
    suspend fun referralList(): ApiResult<List<ReferredUser>>
    suspend fun rewards(): ApiResult<Rewards>
    suspend fun rewardsHistory(): ApiResult<List<RewardsHistoryEntry>>
    suspend fun rewardsCatalog(): ApiResult<List<CatalogReward>>
    suspend fun redeem(rewardId: String): ApiResult<RedeemResult>
    suspend fun referralLeaderboard(period: LeaderboardPeriod): ApiResult<ReferralLeaderboard>
    /**
     * OPTIONAL authoritative trading-rewards read. A 404 (undeployed) degrades to an honest
     * unavailable value so the card falls back to the client estimate; network errors surface.
     */
    suspend fun tradingRewards(): ApiResult<TradingRewards>
}

@Singleton
class RewardsRepositoryImpl @Inject constructor(
    private val api: RewardsApi,
    private val errorParser: ApiErrorParser,
) : RewardsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    /** Referral summary. A 404 (undeployed) degrades to an honest unavailable summary; network errors surface. */
    override suspend fun referral(): ApiResult<ReferralSummary> = degrading(
        block = { api.referral().toDomain() },
        onHttpError = { ReferralSummary.unavailable() },
    )

    /** Referred-user list. A 404 degrades to an empty list; network errors surface. */
    override suspend fun referralList(): ApiResult<List<ReferredUser>> = degrading(
        block = { api.referralList().toDomain() },
        onHttpError = { emptyList() },
    )

    /** Rewards summary. A 404 degrades to an honest unavailable rewards value; network errors surface. */
    override suspend fun rewards(): ApiResult<Rewards> = degrading(
        block = { api.rewards().toDomain() },
        onHttpError = { Rewards.unavailable() },
    )

    /** Rewards history. A 404 degrades to an empty list; network errors surface. */
    override suspend fun rewardsHistory(): ApiResult<List<RewardsHistoryEntry>> = degrading(
        block = { api.rewardsHistory().toDomain() },
        onHttpError = { emptyList() },
    )

    /** Redeem catalog. A 404 degrades to an empty list; network errors surface. */
    override suspend fun rewardsCatalog(): ApiResult<List<CatalogReward>> = degrading(
        block = { api.rewardsCatalog().toDomain() },
        onHttpError = { emptyList() },
    )

    /** Redeem a reward (MUTATION). A rejection or undeployed 404 surfaces as a clear error, never a silent success. */
    override suspend fun redeem(rewardId: String): ApiResult<RedeemResult> = call {
        api.redeem(RedeemRequestDto(rewardId = rewardId.trim())).toDomain()
    }

    /** Referral leaderboard. A 404 (undeployed) degrades to an honest unavailable board; network errors surface. */
    override suspend fun referralLeaderboard(period: LeaderboardPeriod): ApiResult<ReferralLeaderboard> = degrading(
        block = { api.referralLeaderboard(period.wire).toDomain(period) },
        onHttpError = { ReferralLeaderboard.unavailable(period) },
    )

    /** Trading rewards. A 404 (undeployed) degrades to an honest unavailable value; network errors surface. */
    override suspend fun tradingRewards(): ApiResult<TradingRewards> = degrading(
        block = { api.tradingRewards().toDomain() },
        onHttpError = { TradingRewards.unavailable() },
    )

    /** Read wrapper: HTTP-error (incl. 404) degrades to [onHttpError]; transport -> NetworkError. */
    private suspend fun <T> degrading(
        block: suspend () -> T,
        onHttpError: () -> T,
    ): ApiResult<T> = withContext(io) {
        try {
            ApiResult.Success(block())
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Success(onHttpError())
        } catch (e: com.squareup.moshi.JsonDataException) {
            ApiResult.Success(onHttpError())
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }

    /** Mutation wrapper: HTTP-error -> Failure (clear error), transport -> NetworkError. */
    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = withContext(io) {
        try {
            ApiResult.Success(block())
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Failure(errorParser.from(e))
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }
}

/** Provides [RewardsApi] on the shared authenticated Retrofit + binds the repository impl. */
@Module
@InstallIn(SingletonComponent::class)
object RewardsApiModule {
    @Provides
    @Singleton
    fun provideRewardsApi(retrofit: Retrofit): RewardsApi = retrofit.create(RewardsApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class RewardsDataModule {
    @Binds
    @Singleton
    abstract fun bindRewardsRepository(impl: RewardsRepositoryImpl): RewardsRepository
}
