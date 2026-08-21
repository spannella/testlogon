package com.testlogon.android.data.strategies

import com.testlogon.android.core.model.ApiResult
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
 * Data layer over [StrategiesApi] for the USER-CREATED STRATEGIES / BASKETS surface.
 *
 * The `me/strategies/(all)` endpoints do NOT exist on the backend yet, so every READ DEGRADES to an
 * empty-but-honest value on 404/HTTP-error (the UI shows an honest "pending backend" / empty state),
 * while a real transport failure ([ApiResult.NetworkError]) is surfaced so the UI can offer retry.
 * Every MUTATION passes failures through as [ApiResult.Failure]/[ApiResult.NetworkError] so a 404
 * (undeployed) surfaces as a clear error and never a silent success.
 */
interface StrategiesRepository {
    /** Strategies authored by the caller (degrades to empty). */
    suspend fun mine(): ApiResult<List<Strategy>>

    /** Published strategies to browse — the marketplace (degrades to empty). */
    suspend fun market(): ApiResult<List<Strategy>>

    /** A single strategy by id (degrades to null when absent/undeployed). */
    suspend fun strategy(id: String): ApiResult<Strategy?>

    /** Current NAV read (degrades to null when none / undeployed). */
    suspend fun nav(id: String): ApiResult<StrategyNav?>

    /** Holdings breakdown (degrades to empty). */
    suspend fun holdings(id: String): ApiResult<List<StrategyHolding>>

    /** The caller's investor position (degrades to null when none / undeployed). */
    suspend fun position(id: String): ApiResult<InvestorPosition?>

    /** Creator-view fee schedule (degrades to a zeroed, empty read). */
    suspend fun fees(id: String): ApiResult<StrategyFees>

    // ---- Mutations (errors surface; never silent success) ----
    suspend fun create(body: UpsertStrategyRequestDto): ApiResult<Strategy>
    suspend fun update(id: String, body: UpsertStrategyRequestDto): ApiResult<Strategy>
    suspend fun publish(id: String): ApiResult<Strategy>
    suspend fun invest(id: String, amountCents: Long): ApiResult<StrategyAck>
    suspend fun redeem(id: String, units: Long): ApiResult<StrategyAck>
}

@Singleton
class StrategiesRepositoryImpl @Inject constructor(
    private val api: StrategiesApi,
    private val errorParser: ApiErrorParser,
) : StrategiesRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun mine(): ApiResult<List<Strategy>> = withContext(io) {
        degradeToEmpty(emptyList()) { api.getMine().toDomain() }
    }

    override suspend fun market(): ApiResult<List<Strategy>> = withContext(io) {
        degradeToEmpty(emptyList()) { api.getMarket().toDomain() }
    }

    override suspend fun strategy(id: String): ApiResult<Strategy?> = withContext(io) {
        degradeToEmpty(null) { api.getStrategy(id).toDomain() }
    }

    override suspend fun nav(id: String): ApiResult<StrategyNav?> = withContext(io) {
        degradeToEmpty(null) { api.getNav(id).toDomain(id) }
    }

    override suspend fun holdings(id: String): ApiResult<List<StrategyHolding>> = withContext(io) {
        degradeToEmpty(emptyList()) { api.getHoldings(id).toDomain() }
    }

    override suspend fun position(id: String): ApiResult<InvestorPosition?> = withContext(io) {
        degradeToEmpty(null) { api.getPosition(id).toDomain(id) }
    }

    override suspend fun fees(id: String): ApiResult<StrategyFees> = withContext(io) {
        degradeToEmpty(StrategyFees(id, 0L, 0L, 0L, emptyList())) { api.getFees(id).toDomain(id) }
    }

    override suspend fun create(body: UpsertStrategyRequestDto): ApiResult<Strategy> =
        withContext(io) { apiCall { api.create(body).toDomain() } }

    override suspend fun update(id: String, body: UpsertStrategyRequestDto): ApiResult<Strategy> =
        withContext(io) { apiCall { api.update(id, body).toDomain() } }

    override suspend fun publish(id: String): ApiResult<Strategy> =
        withContext(io) { apiCall { api.publish(id).toDomain() } }

    override suspend fun invest(id: String, amountCents: Long): ApiResult<StrategyAck> =
        withContext(io) { apiCall { api.invest(id, InvestRequestDto(amountCents)).toDomain() } }

    override suspend fun redeem(id: String, units: Long): ApiResult<StrategyAck> =
        withContext(io) { apiCall { api.redeem(id, RedeemRequestDto(units)).toDomain() } }

    /**
     * Read helper: run [block]; on an HTTP error (the endpoint doesn't exist yet -> 404) DEGRADE to
     * [empty]; only a transport [ApiResult.NetworkError] is surfaced (so the UI can offer retry).
     */
    private suspend fun <T> degradeToEmpty(empty: T, block: suspend () -> T): ApiResult<T> =
        when (val r = apiCall(block)) {
            is ApiResult.Success -> r
            is ApiResult.Failure -> ApiResult.Success(empty)
            is ApiResult.NetworkError -> r
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
