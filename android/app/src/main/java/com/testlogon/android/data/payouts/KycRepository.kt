package com.testlogon.android.data.payouts

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
 * AND-259 — KYC tier data layer over [KycApi] (the payout gate's source).
 *
 * Reads the current tier and the requirements toward [PAYOUT_REQUIRED_TIER], folding both into a
 * [TierStatus] (server `eligible` boolean preferred; falls back to a rank compare in the gate). All
 * calls are [ApiResult]-wrapped (CancellationException re-thrown; HTTP -> Failure; transport ->
 * NetworkError). `evaluate` is a mutation used to refresh after a (scaffolded) verification return; it
 * does NOT launch a vendor flow.
 */
interface KycRepository {

    /**
     * Loads tier status + requirements toward [requiredTier] in one combined call. If the requirements
     * leg fails it is treated as "not resolved" (eligible = null) rather than failing the whole load, so
     * the gate can still rank-compare; if the tier leg itself fails, the whole call fails (fail-closed).
     */
    suspend fun loadTierStatus(requiredTier: Int = PAYOUT_REQUIRED_TIER): ApiResult<TierStatus>

    /** Re-evaluate the tier (refresh after KYC return), then re-resolve requirements. Mutation. */
    suspend fun evaluateTierStatus(requiredTier: Int = PAYOUT_REQUIRED_TIER): ApiResult<TierStatus>
}

@Singleton
class KycRepositoryImpl @Inject constructor(
    private val api: KycApi,
    private val errorParser: ApiErrorParser,
) : KycRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun loadTierStatus(requiredTier: Int): ApiResult<TierStatus> = withContext(io) {
        call { combine(api.getMyTier(), requiredTier) }
    }

    override suspend fun evaluateTierStatus(requiredTier: Int): ApiResult<TierStatus> = withContext(io) {
        call { combine(api.evaluate(), requiredTier) }
    }

    /**
     * Combines a [TierDetailsDto] with a best-effort requirements lookup. The requirements call is
     * tolerant: any failure leaves `eligible = null` (the gate falls back to a rank compare).
     */
    private suspend fun combine(details: TierDetailsDto, requiredTier: Int): TierStatus {
        val reqs: TierRequirementsDto? = try {
            api.getRequirements(requiredTier)
        } catch (e: CancellationException) {
            throw e
        } catch (_: HttpException) {
            null
        } catch (_: IOException) {
            null
        }
        return details.toDomain(
            requiredTier = KycTier(requiredTier),
            eligible = reqs?.eligible,
            unmet = reqs?.unmet ?: emptyList(),
        )
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
