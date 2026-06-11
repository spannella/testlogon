package com.testlogon.android.data.referrals

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
 * AND-264 — referrals data layer over [ReferralsApi].
 *
 * Thin orchestration: loadDashboard() issues the idempotent GET ui/referrals/dashboard and maps the DTO
 * to [ReferralDashboard]; createCode() POSTs ui/referrals/code (mutation, not auto-retried) and returns
 * the new [ReferralCode]. Every call is wrapped in [ApiResult] (CancellationException re-thrown,
 * HTTP -> Failure, transport -> NetworkError). DTOs map to domain before returning (no raw DTOs leak).
 *
 * A last-known-good [ReferralDashboard] is held in memory so a failed refresh can fall back to a stale
 * snapshot for the offline/stale UI; [clear] empties it (logout cleanup).
 */
interface ReferralsRepository {

    suspend fun loadDashboard(): ApiResult<ReferralDashboard>

    suspend fun createCode(): ApiResult<ReferralCode>

    /** Last successful dashboard snapshot, or null if none cached. */
    fun cached(): ReferralDashboard?

    /** Drop the cached snapshot (logout cleanup). */
    fun clear()
}

@Singleton
class ReferralsRepositoryImpl @Inject constructor(
    private val api: ReferralsApi,
    private val errorParser: ApiErrorParser,
) : ReferralsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    @Volatile
    private var snapshot: ReferralDashboard? = null

    override suspend fun loadDashboard(): ApiResult<ReferralDashboard> = withContext(io) {
        call { api.getDashboard().toDomain() }
            .also { if (it is ApiResult.Success) snapshot = it.data }
    }

    override suspend fun createCode(): ApiResult<ReferralCode> = withContext(io) {
        call { api.createCode().toDomain() }
    }

    override fun cached(): ReferralDashboard? = snapshot

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
