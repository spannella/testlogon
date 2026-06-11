package com.testlogon.android.data.discounts

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
 * AND-267 — affiliate-discounts data layer over [AffiliateDiscountsApi].
 *
 * Thin orchestration mirroring the AND-264/265 repos: loadDiscounts() issues the single idempotent GET
 * ui/ads/affiliate/discounts and maps the DTO list to domain; loadDiscount(creativeId) reads a single row
 * (FR-7 detail) via the per-creative GET. Every call is wrapped in [ApiResult] (CancellationException
 * re-thrown, HTTP -> Failure, JsonDataException -> Failure, transport -> NetworkError). DTOs map to domain
 * before returning (no raw DTOs leak).
 *
 * A last-known-good [AffiliateDiscounts] snapshot is held in memory so a failed refresh can fall back to a
 * stale snapshot for the offline/stale UI; [clear] empties it (logout cleanup).
 */
interface AffiliateDiscountsRepository {

    suspend fun loadDiscounts(): ApiResult<AffiliateDiscounts>

    suspend fun loadDiscount(creativeId: String): ApiResult<AffiliateDiscount>

    /** Last successful discounts snapshot, or null if none cached. */
    fun cached(): AffiliateDiscounts?

    /** Drop the cached snapshot (logout cleanup). */
    fun clear()
}

@Singleton
class AffiliateDiscountsRepositoryImpl @Inject constructor(
    private val api: AffiliateDiscountsApi,
    private val errorParser: ApiErrorParser,
) : AffiliateDiscountsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    @Volatile
    private var snapshot: AffiliateDiscounts? = null

    override suspend fun loadDiscounts(): ApiResult<AffiliateDiscounts> = withContext(io) {
        call { api.listDiscounts().toDomain() }
            .also { if (it is ApiResult.Success) snapshot = it.data }
    }

    override suspend fun loadDiscount(creativeId: String): ApiResult<AffiliateDiscount> = withContext(io) {
        call { api.getDiscount(creativeId).toDomain() }
    }

    override fun cached(): AffiliateDiscounts? = snapshot

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
    } catch (e: com.squareup.moshi.JsonEncodingException) {
        // Malformed JSON body (an IOException subclass) is a server contract violation -> Failure, not a
        // transport NetworkError. Must precede the IOException catch since it extends IOException.
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
