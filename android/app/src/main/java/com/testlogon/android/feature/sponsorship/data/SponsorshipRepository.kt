package com.testlogon.android.feature.sponsorship.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.sponsorship.SponsorshipDeal
import com.testlogon.android.core.model.sponsorship.SponsorshipDealDetail
import com.testlogon.android.core.model.sponsorship.SponsorshipDealEvent
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.sponsorship.SponsorshipApi
import com.testlogon.android.core.network.sponsorship.SponsorshipCounterReq
import com.testlogon.android.core.network.sponsorship.SponsorshipRejectReq
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-365 - READ-ONLY data layer for the sponsorship inbox, over the [SponsorshipApi].
 *
 * A SINGLE GET loads the FULL deal array in one response (NO cursor / limit / paging - the endpoint is
 * unordered and returns every deal). The RAW DTOs are mapped to the core-model domain and folded into
 * [ApiResult] via [call] (mirrors AND-356 / AND-358). Sorting (newest-first by created_at) and the
 * status-group filter are applied CLIENT-SIDE in the ViewModel, NOT here.
 *
 * AND-366 extends this with the deal-detail read (getDeal + getHistory, kept SEPARATE) and the three
 * NON-idempotent management mutations (accept / reject / counter). Each call is folded into [ApiResult] via
 * [call]; the VM owns confirm-then-POST, in-flight gating and the NO-auto-retry policy.
 *
 * ROOM / STALE: there is intentionally NO Room-backed cache and NO migration this wave. The stale-while-
 * offline snapshot is kept IN-MEMORY in the ViewModel (an isStale flag over the last-good list), NOT on
 * disk; persistence across process death is DEFERRED to a later ticket.
 */
interface SponsorshipRepository {

    /** GET the full inbox (bare array), mapped to domain. CLIENT-SIDE sort + filter happen at the VM. */
    suspend fun listDeals(): ApiResult<List<SponsorshipDeal>>

    /** GET the FULL deal by id, mapped to domain. Idempotent. (AND-366) */
    suspend fun getDeal(dealId: String): ApiResult<SponsorshipDealDetail>

    /** GET the deal's history (bare array), mapped. Idempotent; the VM tolerates this failing. (AND-366) */
    suspend fun getHistory(dealId: String): ApiResult<List<SponsorshipDealEvent>>

    /** POST accept (NO body) -> the updated deal. NON-idempotent (never auto-retried). (AND-366) */
    suspend fun accept(dealId: String): ApiResult<SponsorshipDealDetail>

    /** POST reject with an optional [reason] -> the updated deal. NON-idempotent. (AND-366) */
    suspend fun reject(dealId: String, reason: String): ApiResult<SponsorshipDealDetail>

    /**
     * POST a counter-offer -> the updated (negotiating) deal. BOTH [compensationCents] and [note] are
     * optional (null omits the field). NON-idempotent. (AND-366)
     */
    suspend fun counter(
        dealId: String,
        compensationCents: Long?,
        note: String?,
    ): ApiResult<SponsorshipDealDetail>
}

@Singleton
class SponsorshipRepositoryImpl @Inject constructor(
    private val api: SponsorshipApi,
    private val errorParser: ApiErrorParser,
) : SponsorshipRepository {

    override suspend fun listDeals(): ApiResult<List<SponsorshipDeal>> =
        withContext(Dispatchers.IO) {
            call { api.listDeals().map { it.toDomain() } }
        }

    override suspend fun getDeal(dealId: String): ApiResult<SponsorshipDealDetail> =
        withContext(Dispatchers.IO) {
            call { api.getDeal(dealId).toDomain() }
        }

    override suspend fun getHistory(dealId: String): ApiResult<List<SponsorshipDealEvent>> =
        withContext(Dispatchers.IO) {
            call { api.getHistory(dealId).map { it.toDomain() } }
        }

    override suspend fun accept(dealId: String): ApiResult<SponsorshipDealDetail> =
        withContext(Dispatchers.IO) {
            call { api.accept(dealId).toDomain() }
        }

    override suspend fun reject(dealId: String, reason: String): ApiResult<SponsorshipDealDetail> =
        withContext(Dispatchers.IO) {
            call { api.reject(dealId, SponsorshipRejectReq(reason = reason)).toDomain() }
        }

    override suspend fun counter(
        dealId: String,
        compensationCents: Long?,
        note: String?,
    ): ApiResult<SponsorshipDealDetail> =
        withContext(Dispatchers.IO) {
            call {
                api.counter(
                    dealId,
                    SponsorshipCounterReq(compensationCents = compensationCents, note = note),
                ).toDomain()
            }
        }

    /**
     * Folds a block into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser], preserving the status, so
     * a 401 surfaces as Failure(status=401)); malformed JSON -> Failure; transport failures -> NetworkError.
     * JsonEncodingException precedes IOException (it is a subtype). Cancellation is re-thrown. Mirrors AND-358.
     */
    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonEncodingException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
