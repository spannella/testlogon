package com.testlogon.android.feature.kyc.screening.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.kyc.KycApi
import com.testlogon.android.core.network.kyc.KycScreeningApi
import com.testlogon.android.feature.kyc.screening.model.KycScreeningResult
import com.testlogon.android.feature.kyc.screening.model.toDomain
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-328 - data layer for the READ-ONLY KYC screening surface (sanctions / PEP / adverse-media results).
 *
 * Wraps AND-328's [KycScreeningApi] (the `ui/kyc/screening/cases/{case_id}` GET, provided by core-network's
 * KycNetworkModule) and REUSES AND-319's [KycApi.listCases] to source the case id. DTOs are mapped to the
 * feature domain BEFORE the typed [ApiResult] (mirrors AND-326 / AND-327).
 *
 * READ-ONLY REST: there are NO writes / mutations / SDK; both calls are idempotent GETs.
 *
 * CASE ID SOURCING: when no [caseId] is supplied, the latest case is picked from KycApi.listCases (by
 * created_at). When there is NO case at all, this returns Success(emptyList()) -> the ViewModel aggregates it
 * to NOT_STARTED rather than treating it as an error.
 *
 * LAST-KNOWN CACHE: the most recent successful result list is kept in memory so the ViewModel can show a stale
 * snapshot if a later refresh fails. There is NO Room / disk persistence (no migration).
 */
interface ScreeningRepository {

    /**
     * Reads the per-screen screening results for [caseId] (when supplied) or for the latest case (when null).
     * No case at all -> Success(emptyList()). Idempotent GET.
     */
    suspend fun screening(caseId: String? = null): ApiResult<List<KycScreeningResult>>

    /** The most recent successful result list (for stale display), or null if none seen yet. */
    fun lastKnown(): List<KycScreeningResult>?
}

@Singleton
class ScreeningRepositoryImpl @Inject constructor(
    private val screeningApi: KycScreeningApi,
    private val kycApi: KycApi,
    private val errorParser: ApiErrorParser,
) : ScreeningRepository {

    @Volatile
    private var cached: List<KycScreeningResult>? = null

    override fun lastKnown(): List<KycScreeningResult>? = cached

    override suspend fun screening(caseId: String?): ApiResult<List<KycScreeningResult>> =
        withContext(Dispatchers.IO) {
            call {
                val id = caseId ?: latestCaseId()
                if (id == null) {
                    emptyList()
                } else {
                    screeningApi.screening(id).results.map { it.toDomain() }
                }
            }.also { result ->
                if (result is ApiResult.Success) cached = result.data
            }
        }

    /** Picks the latest case id from KycApi.listCases (by created_at); null when there are no cases. */
    private suspend fun latestCaseId(): String? =
        kycApi.listCases().items.maxByOrNull { it.created_at }?.kyc_case_id

    /**
     * Folds a block into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser], preserving the status,
     * covering the documented 422 + global 401); malformed JSON -> Failure(parse); transport failures ->
     * NetworkError. The JsonEncodingException catch precedes the IOException catch (it is an IOException
     * subtype). Cancellation is re-thrown. Mirrors AND-326 / AND-327.
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
