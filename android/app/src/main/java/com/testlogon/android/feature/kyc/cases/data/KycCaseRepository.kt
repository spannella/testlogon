package com.testlogon.android.feature.kyc.cases.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.kyc.KycApi
import com.testlogon.android.core.network.kyc.KycMonitoringApi
import com.testlogon.android.feature.kyc.cases.model.KycCaseDetail
import com.testlogon.android.feature.kyc.cases.model.KycCaseSummary
import com.testlogon.android.feature.kyc.cases.model.MonitoringState
import com.testlogon.android.feature.kyc.cases.model.monitoringActive
import com.testlogon.android.feature.kyc.cases.model.synthesizeTimeline
import com.testlogon.android.feature.kyc.cases.model.toDomain
import com.testlogon.android.feature.kyc.cases.model.toSummary
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-329 - data layer for the READ-ONLY KYC case-status & ongoing-monitoring surface.
 *
 * REUSE: the case list + per-case detail REUSE AND-319's [KycApi] (listCases / getCase). Only the
 * ongoing-monitoring schedule + triggers use AND-329's [KycMonitoringApi]. All three reads are idempotent GETs
 * (READ-ONLY REST: no writes / SDK / flagged seam). DTOs are mapped to the feature domain BEFORE the typed
 * [ApiResult] (mirrors AND-326..328).
 *
 * TIMELINE: there is no wire history array, so [caseDetail] SYNTHESIZES the timeline client-side via the pure
 * [synthesizeTimeline]. MONITORING: [monitoring] derives the banner state via the pure [monitoringActive].
 *
 * There is NO Room / disk persistence (no migration) and NO poll loop here — refresh is driven by the
 * ViewModel.
 */
interface KycCaseRepository {

    /** Lists the caller's KYC cases (mapped summaries). REUSES AND-319 KycApi.listCases. Idempotent GET. */
    suspend fun cases(): ApiResult<List<KycCaseSummary>>

    /**
     * Reads one case + its synthesized timeline. REUSES AND-319 KycApi.getCase, then synthesizes the timeline
     * client-side. Idempotent GET.
     */
    suspend fun caseDetail(caseId: String): ApiResult<KycCaseDetail>

    /**
     * Reads the ongoing-monitoring schedule + recent triggers and derives the banner [MonitoringState]. Two
     * idempotent GETs; the result is folded by the pure [monitoringActive] reducer.
     */
    suspend fun monitoring(): ApiResult<MonitoringState>
}

@Singleton
class KycCaseRepositoryImpl @Inject constructor(
    private val kycApi: KycApi,
    private val monitoringApi: KycMonitoringApi,
    private val errorParser: ApiErrorParser,
) : KycCaseRepository {

    override suspend fun cases(): ApiResult<List<KycCaseSummary>> = withContext(Dispatchers.IO) {
        call { kycApi.listCases().items.map { it.toSummary() } }
    }

    override suspend fun caseDetail(caseId: String): ApiResult<KycCaseDetail> =
        withContext(Dispatchers.IO) {
            call {
                val case = kycApi.getCase(caseId).case
                KycCaseDetail(
                    case = case.toSummary(),
                    timeline = synthesizeTimeline(case),
                    reasonCodes = case.review?.reason_codes ?: emptyList(),
                )
            }
        }

    override suspend fun monitoring(): ApiResult<MonitoringState> = withContext(Dispatchers.IO) {
        call {
            val schedule = monitoringApi.schedule().toDomain()
            val triggers = monitoringApi.triggers().toDomain()
            monitoringActive(schedule, triggers)
        }
    }

    /**
     * Folds a block into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser], preserving the status,
     * covering the documented 422 + global 401); malformed JSON -> Failure(parse); transport failures ->
     * NetworkError. The JsonEncodingException catch precedes the IOException catch (it is an IOException
     * subtype). Cancellation is re-thrown. Mirrors AND-326..328.
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
