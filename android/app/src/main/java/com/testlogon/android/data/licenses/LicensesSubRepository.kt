package com.testlogon.android.data.licenses

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

interface LicensesSubRepository {

    suspend fun loadCompliance(status: String?): ApiResult<CompliancePage>
    suspend fun loadComplianceDetail(contentId: String): ApiResult<ComplianceDetail>
    suspend fun checkCompliance(contentId: String): ApiResult<Unit>
    suspend fun flagContent(contentId: String, reason: String, evidence: String): ApiResult<Unit>

    suspend fun loadReceived(status: String?): ApiResult<FullLicenseRequestsPage>
    suspend fun loadSent(status: String?): ApiResult<FullLicenseRequestsPage>
    suspend fun approve(requestId: String, contentId: String): ApiResult<Unit>
    suspend fun deny(requestId: String, contentId: String, reason: String): ApiResult<Unit>
    suspend fun counter(requestId: String, contentId: String, terms: LicenseTerms): ApiResult<Unit>
    suspend fun acceptCounter(requestId: String, contentId: String): ApiResult<Unit>
    suspend fun rejectCounter(requestId: String, contentId: String): ApiResult<Unit>
    suspend fun withdraw(requestId: String, contentId: String): ApiResult<Unit>

    suspend fun loadEarned(sourceType: String?): ApiResult<FullRevenuePage>
    suspend fun loadPaid(sourceType: String?): ApiResult<FullRevenuePage>
    suspend fun calculate(
        amountCents: Long,
        revenueSharePct: Int,
        profitSharePct: Int,
    ): ApiResult<RevenueSplitPreview>
}

@Singleton
class LicensesSubRepositoryImpl @Inject constructor(
    private val complianceApi: LicenseComplianceApi,
    private val requestsApi: LicenseRequestsActionsApi,
    private val revenueApi: LicenseRevenueExtrasApi,
    private val errorParser: ApiErrorParser,
) : LicensesSubRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun loadCompliance(status: String?): ApiResult<CompliancePage> = withContext(io) {
        call { complianceApi.getMyContentCompliance(status = status, limit = PAGE_SIZE).toDomain() }
    }

    override suspend fun loadComplianceDetail(contentId: String): ApiResult<ComplianceDetail> =
        withContext(io) {
            call {
                val status = try {
                    complianceApi.getContentCompliance(contentId)
                } catch (e: HttpException) {
                    if (e.code() == 404) null else throw e
                }
                val refs = complianceApi.getContentLicenseRefs(contentId)
                val flags = complianceApi.getContentFlags(contentId, status = null)
                ComplianceDetail(
                    contentId = contentId,
                    status = status?.complianceStatus.orEmpty(),
                    hasRecord = status != null,
                    issues = status?.issues?.map { it.toDomain() }.orEmpty(),
                    refs = refs.items.map { it.toDomain() },
                    flags = flags.items.map { it.toDomain() },
                )
            }
        }

    override suspend fun checkCompliance(contentId: String): ApiResult<Unit> = withContext(io) {
        call { complianceApi.checkContentCompliance(contentId); Unit }
    }

    override suspend fun flagContent(
        contentId: String,
        reason: String,
        evidence: String,
    ): ApiResult<Unit> = withContext(io) {
        call {
            complianceApi.flagContent(
                FlagContentReqDto(contentId = contentId, reason = reason, evidence = evidence),
            )
            Unit
        }
    }

    override suspend fun loadReceived(status: String?): ApiResult<FullLicenseRequestsPage> =
        withContext(io) {
            call { requestsApi.getReceivedRequests(status = status, limit = PAGE_SIZE).toDomain() }
        }

    override suspend fun loadSent(status: String?): ApiResult<FullLicenseRequestsPage> =
        withContext(io) {
            call { requestsApi.getSentRequests(status = status, limit = PAGE_SIZE).toDomain() }
        }

    override suspend fun approve(requestId: String, contentId: String): ApiResult<Unit> =
        withContext(io) { call { requestsApi.approve(requestId, contentId); Unit } }

    override suspend fun deny(requestId: String, contentId: String, reason: String): ApiResult<Unit> =
        withContext(io) { call { requestsApi.deny(requestId, contentId, DenyReqDto(reason)); Unit } }

    override suspend fun counter(
        requestId: String,
        contentId: String,
        terms: LicenseTerms,
    ): ApiResult<Unit> = withContext(io) {
        call {
            requestsApi.counter(
                requestId,
                contentId,
                CounterReqDto(
                    LicenseTermsDto(
                        profitSharePct = terms.profitSharePct,
                        fixedCostCents = terms.fixedCostCents,
                        revenueSharePct = terms.revenueSharePct,
                    ),
                ),
            )
            Unit
        }
    }

    override suspend fun acceptCounter(requestId: String, contentId: String): ApiResult<Unit> =
        withContext(io) { call { requestsApi.acceptCounter(requestId, contentId); Unit } }

    override suspend fun rejectCounter(requestId: String, contentId: String): ApiResult<Unit> =
        withContext(io) { call { requestsApi.rejectCounter(requestId, contentId); Unit } }

    override suspend fun withdraw(requestId: String, contentId: String): ApiResult<Unit> =
        withContext(io) { call { requestsApi.withdraw(requestId, contentId); Unit } }

    override suspend fun loadEarned(sourceType: String?): ApiResult<FullRevenuePage> =
        withContext(io) {
            call { revenueApi.getEarned(sourceType = sourceType, limit = PAGE_SIZE).toDomain() }
        }

    override suspend fun loadPaid(sourceType: String?): ApiResult<FullRevenuePage> =
        withContext(io) {
            call { revenueApi.getPaid(sourceType = sourceType, limit = PAGE_SIZE).toDomain() }
        }

    override suspend fun calculate(
        amountCents: Long,
        revenueSharePct: Int,
        profitSharePct: Int,
    ): ApiResult<RevenueSplitPreview> = withContext(io) {
        call {
            revenueApi.calculate(
                amount = amountCents,
                revenueSharePct = revenueSharePct,
                profitSharePct = profitSharePct,
            ).toDomain()
        }
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

    private companion object {
        private const val PAGE_SIZE = 100
    }
}
