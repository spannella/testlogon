package com.testlogon.android.data.compliance

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
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
 * Compliance/security data layer over [ComplianceApi].
 *
 * loadSummary() fans out open-findings + compliance-status to derive the 4 summary tiles. The tabs load
 * findings (filtered), audits, trends, and framework status. Mutations (finding status transition, audit
 * trigger) map 1:1. Every call is wrapped in [ApiResult].
 */
interface ComplianceRepository {
    suspend fun loadSummary(): ApiResult<ComplianceSummary>
    suspend fun loadFindings(severity: String?, status: String?): ApiResult<FindingsResult>
    suspend fun updateFindingStatus(findingId: String, status: FindingStatus): ApiResult<Unit>
    suspend fun loadAudits(): ApiResult<List<Audit>>
    suspend fun triggerAudit(): ApiResult<Unit>
    suspend fun loadTrends(): ApiResult<Trends>
    suspend fun loadFrameworks(): ApiResult<List<FrameworkStatus>>
}

@Singleton
class ComplianceRepositoryImpl @Inject constructor(
    private val api: ComplianceApi,
    private val errorParser: ApiErrorParser,
) : ComplianceRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun loadSummary(): ApiResult<ComplianceSummary> = withContext(io) {
        call {
            coroutineScope {
                val openD = async { api.listFindings(status = "open", limit = 200) }
                val complianceD = async { api.getComplianceStatus() }
                val findings = openD.await().findings.map { FindingSeverity.from(it.severity) }
                val frameworks = complianceD.await().toDomain()
                ComplianceSummary(
                    openCritical = findings.count { it == FindingSeverity.CRITICAL },
                    openHigh = findings.count { it == FindingSeverity.HIGH },
                    openTotal = findings.size,
                    frameworksFailing = frameworks.count { !it.passing },
                )
            }
        }
    }

    override suspend fun loadFindings(severity: String?, status: String?): ApiResult<FindingsResult> = withContext(io) {
        call { api.listFindings(severity = severity, status = status, limit = 100).toDomain() }
    }

    override suspend fun updateFindingStatus(findingId: String, status: FindingStatus): ApiResult<Unit> = withContext(io) {
        call {
            api.updateFindingStatus(findingId, UpdateFindingStatusReqDto(status = status.serverValue))
            Unit
        }
    }

    override suspend fun loadAudits(): ApiResult<List<Audit>> = withContext(io) {
        call { api.listAudits(limit = 50).audits.map { it.toDomain() } }
    }

    override suspend fun triggerAudit(): ApiResult<Unit> = withContext(io) {
        call {
            api.triggerAudit()
            Unit
        }
    }

    override suspend fun loadTrends(): ApiResult<Trends> = withContext(io) {
        call { api.getTrends(90).toDomain() }
    }

    override suspend fun loadFrameworks(): ApiResult<List<FrameworkStatus>> = withContext(io) {
        call { api.getComplianceStatus().toDomain() }
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
