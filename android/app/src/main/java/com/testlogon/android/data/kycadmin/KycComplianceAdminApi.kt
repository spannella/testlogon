package com.testlogon.android.data.kycadmin

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Retrofit
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * B7 - KYC compliance reports. Mirrors web /admin/kyc/compliance (KycComplianceReportsPage.tsx +
 * api/endpoints/kycCompliance.ts). Backend kyc_compliance_reports.py, prefix /v1/kyc/compliance,
 * admin-gated. Surfaces the four period reports (volume / screening / processing-time / deadlines) +
 * retention inventory summary + on-demand SAR generation (subject user_sub + reason). Epoch SECONDS.
 */
interface KycComplianceAdminApi {

    @GET("v1/kyc/compliance/reports/volume")
    suspend fun volume(): KycVolumeReportDto

    @GET("v1/kyc/compliance/reports/screening")
    suspend fun screening(): KycScreeningReportDto

    @GET("v1/kyc/compliance/reports/processing-time")
    suspend fun processingTime(): KycProcessingTimeReportDto

    @GET("v1/kyc/compliance/reports/deadlines")
    suspend fun deadlines(): KycDeadlineReportDto

    @GET("v1/kyc/compliance/reports/retention")
    suspend fun retention(): KycRetentionReportDto

    @POST("v1/kyc/compliance/sar")
    suspend fun generateSar(@Body body: KycSarReq): KycSarDto
}

@JsonClass(generateAdapter = true)
data class KycVolumeReportDto(
    @Json(name = "period_start") val periodStart: Long = 0L,
    @Json(name = "period_end") val periodEnd: Long = 0L,
    @Json(name = "total_cases") val totalCases: Int = 0,
    @Json(name = "counts_by_status") val countsByStatus: Map<String, Int> = emptyMap(),
    @Json(name = "approval_rate") val approvalRate: Double = 0.0,
    @Json(name = "rejection_rate") val rejectionRate: Double = 0.0,
    @Json(name = "generated_at") val generatedAt: Long = 0L,
)

@JsonClass(generateAdapter = true)
data class KycScreeningReportDto(
    @Json(name = "total_screenings") val totalScreenings: Int = 0,
    @Json(name = "total_hits") val totalHits: Int = 0,
    @Json(name = "hit_rate_pct") val hitRatePct: Double = 0.0,
    @Json(name = "false_positive_count") val falsePositiveCount: Int = 0,
    @Json(name = "escalated_count") val escalatedCount: Int = 0,
    @Json(name = "confirmed_count") val confirmedCount: Int = 0,
    @Json(name = "resolutions") val resolutions: Map<String, Int> = emptyMap(),
)

@JsonClass(generateAdapter = true)
data class KycProcessingTimeReportDto(
    @Json(name = "total_decided") val totalDecided: Int = 0,
    @Json(name = "avg_seconds") val avgSeconds: Double = 0.0,
    @Json(name = "p50_seconds") val p50Seconds: Double? = null,
    @Json(name = "p90_seconds") val p90Seconds: Double? = null,
    @Json(name = "p95_seconds") val p95Seconds: Double? = null,
)

@JsonClass(generateAdapter = true)
data class KycOverdueCaseDto(
    @Json(name = "case_id") val caseId: String = "",
    @Json(name = "user_sub") val userSub: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "age_hours") val ageHours: Double = 0.0,
    @Json(name = "severity") val severity: String = "",
    @Json(name = "assigned_admin") val assignedAdmin: String? = null,
)

@JsonClass(generateAdapter = true)
data class KycDeadlineReportDto(
    @Json(name = "warn_after_hours") val warnAfterHours: Double = 0.0,
    @Json(name = "critical_after_hours") val criticalAfterHours: Double = 0.0,
    @Json(name = "total_overdue") val totalOverdue: Int = 0,
    @Json(name = "critical_count") val criticalCount: Int = 0,
    @Json(name = "warning_count") val warningCount: Int = 0,
    @Json(name = "cases") val cases: List<KycOverdueCaseDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class KycRetentionReportDto(
    @Json(name = "total_records") val totalRecords: Int = 0,
    @Json(name = "overdue_purge_count") val overduePurgeCount: Int = 0,
    @Json(name = "already_purged_count") val alreadyPurgedCount: Int = 0,
    @Json(name = "policies") val policies: Map<String, String> = emptyMap(),
)

@JsonClass(generateAdapter = true)
data class KycSarReq(
    @Json(name = "user_sub") val userSub: String,
    @Json(name = "reason") val reason: String,
)

@JsonClass(generateAdapter = true)
data class KycSarDto(
    @Json(name = "sar_id") val sarId: String = "",
    @Json(name = "generated_at") val generatedAt: Long = 0L,
    @Json(name = "subject_user_sub") val subjectUserSub: String = "",
    @Json(name = "reason") val reason: String = "",
)

data class KycComplianceData(
    val volume: KycVolumeReportDto,
    val screening: KycScreeningReportDto,
    val processingTime: KycProcessingTimeReportDto,
    val deadlines: KycDeadlineReportDto,
    val retention: KycRetentionReportDto,
)

interface KycComplianceAdminRepository {
    suspend fun load(): ApiResult<KycComplianceData>
    suspend fun generateSar(userSub: String, reason: String): ApiResult<KycSarDto>
}

@Singleton
class DefaultKycComplianceAdminRepository @Inject constructor(
    private val api: KycComplianceAdminApi,
    private val errorParser: ApiErrorParser,
) : KycComplianceAdminRepository {

    override suspend fun load(): ApiResult<KycComplianceData> = io {
        KycComplianceData(
            volume = api.volume(),
            screening = api.screening(),
            processingTime = api.processingTime(),
            deadlines = api.deadlines(),
            retention = api.retention(),
        )
    }

    override suspend fun generateSar(userSub: String, reason: String): ApiResult<KycSarDto> =
        io { api.generateSar(KycSarReq(userSub.trim(), reason.trim())) }

    private suspend fun <T> io(block: suspend () -> T): ApiResult<T> = withContext(Dispatchers.IO) {
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

@Module
@InstallIn(SingletonComponent::class)
object KycComplianceAdminApiModule {
    @Provides
    @Singleton
    fun provideKycComplianceAdminApi(retrofit: Retrofit): KycComplianceAdminApi =
        retrofit.create(KycComplianceAdminApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class KycComplianceAdminDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindKycComplianceAdminRepository(impl: DefaultKycComplianceAdminRepository): KycComplianceAdminRepository
}
