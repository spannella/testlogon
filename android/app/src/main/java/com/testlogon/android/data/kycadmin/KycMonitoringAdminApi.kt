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
import retrofit2.http.POST
import retrofit2.http.GET
import retrofit2.http.Path
import retrofit2.http.Query
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * B5 - KYC ongoing-monitoring dashboard. Mirrors web /admin/kyc/monitoring (KycMonitoringPage.tsx +
 * api/endpoints/kycMonitoring.ts). Backend kyc_monitoring.py, prefix /v1/kyc/monitoring, admin-gated.
 * Dashboard read (admin/dashboard) + two batch jobs (admin/review-check, admin/rescreening, both take
 * a dry_run query) + per-user trigger (admin/{userSub}/trigger). Epoch SECONDS.
 */
interface KycMonitoringAdminApi {

    @GET("v1/kyc/monitoring/admin/dashboard")
    suspend fun dashboard(): KycMonitoringDashboardDto

    @POST("v1/kyc/monitoring/admin/review-check")
    suspend fun reviewCheck(@Query("dry_run") dryRun: Boolean): KycReviewCheckResultDto

    @POST("v1/kyc/monitoring/admin/rescreening")
    suspend fun rescreening(@Query("dry_run") dryRun: Boolean): KycRescreeningResultDto

    @POST("v1/kyc/monitoring/admin/{userSub}/trigger")
    suspend fun triggerReview(@Path("userSub") userSub: String, @Body body: KycTriggerReq)
}

@JsonClass(generateAdapter = true)
data class KycUpcomingReviewDto(
    @Json(name = "user_sub") val userSub: String = "",
    @Json(name = "risk_tier") val riskTier: String = "",
    @Json(name = "next_review_date") val nextReviewDate: Long = 0L,
    @Json(name = "days_until_due") val daysUntilDue: Int = 0,
)

@JsonClass(generateAdapter = true)
data class KycOverdueReviewDto(
    @Json(name = "user_sub") val userSub: String = "",
    @Json(name = "risk_tier") val riskTier: String = "",
    @Json(name = "next_review_date") val nextReviewDate: Long = 0L,
    @Json(name = "status") val status: String = "",
    @Json(name = "days_overdue") val daysOverdue: Int = 0,
    @Json(name = "grace_deadline") val graceDeadline: Long = 0L,
)

@JsonClass(generateAdapter = true)
data class KycMonitoringDashboardDto(
    @Json(name = "generated_at") val generatedAt: Long = 0L,
    @Json(name = "upcoming_reviews") val upcomingReviews: List<KycUpcomingReviewDto> = emptyList(),
    @Json(name = "overdue_reviews") val overdueReviews: List<KycOverdueReviewDto> = emptyList(),
    @Json(name = "needs_review_count") val needsReviewCount: Int = 0,
)

@JsonClass(generateAdapter = true)
data class KycReviewCheckResultDto(
    @Json(name = "checked_at") val checkedAt: Long = 0L,
    @Json(name = "dry_run") val dryRun: Boolean = false,
    @Json(name = "entered_grace_period") val enteredGracePeriod: Int = 0,
    @Json(name = "auto_downgraded") val autoDowngraded: Int = 0,
)

@JsonClass(generateAdapter = true)
data class KycRescreeningResultDto(
    @Json(name = "screened_at") val screenedAt: Long = 0L,
    @Json(name = "dry_run") val dryRun: Boolean = false,
    @Json(name = "total_screened") val totalScreened: Int = 0,
    @Json(name = "matches_found") val matchesFound: Int = 0,
    @Json(name = "triggers_created") val triggersCreated: Int = 0,
)

@JsonClass(generateAdapter = true)
data class KycTriggerReq(
    @Json(name = "reason") val reason: String,
)

interface KycMonitoringAdminRepository {
    suspend fun load(): ApiResult<KycMonitoringDashboardDto>
    suspend fun reviewCheck(dryRun: Boolean): ApiResult<KycReviewCheckResultDto>
    suspend fun rescreening(dryRun: Boolean): ApiResult<KycRescreeningResultDto>
    suspend fun triggerReview(userSub: String, reason: String): ApiResult<Unit>
}

@Singleton
class DefaultKycMonitoringAdminRepository @Inject constructor(
    private val api: KycMonitoringAdminApi,
    private val errorParser: ApiErrorParser,
) : KycMonitoringAdminRepository {

    override suspend fun load(): ApiResult<KycMonitoringDashboardDto> = io { api.dashboard() }
    override suspend fun reviewCheck(dryRun: Boolean): ApiResult<KycReviewCheckResultDto> = io { api.reviewCheck(dryRun) }
    override suspend fun rescreening(dryRun: Boolean): ApiResult<KycRescreeningResultDto> = io { api.rescreening(dryRun) }
    override suspend fun triggerReview(userSub: String, reason: String): ApiResult<Unit> =
        io { api.triggerReview(userSub.trim(), KycTriggerReq(reason.trim())) }

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
object KycMonitoringAdminApiModule {
    @Provides
    @Singleton
    fun provideKycMonitoringAdminApi(retrofit: Retrofit): KycMonitoringAdminApi =
        retrofit.create(KycMonitoringAdminApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class KycMonitoringAdminDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindKycMonitoringAdminRepository(impl: DefaultKycMonitoringAdminRepository): KycMonitoringAdminRepository
}
