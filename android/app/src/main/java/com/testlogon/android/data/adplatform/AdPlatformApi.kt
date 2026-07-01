package com.testlogon.android.data.adplatform

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Retrofit
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Web-parity admin AD-PLATFORM console - mirrors the web /admin/ad-platform page
 * (pages/admin/AdPlatformDashboard.tsx + api/endpoints/adminAdPlatform.ts). Backend:
 * app/routers/admin_ad_platform.py, prefix /ui/admin/ad-platform. Read + moderate endpoints are
 * require_admin_or_root (ADMIN-drivable); the kill-switch TOGGLE (POST) is require_root_session
 * (ROOT-only -> our admin account gets 403 -> a Forbidden inline note). The kill-switch READ (GET) and
 * the moderate actions are admin-drivable.
 *
 * All money is integer cents; timestamps are epoch SECONDS.
 */
interface AdPlatformApi {

    @GET("ui/admin/ad-platform/metrics")
    suspend fun metrics(): AdPlatformMetricsDto

    @GET("ui/admin/ad-platform/metrics/top-spenders")
    suspend fun topSpenders(@Query("limit") limit: Int? = null): List<AdTopSpenderDto>

    @GET("ui/admin/ad-platform/metrics/revenue-series")
    suspend fun revenueSeries(): List<AdRevenuePointDto>

    @GET("ui/admin/ad-platform/moderation/queue")
    suspend fun moderationQueue(): AdModerationQueueDto

    @GET("ui/admin/ad-platform/kill-switch")
    suspend fun killSwitch(): AdKillSwitchDto

    @POST("ui/admin/ad-platform/accounts/{account_id}/moderate")
    suspend fun moderateAccount(
        @Path("account_id") accountId: String,
        @Body body: AdModerationActionReq,
    ): AdModerationResultDto

    @POST("ui/admin/ad-platform/creatives/{creative_id}/moderate")
    suspend fun moderateCreative(
        @Path("creative_id") creativeId: String,
        @Body body: AdModerationActionReq,
    ): AdModerationResultDto
}

// ---- DTOs (verified 1:1 against types.ts AdminAd* + admin_ad_platform.py) ----

@JsonClass(generateAdapter = true)
data class AdPlatformMetricsDto(
    @Json(name = "total_spend_cents") val totalSpendCents: Long = 0,
    @Json(name = "platform_revenue_cents") val platformRevenueCents: Long = 0,
    @Json(name = "creator_share_cents") val creatorShareCents: Long = 0,
    @Json(name = "revenue_share_percent") val revenueSharePercent: Double = 0.0,
    @Json(name = "impressions") val impressions: Long = 0,
    @Json(name = "clicks") val clicks: Long = 0,
    @Json(name = "conversions") val conversions: Long = 0,
    @Json(name = "effective_cpm_cents") val effectiveCpmCents: Long = 0,
    @Json(name = "account_count") val accountCount: Int = 0,
    @Json(name = "campaign_count") val campaignCount: Int = 0,
    @Json(name = "creative_count") val creativeCount: Int = 0,
    @Json(name = "pending_account_reviews") val pendingAccountReviews: Int = 0,
    @Json(name = "pending_creative_reviews") val pendingCreativeReviews: Int = 0,
)

@JsonClass(generateAdapter = true)
data class AdTopSpenderDto(
    @Json(name = "account_id") val accountId: String = "",
    @Json(name = "company_name") val companyName: String = "",
    @Json(name = "owner_sub") val ownerSub: String = "",
    @Json(name = "spend_cents") val spendCents: Long = 0,
)

@JsonClass(generateAdapter = true)
data class AdRevenuePointDto(
    @Json(name = "month") val month: String = "",
    @Json(name = "spend_cents") val spendCents: Long = 0,
    @Json(name = "platform_revenue_cents") val platformRevenueCents: Long = 0,
    @Json(name = "creator_share_cents") val creatorShareCents: Long = 0,
    @Json(name = "impressions") val impressions: Long = 0,
    @Json(name = "clicks") val clicks: Long = 0,
)

/**
 * Moderation-queue account row. The queue endpoint has response_model=dict (NO Pydantic coercion), so
 * on the live backend the numeric fields (balance/spend/created_at) arrive as STRINGS from raw DDB items.
 * The UI only needs id/company/email/status, so numeric fields are intentionally omitted to keep Moshi
 * from choking on string-typed numbers. (The typed /accounts endpoint returns proper numbers, but this
 * DTO is only used for the moderation queue.)
 */
@JsonClass(generateAdapter = true)
data class AdPlatformAccountDto(
    @Json(name = "account_id") val accountId: String = "",
    @Json(name = "owner_sub") val ownerSub: String = "",
    @Json(name = "company_name") val companyName: String = "",
    @Json(name = "billing_email") val billingEmail: String = "",
    @Json(name = "status") val status: String = "",
)

@JsonClass(generateAdapter = true)
data class AdPlatformCreativeDto(
    @Json(name = "creative_id") val creativeId: String = "",
    @Json(name = "campaign_id") val campaignId: String = "",
    @Json(name = "account_id") val accountId: String = "",
    @Json(name = "format") val format: String = "",
    @Json(name = "title") val title: String = "",
    @Json(name = "status") val status: String = "",
)

@JsonClass(generateAdapter = true)
data class AdModerationQueueDto(
    @Json(name = "accounts") val accounts: List<AdPlatformAccountDto> = emptyList(),
    @Json(name = "creatives") val creatives: List<AdPlatformCreativeDto> = emptyList(),
    @Json(name = "account_count") val accountCount: Int = 0,
    @Json(name = "creative_count") val creativeCount: Int = 0,
)

@JsonClass(generateAdapter = true)
data class AdKillSwitchDto(
    @Json(name = "active") val active: Boolean = false,
    @Json(name = "toggled_by") val toggledBy: String = "",
    @Json(name = "reason") val reason: String = "",
    @Json(name = "updated_at") val updatedAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class AdModerationActionReq(
    @Json(name = "action") val action: String,
    @Json(name = "reason") val reason: String? = null,
    @Json(name = "notes") val notes: String? = null,
)

@JsonClass(generateAdapter = true)
data class AdModerationResultDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "item_type") val itemType: String = "",
    @Json(name = "item_id") val itemId: String = "",
    @Json(name = "status") val status: String = "",
)

/** Combined console snapshot (metrics + top spenders + revenue series + moderation queue + kill switch). */
data class AdPlatformConsole(
    val metrics: AdPlatformMetricsDto,
    val topSpenders: List<AdTopSpenderDto>,
    val revenue: List<AdRevenuePointDto>,
    val moderation: AdModerationQueueDto,
    val killSwitch: AdKillSwitchDto,
)

interface AdPlatformRepository {
    suspend fun load(): ApiResult<AdPlatformConsole>
    suspend fun moderateAccount(accountId: String, action: String, reason: String?): ApiResult<AdModerationResultDto>
    suspend fun moderateCreative(creativeId: String, action: String, reason: String?): ApiResult<AdModerationResultDto>
}

@Singleton
class DefaultAdPlatformRepository @Inject constructor(
    private val api: AdPlatformApi,
    private val errorParser: ApiErrorParser,
) : AdPlatformRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun load(): ApiResult<AdPlatformConsole> = withContext(io) {
        call {
            AdPlatformConsole(
                metrics = api.metrics(),
                topSpenders = api.topSpenders(limit = 10),
                revenue = api.revenueSeries(),
                moderation = api.moderationQueue(),
                killSwitch = api.killSwitch(),
            )
        }
    }

    override suspend fun moderateAccount(
        accountId: String,
        action: String,
        reason: String?,
    ): ApiResult<AdModerationResultDto> = withContext(io) {
        call { api.moderateAccount(accountId, AdModerationActionReq(action, reason?.trim()?.takeIf { it.isNotEmpty() })) }
    }

    override suspend fun moderateCreative(
        creativeId: String,
        action: String,
        reason: String?,
    ): ApiResult<AdModerationResultDto> = withContext(io) {
        call { api.moderateCreative(creativeId, AdModerationActionReq(action, reason?.trim()?.takeIf { it.isNotEmpty() })) }
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

@Module
@InstallIn(SingletonComponent::class)
object AdPlatformApiModule {
    @Provides
    @Singleton
    fun provideAdPlatformApi(retrofit: Retrofit): AdPlatformApi = retrofit.create(AdPlatformApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class AdPlatformDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindAdPlatformRepository(impl: DefaultAdPlatformRepository): AdPlatformRepository
}
