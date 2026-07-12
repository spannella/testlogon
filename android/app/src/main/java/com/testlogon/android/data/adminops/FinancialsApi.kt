package com.testlogon.android.data.adminops

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
import retrofit2.http.GET
import retrofit2.http.Query
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * B6 admin platform-financial dashboard - mirrors the web /admin/financials page
 * (pages/admin/financials/FinancialDashboard.tsx). Backend: platform_financial_dashboard.py,
 * prefix /ui/admin/financial-dashboard, reads gated by require_admin_or_root (our admin CAN drive).
 * The manual rollup (POST /rollup) is require_root and is intentionally NOT surfaced.
 * All money fields are cents; take_rate is basis points; timestamps epoch seconds.
 */
interface FinancialsApi {

    @GET("ui/admin/financial-dashboard/kpis")
    suspend fun kpis(
        @Query("start_date") startDate: String,
        @Query("end_date") endDate: String,
    ): FinancialKpisDto

    @GET("ui/admin/financial-dashboard/trends")
    suspend fun trends(
        @Query("start_date") startDate: String,
        @Query("end_date") endDate: String,
        @Query("granularity") granularity: String = "daily",
    ): FinancialTrendsDto

    @GET("ui/admin/financial-dashboard/providers")
    suspend fun providers(
        @Query("start_date") startDate: String,
        @Query("end_date") endDate: String,
    ): FinancialProvidersDto

    @GET("ui/admin/financial-dashboard/types")
    suspend fun types(
        @Query("start_date") startDate: String,
        @Query("end_date") endDate: String,
    ): FinancialTypesDto

    @GET("ui/admin/financial-dashboard/top-creators")
    suspend fun topCreators(
        @Query("start_date") startDate: String,
        @Query("end_date") endDate: String,
        @Query("limit") limit: Int = 20,
    ): FinancialTopCreatorsDto
}

@JsonClass(generateAdapter = true)
data class FinancialKpisDto(
    @Json(name = "gmv_cents") val gmvCents: Long = 0,
    @Json(name = "net_revenue_cents") val netRevenueCents: Long = 0,
    @Json(name = "refunds_cents") val refundsCents: Long = 0,
    @Json(name = "take_rate_bps") val takeRateBps: Int = 0,
    @Json(name = "tx_count") val txCount: Int = 0,
    @Json(name = "unique_payers") val uniquePayers: Int = 0,
    @Json(name = "avg_tx_cents") val avgTxCents: Long = 0,
    @Json(name = "period") val period: Map<String, String> = emptyMap(),
)

@JsonClass(generateAdapter = true)
data class FinancialTrendPointDto(
    @Json(name = "date") val date: String = "",
    @Json(name = "gmv_cents") val gmvCents: Long = 0,
    @Json(name = "net_revenue_cents") val netRevenueCents: Long = 0,
    @Json(name = "tx_count") val txCount: Int = 0,
)

@JsonClass(generateAdapter = true)
data class FinancialTrendsDto(
    @Json(name = "data") val data: List<FinancialTrendPointDto> = emptyList(),
    @Json(name = "granularity") val granularity: String = "daily",
)

@JsonClass(generateAdapter = true)
data class FinancialProviderEntryDto(
    @Json(name = "provider") val provider: String = "",
    @Json(name = "total_cents") val totalCents: Long = 0,
    @Json(name = "tx_count") val txCount: Int = 0,
    @Json(name = "avg_cents") val avgCents: Long = 0,
    @Json(name = "pct") val pct: Double = 0.0,
    @Json(name = "success_rate") val successRate: Double = 0.0,
)

@JsonClass(generateAdapter = true)
data class FinancialProvidersDto(
    @Json(name = "data") val data: List<FinancialProviderEntryDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class FinancialTypeEntryDto(
    @Json(name = "entry_type") val entryType: String = "",
    @Json(name = "total_cents") val totalCents: Long = 0,
    @Json(name = "tx_count") val txCount: Int = 0,
    @Json(name = "avg_cents") val avgCents: Long = 0,
)

@JsonClass(generateAdapter = true)
data class FinancialTypesDto(
    @Json(name = "data") val data: List<FinancialTypeEntryDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class FinancialTopCreatorEntryDto(
    @Json(name = "user_id") val userId: String = "",
    @Json(name = "revenue_cents") val revenueCents: Long = 0,
    @Json(name = "tx_count") val txCount: Int = 0,
    @Json(name = "avg_cents") val avgCents: Long = 0,
)

@JsonClass(generateAdapter = true)
data class FinancialTopCreatorsDto(
    @Json(name = "data") val data: List<FinancialTopCreatorEntryDto> = emptyList(),
)

/** Aggregated read result for one date range (all five fan-out calls). */
data class FinancialDashboardData(
    val kpis: FinancialKpisDto,
    val trends: List<FinancialTrendPointDto>,
    val providers: List<FinancialProviderEntryDto>,
    val types: List<FinancialTypeEntryDto>,
    val topCreators: List<FinancialTopCreatorEntryDto>,
)

interface FinancialsRepository {
    suspend fun load(startDate: String, endDate: String): ApiResult<FinancialDashboardData>
}

@Singleton
class DefaultFinancialsRepository @Inject constructor(
    private val api: FinancialsApi,
    private val errorParser: ApiErrorParser,
) : FinancialsRepository {

    override suspend fun load(startDate: String, endDate: String): ApiResult<FinancialDashboardData> =
        withContext(Dispatchers.IO) {
            try {
                val kpis = api.kpis(startDate, endDate)
                val trends = api.trends(startDate, endDate)
                val providers = api.providers(startDate, endDate)
                val types = api.types(startDate, endDate)
                val top = api.topCreators(startDate, endDate)
                ApiResult.Success(
                    FinancialDashboardData(
                        kpis = kpis,
                        trends = trends.data,
                        providers = providers.data,
                        types = types.data,
                        topCreators = top.data,
                    ),
                )
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
object FinancialsApiModule {
    @Provides
    @Singleton
    fun provideFinancialsApi(retrofit: Retrofit): FinancialsApi = retrofit.create(FinancialsApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class FinancialsDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindFinancialsRepository(impl: DefaultFinancialsRepository): FinancialsRepository
}
