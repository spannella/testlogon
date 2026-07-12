package com.testlogon.android.data.infrabilling

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.squareup.moshi.JsonDataException
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
import retrofit2.http.Query
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * B7 Cloud-Infra: Compute billing / spend dashboard. Mirrors ComputeSpendingPage.tsx +
 * api/endpoints/computeBilling.ts. Backend: compute_billing.py, prefix /ui/remote/billing,
 * require_ui_session. Shows the monthly spend summary, resource breakdown, ledger history, and lets the
 * user set a monthly budget. Self-contained per the B5 pattern.
 */
interface ComputeBillingApi {

    @GET("ui/remote/billing/spending")
    suspend fun spending(@Query("month") month: String? = null): SpendingSummaryDto

    @GET("ui/remote/billing/resources")
    suspend fun resources(@Query("month") month: String? = null): ResourceBreakdownDto

    @GET("ui/remote/billing/history")
    suspend fun history(@Query("limit") limit: Int? = null): BillingLedgerDto

    @GET("ui/remote/billing/budget")
    suspend fun budget(): BudgetDto

    @POST("ui/remote/billing/budget")
    suspend fun setBudget(@Body body: UpdateBudgetReq): BudgetDto
}

@JsonClass(generateAdapter = true)
data class SpendingSummaryDto(
    @Json(name = "month") val month: String = "",
    @Json(name = "total_cents") val totalCents: Long = 0L,
    @Json(name = "budget_cents") val budgetCents: Long = 0L,
    @Json(name = "budget_pct") val budgetPct: Double = 0.0,
    @Json(name = "ec2_total_cents") val ec2TotalCents: Long = 0L,
    @Json(name = "k8s_total_cents") val k8sTotalCents: Long = 0L,
    @Json(name = "resource_count") val resourceCount: Int = 0,
)

@JsonClass(generateAdapter = true)
data class ResourceBreakdownEntryDto(
    @Json(name = "resource_id") val resourceId: String = "",
    @Json(name = "resource_label") val resourceLabel: String = "",
    @Json(name = "resource_type") val resourceType: String = "",
    @Json(name = "instance_type_or_preset") val instanceTypeOrPreset: String = "",
    @Json(name = "total_cents") val totalCents: Long = 0L,
    @Json(name = "total_minutes") val totalMinutes: Double = 0.0,
    @Json(name = "status") val status: String = "",
)

@JsonClass(generateAdapter = true)
data class ResourceBreakdownDto(
    @Json(name = "resources") val resources: List<ResourceBreakdownEntryDto> = emptyList(),
    @Json(name = "month") val month: String = "",
)

@JsonClass(generateAdapter = true)
data class BillingLedgerEntryDto(
    @Json(name = "entry_id") val entryId: String = "",
    @Json(name = "resource_type") val resourceType: String = "",
    @Json(name = "resource_label") val resourceLabel: String = "",
    @Json(name = "instance_type_or_preset") val instanceTypeOrPreset: String = "",
    @Json(name = "event") val event: String = "",
    @Json(name = "amount_cents") val amountCents: Long = 0L,
    @Json(name = "duration_minutes") val durationMinutes: Double = 0.0,
    @Json(name = "created_at") val createdAt: Long = 0L,
)

@JsonClass(generateAdapter = true)
data class BillingLedgerDto(
    @Json(name = "entries") val entries: List<BillingLedgerEntryDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
    @Json(name = "cursor") val cursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class BudgetDto(
    @Json(name = "budget_monthly_cents") val budgetMonthlyCents: Long = 0L,
    @Json(name = "alert_thresholds") val alertThresholds: List<Int> = emptyList(),
    @Json(name = "current_month_total_cents") val currentMonthTotalCents: Long = 0L,
    @Json(name = "current_month_pct") val currentMonthPct: Double = 0.0,
)

@JsonClass(generateAdapter = true)
data class UpdateBudgetReq(
    @Json(name = "budget_monthly_cents") val budgetMonthlyCents: Int,
)

/** Everything the spend dashboard shows, fetched together. */
data class ComputeSpendSnapshot(
    val spending: SpendingSummaryDto,
    val resources: List<ResourceBreakdownEntryDto>,
    val history: List<BillingLedgerEntryDto>,
    val budget: BudgetDto,
)

interface ComputeBillingRepository {
    suspend fun snapshot(): ApiResult<ComputeSpendSnapshot>
    suspend fun setBudget(monthlyCents: Int): ApiResult<BudgetDto>
}

@Singleton
class DefaultComputeBillingRepository @Inject constructor(
    private val api: ComputeBillingApi,
    private val errorParser: ApiErrorParser,
) : ComputeBillingRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun snapshot(): ApiResult<ComputeSpendSnapshot> = withContext(io) {
        call {
            ComputeSpendSnapshot(
                spending = api.spending(null),
                resources = api.resources(null).resources,
                history = api.history(limit = 50).entries,
                budget = api.budget(),
            )
        }
    }

    override suspend fun setBudget(monthlyCents: Int): ApiResult<BudgetDto> =
        withContext(io) { call { api.setBudget(UpdateBudgetReq(monthlyCents)) } }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}

@Module
@InstallIn(SingletonComponent::class)
object ComputeBillingApiModule {
    @Provides
    @Singleton
    fun provideComputeBillingApi(retrofit: Retrofit): ComputeBillingApi =
        retrofit.create(ComputeBillingApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class ComputeBillingDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindComputeBillingRepository(impl: DefaultComputeBillingRepository): ComputeBillingRepository
}
