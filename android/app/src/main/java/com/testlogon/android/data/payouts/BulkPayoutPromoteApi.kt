package com.testlogon.android.data.payouts

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
import retrofit2.http.Query
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Web-parity admin bulk-payout PROMOTE flow (eligible -> preview -> execute) - mirrors the write half of
 * the web /admin/bulk-payouts console (pages/admin/BulkPayoutConsole.tsx + api/endpoints/
 * bulkPayoutTools.ts). Backend: app/routers/bulk_payout_tools.py, prefix /ui/admin/bulk-payouts, all
 * gated by require_admin_or_root (ADMIN-drivable). This is ADDITIVE to the existing READ-ONLY
 * [BulkPayoutsApi] (AND-261, batches list/detail) - it deliberately lives in its own file/DI module so
 * the read module is untouched.
 *
 * EXECUTE MOVES REAL FUNDS: the UI gates it behind an explicit confirm dialog (see the feature layer);
 * this data layer just carries the call. All money is integer cents.
 *
 *  - GET  /ui/admin/bulk-payouts/eligible?kind=payout   -> bare array of BulkEligibleItem
 *  - POST /ui/admin/bulk-payouts/preview  {kind, ref_ids[]}          -> BulkBatchOut (draft, not executed)
 *  - POST /ui/admin/bulk-payouts/execute  {kind, ref_ids[], batch_id?} -> BulkBatchOut (funds moved)
 */
interface BulkPayoutPromoteApi {

    @GET("ui/admin/bulk-payouts/eligible")
    suspend fun eligible(@Query("kind") kind: String = "payout"): List<BulkEligibleItemDto>

    @POST("ui/admin/bulk-payouts/preview")
    suspend fun preview(@Body body: BulkPreviewReq): PayoutBatchDto

    @POST("ui/admin/bulk-payouts/execute")
    suspend fun execute(@Body body: BulkExecuteReq): PayoutBatchDto
}

// ---- DTOs (verified 1:1 against models.py BulkEligibleItem/BulkPreviewIn/BulkExecuteIn; batch reuses
// the AND-261 PayoutBatchDto) ----

@JsonClass(generateAdapter = true)
data class BulkEligibleItemDto(
    @Json(name = "ref_id") val refId: String,
    @Json(name = "amount_cents") val amountCents: Long = 0,
    @Json(name = "recipient") val recipient: String = "",
    @Json(name = "currency") val currency: String = "usd",
    @Json(name = "status") val status: String = "pending",
    @Json(name = "created_at") val createdAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class BulkPreviewReq(
    @Json(name = "kind") val kind: String,
    @Json(name = "ref_ids") val refIds: List<String>,
)

@JsonClass(generateAdapter = true)
data class BulkExecuteReq(
    @Json(name = "kind") val kind: String,
    @Json(name = "ref_ids") val refIds: List<String>,
    @Json(name = "batch_id") val batchId: String? = null,
)

/** An eligible payout/refund line item (BulkEligibleItem). */
data class BulkEligibleItem(
    val refId: String,
    val amount: PayoutMoney,
    val recipient: String,
    val status: String,
    val createdAtEpochSeconds: Long?,
)

internal fun BulkEligibleItemDto.toDomain(): BulkEligibleItem = BulkEligibleItem(
    refId = refId,
    amount = PayoutMoney(amountCents, currency.uppercase()),
    recipient = recipient,
    status = status,
    createdAtEpochSeconds = createdAt.takeIf { it > 0 },
)

interface BulkPayoutPromoteRepository {
    /** Eligible items for [kind] ("payout"|"refund"). Idempotent GET. */
    suspend fun eligible(kind: String): ApiResult<List<BulkEligibleItem>>

    /** Preview a draft batch over the selected ref ids (does NOT move funds). */
    suspend fun preview(kind: String, refIds: List<String>): ApiResult<PayoutBatch>

    /** Execute the batch - MOVES REAL FUNDS. Pass the preview's batch_id to execute that exact draft. */
    suspend fun execute(kind: String, refIds: List<String>, batchId: String?): ApiResult<PayoutBatch>
}

@Singleton
class DefaultBulkPayoutPromoteRepository @Inject constructor(
    private val api: BulkPayoutPromoteApi,
    private val errorParser: ApiErrorParser,
) : BulkPayoutPromoteRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun eligible(kind: String): ApiResult<List<BulkEligibleItem>> =
        withContext(io) { call { api.eligible(kind).map { it.toDomain() } } }

    override suspend fun preview(kind: String, refIds: List<String>): ApiResult<PayoutBatch> =
        withContext(io) { call { api.preview(BulkPreviewReq(kind, refIds)).toDomain() } }

    override suspend fun execute(
        kind: String,
        refIds: List<String>,
        batchId: String?,
    ): ApiResult<PayoutBatch> =
        withContext(io) { call { api.execute(BulkExecuteReq(kind, refIds, batchId)).toDomain() } }

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
object BulkPayoutPromoteApiModule {
    @Provides
    @Singleton
    fun provideBulkPayoutPromoteApi(retrofit: Retrofit): BulkPayoutPromoteApi =
        retrofit.create(BulkPayoutPromoteApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class BulkPayoutPromoteDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindBulkPayoutPromoteRepository(
        impl: DefaultBulkPayoutPromoteRepository,
    ): BulkPayoutPromoteRepository
}
