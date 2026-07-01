package com.testlogon.android.data.adminrefunds

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
 * B5 admin refund-requests queue - mirrors the web /admin/refunds page (AdminRefundQueuePage.tsx +
 * api/endpoints/refundRequests.ts). Backend: refund_requests.py, gated by require_admin_or_root. The
 * LIST carries full request detail; approve/reject are the admin actions. Timestamps are epoch SECONDS.
 */
interface RefundAdminApi {

    @GET("ui/admin/refund-requests")
    suspend fun list(@Query("status") status: String): RefundRequestListDto

    @POST("ui/admin/refund-requests/{id}/approve")
    suspend fun approve(
        @Path("id") requestId: String,
        @Body body: RefundApproveReq,
    ): RefundApproveDto

    @POST("ui/admin/refund-requests/{id}/reject")
    suspend fun reject(
        @Path("id") requestId: String,
        @Body body: RefundRejectReq,
    ): RefundRejectDto
}

@JsonClass(generateAdapter = true)
data class RefundRequestDto(
    @Json(name = "refund_request_id") val refundRequestId: String,
    @Json(name = "status") val status: String = "",
    @Json(name = "amount_cents") val amountCents: Long = 0L,
    @Json(name = "currency") val currency: String = "USD",
    @Json(name = "reason") val reason: String = "",
    @Json(name = "transaction_type") val transactionType: String? = null,
    @Json(name = "transaction_entry_id") val transactionEntryId: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "admin_notes") val adminNotes: String? = null,
    @Json(name = "completed_at") val completedAt: Long? = null,
    @Json(name = "requester_user_id") val requesterUserId: String? = null,
)

@JsonClass(generateAdapter = true)
data class RefundRequestListDto(
    @Json(name = "items") val items: List<RefundRequestDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class RefundApproveReq(
    @Json(name = "notes") val notes: String? = null,
    @Json(name = "amount_cents") val amountCents: Long? = null,
)

@JsonClass(generateAdapter = true)
data class RefundApproveDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "refund_request_id") val refundRequestId: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "approved_amount_cents") val approvedAmountCents: Long = 0L,
)

@JsonClass(generateAdapter = true)
data class RefundRejectReq(
    @Json(name = "notes") val notes: String,
)

@JsonClass(generateAdapter = true)
data class RefundRejectDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "refund_request_id") val refundRequestId: String = "",
    @Json(name = "status") val status: String = "",
)

interface RefundAdminRepository {
    suspend fun list(status: String): ApiResult<RefundRequestListDto>
    suspend fun approve(requestId: String, notes: String?, amountCents: Long?): ApiResult<RefundApproveDto>
    suspend fun reject(requestId: String, notes: String): ApiResult<RefundRejectDto>
}

@Singleton
class DefaultRefundAdminRepository @Inject constructor(
    private val api: RefundAdminApi,
    private val errorParser: ApiErrorParser,
) : RefundAdminRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun list(status: String): ApiResult<RefundRequestListDto> =
        withContext(io) { call { api.list(status) } }

    override suspend fun approve(requestId: String, notes: String?, amountCents: Long?): ApiResult<RefundApproveDto> =
        withContext(io) {
            call { api.approve(requestId, RefundApproveReq(notes?.trim()?.takeIf { it.isNotEmpty() }, amountCents)) }
        }

    override suspend fun reject(requestId: String, notes: String): ApiResult<RefundRejectDto> =
        withContext(io) { call { api.reject(requestId, RefundRejectReq(notes.trim())) } }

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
object RefundAdminApiModule {
    @Provides
    @Singleton
    fun provideRefundAdminApi(retrofit: Retrofit): RefundAdminApi =
        retrofit.create(RefundAdminApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class RefundAdminDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindRefundAdminRepository(impl: DefaultRefundAdminRepository): RefundAdminRepository
}
