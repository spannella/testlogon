package com.testlogon.android.data.admindisputes

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
 * B5 admin billing-disputes queue - mirrors the web /admin/disputes page (AdminDisputeQueuePage.tsx +
 * api/endpoints/billingDisputes.ts). Backend: billing_disputes.py, gated by require_admin_or_root. The
 * LIST carries full dispute detail; respond (submit evidence) + resolve are the admin actions.
 * Timestamps are epoch SECONDS.
 */
interface DisputeAdminApi {

    @GET("ui/admin/disputes")
    suspend fun list(@Query("status") status: String): DisputeListDto

    @POST("ui/admin/disputes/{id}/respond")
    suspend fun respond(
        @Path("id") disputeId: String,
        @Body body: DisputeRespondReq,
    ): DisputeRespondDto

    @POST("ui/admin/disputes/{id}/resolve")
    suspend fun resolve(
        @Path("id") disputeId: String,
        @Body body: DisputeResolveReq,
    ): DisputeResolveDto
}

@JsonClass(generateAdapter = true)
data class DisputeDto(
    @Json(name = "dispute_id") val disputeId: String,
    @Json(name = "provider") val provider: String = "manual",
    @Json(name = "provider_dispute_id") val providerDisputeId: String? = null,
    @Json(name = "user_id") val userId: String? = null,
    @Json(name = "amount_cents") val amountCents: Long = 0L,
    @Json(name = "currency") val currency: String = "USD",
    @Json(name = "reason") val reason: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "evidence_submitted") val evidenceSubmitted: Boolean = false,
    @Json(name = "evidence_text") val evidenceText: String? = null,
    @Json(name = "resolution") val resolution: String? = null,
    @Json(name = "admin_notes") val adminNotes: String? = null,
    @Json(name = "transaction_entry_id") val transactionEntryId: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "updated_at") val updatedAt: Long? = null,
    @Json(name = "deadline_at") val deadlineAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class DisputeListDto(
    @Json(name = "items") val items: List<DisputeDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class DisputeRespondReq(
    @Json(name = "evidence_text") val evidenceText: String,
)

@JsonClass(generateAdapter = true)
data class DisputeRespondDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "dispute_id") val disputeId: String = "",
    @Json(name = "evidence_submitted") val evidenceSubmitted: Boolean = false,
    @Json(name = "status") val status: String = "",
)

@JsonClass(generateAdapter = true)
data class DisputeResolveReq(
    @Json(name = "resolution") val resolution: String,
    @Json(name = "notes") val notes: String? = null,
)

@JsonClass(generateAdapter = true)
data class DisputeResolveDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "dispute_id") val disputeId: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "resolution") val resolution: String = "",
)

interface DisputeAdminRepository {
    suspend fun list(status: String): ApiResult<DisputeListDto>
    suspend fun respond(disputeId: String, evidenceText: String): ApiResult<DisputeRespondDto>
    suspend fun resolve(disputeId: String, resolution: String, notes: String?): ApiResult<DisputeResolveDto>
}

@Singleton
class DefaultDisputeAdminRepository @Inject constructor(
    private val api: DisputeAdminApi,
    private val errorParser: ApiErrorParser,
) : DisputeAdminRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun list(status: String): ApiResult<DisputeListDto> =
        withContext(io) { call { api.list(status) } }

    override suspend fun respond(disputeId: String, evidenceText: String): ApiResult<DisputeRespondDto> =
        withContext(io) { call { api.respond(disputeId, DisputeRespondReq(evidenceText.trim())) } }

    override suspend fun resolve(disputeId: String, resolution: String, notes: String?): ApiResult<DisputeResolveDto> =
        withContext(io) {
            call { api.resolve(disputeId, DisputeResolveReq(resolution, notes?.trim()?.takeIf { it.isNotEmpty() })) }
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
object DisputeAdminApiModule {
    @Provides
    @Singleton
    fun provideDisputeAdminApi(retrofit: Retrofit): DisputeAdminApi =
        retrofit.create(DisputeAdminApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class DisputeAdminDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindDisputeAdminRepository(impl: DefaultDisputeAdminRepository): DisputeAdminRepository
}
