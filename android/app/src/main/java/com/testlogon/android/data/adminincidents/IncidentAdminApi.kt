package com.testlogon.android.data.adminincidents

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
 * B5 admin payment-incidents queue - mirrors the web /admin/payment-incidents page
 * (PaymentIncidentQueuePage.tsx + api/endpoints/paymentIncidents.ts). Backend: billing.py, routes under
 * /api/admin/payment-incidents, gated by require_admin_scope("billing_support"). The list returns raw
 * provider incident dicts (shape varies by provider); we surface the reliable common fields. The admin
 * action for a DISPUTE incident is submit-response (evidence upload is folded into the response summary).
 * Timestamps are epoch SECONDS.
 */
interface IncidentAdminApi {

    @GET("api/admin/payment-incidents")
    suspend fun list(
        @Query("status") status: String? = null,
        @Query("incident_type") incidentType: String? = null,
        @Query("limit") limit: Int = 100,
    ): IncidentListDto

    @POST("api/admin/payment-incidents/{id}/submit-response")
    suspend fun submitResponse(
        @Path("id") incidentId: String,
        @Body body: IncidentSubmitResponseReq,
    ): IncidentSubmitResponseDto
}

@JsonClass(generateAdapter = true)
data class IncidentDto(
    @Json(name = "incident_id") val incidentId: String,
    @Json(name = "provider") val provider: String = "",
    @Json(name = "incident_type") val incidentType: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "customer_id") val customerId: String? = null,
    @Json(name = "amount_cents") val amountCents: Long? = null,
    @Json(name = "amount") val amount: Double? = null,
    @Json(name = "currency") val currency: String? = null,
    @Json(name = "reason") val reason: String? = null,
    @Json(name = "provider_incident_id") val providerIncidentId: String? = null,
    @Json(name = "due_at_ts") val dueAtTs: Long? = null,
    @Json(name = "created_at") val createdAt: Long = 0L,
)

@JsonClass(generateAdapter = true)
data class IncidentListDto(
    @Json(name = "items") val items: List<IncidentDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
)

@JsonClass(generateAdapter = true)
data class IncidentSubmitResponseReq(
    @Json(name = "response_summary") val responseSummary: String,
    @Json(name = "rationale") val rationale: String? = null,
)

@JsonClass(generateAdapter = true)
data class IncidentSubmitResponseDto(
    @Json(name = "incident_id") val incidentId: String? = null,
    @Json(name = "status") val status: String? = null,
)

interface IncidentAdminRepository {
    suspend fun list(status: String?): ApiResult<IncidentListDto>
    suspend fun submitResponse(incidentId: String, summary: String, rationale: String?): ApiResult<IncidentSubmitResponseDto>
}

@Singleton
class DefaultIncidentAdminRepository @Inject constructor(
    private val api: IncidentAdminApi,
    private val errorParser: ApiErrorParser,
) : IncidentAdminRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun list(status: String?): ApiResult<IncidentListDto> =
        withContext(io) { call { api.list(status = status) } }

    override suspend fun submitResponse(incidentId: String, summary: String, rationale: String?): ApiResult<IncidentSubmitResponseDto> =
        withContext(io) {
            call {
                api.submitResponse(
                    incidentId,
                    IncidentSubmitResponseReq(summary.trim(), rationale?.trim()?.takeIf { it.isNotEmpty() }),
                )
            }
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
object IncidentAdminApiModule {
    @Provides
    @Singleton
    fun provideIncidentAdminApi(retrofit: Retrofit): IncidentAdminApi =
        retrofit.create(IncidentAdminApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class IncidentAdminDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindIncidentAdminRepository(impl: DefaultIncidentAdminRepository): IncidentAdminRepository
}
