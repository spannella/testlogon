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
import retrofit2.http.Path
import retrofit2.http.Query
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * A5 — KYC liveness-call verifier. Mirrors web /admin/kyc/liveness-call (kycLivenessCall.ts). Backend
 * /ui/kyc/liveness-call/admin/{by-status,{id},{id}/conduct,{id}/result,{id}/cancel}. join_url opens
 * externally (ACTION_VIEW). Result body = {result: passed|failed, notes}. Epoch SECONDS.
 */
interface KycLivenessAdminApi {
    @GET("ui/kyc/liveness-call/admin/by-status")
    suspend fun byStatus(@Query("status") status: String, @Query("limit") limit: Int = 100): KycLivenessListDto

    @GET("ui/kyc/liveness-call/admin/{id}")
    suspend fun detail(@Path("id") callId: String): KycLivenessDto

    @POST("ui/kyc/liveness-call/admin/{id}/conduct")
    suspend fun conduct(@Path("id") callId: String): KycLivenessDto

    @POST("ui/kyc/liveness-call/admin/{id}/result")
    suspend fun result(@Path("id") callId: String, @Body body: KycLivenessResultReq): KycLivenessDto

    @POST("ui/kyc/liveness-call/admin/{id}/cancel")
    suspend fun cancel(@Path("id") callId: String): KycLivenessDto
}

@JsonClass(generateAdapter = true)
data class KycLivenessDto(
    @Json(name = "call_id") val callId: String,
    @Json(name = "case_id") val caseId: String = "",
    @Json(name = "user_sub") val userSub: String? = null,
    @Json(name = "status") val status: String = "",
    @Json(name = "scheduled_at") val scheduledAt: Long = 0L,
    @Json(name = "duration_minutes") val durationMinutes: Int = 0,
    @Json(name = "note") val note: String? = null,
    @Json(name = "verifier_sub") val verifierSub: String? = null,
    @Json(name = "result") val result: String? = null,
    @Json(name = "result_notes") val resultNotes: String? = null,
    @Json(name = "join_url") val joinUrl: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0L,
)

@JsonClass(generateAdapter = true)
data class KycLivenessListDto(
    @Json(name = "calls") val calls: List<KycLivenessDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class KycLivenessResultReq(
    @Json(name = "result") val result: String,
    @Json(name = "notes") val notes: String,
    @Json(name = "recording_linked") val recordingLinked: Boolean = false,
)

interface KycLivenessAdminRepository {
    suspend fun byStatus(status: String): ApiResult<List<KycLivenessDto>>
    suspend fun detail(callId: String): ApiResult<KycLivenessDto>
    suspend fun conduct(callId: String): ApiResult<KycLivenessDto>
    suspend fun result(callId: String, result: String, notes: String): ApiResult<KycLivenessDto>
    suspend fun cancel(callId: String): ApiResult<KycLivenessDto>
}

@Singleton
class DefaultKycLivenessAdminRepository @Inject constructor(
    private val api: KycLivenessAdminApi,
    private val errorParser: ApiErrorParser,
) : KycLivenessAdminRepository {
    override suspend fun byStatus(status: String) = io { api.byStatus(status).calls }
    override suspend fun detail(callId: String) = io { api.detail(callId) }
    override suspend fun conduct(callId: String) = io { api.conduct(callId) }
    override suspend fun result(callId: String, result: String, notes: String) = io { api.result(callId, KycLivenessResultReq(result, notes.trim())) }
    override suspend fun cancel(callId: String) = io { api.cancel(callId) }

    private suspend fun <T> io(block: suspend () -> T): ApiResult<T> = withContext(Dispatchers.IO) {
        try { ApiResult.Success(block()) }
        catch (e: CancellationException) { throw e }
        catch (e: HttpException) { ApiResult.Failure(errorParser.from(e)) }
        catch (e: IOException) { ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException) }
    }
}

@Module
@InstallIn(SingletonComponent::class)
object KycLivenessAdminApiModule {
    @Provides @Singleton
    fun provideKycLivenessAdminApi(retrofit: Retrofit): KycLivenessAdminApi = retrofit.create(KycLivenessAdminApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class KycLivenessAdminDataModule {
    @dagger.Binds @Singleton
    abstract fun bindKycLivenessAdminRepository(impl: DefaultKycLivenessAdminRepository): KycLivenessAdminRepository
}
