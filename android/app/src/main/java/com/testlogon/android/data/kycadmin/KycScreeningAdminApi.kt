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
 * A6 — KYC sanctions/PEP screening review queue. Mirrors web /admin/kyc/screening (kycScreening.ts).
 * Backend /ui/kyc/screening/admin/{pending,cases/{caseId},cases/{caseId}/{screenKey}/review,
 * cases/{caseId}/rescreen}. Review body = {decision: clear|confirm|escalate, note}. Epoch SECONDS.
 */
interface KycScreeningAdminApi {
    @GET("ui/kyc/screening/admin/pending")
    suspend fun pending(@Query("result") result: String = "potential_match", @Query("limit") limit: Int = 50): KycScreeningPendingDto

    @POST("ui/kyc/screening/admin/cases/{caseId}/{screenKey}/review")
    suspend fun review(
        @Path("caseId") caseId: String,
        @Path("screenKey") screenKey: String,
        @Body body: KycScreeningReviewReq,
    ): KycScreeningResultDto

    @POST("ui/kyc/screening/admin/cases/{caseId}/rescreen")
    suspend fun rescreen(@Path("caseId") caseId: String): Unit
}

@JsonClass(generateAdapter = true)
data class KycScreeningMatchDto(
    @Json(name = "list_name") val listName: String = "",
    @Json(name = "matched_name") val matchedName: String = "",
    @Json(name = "match_score") val matchScore: Double = 0.0,
    @Json(name = "entity_type") val entityType: String = "",
)

@JsonClass(generateAdapter = true)
data class KycScreeningResultDto(
    @Json(name = "screening_id") val screeningId: String = "",
    @Json(name = "case_id") val caseId: String? = null,
    @Json(name = "screen_key") val screenKey: String? = null,
    @Json(name = "screen_type") val screenType: String = "",
    @Json(name = "user_sub") val userSub: String? = null,
    @Json(name = "result") val result: String = "",
    @Json(name = "match_details") val matchDetails: List<KycScreeningMatchDto> = emptyList(),
    @Json(name = "review_decision") val reviewDecision: String? = null,
    @Json(name = "provider") val provider: String = "",
    @Json(name = "created_at") val createdAt: Long = 0L,
)

@JsonClass(generateAdapter = true)
data class KycScreeningPendingDto(
    @Json(name = "items") val items: List<KycScreeningResultDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class KycScreeningReviewReq(
    @Json(name = "decision") val decision: String,
    @Json(name = "note") val note: String,
)

interface KycScreeningAdminRepository {
    suspend fun pending(result: String): ApiResult<List<KycScreeningResultDto>>
    suspend fun review(caseId: String, screenKey: String, decision: String, note: String): ApiResult<KycScreeningResultDto>
    suspend fun rescreen(caseId: String): ApiResult<Unit>
}

@Singleton
class DefaultKycScreeningAdminRepository @Inject constructor(
    private val api: KycScreeningAdminApi,
    private val errorParser: ApiErrorParser,
) : KycScreeningAdminRepository {
    override suspend fun pending(result: String) = io { api.pending(result).items }
    override suspend fun review(caseId: String, screenKey: String, decision: String, note: String) =
        io { api.review(caseId, screenKey, KycScreeningReviewReq(decision, note.trim())) }
    override suspend fun rescreen(caseId: String) = io { api.rescreen(caseId) }

    private suspend fun <T> io(block: suspend () -> T): ApiResult<T> = withContext(Dispatchers.IO) {
        try { ApiResult.Success(block()) }
        catch (e: CancellationException) { throw e }
        catch (e: HttpException) { ApiResult.Failure(errorParser.from(e)) }
        catch (e: IOException) { ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException) }
    }
}

@Module
@InstallIn(SingletonComponent::class)
object KycScreeningAdminApiModule {
    @Provides @Singleton
    fun provideKycScreeningAdminApi(retrofit: Retrofit): KycScreeningAdminApi = retrofit.create(KycScreeningAdminApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class KycScreeningAdminDataModule {
    @dagger.Binds @Singleton
    abstract fun bindKycScreeningAdminRepository(impl: DefaultKycScreeningAdminRepository): KycScreeningAdminRepository
}
