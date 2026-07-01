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
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * A4 — KYC proof-of-funds review queue. Mirrors web /admin/kyc/proof-of-funds (kycProofOfFunds.ts).
 * Backend /ui/kyc/proof-of-funds/{review/by-status/{status},submissions/{id},review/{id}/adjudicate}.
 * Adjudicate body = {decision, reviewer_note}. Epoch SECONDS.
 */
interface KycPofAdminApi {
    @GET("ui/kyc/proof-of-funds/review/by-status/{status}")
    suspend fun byStatus(@Path("status") status: String): KycPofListDto

    @GET("ui/kyc/proof-of-funds/submissions/{id}")
    suspend fun detail(@Path("id") submissionId: String): KycPofDto

    @POST("ui/kyc/proof-of-funds/review/{id}/adjudicate")
    suspend fun adjudicate(@Path("id") submissionId: String, @Body body: KycPofAdjudicateReq): KycPofDto
}

@JsonClass(generateAdapter = true)
data class KycPofDto(
    @Json(name = "submission_id") val submissionId: String,
    @Json(name = "user_sub") val userSub: String = "",
    @Json(name = "source_category") val sourceCategory: String? = null,
    @Json(name = "declared_amount_cents") val declaredAmountCents: Long? = null,
    @Json(name = "currency") val currency: String? = null,
    @Json(name = "document_s3_key") val documentS3Key: String? = null,
    @Json(name = "note") val note: String? = null,
    @Json(name = "status") val status: String = "",
    @Json(name = "score") val score: Double = 0.0,
    @Json(name = "risk_contribution") val riskContribution: Double = 0.0,
    @Json(name = "reviewer_note") val reviewerNote: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0L,
)

@JsonClass(generateAdapter = true)
data class KycPofListDto(
    @Json(name = "submissions") val submissions: List<KycPofDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class KycPofAdjudicateReq(
    @Json(name = "decision") val decision: String,
    @Json(name = "reviewer_note") val reviewerNote: String? = null,
)

interface KycPofAdminRepository {
    suspend fun byStatus(status: String): ApiResult<List<KycPofDto>>
    suspend fun detail(submissionId: String): ApiResult<KycPofDto>
    suspend fun adjudicate(submissionId: String, decision: String, note: String): ApiResult<KycPofDto>
}

@Singleton
class DefaultKycPofAdminRepository @Inject constructor(
    private val api: KycPofAdminApi,
    private val errorParser: ApiErrorParser,
) : KycPofAdminRepository {
    override suspend fun byStatus(status: String) = io { api.byStatus(status).submissions }
    override suspend fun detail(submissionId: String) = io { api.detail(submissionId) }
    override suspend fun adjudicate(submissionId: String, decision: String, note: String) =
        io { api.adjudicate(submissionId, KycPofAdjudicateReq(decision, note.trim().ifBlank { null })) }

    private suspend fun <T> io(block: suspend () -> T): ApiResult<T> = withContext(Dispatchers.IO) {
        try { ApiResult.Success(block()) }
        catch (e: CancellationException) { throw e }
        catch (e: HttpException) { ApiResult.Failure(errorParser.from(e)) }
        catch (e: IOException) { ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException) }
    }
}

@Module
@InstallIn(SingletonComponent::class)
object KycPofAdminApiModule {
    @Provides @Singleton
    fun provideKycPofAdminApi(retrofit: Retrofit): KycPofAdminApi = retrofit.create(KycPofAdminApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class KycPofAdminDataModule {
    @dagger.Binds @Singleton
    abstract fun bindKycPofAdminRepository(impl: DefaultKycPofAdminRepository): KycPofAdminRepository
}
