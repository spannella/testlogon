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
 * A3 — KYC proof-of-residency review queue. Mirrors web /admin/kyc/residency (kycResidency.ts).
 * Backend /ui/kyc/residency/admin/{by-status,{id},{id}/review}. Detail carries document_url (Coil).
 * Decision: approve/reject. Epoch SECONDS.
 */
interface KycResidencyAdminApi {
    @GET("ui/kyc/residency/admin/by-status")
    suspend fun byStatus(@Query("status") status: String, @Query("limit") limit: Int = 100): KycResidencyListDto

    @GET("ui/kyc/residency/admin/{id}")
    suspend fun detail(@Path("id") documentId: String): KycResidencyDto

    @POST("ui/kyc/residency/admin/{id}/review")
    suspend fun review(@Path("id") documentId: String, @Body body: KycReviewReq): KycResidencyDto
}

@JsonClass(generateAdapter = true)
data class KycResidencyDto(
    @Json(name = "document_id") val documentId: String,
    @Json(name = "case_id") val caseId: String? = null,
    @Json(name = "user_sub") val userSub: String? = null,
    @Json(name = "document_type") val documentType: String = "",
    @Json(name = "issuing_entity") val issuingEntity: String? = null,
    @Json(name = "document_date") val documentDate: String? = null,
    @Json(name = "file_name") val fileName: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "document_url") val documentUrl: String? = null,
    @Json(name = "recency_valid") val recencyValid: Boolean = false,
    @Json(name = "recency_days") val recencyDays: Int = 0,
    @Json(name = "extracted_address") val extractedAddress: Map<String, String>? = null,
    @Json(name = "review_decision") val reviewDecision: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0L,
)

@JsonClass(generateAdapter = true)
data class KycResidencyListDto(
    @Json(name = "documents") val documents: List<KycResidencyDto> = emptyList(),
)

interface KycResidencyAdminRepository {
    suspend fun byStatus(status: String): ApiResult<List<KycResidencyDto>>
    suspend fun detail(documentId: String): ApiResult<KycResidencyDto>
    suspend fun review(documentId: String, decision: String, note: String): ApiResult<KycResidencyDto>
}

@Singleton
class DefaultKycResidencyAdminRepository @Inject constructor(
    private val api: KycResidencyAdminApi,
    private val errorParser: ApiErrorParser,
) : KycResidencyAdminRepository {
    override suspend fun byStatus(status: String) = io { api.byStatus(status).documents }
    override suspend fun detail(documentId: String) = io { api.detail(documentId) }
    override suspend fun review(documentId: String, decision: String, note: String) =
        io { api.review(documentId, KycReviewReq(decision, note.trim().ifBlank { null })) }

    private suspend fun <T> io(block: suspend () -> T): ApiResult<T> = withContext(Dispatchers.IO) {
        try { ApiResult.Success(block()) }
        catch (e: CancellationException) { throw e }
        catch (e: HttpException) { ApiResult.Failure(errorParser.from(e)) }
        catch (e: IOException) { ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException) }
    }
}

@Module
@InstallIn(SingletonComponent::class)
object KycResidencyAdminApiModule {
    @Provides @Singleton
    fun provideKycResidencyAdminApi(retrofit: Retrofit): KycResidencyAdminApi = retrofit.create(KycResidencyAdminApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class KycResidencyAdminDataModule {
    @dagger.Binds @Singleton
    abstract fun bindKycResidencyAdminRepository(impl: DefaultKycResidencyAdminRepository): KycResidencyAdminRepository
}
