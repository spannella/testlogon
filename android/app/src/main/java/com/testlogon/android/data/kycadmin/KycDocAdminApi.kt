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
 * A2 — KYC document review queue. Mirrors web /admin/kyc/documents (kycDocuments.ts). Backend
 * /ui/kyc/documents/admin/{by-status,{id},{id}/review}, admin-gated. Detail carries image_url (Coil).
 * Decision: approve/reject with an optional note. Epoch SECONDS.
 */
interface KycDocAdminApi {
    @GET("ui/kyc/documents/admin/by-status")
    suspend fun byStatus(@Query("status") status: String, @Query("limit") limit: Int = 100): KycDocListDto

    @GET("ui/kyc/documents/admin/{id}")
    suspend fun detail(@Path("id") documentId: String): KycDocDto

    @POST("ui/kyc/documents/admin/{id}/review")
    suspend fun review(@Path("id") documentId: String, @Body body: KycReviewReq): KycDocDto
}

@JsonClass(generateAdapter = true)
data class KycDocDto(
    @Json(name = "document_id") val documentId: String,
    @Json(name = "case_id") val caseId: String? = null,
    @Json(name = "user_sub") val userSub: String? = null,
    @Json(name = "document_type") val documentType: String = "",
    @Json(name = "file_name") val fileName: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "image_url") val imageUrl: String? = null,
    @Json(name = "overall_confidence") val overallConfidence: String? = null,
    @Json(name = "review_decision") val reviewDecision: String? = null,
    @Json(name = "review_note") val reviewNote: String? = null,
    @Json(name = "extracted_fields") val extractedFields: Map<String, String> = emptyMap(),
    @Json(name = "created_at") val createdAt: Long = 0L,
)

@JsonClass(generateAdapter = true)
data class KycDocListDto(
    @Json(name = "documents") val documents: List<KycDocDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class KycReviewReq(
    @Json(name = "decision") val decision: String,
    @Json(name = "note") val note: String? = null,
)

interface KycDocAdminRepository {
    suspend fun byStatus(status: String): ApiResult<List<KycDocDto>>
    suspend fun detail(documentId: String): ApiResult<KycDocDto>
    suspend fun review(documentId: String, decision: String, note: String): ApiResult<KycDocDto>
}

@Singleton
class DefaultKycDocAdminRepository @Inject constructor(
    private val api: KycDocAdminApi,
    private val errorParser: ApiErrorParser,
) : KycDocAdminRepository {
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
object KycDocAdminApiModule {
    @Provides @Singleton
    fun provideKycDocAdminApi(retrofit: Retrofit): KycDocAdminApi = retrofit.create(KycDocAdminApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class KycDocAdminDataModule {
    @dagger.Binds @Singleton
    abstract fun bindKycDocAdminRepository(impl: DefaultKycDocAdminRepository): KycDocAdminRepository
}
