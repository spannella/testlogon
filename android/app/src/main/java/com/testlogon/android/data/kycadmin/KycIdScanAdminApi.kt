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
 * A7 — KYC ID-scanner review queue. Mirrors web /admin/kyc/id-scanner (kycIdScanner.ts). Backend
 * /ui/kyc/id-scanner/admin/{by-status,scans/{id},scans/{id}/adjudicate}. List = scan summaries;
 * detail = full scan with image_url + MRZ extraction. Decision: approve/decline. Epoch SECONDS.
 */
interface KycIdScanAdminApi {
    @GET("ui/kyc/id-scanner/admin/by-status")
    suspend fun byStatus(@Query("status") status: String, @Query("limit") limit: Int = 100): KycIdScanListDto

    @GET("ui/kyc/id-scanner/admin/scans/{id}")
    suspend fun detail(@Path("id") scanId: String): KycIdScanDto

    @POST("ui/kyc/id-scanner/admin/scans/{id}/adjudicate")
    suspend fun adjudicate(@Path("id") scanId: String, @Body body: KycReviewReq): KycIdScanDto
}

@JsonClass(generateAdapter = true)
data class KycIdScanSummaryDto(
    @Json(name = "scan_id") val scanId: String,
    @Json(name = "case_id") val caseId: String = "",
    @Json(name = "document_type") val documentType: String = "",
    @Json(name = "file_type") val fileType: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "mrz_valid") val mrzValid: Boolean = false,
    @Json(name = "match_score") val matchScore: Double? = null,
    @Json(name = "created_at") val createdAt: Long = 0L,
)

@JsonClass(generateAdapter = true)
data class KycIdScanExtractionDto(
    @Json(name = "document_number") val documentNumber: String? = null,
    @Json(name = "surname") val surname: String? = null,
    @Json(name = "given_names") val givenNames: String? = null,
    @Json(name = "nationality") val nationality: String? = null,
    @Json(name = "date_of_birth") val dateOfBirth: String? = null,
    @Json(name = "expiry_date") val expiryDate: String? = null,
)

@JsonClass(generateAdapter = true)
data class KycIdScanDto(
    @Json(name = "scan_id") val scanId: String,
    @Json(name = "case_id") val caseId: String = "",
    @Json(name = "user_sub") val userSub: String? = null,
    @Json(name = "document_type") val documentType: String = "",
    @Json(name = "file_type") val fileType: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "mrz_valid") val mrzValid: Boolean = false,
    @Json(name = "extraction") val extraction: KycIdScanExtractionDto? = null,
    @Json(name = "image_url") val imageUrl: String? = null,
    @Json(name = "review_decision") val reviewDecision: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0L,
)

@JsonClass(generateAdapter = true)
data class KycIdScanListDto(
    @Json(name = "scans") val scans: List<KycIdScanSummaryDto> = emptyList(),
)

interface KycIdScanAdminRepository {
    suspend fun byStatus(status: String): ApiResult<List<KycIdScanSummaryDto>>
    suspend fun detail(scanId: String): ApiResult<KycIdScanDto>
    suspend fun adjudicate(scanId: String, decision: String, note: String): ApiResult<KycIdScanDto>
}

@Singleton
class DefaultKycIdScanAdminRepository @Inject constructor(
    private val api: KycIdScanAdminApi,
    private val errorParser: ApiErrorParser,
) : KycIdScanAdminRepository {
    override suspend fun byStatus(status: String) = io { api.byStatus(status).scans }
    override suspend fun detail(scanId: String) = io { api.detail(scanId) }
    override suspend fun adjudicate(scanId: String, decision: String, note: String) =
        io { api.adjudicate(scanId, KycReviewReq(decision, note.trim().ifBlank { null })) }

    private suspend fun <T> io(block: suspend () -> T): ApiResult<T> = withContext(Dispatchers.IO) {
        try { ApiResult.Success(block()) }
        catch (e: CancellationException) { throw e }
        catch (e: HttpException) { ApiResult.Failure(errorParser.from(e)) }
        catch (e: IOException) { ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException) }
    }
}

@Module
@InstallIn(SingletonComponent::class)
object KycIdScanAdminApiModule {
    @Provides @Singleton
    fun provideKycIdScanAdminApi(retrofit: Retrofit): KycIdScanAdminApi = retrofit.create(KycIdScanAdminApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class KycIdScanAdminDataModule {
    @dagger.Binds @Singleton
    abstract fun bindKycIdScanAdminRepository(impl: DefaultKycIdScanAdminRepository): KycIdScanAdminRepository
}
