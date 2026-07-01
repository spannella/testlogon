package com.testlogon.android.data.admintax

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
 * Web-parity admin 1099-NEC MANAGER - mirrors the web /admin/tax-forms-1099 page
 * (pages/admin/TaxForm1099AdminPage.tsx). Backend: app/routers/tax_form_1099.py admin endpoints
 * (prefix /ui/tax-forms), all gated by require_admin_or_root (ADMIN-drivable). Distinct from the
 * existing user-facing `taxforms` module (own 1099 view/download only).
 *
 *  - GET  /ui/tax-forms/admin/year/{tax_year}                       -> {items:[TaxForm1099Out]}
 *  - POST /ui/tax-forms/admin/1099s/{tax_year}/generate?user_sub=   -> TaxForm1099Out
 *  - POST /ui/tax-forms/admin/1099s/{tax_year}/correct?user_sub=    -> TaxForm1099Out
 *  - POST /ui/tax-forms/admin/batch  {tax_year}                     -> BatchGenerateTaxForm1099Out
 *
 * total_earnings_cents is integer minor units; generated_at/updated_at are epoch SECONDS.
 */
interface AdminTaxFormApi {

    @GET("ui/tax-forms/admin/year/{tax_year}")
    suspend fun listYear(@Path("tax_year") taxYear: Int): AdminForm1099ListDto

    @POST("ui/tax-forms/admin/1099s/{tax_year}/generate")
    suspend fun generate(
        @Path("tax_year") taxYear: Int,
        @Query("user_sub") userSub: String,
    ): AdminForm1099Dto

    @POST("ui/tax-forms/admin/1099s/{tax_year}/correct")
    suspend fun correct(
        @Path("tax_year") taxYear: Int,
        @Query("user_sub") userSub: String,
    ): AdminForm1099Dto

    @POST("ui/tax-forms/admin/batch")
    suspend fun batch(@Body body: AdminBatch1099Req): AdminBatch1099ResultDto
}

// ---- DTOs (verified 1:1 against models.py TaxForm1099Out / BatchGenerateTaxForm1099*) ----

@JsonClass(generateAdapter = true)
data class AdminForm1099ListDto(
    @Json(name = "items") val items: List<AdminForm1099Dto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class AdminForm1099Dto(
    @Json(name = "form_id") val formId: String = "",
    @Json(name = "user_sub") val userSub: String = "",
    @Json(name = "tax_year") val taxYear: Int = 0,
    @Json(name = "total_earnings_cents") val totalEarningsCents: Long = 0,
    @Json(name = "qualifies") val qualifies: Boolean = false,
    @Json(name = "status") val status: String = "generated",
    @Json(name = "correction_count") val correctionCount: Int = 0,
    @Json(name = "payer_name") val payerName: String = "",
    @Json(name = "payer_tin_last4") val payerTinLast4: String = "",
    @Json(name = "generated_at") val generatedAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
    @Json(name = "download_url") val downloadUrl: String? = null,
)

@JsonClass(generateAdapter = true)
data class AdminBatch1099Req(
    @Json(name = "tax_year") val taxYear: Int,
)

@JsonClass(generateAdapter = true)
data class AdminBatch1099ResultDto(
    @Json(name = "tax_year") val taxYear: Int = 0,
    @Json(name = "total_creators") val totalCreators: Int = 0,
    @Json(name = "qualifying") val qualifying: Int = 0,
    @Json(name = "generated") val generated: Int = 0,
    @Json(name = "skipped") val skipped: Int = 0,
    @Json(name = "errors") val errors: Int = 0,
)

interface AdminTaxFormRepository {
    suspend fun listYear(taxYear: Int): ApiResult<List<AdminForm1099Dto>>
    suspend fun generate(taxYear: Int, userSub: String): ApiResult<AdminForm1099Dto>
    suspend fun correct(taxYear: Int, userSub: String): ApiResult<AdminForm1099Dto>
    suspend fun batch(taxYear: Int): ApiResult<AdminBatch1099ResultDto>
}

@Singleton
class DefaultAdminTaxFormRepository @Inject constructor(
    private val api: AdminTaxFormApi,
    private val errorParser: ApiErrorParser,
) : AdminTaxFormRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun listYear(taxYear: Int): ApiResult<List<AdminForm1099Dto>> =
        withContext(io) { call { api.listYear(taxYear).items } }

    override suspend fun generate(taxYear: Int, userSub: String): ApiResult<AdminForm1099Dto> =
        withContext(io) { call { api.generate(taxYear, userSub) } }

    override suspend fun correct(taxYear: Int, userSub: String): ApiResult<AdminForm1099Dto> =
        withContext(io) { call { api.correct(taxYear, userSub) } }

    override suspend fun batch(taxYear: Int): ApiResult<AdminBatch1099ResultDto> =
        withContext(io) { call { api.batch(AdminBatch1099Req(taxYear)) } }

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
object AdminTaxFormApiModule {
    @Provides
    @Singleton
    fun provideAdminTaxFormApi(retrofit: Retrofit): AdminTaxFormApi =
        retrofit.create(AdminTaxFormApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class AdminTaxFormDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindAdminTaxFormRepository(impl: DefaultAdminTaxFormRepository): AdminTaxFormRepository
}
