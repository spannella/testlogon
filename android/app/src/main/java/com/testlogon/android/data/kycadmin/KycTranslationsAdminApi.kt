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
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.PUT
import retrofit2.http.Path
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * B9 - KYC translations manager (CRUD). Mirrors web /admin/kyc/translations (KycTranslationsPage.tsx +
 * api/endpoints/kycTranslations.ts). Backend kyc_translations.py, prefix /v1/kyc/i18n, admin-gated.
 * coverage report + list per language + upsert (PUT) / delete a key. The key segment is a path param
 * ({key:path} server-side) so it is passed encoded=false to allow dotted keys. Epoch SECONDS.
 */
interface KycTranslationsAdminApi {

    @GET("v1/kyc/i18n/admin/coverage")
    suspend fun coverage(): KycCoverageReportDto

    @GET("v1/kyc/i18n/admin/translations/{language}")
    suspend fun list(@Path("language") language: String): KycTranslationListDto

    @PUT("v1/kyc/i18n/admin/translations/{language}/{key}")
    suspend fun set(
        @Path("language") language: String,
        @Path(value = "key", encoded = true) key: String,
        @Body body: KycSetTranslationReq,
    ): KycTranslationDto

    @DELETE("v1/kyc/i18n/admin/translations/{language}/{key}")
    suspend fun delete(
        @Path("language") language: String,
        @Path(value = "key", encoded = true) key: String,
    )
}

@JsonClass(generateAdapter = true)
data class KycTranslationCoverageDto(
    @Json(name = "language_code") val languageCode: String = "",
    @Json(name = "total_keys") val totalKeys: Int = 0,
    @Json(name = "translated_keys") val translatedKeys: Int = 0,
    @Json(name = "missing_keys") val missingKeys: Int = 0,
    @Json(name = "coverage_pct") val coveragePct: Double = 0.0,
)

@JsonClass(generateAdapter = true)
data class KycCoverageReportDto(
    @Json(name = "languages") val languages: Map<String, KycTranslationCoverageDto> = emptyMap(),
)

@JsonClass(generateAdapter = true)
data class KycTranslationDto(
    @Json(name = "language_code") val languageCode: String = "",
    @Json(name = "key") val key: String = "",
    @Json(name = "value") val value: String = "",
    @Json(name = "context") val context: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "updated_at") val updatedAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class KycTranslationListDto(
    @Json(name = "items") val items: List<KycTranslationDto> = emptyList(),
    @Json(name = "total") val total: Int = 0,
)

@JsonClass(generateAdapter = true)
data class KycSetTranslationReq(
    @Json(name = "value") val value: String,
    @Json(name = "context") val context: String? = null,
    @Json(name = "status") val status: String? = null,
)

interface KycTranslationsAdminRepository {
    suspend fun coverage(): ApiResult<Map<String, KycTranslationCoverageDto>>
    suspend fun list(language: String): ApiResult<List<KycTranslationDto>>
    suspend fun set(language: String, key: String, value: String, status: String?): ApiResult<Unit>
    suspend fun delete(language: String, key: String): ApiResult<Unit>
}

@Singleton
class DefaultKycTranslationsAdminRepository @Inject constructor(
    private val api: KycTranslationsAdminApi,
    private val errorParser: ApiErrorParser,
) : KycTranslationsAdminRepository {

    override suspend fun coverage(): ApiResult<Map<String, KycTranslationCoverageDto>> =
        io { api.coverage().languages }

    override suspend fun list(language: String): ApiResult<List<KycTranslationDto>> =
        io { api.list(language.trim()).items }

    override suspend fun set(language: String, key: String, value: String, status: String?): ApiResult<Unit> =
        io { api.set(language.trim(), key.trim(), KycSetTranslationReq(value, status = status)) }

    override suspend fun delete(language: String, key: String): ApiResult<Unit> =
        io { api.delete(language.trim(), key.trim()) }

    private suspend fun <T> io(block: suspend () -> T): ApiResult<T> = withContext(Dispatchers.IO) {
        try {
            ApiResult.Success(block())
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Failure(errorParser.from(e))
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }
}

@Module
@InstallIn(SingletonComponent::class)
object KycTranslationsAdminApiModule {
    @Provides
    @Singleton
    fun provideKycTranslationsAdminApi(retrofit: Retrofit): KycTranslationsAdminApi =
        retrofit.create(KycTranslationsAdminApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class KycTranslationsAdminDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindKycTranslationsAdminRepository(impl: DefaultKycTranslationsAdminRepository): KycTranslationsAdminRepository
}
