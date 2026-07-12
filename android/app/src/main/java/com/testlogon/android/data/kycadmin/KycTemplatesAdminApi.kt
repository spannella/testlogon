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
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * B8 - KYC document-template library (CRUD). Mirrors web /admin/kyc/templates
 * (KycDocumentTemplatesPage.tsx + api/endpoints/kycDocumentTemplates.ts). Backend
 * kyc_document_templates.py, prefix /v1/kyc/document-templates, admin-gated. list/create/get/archive +
 * activate/deactivate a template version. (Uploading a version PDF is a file-picker flow left to the
 * web tool; the app surfaces the metadata CRUD + version activation.) Epoch SECONDS.
 */
interface KycTemplatesAdminApi {

    @GET("v1/kyc/document-templates")
    suspend fun list(): KycTemplateListDto

    @GET("v1/kyc/document-templates/{templateId}")
    suspend fun get(@Path("templateId") templateId: String): KycTemplateDto

    @POST("v1/kyc/document-templates")
    suspend fun create(@Body body: KycCreateTemplateReq): KycTemplateDto

    @DELETE("v1/kyc/document-templates/{templateId}")
    suspend fun archive(@Path("templateId") templateId: String): KycTemplateDto

    @PATCH("v1/kyc/document-templates/{templateId}/versions/{version}/activate")
    suspend fun activateVersion(@Path("templateId") templateId: String, @Path("version") version: Int): KycTemplateVersionDto

    @PATCH("v1/kyc/document-templates/{templateId}/versions/{version}/deactivate")
    suspend fun deactivateVersion(@Path("templateId") templateId: String, @Path("version") version: Int): KycTemplateVersionDto
}

@JsonClass(generateAdapter = true)
data class KycTemplateVersionDto(
    @Json(name = "template_id") val templateId: String = "",
    @Json(name = "version") val version: Int = 0,
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "required_tier") val requiredTier: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "pdf_uploaded") val pdfUploaded: Boolean = false,
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "updated_at") val updatedAt: Long = 0L,
)

@JsonClass(generateAdapter = true)
data class KycTemplateDto(
    @Json(name = "template_id") val templateId: String = "",
    @Json(name = "slug") val slug: String = "",
    @Json(name = "display_name") val displayName: String = "",
    @Json(name = "description") val description: String = "",
    @Json(name = "required_tier") val requiredTier: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "placeholder_fields") val placeholderFields: List<String> = emptyList(),
    @Json(name = "latest_version") val latestVersion: Int = 0,
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "updated_at") val updatedAt: Long = 0L,
    @Json(name = "versions") val versions: List<KycTemplateVersionDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class KycTemplateListDto(
    @Json(name = "items") val items: List<KycTemplateDto> = emptyList(),
    @Json(name = "total") val total: Int = 0,
)

@JsonClass(generateAdapter = true)
data class KycCreateTemplateReq(
    @Json(name = "slug") val slug: String,
    @Json(name = "display_name") val displayName: String,
    @Json(name = "description") val description: String? = null,
    @Json(name = "required_tier") val requiredTier: String,
    @Json(name = "placeholder_fields") val placeholderFields: List<String>,
)

interface KycTemplatesAdminRepository {
    suspend fun list(): ApiResult<List<KycTemplateDto>>
    suspend fun get(templateId: String): ApiResult<KycTemplateDto>
    suspend fun create(slug: String, displayName: String, description: String, tier: String, fields: List<String>): ApiResult<KycTemplateDto>
    suspend fun archive(templateId: String): ApiResult<Unit>
    suspend fun activateVersion(templateId: String, version: Int): ApiResult<Unit>
    suspend fun deactivateVersion(templateId: String, version: Int): ApiResult<Unit>
}

@Singleton
class DefaultKycTemplatesAdminRepository @Inject constructor(
    private val api: KycTemplatesAdminApi,
    private val errorParser: ApiErrorParser,
) : KycTemplatesAdminRepository {

    override suspend fun list(): ApiResult<List<KycTemplateDto>> = io { api.list().items }
    override suspend fun get(templateId: String): ApiResult<KycTemplateDto> = io { api.get(templateId) }

    override suspend fun create(slug: String, displayName: String, description: String, tier: String, fields: List<String>): ApiResult<KycTemplateDto> =
        io {
            api.create(
                KycCreateTemplateReq(
                    slug = slug.trim(),
                    displayName = displayName.trim(),
                    description = description.trim().ifEmpty { null },
                    requiredTier = tier,
                    placeholderFields = fields,
                ),
            )
        }

    override suspend fun archive(templateId: String): ApiResult<Unit> = io { api.archive(templateId) }
    override suspend fun activateVersion(templateId: String, version: Int): ApiResult<Unit> = io { api.activateVersion(templateId, version) }
    override suspend fun deactivateVersion(templateId: String, version: Int): ApiResult<Unit> = io { api.deactivateVersion(templateId, version) }

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
object KycTemplatesAdminApiModule {
    @Provides
    @Singleton
    fun provideKycTemplatesAdminApi(retrofit: Retrofit): KycTemplatesAdminApi =
        retrofit.create(KycTemplatesAdminApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class KycTemplatesAdminDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindKycTemplatesAdminRepository(impl: DefaultKycTemplatesAdminRepository): KycTemplatesAdminRepository
}
