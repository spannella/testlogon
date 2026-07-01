package com.testlogon.android.data.adminroot

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
import retrofit2.http.Query
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Web-parity: SSO / SAML providers admin (mirrors web /admin/sso -> SsoProvidersPage.tsx). Backend
 * sso_saml.py, prefix /v1/admin/sso/providers. EVERY CRUD op is require_root_session -> our ADMIN
 * account gets 403 -> the screen renders the Forbidden state (ROOT-GATED). Config CRUD form is built to
 * verify Forbidden, matching the web page fields. Metadata upload uses the base64 metadata_xml path; the
 * app surfaces the identity fields + JIT/role toggles (metadata paste omitted — file-picker deferred).
 */
interface AdminSsoApi {

    @GET("v1/admin/sso/providers")
    suspend fun list(@Query("tenant_id") tenantId: String = "default"): SsoProviderListDto

    @GET("v1/admin/sso/providers/{id}")
    suspend fun get(@Path("id") providerId: String, @Query("tenant_id") tenantId: String = "default"): SsoProviderDto

    @POST("v1/admin/sso/providers")
    suspend fun create(@Body body: Map<String, @JvmSuppressWildcards Any?>): SsoProviderDto

    @PATCH("v1/admin/sso/providers/{id}")
    suspend fun update(@Path("id") providerId: String, @Body body: Map<String, @JvmSuppressWildcards Any?>): SsoProviderDto

    @DELETE("v1/admin/sso/providers/{id}")
    suspend fun delete(@Path("id") providerId: String, @Query("tenant_id") tenantId: String = "default"): OkDto
}

@JsonClass(generateAdapter = true)
data class SsoProviderDto(
    @Json(name = "provider_id") val providerId: String = "",
    @Json(name = "tenant_id") val tenantId: String = "default",
    @Json(name = "display_name") val displayName: String = "",
    @Json(name = "protocol") val protocol: String = "saml",
    @Json(name = "status") val status: String? = null,
    @Json(name = "sso_only") val ssoOnly: Boolean = false,
    @Json(name = "jit_provisioning_enabled") val jitProvisioningEnabled: Boolean = true,
    @Json(name = "auto_update_profile") val autoUpdateProfile: Boolean = true,
    @Json(name = "auto_update_role") val autoUpdateRole: Boolean = false,
    @Json(name = "default_role") val defaultRole: String = "user",
    @Json(name = "allowed_email_domains") val allowedEmailDomains: List<String> = emptyList(),
    @Json(name = "idp_entity_id") val idpEntityId: String? = null,
    @Json(name = "idp_sso_url") val idpSsoUrl: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class SsoProviderListDto(
    @Json(name = "providers") val providers: List<SsoProviderDto> = emptyList(),
)

data class SsoProviderForm(
    val displayName: String,
    val protocol: String,
    val defaultRole: String,
    val ssoOnly: Boolean,
    val jitProvisioningEnabled: Boolean,
    val autoUpdateProfile: Boolean,
    val autoUpdateRole: Boolean,
    val allowedEmailDomains: List<String>,
)

interface AdminSsoRepository {
    suspend fun list(): ApiResult<List<SsoProviderDto>>
    suspend fun create(form: SsoProviderForm): ApiResult<SsoProviderDto>
    suspend fun update(providerId: String, form: SsoProviderForm): ApiResult<SsoProviderDto>
    suspend fun delete(providerId: String): ApiResult<Unit>
}

@Singleton
class DefaultAdminSsoRepository @Inject constructor(
    private val api: AdminSsoApi,
    private val errorParser: ApiErrorParser,
) : AdminSsoRepository {

    override suspend fun list(): ApiResult<List<SsoProviderDto>> = call { api.list().providers }

    override suspend fun create(form: SsoProviderForm): ApiResult<SsoProviderDto> =
        call { api.create(form.toBody(includeTenant = true)) }

    override suspend fun update(providerId: String, form: SsoProviderForm): ApiResult<SsoProviderDto> =
        call { api.update(providerId, form.toBody(includeTenant = true)) }

    override suspend fun delete(providerId: String): ApiResult<Unit> = call { api.delete(providerId); Unit }

    private fun SsoProviderForm.toBody(includeTenant: Boolean): Map<String, Any?> = buildMap {
        if (includeTenant) put("tenant_id", "default")
        put("display_name", displayName)
        put("protocol", protocol)
        put("default_role", defaultRole)
        put("sso_only", ssoOnly)
        put("jit_provisioning_enabled", jitProvisioningEnabled)
        put("auto_update_profile", autoUpdateProfile)
        put("auto_update_role", autoUpdateRole)
        put("allowed_email_domains", allowedEmailDomains)
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = withContext(Dispatchers.IO) {
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
object AdminSsoApiModule {
    @Provides
    @Singleton
    fun provideAdminSsoApi(retrofit: Retrofit): AdminSsoApi = retrofit.create(AdminSsoApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class AdminSsoDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindAdminSsoRepository(impl: DefaultAdminSsoRepository): AdminSsoRepository
}
