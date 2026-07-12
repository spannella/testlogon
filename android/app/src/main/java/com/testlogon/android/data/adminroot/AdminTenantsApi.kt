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
 * Web-parity: multi-tenant admin (mirrors web /admin/tenants -> TenantAdmin.tsx). Backend
 * tenant_admin.py, prefix /v1/admin/tenants. EVERY CRUD op is require_root_session -> our ADMIN
 * account gets 403 -> the screen renders the Forbidden state (ROOT-GATED). Config CRUD form + domain
 * list are still built (verify Forbidden), matching the web page fields.
 */
interface AdminTenantsApi {

    @GET("v1/admin/tenants")
    suspend fun list(
        @Query("limit") limit: Int = 50,
        @Query("cursor") cursor: String? = null,
        @Query("status") status: String? = null,
    ): TenantListDto

    @GET("v1/admin/tenants/{id}")
    suspend fun get(@Path("id") tenantId: String): TenantDto

    @POST("v1/admin/tenants")
    suspend fun create(@Body body: TenantCreateReqDto): TenantDto

    @PATCH("v1/admin/tenants/{id}")
    suspend fun update(@Path("id") tenantId: String, @Body body: TenantUpdateReqDto): TenantDto

    @DELETE("v1/admin/tenants/{id}")
    suspend fun delete(@Path("id") tenantId: String): TenantDto

    @POST("v1/admin/tenants/{id}/domains")
    suspend fun addDomain(@Path("id") tenantId: String, @Body body: TenantDomainReqDto): OkDto
}

@JsonClass(generateAdapter = true)
data class TenantDto(
    @Json(name = "tenant_id") val tenantId: String = "",
    @Json(name = "slug") val slug: String = "",
    @Json(name = "display_name") val displayName: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "plan") val plan: String = "",
    @Json(name = "custom_domains") val customDomains: List<String> = emptyList(),
    @Json(name = "primary_domain") val primaryDomain: String? = null,
    @Json(name = "member_count") val memberCount: Int = 0,
    @Json(name = "storage_used_bytes") val storageUsedBytes: Long = 0,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class TenantListDto(
    @Json(name = "tenants") val tenants: List<TenantDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class TenantCreateReqDto(
    @Json(name = "slug") val slug: String,
    @Json(name = "display_name") val displayName: String,
    @Json(name = "plan") val plan: String = "starter",
    @Json(name = "primary_domain") val primaryDomain: String? = null,
)

@JsonClass(generateAdapter = true)
data class TenantUpdateReqDto(
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "plan") val plan: String? = null,
    @Json(name = "status") val status: String? = null,
)

@JsonClass(generateAdapter = true)
data class TenantDomainReqDto(
    @Json(name = "domain") val domain: String,
)

@JsonClass(generateAdapter = true)
data class OkDto(
    @Json(name = "ok") val ok: Boolean = true,
)

interface AdminTenantsRepository {
    suspend fun list(): ApiResult<List<TenantDto>>
    suspend fun create(slug: String, displayName: String, plan: String, primaryDomain: String?): ApiResult<TenantDto>
    suspend fun update(tenantId: String, displayName: String?, plan: String?, status: String?): ApiResult<TenantDto>
    suspend fun delete(tenantId: String): ApiResult<TenantDto>
    suspend fun addDomain(tenantId: String, domain: String): ApiResult<Unit>
}

@Singleton
class DefaultAdminTenantsRepository @Inject constructor(
    private val api: AdminTenantsApi,
    private val errorParser: ApiErrorParser,
) : AdminTenantsRepository {

    override suspend fun list(): ApiResult<List<TenantDto>> = call { api.list().tenants }

    override suspend fun create(
        slug: String,
        displayName: String,
        plan: String,
        primaryDomain: String?,
    ): ApiResult<TenantDto> = call {
        api.create(TenantCreateReqDto(slug = slug, displayName = displayName, plan = plan, primaryDomain = primaryDomain))
    }

    override suspend fun update(
        tenantId: String,
        displayName: String?,
        plan: String?,
        status: String?,
    ): ApiResult<TenantDto> = call {
        api.update(tenantId, TenantUpdateReqDto(displayName = displayName, plan = plan, status = status))
    }

    override suspend fun delete(tenantId: String): ApiResult<TenantDto> = call { api.delete(tenantId) }

    override suspend fun addDomain(tenantId: String, domain: String): ApiResult<Unit> =
        call { api.addDomain(tenantId, TenantDomainReqDto(domain)); Unit }

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
object AdminTenantsApiModule {
    @Provides
    @Singleton
    fun provideAdminTenantsApi(retrofit: Retrofit): AdminTenantsApi = retrofit.create(AdminTenantsApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class AdminTenantsDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindAdminTenantsRepository(impl: DefaultAdminTenantsRepository): AdminTenantsRepository
}
