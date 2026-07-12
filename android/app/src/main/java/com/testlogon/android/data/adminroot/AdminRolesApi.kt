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
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Query
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Web-parity: ROOT role management (mirrors web RootRoleManagementPage.tsx, route root/roles). Backend
 * admin_roles.py, prefix /admin/roles. grant/revoke/update-profile/audit are all require_root -> our
 * ADMIN account gets 403 -> the screen renders the Forbidden state (ROOT-GATED). The governance list
 * (audit) + grant/revoke actions are built to verify Forbidden, matching the web page.
 */
interface AdminRolesApi {

    @GET("admin/roles/audit")
    suspend fun audit(
        @Query("limit") limit: Int = 50,
        @Query("actor_sub") actorSub: String? = null,
    ): RoleAuditListDto

    @POST("admin/roles/grant")
    suspend fun grant(@Body body: RoleGrantReqDto): RoleActionResultDto

    @POST("admin/roles/revoke")
    suspend fun revoke(@Body body: RoleRevokeReqDto): RoleActionResultDto
}

@JsonClass(generateAdapter = true)
data class RoleGrantReqDto(
    @Json(name = "target_user_sub") val targetUserSub: String,
    @Json(name = "role") val role: String = "admin",
    @Json(name = "reason") val reason: String = "",
    @Json(name = "admin_profile_type") val adminProfileType: String = "general",
)

@JsonClass(generateAdapter = true)
data class RoleRevokeReqDto(
    @Json(name = "target_user_sub") val targetUserSub: String,
    @Json(name = "role") val role: String = "admin",
    @Json(name = "reason") val reason: String = "",
)

@JsonClass(generateAdapter = true)
data class RoleActionResultDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "target_user_sub") val targetUserSub: String = "",
    @Json(name = "role") val role: String = "",
    @Json(name = "event_id") val eventId: String? = null,
)

@JsonClass(generateAdapter = true)
data class RoleAuditEntryDto(
    @Json(name = "event_id") val eventId: String? = null,
    @Json(name = "action") val action: String? = null,
    @Json(name = "actor_sub") val actorSub: String? = null,
    @Json(name = "target_user_sub") val targetUserSub: String? = null,
    @Json(name = "previous_role") val previousRole: String? = null,
    @Json(name = "new_role") val newRole: String? = null,
    @Json(name = "reason") val reason: String? = null,
    @Json(name = "ts") val ts: Long? = null,
)

@JsonClass(generateAdapter = true)
data class RoleAuditListDto(
    @Json(name = "items") val items: List<RoleAuditEntryDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,
)

interface AdminRolesRepository {
    suspend fun audit(): ApiResult<List<RoleAuditEntryDto>>
    suspend fun grant(targetUserSub: String, reason: String): ApiResult<RoleActionResultDto>
    suspend fun revoke(targetUserSub: String, reason: String): ApiResult<RoleActionResultDto>
}

@Singleton
class DefaultAdminRolesRepository @Inject constructor(
    private val api: AdminRolesApi,
    private val errorParser: ApiErrorParser,
) : AdminRolesRepository {

    override suspend fun audit(): ApiResult<List<RoleAuditEntryDto>> = call { api.audit().items }

    override suspend fun grant(targetUserSub: String, reason: String): ApiResult<RoleActionResultDto> =
        call { api.grant(RoleGrantReqDto(targetUserSub = targetUserSub, reason = reason)) }

    override suspend fun revoke(targetUserSub: String, reason: String): ApiResult<RoleActionResultDto> =
        call { api.revoke(RoleRevokeReqDto(targetUserSub = targetUserSub, reason = reason)) }

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
object AdminRolesApiModule {
    @Provides
    @Singleton
    fun provideAdminRolesApi(retrofit: Retrofit): AdminRolesApi = retrofit.create(AdminRolesApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class AdminRolesDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindAdminRolesRepository(impl: DefaultAdminRolesRepository): AdminRolesRepository
}
