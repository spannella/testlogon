package com.testlogon.android.data.infrasg

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.squareup.moshi.JsonDataException
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
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.PATCH
import retrofit2.http.Path
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * B7 Cloud-Infra: Security Groups management (list + full CRUD incl. nested rules add/edit/remove).
 * Mirrors SecurityGroupsPage.tsx + api/endpoints/securityGroups.ts. Backend: security_groups.py,
 * prefix /ui/compute/security-groups, require_ui_session. Self-contained per the B5 pattern.
 */
interface SecurityGroupsApi {

    @GET("ui/compute/security-groups")
    suspend fun list(): SgListDto

    @POST("ui/compute/security-groups")
    suspend fun create(@Body body: CreateSgReq): SecurityGroupDto

    @PATCH("ui/compute/security-groups/{id}")
    suspend fun update(@Path("id") sgId: String, @Body body: UpdateSgReq): SecurityGroupDto

    @DELETE("ui/compute/security-groups/{id}")
    suspend fun delete(@Path("id") sgId: String)

    @POST("ui/compute/security-groups/{id}/rules")
    suspend fun addRule(@Path("id") sgId: String, @Body body: SecurityRuleReq): SecurityGroupDto

    @PATCH("ui/compute/security-groups/{id}/rules/{ruleId}")
    suspend fun updateRule(
        @Path("id") sgId: String,
        @Path("ruleId") ruleId: String,
        @Body body: SecurityRuleReq,
    ): SecurityGroupDto

    @DELETE("ui/compute/security-groups/{id}/rules/{ruleId}")
    suspend fun removeRule(@Path("id") sgId: String, @Path("ruleId") ruleId: String): SecurityGroupDto
}

@JsonClass(generateAdapter = true)
data class SecurityRuleDto(
    @Json(name = "rule_id") val ruleId: String = "",
    @Json(name = "protocol") val protocol: String = "",
    @Json(name = "port_from") val portFrom: Int = 0,
    @Json(name = "port_to") val portTo: Int = 0,
    @Json(name = "source") val source: String = "",
    @Json(name = "direction") val direction: String = "inbound",
    @Json(name = "description") val description: String = "",
)

@JsonClass(generateAdapter = true)
data class SecurityGroupDto(
    @Json(name = "sg_id") val sgId: String = "",
    @Json(name = "name") val name: String = "",
    @Json(name = "description") val description: String = "",
    @Json(name = "rules") val rules: List<SecurityRuleDto> = emptyList(),
    @Json(name = "is_default") val isDefault: Boolean = false,
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "updated_at") val updatedAt: Long = 0L,
    @Json(name = "associated_instances") val associatedInstances: List<String> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class SgListDto(
    @Json(name = "security_groups") val securityGroups: List<SecurityGroupDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
)

@JsonClass(generateAdapter = true)
data class CreateSgReq(
    @Json(name = "name") val name: String,
    @Json(name = "description") val description: String = "",
)

@JsonClass(generateAdapter = true)
data class UpdateSgReq(
    @Json(name = "name") val name: String? = null,
    @Json(name = "description") val description: String? = null,
)

@JsonClass(generateAdapter = true)
data class SecurityRuleReq(
    @Json(name = "protocol") val protocol: String,
    @Json(name = "port_from") val portFrom: Int = 0,
    @Json(name = "port_to") val portTo: Int = 0,
    @Json(name = "source") val source: String,
    @Json(name = "direction") val direction: String = "inbound",
    @Json(name = "description") val description: String = "",
)

interface SecurityGroupsRepository {
    suspend fun list(): ApiResult<List<SecurityGroupDto>>
    suspend fun create(name: String, description: String): ApiResult<SecurityGroupDto>
    suspend fun update(sgId: String, name: String?, description: String?): ApiResult<SecurityGroupDto>
    suspend fun delete(sgId: String): ApiResult<Unit>
    suspend fun addRule(sgId: String, rule: SecurityRuleReq): ApiResult<SecurityGroupDto>
    suspend fun updateRule(sgId: String, ruleId: String, rule: SecurityRuleReq): ApiResult<SecurityGroupDto>
    suspend fun removeRule(sgId: String, ruleId: String): ApiResult<SecurityGroupDto>
}

@Singleton
class DefaultSecurityGroupsRepository @Inject constructor(
    private val api: SecurityGroupsApi,
    private val errorParser: ApiErrorParser,
) : SecurityGroupsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun list(): ApiResult<List<SecurityGroupDto>> =
        withContext(io) { call { api.list().securityGroups } }

    override suspend fun create(name: String, description: String): ApiResult<SecurityGroupDto> =
        withContext(io) { call { api.create(CreateSgReq(name.trim(), description.trim())) } }

    override suspend fun update(sgId: String, name: String?, description: String?): ApiResult<SecurityGroupDto> =
        withContext(io) { call { api.update(sgId, UpdateSgReq(name?.trim(), description?.trim())) } }

    override suspend fun delete(sgId: String): ApiResult<Unit> =
        withContext(io) { call { api.delete(sgId) } }

    override suspend fun addRule(sgId: String, rule: SecurityRuleReq): ApiResult<SecurityGroupDto> =
        withContext(io) { call { api.addRule(sgId, rule) } }

    override suspend fun updateRule(sgId: String, ruleId: String, rule: SecurityRuleReq): ApiResult<SecurityGroupDto> =
        withContext(io) { call { api.updateRule(sgId, ruleId, rule) } }

    override suspend fun removeRule(sgId: String, ruleId: String): ApiResult<SecurityGroupDto> =
        withContext(io) { call { api.removeRule(sgId, ruleId) } }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}

@Module
@InstallIn(SingletonComponent::class)
object SecurityGroupsApiModule {
    @Provides
    @Singleton
    fun provideSecurityGroupsApi(retrofit: Retrofit): SecurityGroupsApi =
        retrofit.create(SecurityGroupsApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class SecurityGroupsDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindSecurityGroupsRepository(impl: DefaultSecurityGroupsRepository): SecurityGroupsRepository
}
