package com.testlogon.android.data.connprofiles

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
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * B7 Remote-Access: Connection Profiles (CRUD + quick-connect). Mirrors the web
 * /remote/connection-profiles page (ConnectionProfilesPage.tsx + api/endpoints/connectionProfiles.ts).
 * Backend: connection_profiles.py, prefix /ui/compute/connection-profiles, require_ui_session
 * (owner-scoped). Timestamps epoch SECONDS. quick-connect returns computed connection info (no live
 * session client — the interactive terminal is not a mobile surface). Self-contained (Api + DTOs +
 * Repository + DI). Stored passwords are write-only (responses only expose has_password).
 */
interface ConnProfilesApi {

    @GET("ui/compute/connection-profiles")
    suspend fun list(): ConnProfileListDto

    @GET("ui/compute/connection-profiles/{id}")
    suspend fun get(@Path("id") profileId: String): ConnProfileDto

    @POST("ui/compute/connection-profiles")
    suspend fun create(@Body body: CreateConnProfileReq): ConnProfileDto

    @PATCH("ui/compute/connection-profiles/{id}")
    suspend fun update(@Path("id") profileId: String, @Body body: UpdateConnProfileReq): ConnProfileDto

    @DELETE("ui/compute/connection-profiles/{id}")
    suspend fun delete(@Path("id") profileId: String)

    @POST("ui/compute/connection-profiles/{id}/quick-connect")
    suspend fun quickConnect(@Path("id") profileId: String): QuickConnectDto
}

@JsonClass(generateAdapter = true)
data class ConnProfileDto(
    @Json(name = "profile_id") val profileId: String = "",
    @Json(name = "label") val label: String = "",
    @Json(name = "protocol") val protocol: String = "ssh",
    @Json(name = "hostname") val hostname: String = "",
    @Json(name = "instance_id") val instanceId: String = "",
    @Json(name = "port") val port: Int = 22,
    @Json(name = "username") val username: String = "",
    @Json(name = "auth_method") val authMethod: String = "key_ref",
    @Json(name = "has_password") val hasPassword: Boolean = false,
    @Json(name = "ssh_key_id") val sshKeyId: String = "",
    @Json(name = "bastion_path_id") val bastionPathId: String = "",
    @Json(name = "terminal_cols") val terminalCols: Int = 80,
    @Json(name = "terminal_rows") val terminalRows: Int = 24,
    @Json(name = "terminal_font_size") val terminalFontSize: Int = 14,
    @Json(name = "terminal_color_scheme") val terminalColorScheme: String = "dark",
    @Json(name = "is_favorite") val isFavorite: Boolean = false,
    @Json(name = "auto_connect") val autoConnect: Boolean = false,
    @Json(name = "use_count") val useCount: Int = 0,
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "updated_at") val updatedAt: Long = 0L,
    @Json(name = "last_used_at") val lastUsedAt: Long = 0L,
)

@JsonClass(generateAdapter = true)
data class ConnProfileListDto(
    @Json(name = "profiles") val profiles: List<ConnProfileDto> = emptyList(),
    @Json(name = "total") val total: Int = 0,
)

@JsonClass(generateAdapter = true)
data class CreateConnProfileReq(
    @Json(name = "label") val label: String,
    @Json(name = "protocol") val protocol: String = "ssh",
    @Json(name = "hostname") val hostname: String? = null,
    @Json(name = "instance_id") val instanceId: String? = null,
    @Json(name = "port") val port: Int = 22,
    @Json(name = "username") val username: String? = null,
    @Json(name = "auth_method") val authMethod: String = "key_ref",
    @Json(name = "ssh_key_id") val sshKeyId: String? = null,
    @Json(name = "bastion_path_id") val bastionPathId: String? = null,
    @Json(name = "is_favorite") val isFavorite: Boolean = false,
    @Json(name = "auto_connect") val autoConnect: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class UpdateConnProfileReq(
    @Json(name = "label") val label: String? = null,
    @Json(name = "hostname") val hostname: String? = null,
    @Json(name = "port") val port: Int? = null,
    @Json(name = "username") val username: String? = null,
    @Json(name = "auth_method") val authMethod: String? = null,
    @Json(name = "ssh_key_id") val sshKeyId: String? = null,
    @Json(name = "is_favorite") val isFavorite: Boolean? = null,
    @Json(name = "auto_connect") val autoConnect: Boolean? = null,
)

@JsonClass(generateAdapter = true)
data class QuickConnectBastionDto(
    @Json(name = "path_id") val pathId: String = "",
    @Json(name = "proxy_jump") val proxyJump: String = "",
    @Json(name = "ssh_command") val sshCommand: String = "",
    @Json(name = "total_hops") val totalHops: Int = 0,
)

@JsonClass(generateAdapter = true)
data class QuickConnectDto(
    @Json(name = "profile_id") val profileId: String = "",
    @Json(name = "label") val label: String = "",
    @Json(name = "protocol") val protocol: String = "",
    @Json(name = "hostname") val hostname: String = "",
    @Json(name = "port") val port: Int = 22,
    @Json(name = "username") val username: String = "",
    @Json(name = "auth_method") val authMethod: String = "",
    @Json(name = "has_password") val hasPassword: Boolean = false,
    @Json(name = "ssh_key_id") val sshKeyId: String = "",
    @Json(name = "bastion_path_id") val bastionPathId: String = "",
    @Json(name = "bastion") val bastion: QuickConnectBastionDto? = null,
    @Json(name = "terminal_cols") val terminalCols: Int = 80,
    @Json(name = "terminal_rows") val terminalRows: Int = 24,
)

interface ConnProfilesRepository {
    suspend fun list(): ApiResult<ConnProfileListDto>
    suspend fun create(req: CreateConnProfileReq): ApiResult<ConnProfileDto>
    suspend fun update(profileId: String, req: UpdateConnProfileReq): ApiResult<ConnProfileDto>
    suspend fun delete(profileId: String): ApiResult<Unit>
    suspend fun quickConnect(profileId: String): ApiResult<QuickConnectDto>
}

@Singleton
class DefaultConnProfilesRepository @Inject constructor(
    private val api: ConnProfilesApi,
    private val errorParser: ApiErrorParser,
) : ConnProfilesRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun list(): ApiResult<ConnProfileListDto> = withContext(io) { call { api.list() } }

    override suspend fun create(req: CreateConnProfileReq): ApiResult<ConnProfileDto> =
        withContext(io) { call { api.create(req) } }

    override suspend fun update(profileId: String, req: UpdateConnProfileReq): ApiResult<ConnProfileDto> =
        withContext(io) { call { api.update(profileId, req) } }

    override suspend fun delete(profileId: String): ApiResult<Unit> =
        withContext(io) { call { api.delete(profileId) } }

    override suspend fun quickConnect(profileId: String): ApiResult<QuickConnectDto> =
        withContext(io) { call { api.quickConnect(profileId) } }

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
object ConnProfilesApiModule {
    @Provides
    @Singleton
    fun provideConnProfilesApi(retrofit: Retrofit): ConnProfilesApi =
        retrofit.create(ConnProfilesApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class ConnProfilesDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindConnProfilesRepository(impl: DefaultConnProfilesRepository): ConnProfilesRepository
}
