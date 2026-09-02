package com.testlogon.android.data.sshbastion

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
 * B7 Remote-Access: SSH Bastion / jump-host paths (management). Mirrors the web /remote/bastion page
 * (SshBastionPage.tsx + api/endpoints/sshBastion.ts). Backend: ssh_bastion.py, prefix
 * /ui/compute/bastion, require_ui_session (owner-scoped). A path = ordered jump hops -> target;
 * /resolve returns the computed ProxyJump chain + ssh command/config (read-only). Timestamps epoch
 * SECONDS. Self-contained (Api + DTOs + Repository + DI).
 */
interface SshBastionApi {

    @GET("ui/compute/bastion/paths")
    suspend fun listPaths(): BastionPathListDto

    @GET("ui/compute/bastion/paths/{id}")
    suspend fun getPath(@Path("id") pathId: String): BastionPathDto

    @POST("ui/compute/bastion/paths")
    suspend fun createPath(@Body body: CreateBastionPathReq): BastionPathDto

    @PATCH("ui/compute/bastion/paths/{id}")
    suspend fun updatePath(@Path("id") pathId: String, @Body body: UpdateBastionPathReq): BastionPathDto

    @GET("ui/compute/bastion/paths/{id}/resolve")
    suspend fun resolve(@Path("id") pathId: String): BastionResolvedDto

    @DELETE("ui/compute/bastion/paths/{id}")
    suspend fun deletePath(@Path("id") pathId: String)
}

@JsonClass(generateAdapter = true)
data class BastionHopDto(
    @Json(name = "hostname") val hostname: String = "",
    @Json(name = "port") val port: Int = 22,
    @Json(name = "username") val username: String = "",
    @Json(name = "ssh_key_id") val sshKeyId: String = "",
    @Json(name = "label") val label: String = "",
    @Json(name = "is_bastion") val isBastion: Boolean = false,
    @Json(name = "hop_number") val hopNumber: Int = 0,
)

@JsonClass(generateAdapter = true)
data class BastionHopReq(
    @Json(name = "hostname") val hostname: String,
    @Json(name = "port") val port: Int = 22,
    @Json(name = "username") val username: String,
    @Json(name = "ssh_key_id") val sshKeyId: String = "",
    @Json(name = "label") val label: String = "",
)

@JsonClass(generateAdapter = true)
data class BastionPathDto(
    @Json(name = "path_id") val pathId: String = "",
    @Json(name = "label") val label: String = "",
    @Json(name = "description") val description: String = "",
    @Json(name = "hops") val hops: List<BastionHopDto> = emptyList(),
    @Json(name = "total_hops") val totalHops: Int = 0,
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "updated_at") val updatedAt: Long = 0L,
)

@JsonClass(generateAdapter = true)
data class BastionPathListDto(
    @Json(name = "paths") val paths: List<BastionPathDto> = emptyList(),
    @Json(name = "total") val total: Int = 0,
)

@JsonClass(generateAdapter = true)
data class CreateBastionPathReq(
    @Json(name = "label") val label: String,
    @Json(name = "description") val description: String = "",
    @Json(name = "jump_hops") val jumpHops: List<BastionHopReq> = emptyList(),
    @Json(name = "target") val target: BastionHopReq,
)

@JsonClass(generateAdapter = true)
data class UpdateBastionPathReq(
    @Json(name = "label") val label: String? = null,
    @Json(name = "description") val description: String? = null,
    @Json(name = "jump_hops") val jumpHops: List<BastionHopReq>? = null,
    @Json(name = "target") val target: BastionHopReq? = null,
)

@JsonClass(generateAdapter = true)
data class BastionResolvedDto(
    @Json(name = "path_id") val pathId: String = "",
    @Json(name = "label") val label: String = "",
    @Json(name = "chain") val chain: List<BastionHopDto> = emptyList(),
    @Json(name = "jump_hops") val jumpHops: List<BastionHopDto> = emptyList(),
    @Json(name = "target") val target: BastionHopDto? = null,
    @Json(name = "total_hops") val totalHops: Int = 0,
    @Json(name = "proxy_jump") val proxyJump: String = "",
    @Json(name = "ssh_command") val sshCommand: String = "",
    @Json(name = "ssh_config") val sshConfig: String = "",
)

interface SshBastionRepository {
    suspend fun list(): ApiResult<BastionPathListDto>
    suspend fun create(req: CreateBastionPathReq): ApiResult<BastionPathDto>
    suspend fun update(pathId: String, req: UpdateBastionPathReq): ApiResult<BastionPathDto>
    suspend fun resolve(pathId: String): ApiResult<BastionResolvedDto>
    suspend fun delete(pathId: String): ApiResult<Unit>
}

@Singleton
class DefaultSshBastionRepository @Inject constructor(
    private val api: SshBastionApi,
    private val errorParser: ApiErrorParser,
) : SshBastionRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun list(): ApiResult<BastionPathListDto> = withContext(io) { call { api.listPaths() } }

    override suspend fun create(req: CreateBastionPathReq): ApiResult<BastionPathDto> =
        withContext(io) { call { api.createPath(req) } }

    override suspend fun update(pathId: String, req: UpdateBastionPathReq): ApiResult<BastionPathDto> =
        withContext(io) { call { api.updatePath(pathId, req) } }

    override suspend fun resolve(pathId: String): ApiResult<BastionResolvedDto> =
        withContext(io) { call { api.resolve(pathId) } }

    override suspend fun delete(pathId: String): ApiResult<Unit> =
        withContext(io) { call { api.deletePath(pathId) } }

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
object SshBastionApiModule {
    @Provides
    @Singleton
    fun provideSshBastionApi(retrofit: Retrofit): SshBastionApi = retrofit.create(SshBastionApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class SshBastionDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindSshBastionRepository(impl: DefaultSshBastionRepository): SshBastionRepository
}
