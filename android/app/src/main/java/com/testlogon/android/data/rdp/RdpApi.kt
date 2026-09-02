package com.testlogon.android.data.rdp

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
import retrofit2.http.GET
import retrofit2.http.Query
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * B7 Remote-Access: RDP browser transport, Phase-1 FALLBACK ONLY (ADR-004 / CTI-005). Mirrors the web
 * api/endpoints/rdp.ts, which ships only the `fallback` surface — native in-browser RDP is a future
 * milestone behind RDP_REMOTE_DESKTOP_ENABLED (POST /api/rdp/session currently returns 503/501). We do
 * NOT model the session-bootstrap here for the same reason the web doesn't: there is nothing to render.
 *
 * Backend: rdp_sessions.py, prefix /api/rdp, cookie-auth (require_ui_session) + owner-scoped by host_id
 * (a foreign/unknown host_id fails closed -> RDP_TARGET_NOT_FOUND under an error envelope). The fallback
 * returns copy-ready host:port/username connection details + native-client instructions for a
 * Windows/RDP host. NO session/token is minted; there is NO interactive rendering on mobile — this is a
 * connection-info VIEW only, exactly as the interactive-rendering deferral requires.
 *
 * Self-contained (Api + DTO + Repository + DI) per the infra data-layer pattern. NO new endpoint module,
 * migration, or dependency.
 */
interface RdpApi {

    @GET("api/rdp/fallback")
    suspend fun fallback(@Query("host_id") hostId: String): RdpFallbackDto
}

@JsonClass(generateAdapter = true)
data class RdpFallbackDto(
    @Json(name = "available") val available: Boolean = false,
    @Json(name = "host_id") val hostId: String = "",
    @Json(name = "label") val label: String = "",
    @Json(name = "hostname") val hostname: String = "",
    @Json(name = "port") val port: Int = 3389,
    @Json(name = "username") val username: String = "",
    @Json(name = "address") val address: String = "",
    @Json(name = "instructions") val instructions: String = "",
    @Json(name = "native_clients") val nativeClients: List<String> = emptyList(),
)

interface RdpRepository {
    suspend fun fallback(hostId: String): ApiResult<RdpFallbackDto>
}

@Singleton
class DefaultRdpRepository @Inject constructor(
    private val api: RdpApi,
    private val errorParser: ApiErrorParser,
) : RdpRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun fallback(hostId: String): ApiResult<RdpFallbackDto> =
        withContext(io) { call { api.fallback(hostId.trim()) } }

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
object RdpApiModule {
    @Provides
    @Singleton
    fun provideRdpApi(retrofit: Retrofit): RdpApi = retrofit.create(RdpApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class RdpDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindRdpRepository(impl: DefaultRdpRepository): RdpRepository
}
