package com.testlogon.android.data.vnc

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
import retrofit2.http.Path
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * B7 Remote-Access: Remote Desktop / VNC session broker. Mirrors the web /remote-desktop page
 * (RemoteDesktopPage.tsx + api/endpoints/vnc.ts). Backend: vnc_sessions.py, prefix /api/vnc,
 * require_ui_session (+ role recorded server-side; target validated server-side). Web is FLAGGED behind
 * VITE_VNC_REMOTE_DESKTOP_ENABLED (default true) + a kill-switch (default false).
 *
 * REAL-vs-STUB: the response's `ws_url` is a raw noVNC RFB WebSocket (websockify). The web client
 * attaches @novnc/novnc to a DOM canvas over it — a genuine live pixel session. On mobile there is no
 * trivial RFB renderer, so this module builds the SESSION BROKER (create/target-validate/connection-info/
 * transfer-fallback/teardown) fully and presents the live viewer as an HONEST "open on desktop" state
 * with the connection details. It does NOT fake a working VNC session. Self-contained (Api + DTOs +
 * Repository + DI). Timestamps epoch SECONDS.
 */
interface VncApi {

    @POST("api/vnc/session")
    suspend fun createSession(@Body body: CreateVncSessionReq): CreateVncSessionDto

    @DELETE("api/vnc/session/{id}")
    suspend fun deleteSession(@Path("id") sessionId: String): DeleteVncSessionDto

    @GET("api/vnc/session/{id}/transfer-fallback")
    suspend fun transferFallback(@Path("id") sessionId: String): VncTransferFallbackDto
}

@JsonClass(generateAdapter = true)
data class CreateVncSessionReq(
    @Json(name = "target_id") val targetId: String,
)

@JsonClass(generateAdapter = true)
data class VncCapabilitiesDto(
    @Json(name = "clipboard") val clipboard: Boolean = false,
    @Json(name = "file_transfer") val fileTransfer: Boolean = false,
    @Json(name = "drag_drop_upload") val dragDropUpload: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class VncTimeoutPolicyDto(
    @Json(name = "idle_timeout_seconds") val idleTimeoutSeconds: Int = 300,
    @Json(name = "max_session_duration_seconds") val maxSessionDurationSeconds: Int = 3600,
    @Json(name = "warning_seconds") val warningSeconds: Int = 60,
)

@JsonClass(generateAdapter = true)
data class CreateVncSessionDto(
    @Json(name = "session_id") val sessionId: String = "",
    @Json(name = "ws_url") val wsUrl: String = "",
    @Json(name = "connect_params") val connectParams: Map<String, String> = emptyMap(),
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "expires_at") val expiresAt: Long = 0L,
    @Json(name = "capabilities") val capabilities: VncCapabilitiesDto = VncCapabilitiesDto(),
    @Json(name = "timeout_policy") val timeoutPolicy: VncTimeoutPolicyDto = VncTimeoutPolicyDto(),
)

@JsonClass(generateAdapter = true)
data class DeleteVncSessionDto(
    @Json(name = "session_id") val sessionId: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "closed_at") val closedAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class VncTransferFallbackDto(
    @Json(name = "session_id") val sessionId: String = "",
    @Json(name = "method") val method: String = "",
    @Json(name = "label") val label: String = "",
    @Json(name = "instructions") val instructions: String = "",
    @Json(name = "url") val url: String = "",
    @Json(name = "expires_at") val expiresAt: Long = 0L,
)

interface VncRepository {
    suspend fun createSession(targetId: String): ApiResult<CreateVncSessionDto>
    suspend fun deleteSession(sessionId: String): ApiResult<DeleteVncSessionDto>
    suspend fun transferFallback(sessionId: String): ApiResult<VncTransferFallbackDto>
}

@Singleton
class DefaultVncRepository @Inject constructor(
    private val api: VncApi,
    private val errorParser: ApiErrorParser,
) : VncRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun createSession(targetId: String): ApiResult<CreateVncSessionDto> =
        withContext(io) { call { api.createSession(CreateVncSessionReq(targetId.trim())) } }

    override suspend fun deleteSession(sessionId: String): ApiResult<DeleteVncSessionDto> =
        withContext(io) { call { api.deleteSession(sessionId) } }

    override suspend fun transferFallback(sessionId: String): ApiResult<VncTransferFallbackDto> =
        withContext(io) { call { api.transferFallback(sessionId) } }

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
object VncApiModule {
    @Provides
    @Singleton
    fun provideVncApi(retrofit: Retrofit): VncApi = retrofit.create(VncApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class VncDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindVncRepository(impl: DefaultVncRepository): VncRepository
}
