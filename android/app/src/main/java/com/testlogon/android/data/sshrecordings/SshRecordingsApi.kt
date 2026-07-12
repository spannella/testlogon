package com.testlogon.android.data.sshrecordings

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
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Path
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * B7 Remote-Access: SSH Session Recordings (list + view/playback + delete). Mirrors the web
 * /remote/recordings page (SshRecordingsPage.tsx + SshRecordingPlayer.tsx +
 * api/endpoints/sshSessionRecording.ts). Backend: ssh_session_recording.py, prefix
 * /ui/compute/ssh-recordings, require_ui_session (owner-scoped; an admin-oversight endpoint exists but
 * is not surfaced here). The whole surface is behind SSH_SESSION_RECORDING_ENABLED (default true; a 503
 * -> Disabled state). Playback is RECORDED asciicast events (offset,type,data) -> a real replayable
 * timeline viewer on mobile (NOT a live session). Timestamps epoch SECONDS. Self-contained.
 */
interface SshRecordingsApi {

    @GET("ui/compute/ssh-recordings")
    suspend fun list(): RecordingListDto

    @GET("ui/compute/ssh-recordings/{id}")
    suspend fun get(@Path("id") recordingId: String): RecordingDto

    @GET("ui/compute/ssh-recordings/{id}/playback")
    suspend fun playback(@Path("id") recordingId: String): RecordingPlaybackDto

    @DELETE("ui/compute/ssh-recordings/{id}")
    suspend fun delete(@Path("id") recordingId: String): OkDto
}

@JsonClass(generateAdapter = true)
data class RecordingDto(
    @Json(name = "recording_id") val recordingId: String = "",
    @Json(name = "session_id") val sessionId: String = "",
    @Json(name = "host_id") val hostId: String = "",
    @Json(name = "hostname") val hostname: String = "",
    @Json(name = "port") val port: Int = 22,
    @Json(name = "username") val username: String = "",
    @Json(name = "host_key") val hostKey: String = "",
    @Json(name = "status") val status: String = "recording",
    @Json(name = "start_time") val startTime: Long = 0L,
    @Json(name = "end_time") val endTime: Long = 0L,
    @Json(name = "duration_seconds") val durationSeconds: Int = 0,
    @Json(name = "file_size_bytes") val fileSizeBytes: Long = 0L,
    @Json(name = "terminal_cols") val terminalCols: Int = 80,
    @Json(name = "terminal_rows") val terminalRows: Int = 24,
    @Json(name = "event_count") val eventCount: Int = 0,
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "retention_days") val retentionDays: Int = 0,
    @Json(name = "expires_at") val expiresAt: Long = 0L,
)

@JsonClass(generateAdapter = true)
data class RecordingListDto(
    @Json(name = "recordings") val recordings: List<RecordingDto> = emptyList(),
    @Json(name = "count") val count: Int = 0,
)

@JsonClass(generateAdapter = true)
data class RecordingPlaybackDto(
    @Json(name = "recording_id") val recordingId: String = "",
    @Json(name = "content_type") val contentType: String = "application/x-asciicast",
    // asciicast events: each is [offset(float seconds), type(String "o"/"i"), data(String)]
    @Json(name = "events") val events: List<List<Any>> = emptyList(),
    @Json(name = "event_count") val eventCount: Int = 0,
)

@JsonClass(generateAdapter = true)
data class OkDto(
    @Json(name = "ok") val ok: Boolean = true,
)

interface SshRecordingsRepository {
    suspend fun list(): ApiResult<RecordingListDto>
    suspend fun playback(recordingId: String): ApiResult<RecordingPlaybackDto>
    suspend fun delete(recordingId: String): ApiResult<OkDto>
}

@Singleton
class DefaultSshRecordingsRepository @Inject constructor(
    private val api: SshRecordingsApi,
    private val errorParser: ApiErrorParser,
) : SshRecordingsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun list(): ApiResult<RecordingListDto> = withContext(io) { call { api.list() } }

    override suspend fun playback(recordingId: String): ApiResult<RecordingPlaybackDto> =
        withContext(io) { call { api.playback(recordingId) } }

    override suspend fun delete(recordingId: String): ApiResult<OkDto> =
        withContext(io) { call { api.delete(recordingId) } }

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
object SshRecordingsApiModule {
    @Provides
    @Singleton
    fun provideSshRecordingsApi(retrofit: Retrofit): SshRecordingsApi =
        retrofit.create(SshRecordingsApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class SshRecordingsDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindSshRecordingsRepository(impl: DefaultSshRecordingsRepository): SshRecordingsRepository
}
