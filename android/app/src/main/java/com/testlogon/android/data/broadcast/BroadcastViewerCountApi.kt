package com.testlogon.android.data.broadcast

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
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
import retrofit2.http.Path
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-279 — the separate viewer-count read surface.
 *
 * VERIFIED: viewer_count is NOT on the session DTO; it is served by
 * `GET broadcast/sessions/{session_id}/viewers/count` -> ViewerCountOut (reference/openapi.index.txt;
 * src/api/endpoints/broadcast.ts getViewerCount). An idempotent GET; the browse list fetches it
 * best-effort per LIVE session (failures simply leave the count null — never block the list).
 */
interface BroadcastViewerCountApi {

    @GET("broadcast/sessions/{sessionId}/viewers/count")
    suspend fun viewerCount(@Path("sessionId") sessionId: String): ViewerCountDto
}

/** ViewerCountOut — `{ session_id, viewer_count }`. */
@JsonClass(generateAdapter = true)
data class ViewerCountDto(
    @Json(name = "session_id") val sessionId: String = "",
    @Json(name = "viewer_count") val viewerCount: Int = 0,
)

/** AND-279 — best-effort viewer-count reads, folded into [ApiResult] like the other repos. */
@Singleton
class BroadcastViewerCountRepository @Inject constructor(
    private val api: BroadcastViewerCountApi,
    private val errorParser: ApiErrorParser,
) {
    // Retrofit suspend calls are already main-safe (OkHttp dispatches I/O), so no withContext(IO) hop —
    // that hop made the VM's fire-and-forget seed poll non-deterministic under virtual time.
    suspend fun viewerCount(sessionId: String): ApiResult<Int> =
        try {
            ApiResult.Success(api.viewerCount(sessionId).viewerCount)
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Failure(errorParser.from(e))
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
}

@Module
@InstallIn(SingletonComponent::class)
object BroadcastViewerCountApiModule {

    @Provides
    @Singleton
    fun provideBroadcastViewerCountApi(retrofit: Retrofit): BroadcastViewerCountApi =
        retrofit.create(BroadcastViewerCountApi::class.java)
}
