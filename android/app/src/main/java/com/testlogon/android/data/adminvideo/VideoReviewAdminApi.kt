package com.testlogon.android.data.adminvideo

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
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * B5 admin video-review queue - mirrors the web /admin/video-review page (VideoReviewQueuePage.tsx +
 * api/endpoints/adminVideoReview.ts). Backend: admin_video_review.py, prefix /v1/admin/videos, gated by
 * require_admin_scope(CONTENT_MODERATION). Actions: approve / reject. Timestamps are epoch SECONDS.
 */
interface VideoReviewAdminApi {

    @GET("v1/admin/videos/review-queue")
    suspend fun reviewQueue(
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
        @Query("owner_user_id") ownerUserId: String? = null,
    ): VideoReviewQueueDto

    @GET("v1/admin/videos/{id}/review-detail")
    suspend fun reviewDetail(@Path("id") videoId: String): VideoReviewDetailDto

    @POST("v1/admin/videos/{id}/approve")
    suspend fun approve(
        @Path("id") videoId: String,
        @Body body: VideoApproveReq,
    ): VideoReviewDecisionDto

    @POST("v1/admin/videos/{id}/reject")
    suspend fun reject(
        @Path("id") videoId: String,
        @Body body: VideoRejectReq,
    ): VideoReviewDecisionDto
}

@JsonClass(generateAdapter = true)
data class VideoReviewItemDto(
    @Json(name = "video_id") val videoId: String,
    @Json(name = "owner_user_id") val ownerUserId: String = "",
    @Json(name = "title") val title: String = "",
    @Json(name = "description") val description: String? = null,
    @Json(name = "status") val status: String = "",
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "updated_at") val updatedAt: Long = 0L,
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
    @Json(name = "hls_manifest_url") val hlsManifestUrl: String? = null,
    @Json(name = "duration_seconds") val durationSeconds: Long? = null,
    @Json(name = "source_type") val sourceType: String = "",
    @Json(name = "visibility") val visibility: String = "",
    @Json(name = "owner_display_name") val ownerDisplayName: String? = null,
)

@JsonClass(generateAdapter = true)
data class VideoReviewQueueDto(
    @Json(name = "items") val items: List<VideoReviewItemDto> = emptyList(),
    @Json(name = "total_pending") val totalPending: Int = 0,
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class VideoReviewDetailDto(
    @Json(name = "video") val video: VideoReviewItemDto,
    @Json(name = "prior_rejections_count") val priorRejections: Int = 0,
    @Json(name = "prior_approvals_count") val priorApprovals: Int = 0,
)

@JsonClass(generateAdapter = true)
data class VideoReviewDecisionDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "video_id") val videoId: String = "",
    @Json(name = "decision") val decision: String = "",
    @Json(name = "new_status") val newStatus: String = "",
)

@JsonClass(generateAdapter = true)
data class VideoApproveReq(
    @Json(name = "review_notes") val reviewNotes: String? = null,
    @Json(name = "auto_publish") val autoPublish: Boolean = true,
)

@JsonClass(generateAdapter = true)
data class VideoRejectReq(
    @Json(name = "rejection_reason") val rejectionReason: String,
    @Json(name = "notify_creator") val notifyCreator: Boolean = true,
)

interface VideoReviewAdminRepository {
    suspend fun queue(): ApiResult<VideoReviewQueueDto>
    suspend fun detail(videoId: String): ApiResult<VideoReviewDetailDto>
    suspend fun approve(videoId: String, notes: String?): ApiResult<VideoReviewDecisionDto>
    suspend fun reject(videoId: String, reason: String): ApiResult<VideoReviewDecisionDto>
}

@Singleton
class DefaultVideoReviewAdminRepository @Inject constructor(
    private val api: VideoReviewAdminApi,
    private val errorParser: ApiErrorParser,
) : VideoReviewAdminRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun queue(): ApiResult<VideoReviewQueueDto> =
        withContext(io) { call { api.reviewQueue(limit = 50) } }

    override suspend fun detail(videoId: String): ApiResult<VideoReviewDetailDto> =
        withContext(io) { call { api.reviewDetail(videoId) } }

    override suspend fun approve(videoId: String, notes: String?): ApiResult<VideoReviewDecisionDto> =
        withContext(io) { call { api.approve(videoId, VideoApproveReq(reviewNotes = notes?.trim()?.takeIf { it.isNotEmpty() })) } }

    override suspend fun reject(videoId: String, reason: String): ApiResult<VideoReviewDecisionDto> =
        withContext(io) { call { api.reject(videoId, VideoRejectReq(rejectionReason = reason)) } }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
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
object VideoReviewAdminApiModule {
    @Provides
    @Singleton
    fun provideVideoReviewAdminApi(retrofit: Retrofit): VideoReviewAdminApi =
        retrofit.create(VideoReviewAdminApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class VideoReviewAdminDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindVideoReviewAdminRepository(
        impl: DefaultVideoReviewAdminRepository,
    ): VideoReviewAdminRepository
}
