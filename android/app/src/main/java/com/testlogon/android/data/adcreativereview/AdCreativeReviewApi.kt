package com.testlogon.android.data.adcreativereview

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
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Web-parity admin AD CREATIVE-REVIEW queue - mirrors the web /admin/ads/creatives/review page
 * (pages/ads/AdminCreativeReviewPage.tsx + api/endpoints/ads.ts listPendingCreatives/reviewCreative).
 * Backend: app/routers/ads.py admin_router (prefix /ui/admin/ads), both endpoints gated by
 * require_admin_or_root (ADMIN-drivable on our admin account).
 *
 *  - GET  /ui/admin/ads/creatives/pending          -> bare JSON array of pending creatives (status="pending_review")
 *  - POST /ui/admin/ads/creatives/{creative_id}/review  {decision:"approve"|"reject", notes?} -> {ok, status}
 *
 * Creative items are the raw ad_creatives rows; the web page reads
 * creative_id/title/format/campaign_id/image_url/width/height/duration_seconds/rotation_weight. All
 * fields are defaulted so a lean/varying row never crashes Moshi. A backend 403 -> Failure(status=403)
 * which the ViewModel maps to Forbidden.
 */
interface AdCreativeReviewApi {

    /** Bare JSON array of creatives pending review (no query params). Idempotent GET. */
    @GET("ui/admin/ads/creatives/pending")
    suspend fun listPending(): List<PendingCreativeDto>

    /** Approve or reject one creative. */
    @POST("ui/admin/ads/creatives/{creative_id}/review")
    suspend fun review(
        @Path("creative_id") creativeId: String,
        @Body body: CreativeReviewReq,
    ): CreativeReviewResultDto
}

// ---- DTOs (verified 1:1 against ads.py + AdminCreativeReviewPage.tsx) ----

@JsonClass(generateAdapter = true)
data class PendingCreativeDto(
    @Json(name = "creative_id") val creativeId: String = "",
    @Json(name = "campaign_id") val campaignId: String = "",
    @Json(name = "title") val title: String = "",
    @Json(name = "format") val format: String = "",
    @Json(name = "status") val status: String = "",
    @Json(name = "image_url") val imageUrl: String? = null,
    @Json(name = "video_url") val videoUrl: String? = null,
    @Json(name = "width") val width: Int? = null,
    @Json(name = "height") val height: Int? = null,
    @Json(name = "duration_seconds") val durationSeconds: Int? = null,
    @Json(name = "rotation_weight") val rotationWeight: Int? = null,
)

@JsonClass(generateAdapter = true)
data class CreativeReviewReq(
    @Json(name = "decision") val decision: String,
    @Json(name = "notes") val notes: String? = null,
)

@JsonClass(generateAdapter = true)
data class CreativeReviewResultDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "status") val status: String = "",
)

/**
 * Read + action data layer over [AdCreativeReviewApi]. Read-then-act queue; no cache (operational,
 * auth-scoped). A backend 403 surfaces as Failure(status=403).
 */
interface AdCreativeReviewRepository {
    suspend fun listPending(): ApiResult<List<PendingCreativeDto>>
    suspend fun review(creativeId: String, decision: String, notes: String?): ApiResult<CreativeReviewResultDto>
}

@Singleton
class DefaultAdCreativeReviewRepository @Inject constructor(
    private val api: AdCreativeReviewApi,
    private val errorParser: ApiErrorParser,
) : AdCreativeReviewRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun listPending(): ApiResult<List<PendingCreativeDto>> =
        withContext(io) { call { api.listPending() } }

    override suspend fun review(
        creativeId: String,
        decision: String,
        notes: String?,
    ): ApiResult<CreativeReviewResultDto> = withContext(io) {
        call { api.review(creativeId, CreativeReviewReq(decision, notes?.trim()?.takeIf { it.isNotEmpty() })) }
    }

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
object AdCreativeReviewApiModule {
    @Provides
    @Singleton
    fun provideAdCreativeReviewApi(retrofit: Retrofit): AdCreativeReviewApi =
        retrofit.create(AdCreativeReviewApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class AdCreativeReviewDataModule {
    @dagger.Binds
    @Singleton
    abstract fun bindAdCreativeReviewRepository(
        impl: DefaultAdCreativeReviewRepository,
    ): AdCreativeReviewRepository
}
