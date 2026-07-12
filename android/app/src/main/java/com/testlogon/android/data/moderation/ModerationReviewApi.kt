package com.testlogon.android.data.moderation

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Response
import retrofit2.Retrofit
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path
import javax.inject.Singleton

/**
 * MOD-D2 — Retrofit interface for the POSTER-facing moderation review surface ("My content under
 * review"). Distinct from the ADMIN moderation board ([data.admin] ModerationAdminApi) and from the
 * report-SUBMIT engine ([data.report] ModerationReportApi) so the existing fakes stay untouched.
 *
 * Endpoints (backend prefix /moderation, aliased under /v1/moderation):
 *  - list   -> GET  moderation/cases/mine                 -> MyModerationCasesOut
 *  - respond-> POST moderation/holds/{caseId}/respond     req {statement} -> HoldActionOut
 *  - close  -> POST moderation/holds/{caseId}/close       (empty body)    -> HoldActionOut
 *
 * Paths are relative (no leading slash) so they resolve against the shared base URL; cookies,
 * Authorization + X-CSRF-Token are attached by the core-network interceptor chain. The POSTs are
 * non-idempotent and are NEVER auto-retried.
 */
interface ModerationReviewApi {

    @GET("moderation/cases/mine")
    suspend fun listMyCases(): Response<MyModerationCasesDto>

    @Headers("Content-Type: application/json")
    @POST("moderation/holds/{caseId}/respond")
    suspend fun respondToHold(
        @Path("caseId") caseId: String,
        @Body body: HoldRespondRequestDto,
    ): Response<HoldActionResponseDto>

    /** CLOSE deletes the content immediately — the caller MUST confirm first. */
    @Headers("Content-Type: application/json")
    @POST("moderation/holds/{caseId}/close")
    suspend fun closeHold(
        @Path("caseId") caseId: String,
    ): Response<HoldActionResponseDto>
}

@JsonClass(generateAdapter = true)
data class MyModerationCasesDto(
    val cases: List<MyModerationCaseDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class MyModerationCaseDto(
    @Json(name = "case_id") val caseId: String,
    @Json(name = "content_type") val contentType: String = "",
    @Json(name = "content_id") val contentId: String = "",
    @Json(name = "state") val state: String = "",
    @Json(name = "categories") val categories: List<String> = emptyList(),
    @Json(name = "report_count") val reportCount: Int = 0,
    @Json(name = "hold_until") val holdUntil: Long? = null,
    @Json(name = "days_remaining") val daysRemaining: Int? = null,
    @Json(name = "poster_response") val posterResponse: String? = null,
    @Json(name = "responded_at") val respondedAt: Long? = null,
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "updated_at") val updatedAt: Long = 0L,
)

@JsonClass(generateAdapter = true)
data class HoldRespondRequestDto(
    @Json(name = "statement") val statement: String,
)

@JsonClass(generateAdapter = true)
data class HoldActionResponseDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "case_id") val caseId: String = "",
    @Json(name = "state") val state: String = "",
)

/** Provides [ModerationReviewApi] on the SHARED Retrofit — no new OkHttp / Retrofit instance. */
@Module
@InstallIn(SingletonComponent::class)
object ModerationReviewApiModule {
    @Provides
    @Singleton
    fun provideModerationReviewApi(retrofit: Retrofit): ModerationReviewApi =
        retrofit.create(ModerationReviewApi::class.java)
}
