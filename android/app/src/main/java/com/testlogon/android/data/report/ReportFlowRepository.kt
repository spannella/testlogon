package com.testlogon.android.data.report

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.messaging.report.ReportApi
import com.testlogon.android.data.messaging.report.ReportMessageRequestDto
import com.testlogon.android.data.messaging.report.ReportReason
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Response
import retrofit2.Retrofit
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-383 - data layer for the cross-cutting report flow.
 *
 * Routes by [ReportKind] to one of the two REAL endpoints (the draft's single /ui/report does not exist):
 *  - USER  -> moderation/reports, content_type="profile_photo", profile_user_id set.
 *  - CONTENT -> moderation/reports, content_type=the feed value, post_id (+ comment/media disambiguators).
 *  - MESSAGE -> AND-163's message-scoped endpoint (reused, not re-declared), reason_code=topics.first(),
 *    statement=reason_text.
 *
 * Both responses are normalized to a common [ReportResult]; only the moderation `status=="deduplicated"`
 * sets `alreadyReported` (FR-8 - there is NO 409). The POST is non-idempotent and is NEVER auto-retried;
 * retry is user-initiated only. Failures fold into [ApiResult.Failure] / [ApiResult.NetworkError];
 * [CancellationException] is always re-thrown. The reporter's free-text `reason_text` is NEVER logged.
 */
interface ReportFlowRepository {

    /**
     * Submit a report. [topics] must be non-empty and [reasonText] 5..2000 after trim (the ViewModel
     * gates this); [target]'s kind selects the endpoint. Non-idempotent.
     */
    suspend fun submit(
        target: ReportTarget,
        topics: Set<ReportReason>,
        reasonText: String,
    ): ApiResult<ReportResult>
}

@Singleton
class ReportFlowRepositoryImpl @Inject constructor(
    private val moderationApi: ModerationReportApi,
    private val messageApi: ReportApi,
    private val errorParser: ApiErrorParser,
) : ReportFlowRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun submit(
        target: ReportTarget,
        topics: Set<ReportReason>,
        reasonText: String,
    ): ApiResult<ReportResult> = withContext(io) {
        when (target) {
            is ReportTarget.Message -> submitMessage(target, topics, reasonText)
            is ReportTarget.User -> submitModeration(target, topics, reasonText)
            is ReportTarget.Account -> submitModeration(target, topics, reasonText)
            is ReportTarget.Content -> submitModeration(target, topics, reasonText)
        }
    }

    private suspend fun submitMessage(
        target: ReportTarget.Message,
        topics: Set<ReportReason>,
        reasonText: String,
    ): ApiResult<ReportResult> {
        val first = topics.firstOrNull()
            ?: return ApiResult.Failure(ApiError(ApiError.STATUS_PARSE, "Select at least one topic"))
        // AND-163's reportMessage returns a BARE DTO (not Response) -> apiCall, not apiCallResponse.
        return apiCall {
            messageApi.reportMessage(
                conversationId = target.conversationId,
                messageId = target.id,
                body = ReportMessageRequestDto(reasonCode = first.code, statement = reasonText),
            )
        }.map { dto -> ReportResult(reportId = dto.reportId, alreadyReported = false) }
    }

    private suspend fun submitModeration(
        target: ReportTarget,
        topics: Set<ReportReason>,
        reasonText: String,
    ): ApiResult<ReportResult> {
        val request = buildModerationRequest(target, topics, reasonText)
        return apiCallResponse {
            moderationApi.reportModeration(request)
        }.map { dto ->
            ReportResult(
                reportId = dto.reportId,
                alreadyReported = dto.status.equals("deduplicated", ignoreCase = true),
            )
        }
    }

    private fun buildModerationRequest(
        target: ReportTarget,
        topics: Set<ReportReason>,
        reasonText: String,
    ): ModerationReportRequestDto {
        val base = ModerationReportRequestDto(
            contentType = target.moderationContentType(),
            contentId = target.id,
            topics = ReportTopics.ALL.filter { it in topics }.map { it.code },
            reasonText = reasonText,
        )
        return when (target) {
            is ReportTarget.User -> base.copy(profileUserId = target.id)
            is ReportTarget.Account -> base.copy(profileUserId = target.id)
            is ReportTarget.Content -> {
                val withIds = base.copy(
                    syndicateId = target.syndicateId,
                    categoryId = target.categoryId,
                    itemId = target.itemId,
                    sessionId = target.sessionId,
                )
                when (target.contentType) {
                    "feed_comment" -> withIds.copy(commentId = target.id)
                    "catalog_item", "catalog_review", "broadcast_message", "story", "clip" -> withIds
                    else -> withIds.copy(postId = target.id)
                }
            }
            is ReportTarget.Message -> base // unreachable (routed to the message endpoint)
        }
    }

    private suspend fun <T> apiCall(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }

    /** Unwraps a Retrofit [Response]: a non-2xx becomes [ApiResult.Failure] via [ApiErrorParser]. */
    private suspend fun <T> apiCallResponse(block: suspend () -> Response<T>): ApiResult<T> = try {
        val response = block()
        val body = response.body()
        if (response.isSuccessful && body != null) {
            ApiResult.Success(body)
        } else {
            ApiResult.Failure(errorParser.from(HttpException(response)))
        }
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}

/** AND-383 - provides [ModerationReportApi] on the shared Retrofit and binds the report-flow repository. */
@Module
@InstallIn(SingletonComponent::class)
object ModerationReportApiModule {
    @Provides
    @Singleton
    fun provideModerationReportApi(retrofit: Retrofit): ModerationReportApi =
        retrofit.create(ModerationReportApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class ReportFlowDataModule {
    @Binds
    @Singleton
    abstract fun bindReportFlowRepository(impl: ReportFlowRepositoryImpl): ReportFlowRepository
}
