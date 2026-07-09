package com.testlogon.android.data.moderation

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Response
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/** The moderation state surfaced to the poster on the "My content under review" screen. */
enum class ModerationCaseState {
    /** Hidden from the public, pending an admin's first look. */
    UNDER_REVIEW,

    /** A violation was confirmed; hidden with a 30-day window for the poster to respond. */
    HOLD,

    /** The poster responded; awaiting the admin's final decision. */
    AWAITING_FINAL,

    UNKNOWN;

    companion object {
        fun fromWire(token: String?): ModerationCaseState = when (token?.trim()?.lowercase()) {
            "under_review" -> UNDER_REVIEW
            "hold" -> HOLD
            "awaiting_final" -> AWAITING_FINAL
            else -> UNKNOWN
        }
    }
}

/** One reported piece of the caller's own content, as shown on the review screen. */
data class ModerationCase(
    val caseId: String,
    val contentType: String,
    val contentId: String,
    val state: ModerationCaseState,
    val categories: List<String>,
    val reportCount: Int,
    val holdUntilEpochSeconds: Long?,
    val daysRemaining: Int?,
    val posterResponse: String?,
    val respondedAtEpochSeconds: Long?,
    val createdAtEpochSeconds: Long,
    val updatedAtEpochSeconds: Long,
) {
    /** Only a HOLD case (30-day window, no response yet) accepts a respond / close action. */
    val canRespond: Boolean get() = state == ModerationCaseState.HOLD
    val canClose: Boolean
        get() = state == ModerationCaseState.HOLD || state == ModerationCaseState.AWAITING_FINAL
}

internal fun MyModerationCaseDto.toDomain(): ModerationCase = ModerationCase(
    caseId = caseId,
    contentType = contentType,
    contentId = contentId,
    state = ModerationCaseState.fromWire(state),
    categories = categories,
    reportCount = reportCount,
    holdUntilEpochSeconds = holdUntil,
    daysRemaining = daysRemaining,
    posterResponse = posterResponse?.takeIf { it.isNotBlank() },
    respondedAtEpochSeconds = respondedAt,
    createdAtEpochSeconds = createdAt,
    updatedAtEpochSeconds = updatedAt,
)

/**
 * MOD-D2 — data layer for the poster's content-review flow: list the caller's open cases + the two
 * hold actions (respond / close). All results fold into [ApiResult]; [CancellationException] is
 * always re-thrown. CLOSE hard-deletes the content server-side, so the UI must confirm before calling.
 */
interface ModerationReviewRepository {
    suspend fun listMyCases(): ApiResult<List<ModerationCase>>

    /** Post the poster's single statement on a held case -> the case moves to awaiting_final. */
    suspend fun respond(caseId: String, statement: String): ApiResult<ModerationCaseState>

    /** Close & DELETE the content immediately (irreversible). */
    suspend fun close(caseId: String): ApiResult<ModerationCaseState>
}

@Singleton
class ModerationReviewRepositoryImpl @Inject constructor(
    private val api: ModerationReviewApi,
    private val errorParser: ApiErrorParser,
) : ModerationReviewRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun listMyCases(): ApiResult<List<ModerationCase>> = withContext(io) {
        apiCallResponse { api.listMyCases() }
            .map { dto -> dto.cases.map { it.toDomain() } }
    }

    override suspend fun respond(caseId: String, statement: String): ApiResult<ModerationCaseState> =
        withContext(io) {
            val trimmed = statement.trim()
            if (trimmed.isEmpty()) {
                return@withContext ApiResult.Failure(
                    ApiError(ApiError.STATUS_PARSE, "Enter a statement"),
                )
            }
            apiCallResponse { api.respondToHold(caseId, HoldRespondRequestDto(statement = trimmed)) }
                .map { ModerationCaseState.fromWire(it.state) }
        }

    override suspend fun close(caseId: String): ApiResult<ModerationCaseState> = withContext(io) {
        apiCallResponse { api.closeHold(caseId) }
            .map { ModerationCaseState.fromWire(it.state) }
    }

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

@Module
@InstallIn(SingletonComponent::class)
abstract class ModerationReviewDataModule {
    @Binds
    @Singleton
    abstract fun bindModerationReviewRepository(
        impl: ModerationReviewRepositoryImpl,
    ): ModerationReviewRepository
}
