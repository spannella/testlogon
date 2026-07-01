package com.testlogon.android.data.stylist

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Stylist / UI-design data layer over [StylistApi].
 *
 * loadOverview() fans out the overall + per-page score GETs in parallel and folds them into a single
 * [DesignOverview]; getReview() / rules CRUD / triggerReview map 1:1. Every call is wrapped in
 * [ApiResult] (CancellationException re-thrown, HTTP -> Failure, transport -> NetworkError,
 * JsonDataException -> Failure). A last-known-good overview is cached in-memory for stale fallback.
 */
interface StylistRepository {
    suspend fun loadOverview(): ApiResult<DesignOverview>
    suspend fun triggerReview(pages: List<String>): ApiResult<Unit>
    suspend fun getReview(reviewId: String): ApiResult<UIReview>
    suspend fun createIssueTicket(reviewId: String, issueId: String): ApiResult<String>
    suspend fun loadRules(): ApiResult<List<DesignRule>>
    suspend fun createRule(name: String, category: String, description: String, severity: String): ApiResult<Unit>
    suspend fun setRuleEnabled(ruleId: String, enabled: Boolean): ApiResult<Unit>
    suspend fun deleteRule(ruleId: String): ApiResult<Unit>
    fun cachedOverview(): DesignOverview?
    fun clear()
}

@Singleton
class StylistRepositoryImpl @Inject constructor(
    private val api: StylistApi,
    private val errorParser: ApiErrorParser,
) : StylistRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    @Volatile
    private var overviewSnapshot: DesignOverview? = null

    override suspend fun loadOverview(): ApiResult<DesignOverview> = withContext(io) {
        call {
            coroutineScope {
                val overall = async { api.getOverallScore() }
                val pages = async { api.getPageScores() }
                DesignOverview(
                    overall = overall.await().toDomain(),
                    // worst first, mirroring the web page sort
                    pages = pages.await().map { it.toDomain() }.sortedBy { it.designScore },
                )
            }
        }.also { if (it is ApiResult.Success) overviewSnapshot = it.data }
    }

    override suspend fun triggerReview(pages: List<String>): ApiResult<Unit> = withContext(io) {
        call {
            api.triggerReview(TriggerUIReviewReqDto(pages = pages, reviewType = "full_page"))
            Unit
        }
    }

    override suspend fun getReview(reviewId: String): ApiResult<UIReview> = withContext(io) {
        call { api.getReview(reviewId).toDomain() }
    }

    override suspend fun createIssueTicket(reviewId: String, issueId: String): ApiResult<String> =
        withContext(io) { call { api.createIssueTicket(reviewId, issueId).ticketId } }

    override suspend fun loadRules(): ApiResult<List<DesignRule>> = withContext(io) {
        call { api.listRules().map { it.toDomain() } }
    }

    override suspend fun createRule(
        name: String,
        category: String,
        description: String,
        severity: String,
    ): ApiResult<Unit> = withContext(io) {
        call {
            api.createRule(
                CreateDesignRuleReqDto(
                    name = name.trim(),
                    category = category,
                    description = description.trim(),
                    severity = severity,
                ),
            )
            Unit
        }
    }

    override suspend fun setRuleEnabled(ruleId: String, enabled: Boolean): ApiResult<Unit> =
        withContext(io) {
            call {
                api.updateRule(ruleId, UpdateDesignRuleReqDto(enabled = enabled))
                Unit
            }
        }

    override suspend fun deleteRule(ruleId: String): ApiResult<Unit> = withContext(io) {
        call {
            api.deleteRule(ruleId)
            Unit
        }
    }

    override fun cachedOverview(): DesignOverview? = overviewSnapshot

    override fun clear() {
        overviewSnapshot = null
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: com.squareup.moshi.JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
