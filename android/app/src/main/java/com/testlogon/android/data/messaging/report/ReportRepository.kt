package com.testlogon.android.data.messaging.report

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Retrofit
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-163 — data layer for message reporting.
 *
 * Submits the report (optimistic PENDING -> network -> SUBMITTED, or rollback to NONE on failure) and
 * exposes an observable per-target status so the thread can render a "Reported" affordance. The status
 * cache is CLIENT-SIDE ONLY (in-memory): the verified contract has no report-status GET endpoint and no
 * 409/already_reported, so there is no server source of truth and no Room migration is introduced for
 * this (avoiding a schema bump). The reason set is a compile-time constant ([ReportReason.SELECTABLE]).
 *
 * Failures fold into [ApiResult.Failure] / [ApiResult.NetworkError]; CancellationException is always
 * re-thrown. The reporter's free-text `statement` is NEVER logged or cached.
 */
interface ReportRepository {

    /**
     * Submit a report for [messageId] in [conversationId] with the chosen [reason] and required
     * [statement] (5..2000 chars; validation is enforced upstream by the ViewModel). Non-idempotent.
     */
    suspend fun reportMessage(
        conversationId: String,
        messageId: String,
        reason: ReportReason,
        statement: String,
    ): ApiResult<Report>

    /** Observe the (client-side) report status for a target message id. Defaults to [ReportStatus.NONE]. */
    fun observeStatus(messageId: String): Flow<ReportStatus>

    /** The selectable reason set (hard-coded; no reasons-catalog endpoint exists). */
    fun reasonCatalog(): List<ReportReason> = ReportReason.SELECTABLE
}

@Singleton
class ReportRepositoryImpl @Inject constructor(
    private val api: ReportApi,
    private val errorParser: ApiErrorParser,
) : ReportRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    /** messageId -> client-side report status (in-memory; no server source of truth). */
    private val statuses = MutableStateFlow<Map<String, ReportStatus>>(emptyMap())

    override fun observeStatus(messageId: String): Flow<ReportStatus> =
        statuses.map { it[messageId] ?: ReportStatus.NONE }

    override suspend fun reportMessage(
        conversationId: String,
        messageId: String,
        reason: ReportReason,
        statement: String,
    ): ApiResult<Report> = withContext(io) {
        // Optimistic PENDING; rolled back to NONE on hard failure.
        setStatus(messageId, ReportStatus.PENDING)
        when (
            val r = apiCall {
                api.reportMessage(
                    conversationId = conversationId,
                    messageId = messageId,
                    body = ReportMessageRequestDto(reasonCode = reason.code, statement = statement),
                )
            }
        ) {
            is ApiResult.Success -> {
                val report = r.data.toDomain()
                setStatus(messageId, report.status)
                ApiResult.Success(report)
            }
            is ApiResult.Failure -> { setStatus(messageId, ReportStatus.NONE); r }
            is ApiResult.NetworkError -> { setStatus(messageId, ReportStatus.NONE); r }
        }
    }

    private fun setStatus(messageId: String, status: ReportStatus) {
        statuses.value = statuses.value.toMutableMap().apply {
            if (status == ReportStatus.NONE) remove(messageId) else put(messageId, status)
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
}

/** AND-163 — provides [ReportApi] on the shared Retrofit and binds the repository. */
@Module
@InstallIn(SingletonComponent::class)
object ReportApiModule {
    @Provides
    @Singleton
    fun provideReportApi(retrofit: Retrofit): ReportApi = retrofit.create(ReportApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class ReportDataModule {
    @Binds
    @Singleton
    abstract fun bindReportRepository(impl: ReportRepositoryImpl): ReportRepository
}
