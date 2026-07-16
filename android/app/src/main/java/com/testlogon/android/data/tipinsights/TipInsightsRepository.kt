package com.testlogon.android.data.tipinsights

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

// ---- Domain models (no raw DTOs leak out) ----

/** One per-surface breakdown bucket. */
data class TipSurfaceBreakdown(
    val surface: String,
    val count: Int,
    val totalCents: Long,
)

data class TipTopSupporter(
    val userId: String,
    val displayName: String,
    val totalCents: Long,
    val tipCount: Int,
)

/**
 * TIPX-D3 — the creator's ledger-backed tips-received view. [totalNetCents] is NET and reconciles to
 * the earnings tips bucket and the leaderboard; [bySurface] covers every tip surface.
 */
data class TipsReceived(
    val period: String,
    val totalNetCents: Long,
    val tipCount: Int,
    val uniqueTippers: Int,
    val bySurface: List<TipSurfaceBreakdown>,
    val topSupporters: List<TipTopSupporter>,
)

/** TIPX-D4 — one receipt row (a debit for sent, a credit for received-history). */
data class TipTransaction(
    val entryId: String,
    val ts: Long,
    val amountCents: Long,
    val surface: String,
    val contentId: String,
    val counterpartyUserId: String,
    val counterpartyDisplayName: String,
    val platformFeeCents: Long,
    val currency: String,
)

/** TIPX-D4 — the tipper's aggregate spend header. */
data class TipsSentSummary(
    val totalSentCents: Long,
    val tipCount: Int,
    val uniqueRecipients: Int,
)

/** TIPX-D3/D4 — one combined pull for the Tip Insights screen. */
data class TipInsights(
    val received: TipsReceived,
    val sentSummary: TipsSentSummary,
    val sentReceipts: List<TipTransaction>,
)

interface TipInsightsRepository {
    /** Load the combined creator (received) + tipper (sent) tip insights. */
    suspend fun load(period: String = DEFAULT_PERIOD): ApiResult<TipInsights>

    companion object {
        const val DEFAULT_PERIOD = "30d"
    }
}

@Singleton
class TipInsightsRepositoryImpl @Inject constructor(
    private val api: TipInsightsApi,
    private val errorParser: ApiErrorParser,
) : TipInsightsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun load(period: String): ApiResult<TipInsights> = withContext(io) {
        call {
            coroutineScope {
                val receivedDeferred = async { api.getReceivedSummary(period = period) }
                val sentSummaryDeferred = async { api.getSentSummary(period = "all") }
                val sentDeferred = async { api.getSent(period = "all") }

                TipInsights(
                    received = receivedDeferred.await().toDomain(),
                    sentSummary = sentSummaryDeferred.await().toDomain(),
                    sentReceipts = sentDeferred.await().items.map { it.toDomain() },
                )
            }
        }
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

// ---- DTO -> domain mappers ----

internal fun TipsReceivedSummaryDto.toDomain(): TipsReceived = TipsReceived(
    period = period,
    totalNetCents = totalNetCents,
    tipCount = tipCount,
    uniqueTippers = uniqueTippers,
    bySurface = byType
        .map { (surface, bucket) -> TipSurfaceBreakdown(surface, bucket.count, bucket.totalCents) }
        .filter { it.count > 0 }
        .sortedByDescending { it.totalCents },
    topSupporters = topTippers.map {
        TipTopSupporter(it.userId, it.displayName.ifBlank { it.userId }, it.totalCents, it.tipCount)
    },
)

internal fun TipsSentSummaryDto.toDomain(): TipsSentSummary =
    TipsSentSummary(totalSentCents = totalSentCents, tipCount = tipCount, uniqueRecipients = uniqueRecipients)

internal fun TipTransactionDto.toDomain(): TipTransaction = TipTransaction(
    entryId = entryId,
    ts = ts,
    amountCents = amountCents,
    surface = contentType.ifBlank { "tip" },
    contentId = contentId,
    counterpartyUserId = counterpartyUserId,
    counterpartyDisplayName = counterpartyDisplayName.ifBlank { counterpartyUserId },
    platformFeeCents = platformFeeCents,
    currency = currency,
)
