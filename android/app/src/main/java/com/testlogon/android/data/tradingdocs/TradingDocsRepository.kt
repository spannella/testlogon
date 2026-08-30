package com.testlogon.android.data.tradingdocs

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * FE-170 — trading-documents data layer over [TradingDocsApi].
 *
 * DEGRADE-ON-404 (per the FE-170 acceptance criteria — the backend BE-171/172 may be undeployed):
 * every call is wrapped so that an HttpException (incl. 404) or any transport IOException folds to a
 * SAFE EMPTY result — [listTradingDocuments] returns an empty list and [getDownloadUrl] returns null —
 * so the screen shows the honest "No trading documents yet" empty state and never crashes.
 * CancellationException is always re-thrown (structured concurrency).
 *
 * The list is sorted newest-first (created_at desc). The download flow prefers the row's inline
 * download_url and only calls [getDownloadUrl] as a fallback.
 */
interface TradingDocsRepository {

    /** All trading documents, optionally filtered by [type]. Empty list on any error (degrade-on-404). */
    suspend fun listTradingDocuments(type: String? = null): List<TradingDocument>

    /** Resolve a presigned download URL for [docId]; null on any error (degrade-on-404). */
    suspend fun getDownloadUrl(docId: String): String?

    /**
     * FE-171 (BE-170) — request generation of a trading document. Returns true when the backend
     * ACCEPTED the request; false on any error (incl. a 404 when BE-170 is undeployed) — degrade-on-404,
     * the caller then shows the honest "not available yet" message.
     */
    suspend fun requestTradingDocument(
        type: String,
        periodStart: Long? = null,
        periodEnd: Long? = null,
        taxYear: Int? = null,
    ): Boolean
}

@Singleton
class TradingDocsRepositoryImpl @Inject constructor(
    private val api: TradingDocsApi,
) : TradingDocsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun listTradingDocuments(type: String?): List<TradingDocument> = withContext(io) {
        callOr(emptyList()) {
            api.listTradingDocuments(type)
                .documents
                .map { it.toDomain() }
                .sortedByDescending { it.createdAtEpochSeconds ?: 0L }
        }
    }

    override suspend fun getDownloadUrl(docId: String): String? = withContext(io) {
        callOr(null) { api.getDownload(docId).downloadUrl?.takeIf { it.isNotBlank() } }
    }

    override suspend fun requestTradingDocument(
        type: String,
        periodStart: Long?,
        periodEnd: Long?,
        taxYear: Int?,
    ): Boolean = withContext(io) {
        callOr(false) {
            api.requestTradingDocument(
                TradingDocRequestDto(
                    type = type,
                    periodStart = periodStart,
                    periodEnd = periodEnd,
                    taxYear = taxYear,
                ),
            )
            true
        }
    }

    /** Runs [block], returning [fallback] on HTTP (incl. 404) / transport errors. Re-throws cancellation. */
    private inline fun <T> callOr(fallback: T, block: () -> T): T = try {
        block()
    } catch (e: CancellationException) {
        throw e
    } catch (_: HttpException) {
        fallback
    } catch (_: IOException) {
        fallback
    }
}
