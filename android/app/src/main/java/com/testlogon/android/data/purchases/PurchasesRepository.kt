package com.testlogon.android.data.purchases

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-218 / AND-219 — purchase-history data layer over [PurchasesApi].
 *
 * Wraps the list / search / detail GETs in [ApiResult], mapping wire DTOs to the purchases domain so the
 * paging source / ViewModel never see raw DTOs. Network-only; CancellationException is re-thrown so
 * Paging / coroutine cancellation works; HTTP errors fold to Failure and transport failures to
 * NetworkError. List and search return a single bounded page (the backend has no pagination); the
 * single-page Paging 3 wiring (AND-219/AND-221) layers above this.
 */
interface PurchasesRepository {

    /** History list (optionally server-filtered by [status]); a single [limit]-bounded page. */
    suspend fun list(
        limit: Int = PurchasesApi.PAGE_SIZE,
        status: String? = null,
    ): ApiResult<List<PurchaseListItem>>

    /** Full-text search over the history; a single [limit]-bounded page. [query] must be non-blank. */
    suspend fun search(
        query: String,
        limit: Int = PurchasesApi.PAGE_SIZE,
    ): ApiResult<List<PurchaseListItem>>

    /** One-shot transaction detail by id (maps PurchaseTransactionInfo). */
    suspend fun detail(txnId: String): ApiResult<PurchaseDetail>

    /** ECOMX-42 (B6) — buyer confirms delivery; returns the refreshed (completed) detail. */
    suspend fun confirmReceived(txnId: String): ApiResult<PurchaseDetail>
}

@Singleton
class PurchasesRepositoryImpl @Inject constructor(
    private val api: PurchasesApi,
    private val errorParser: ApiErrorParser,
) : PurchasesRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun list(limit: Int, status: String?): ApiResult<List<PurchaseListItem>> =
        withContext(io) {
            call { api.listTransactions(limit = limit, status = status?.takeIf { it.isNotBlank() }) }
                .map { rows -> rows.map { it.toDomain() } }
        }

    override suspend fun search(query: String, limit: Int): ApiResult<List<PurchaseListItem>> =
        withContext(io) {
            call { api.searchTransactions(q = query, limit = limit) }
                .map { rows -> rows.map { it.toDomain() } }
        }

    override suspend fun detail(txnId: String): ApiResult<PurchaseDetail> =
        withContext(io) {
            call { api.getTransaction(txnId) }.map { it.toDomain() }
        }

    override suspend fun confirmReceived(txnId: String): ApiResult<PurchaseDetail> =
        withContext(io) {
            call { api.confirmReceived(txnId) }.map { it.toDomain() }
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
