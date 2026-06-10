package com.testlogon.android.data.discover

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
 * AND-186 — server-backed recent searches over [SearchApi]'s `ui/search/history` family.
 *
 * The web client treats the server history as the source of truth (search.ts:
 * getSearchHistory/recordSearchHistory/deleteSearchHistoryItem/clearSearchHistory; SearchPage.tsx
 * records on a successful search of length >= 2). The Android port mirrors that server-backed model
 * rather than a local-only DataStore: recents sync across devices like the web, and removal targets
 * the server item id. (Spec §4.3 flagged the local DataStore design as a deviation and RECOMMENDED the
 * server-backed approach — this is the recorded decision; an offline-only cache is intentionally
 * out of scope for the flaky dev host since recents are non-critical.)
 *
 * History records are case-insensitively de-duplicated and capped at [MAX_RECENTS] locally so the UI
 * shows a stable, bounded most-recent-first list even if the server returns more. Blank queries and
 * queries shorter than [MIN_RECORD_LEN] are never recorded (web parity).
 */
interface SearchHistoryRepository {

    /** Most-recent-first recent searches (de-duped, capped at [MAX_RECENTS]); empty on any failure. */
    suspend fun recent(limit: Int = SearchApi.HISTORY_LIMIT): List<RecentSearch>

    /** Records a successful search. No-op for blank / too-short queries. Failures are swallowed. */
    suspend fun record(query: String, resultCount: Int)

    /** Removes one recent entry by its server item id. */
    suspend fun remove(id: String): ApiResult<Unit>

    /** Clears all recent searches. */
    suspend fun clear(): ApiResult<Unit>

    companion object {
        const val MAX_RECENTS = 10
        const val MIN_RECORD_LEN = 2
    }
}

@Singleton
class SearchHistoryRepositoryImpl @Inject constructor(
    private val api: SearchApi,
    private val errorParser: ApiErrorParser,
) : SearchHistoryRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun recent(limit: Int): List<RecentSearch> = withContext(io) {
        when (val raw = call { api.getHistory(limit = limit) }) {
            is ApiResult.Success -> raw.data.items
                .asSequence()
                .map { RecentSearch(id = it.id, query = it.query) }
                .filter { it.query.isNotBlank() }
                .distinctBy { it.query.trim().lowercase() } // keep first (most-recent) per query
                .take(SearchHistoryRepository.MAX_RECENTS)
                .toList()
            is ApiResult.Failure, is ApiResult.NetworkError -> emptyList()
        }
    }

    override suspend fun record(query: String, resultCount: Int) {
        val trimmed = query.trim()
        if (trimmed.length < SearchHistoryRepository.MIN_RECORD_LEN) return
        withContext(io) {
            call { api.recordHistory(RecordSearchHistoryReqDto(query = trimmed, resultCount = resultCount)) }
        }
    }

    override suspend fun remove(id: String): ApiResult<Unit> = withContext(io) {
        call { api.deleteHistoryItem(id) }.map { }
    }

    override suspend fun clear(): ApiResult<Unit> = withContext(io) {
        call { api.clearHistory() }.map { }
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
