package com.testlogon.android.feature.files.data

import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.files.FileNode
import com.testlogon.android.core.model.files.FileNodeType
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.files.FilesApi
import com.testlogon.android.core.network.files.toDomain
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/** AND-332 - which search surface a query targets: filename prefix vs. file-content full text. */
enum class SearchMode { PREFIX, TEXT }

/**
 * AND-332 - read-only data layer for the file-manager browse surface, over the AND-331 [FilesApi].
 *
 * BROWSE is Paging 3: [pagedFolder] wraps [FilesPagingSource] (network-backed) in a [Pager] for the
 * given (path, sort). SEARCH is NON-paginated: the AND-331 search / search-text endpoints return a
 * bounded list (no cursor, no server sort params), so [search] maps the DTO to domain and sorts
 * CLIENT-SIDE per the supplied [FileSort]. Browse DTOs are mapped to domain inside the PagingSource;
 * search DTOs are mapped here. This ticket performs NO mutations (upload / CRUD are AND-333+).
 *
 * ROOM CACHE DEFERRED: there is intentionally NO Room-backed stale-while-revalidate cache and NO Room
 * migration in this ticket - browse is served straight from the network PagingSource. A Room SWR cache
 * for offline browse is DEFERRED to a later ticket.
 */
interface FilesRepository {

    /**
     * A cold [PagingData] stream for browsing [path] under [sort]. Re-collect (or re-create via the VM's
     * trigger) to refresh. The factory builds a fresh [FilesPagingSource] each time, so invalidating /
     * re-collecting re-anchors at the first page (the [invalidateFolder] seam for AND-333).
     */
    fun pagedFolder(path: String, sort: FileSort): Flow<PagingData<FileNode>>

    /**
     * One bounded, non-paginated search over [query] using [mode] (prefix vs. full text), mapped to
     * domain and sorted CLIENT-SIDE per [sort]. Failures fold into [ApiResult.Failure] /
     * [ApiResult.NetworkError]; the call never throws (CancellationException re-thrown).
     */
    suspend fun search(query: String, mode: SearchMode, sort: FileSort): ApiResult<List<FileNode>>

    companion object {
        const val PAGE_SIZE = 50
        const val SEARCH_LIMIT = 50
    }
}

@Singleton
class FilesRepositoryImpl @Inject constructor(
    private val api: FilesApi,
    private val errorParser: ApiErrorParser,
) : FilesRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override fun pagedFolder(path: String, sort: FileSort): Flow<PagingData<FileNode>> =
        Pager(
            config = PagingConfig(
                pageSize = FilesRepository.PAGE_SIZE,
                initialLoadSize = FilesRepository.PAGE_SIZE,
                prefetchDistance = PREFETCH_DISTANCE,
                enablePlaceholders = false,
            ),
            pagingSourceFactory = {
                FilesPagingSource(
                    api = api,
                    path = path,
                    sortBy = sort.sortBy,
                    sortDir = sort.sortDir,
                    foldersFirst = sort.foldersFirst,
                )
            },
        ).flow

    override suspend fun search(
        query: String,
        mode: SearchMode,
        sort: FileSort,
    ): ApiResult<List<FileNode>> = withContext(io) {
        call {
            val nodes = when (mode) {
                SearchMode.PREFIX ->
                    api.search(prefix = query, limit = FilesRepository.SEARCH_LIMIT).toDomain().results
                SearchMode.TEXT ->
                    api.searchText(query = query, limit = FilesRepository.SEARCH_LIMIT).toDomain().results
            }
            sortClientSide(nodes, sort)
        }
    }

    /** Client-side sort of bounded search results (the search endpoints take no server sort params). */
    private fun sortClientSide(nodes: List<FileNode>, sort: FileSort): List<FileNode> {
        val base: Comparator<FileNode> = when (sort.sortBy) {
            FileSortBy.NAME -> compareBy(String.CASE_INSENSITIVE_ORDER) { it.name }
            FileSortBy.UPDATED -> compareBy(nullsFirst()) { it.updatedAt }
            FileSortBy.SIZE -> compareBy(nullsFirst()) { it.sizeBytes }
        }
        val directed = if (sort.sortDir == FileSortDir.DESC) base.reversed() else base
        val comparator = if (sort.foldersFirst && sort.sortBy == FileSortBy.NAME) {
            // Folders before files, then the directed name order within each group.
            compareByDescending<FileNode> { it.type == FileNodeType.FOLDER }.then(directed)
        } else {
            directed
        }
        return nodes.sortedWith(comparator)
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

    private companion object {
        const val PREFETCH_DISTANCE = 12
    }
}
