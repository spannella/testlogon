package com.testlogon.android.feature.files.data

import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.testlogon.android.core.model.files.FileNode
import com.testlogon.android.core.model.files.FileNodeType
import com.testlogon.android.core.network.files.FilesApi
import com.testlogon.android.core.network.files.toDomain
import kotlinx.coroutines.CancellationException
import retrofit2.HttpException
import java.io.IOException

/**
 * AND-332 - cursor-keyed Paging 3 source over the AND-331 [FilesApi] list endpoint for one
 * (path, sortBy, sortDir) browse view. Mirrors the AND-201 GalleryPagingSource / AND-096
 * ActivityPagingSource idiom.
 *
 * Keys are the opaque `cursor` Strings returned by the backend; the listing is forward-only
 * (prevKey null) and a null cursor terminates pagination (a single-page folder renders without an
 * append footer). The DTO is mapped to the domain via the AND-331 mapper (FileListDto.toDomain) before
 * use. HttpException / IOException become LoadResult.Error; CancellationException is re-thrown so
 * Paging cancellation works. getRefreshKey returns null (refresh re-anchors at the first page).
 *
 * FOLDERS-FIRST: when [foldersFirst] is set AND the sort is by NAME, each loaded page is locally
 * re-grouped so folders precede files (stable within each group). This is a per-page client-side
 * grouping toggle only; the server still applies the name asc-or-desc ordering. For the updated / size
 * sorts the server order is left untouched (grouping there would fight the requested ordering).
 *
 * ROOM CACHE DEFERRED: this is a NETWORK-backed PagingSource - there is no Room-backed stale-while-
 * revalidate cache and no RemoteMediator (no Room migration is introduced by this ticket). A Room SWR
 * cache for offline browse is intentionally DEFERRED to a later ticket.
 */
class FilesPagingSource(
    private val api: FilesApi,
    private val path: String,
    private val sortBy: FileSortBy,
    private val sortDir: FileSortDir,
    private val foldersFirst: Boolean,
) : PagingSource<String, FileNode>() {

    override suspend fun load(params: LoadParams<String>): LoadResult<String, FileNode> = try {
        val page = api.list(
            path = path,
            limit = params.loadSize,
            cursor = params.key,
            sortBy = sortBy.apiValue,
            sortDir = sortDir.apiValue,
        ).toDomain()
        LoadResult.Page(
            data = groupFoldersFirst(page.items),
            prevKey = null,
            nextKey = page.cursor,
        )
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        LoadResult.Error(e)
    } catch (e: IOException) {
        LoadResult.Error(e)
    }

    /** Folders-before-files re-grouping, applied only for the NAME sort with [foldersFirst] on. */
    private fun groupFoldersFirst(items: List<FileNode>): List<FileNode> {
        if (!foldersFirst || sortBy != FileSortBy.NAME) return items
        val (folders, rest) = items.partition { it.type == FileNodeType.FOLDER }
        return folders + rest
    }

    override fun getRefreshKey(state: PagingState<String, FileNode>): String? = null
}
