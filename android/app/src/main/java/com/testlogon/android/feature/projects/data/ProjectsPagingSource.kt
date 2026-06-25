package com.testlogon.android.feature.projects.data

import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.testlogon.android.core.model.projects.Project
import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.network.projects.ProjectsApi
import kotlinx.coroutines.CancellationException
import retrofit2.HttpException
import java.io.IOException

/**
 * AND-374 - cursor-keyed Paging 3 source over [ProjectsApi.listProjects] (the caller's projects). Mirrors the
 * AND-372 TicketsPagingSource idiom (network-only, forward-only).
 *
 * Keys are the opaque `cursor` Strings returned by the backend (CORRECTED from next_cursor - spec §16 item 3);
 * the listing is forward-only (prevKey null) and a null / blank cursor terminates pagination. Each [ProjectOut]
 * is mapped to the domain [Project] before use. HttpException / IOException become LoadResult.Error;
 * CancellationException is re-thrown so Paging cancellation works. getRefreshKey returns null (pull-to-refresh
 * re-anchors at the first page).
 *
 * ROOM CACHE DEFERRED: this is a NETWORK-backed PagingSource - there is NO Room-backed cache and NO
 * RemoteMediator (no Room migration this wave; the spec's cache is DEFERRED to avoid a TestLogonDatabase
 * migration the read surface does not strictly need - the established AND-372 tickets pattern is followed).
 */
class ProjectsPagingSource(
    private val api: ProjectsApi,
    private val pageSize: Int,
) : PagingSource<String, Project>() {

    override suspend fun load(params: LoadParams<String>): LoadResult<String, Project> = try {
        val envelope = api.listProjects(cursor = params.key, limit = pageSize)
        LoadResult.Page(
            data = envelope.items.map { it.toDomain() },
            prevKey = null,
            nextKey = envelope.cursor?.takeIf { it.isNotBlank() },
        )
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        LoadResult.Error(e)
    } catch (e: JsonEncodingException) {
        // Malformed / contract-drifted response body (e.g. a missing required key) must surface as a
        // retryable error STATE, not an uncaught throw that crashes the Projects screen on open.
        LoadResult.Error(e)
    } catch (e: JsonDataException) {
        LoadResult.Error(e)
    } catch (e: IOException) {
        LoadResult.Error(e)
    }

    override fun getRefreshKey(state: PagingState<String, Project>): String? = null
}
