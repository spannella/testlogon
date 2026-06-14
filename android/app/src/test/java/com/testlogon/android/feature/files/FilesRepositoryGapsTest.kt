package com.testlogon.android.feature.files

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.files.FileSearchDto
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.feature.files.data.FileSort
import com.testlogon.android.feature.files.data.FileSortBy
import com.testlogon.android.feature.files.data.FileSortDir
import com.testlogon.android.feature.files.data.FilesRepositoryImpl
import com.testlogon.android.feature.files.data.FolderRefreshBus
import com.testlogon.android.feature.files.data.SearchMode
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/**
 * AND-338 - additional [FilesRepositoryImpl] coverage beyond [FilesRepositorySearchTest] /
 * [FilesRepositoryCrudTest].
 *
 * These ADD: the client-side folders-first grouping for a NAME search; that a successful move signals
 * the FolderRefreshBus for BOTH the source parent and the destination; and that a transport IOException
 * folds into [ApiResult.NetworkError] (not Failure) for both search and CRUD. The shared [FakeFilesApi]
 * is reused (its read verbs already record args and its mutating verbs serve configurable results).
 *
 * ANTI-HANG: every call is a bounded suspend fn under runTest; bus signals are drained off a
 * backgroundScope collector (replay = 1 only keeps the last signal, so a collector is needed to see
 * BOTH move signals). No nested runTest; distinct fake-helper names.
 */
class FilesRepositoryGapsTest {

    private val parser = ApiErrorParser(Moshi.Builder().build())

    private fun repo(api: FakeFilesApi, bus: FolderRefreshBus = FolderRefreshBus()) =
        FilesRepositoryImpl(api = api, errorParser = parser, refreshBus = bus)

    /** An IOException-throwing closure for the NetworkError-folding cases. */
    private fun ioThrow(): () -> Throwable = { IOException("offline") }

    @Test
    fun search_foldersFirstNameSort_groupsFoldersBeforeFiles() = runTest {
        val api = FakeFilesApi(
            searchResult = {
                FileSearchDto(
                    prefix = "a",
                    results = listOf(
                        fileEntry("apple.txt"),
                        fileEntry("archive", path = "/archive", type = "folder"),
                        fileEntry("ant.txt"),
                    ),
                )
            },
        )
        val sort = FileSort(FileSortBy.NAME, FileSortDir.ASC, foldersFirst = true)
        val result = repo(api).search("a", SearchMode.PREFIX, sort)

        assertTrue(result is ApiResult.Success)
        val names = (result as ApiResult.Success).data.map { it.name }
        // the folder leads, then files in name-asc order.
        assertEquals(listOf("archive", "ant.txt", "apple.txt"), names)
    }

    @Test
    fun move_success_signalsRefreshBus_forSourceParentAndDestination() = runTest {
        val bus = FolderRefreshBus()
        val api = FakeFilesApi()

        val signals = mutableListOf<String>()
        val job = backgroundScope.launch { bus.refreshes.collect { signals += it } }
        runCurrent()

        // src under "/sub" moved to "/dst": both the source parent and the destination must be signalled.
        val result = repo(api, bus).move("/sub/a.txt", "/dst")
        runCurrent()

        assertTrue(result is ApiResult.Success)
        assertTrue(signals.contains("/sub"))
        assertTrue(signals.contains("/dst"))
        job.cancel()
    }

    @Test
    fun search_ioException_becomesNetworkError() = runTest {
        val api = FakeFilesApi(searchResult = { throw IOException("offline") })
        val result = repo(api).search("re", SearchMode.PREFIX, FileSort())
        assertTrue(result is ApiResult.NetworkError)
    }

    @Test
    fun crud_ioException_becomesNetworkError() = runTest {
        val api = FakeFilesApi().apply { crudError = ioThrow() }
        val result = repo(api).createFolder("/docs", "photos")
        assertTrue(result is ApiResult.NetworkError)
    }

    @Test
    fun createFolder_ioException_doesNotSignalRefreshBus() = runTest {
        val bus = FolderRefreshBus()
        val api = FakeFilesApi().apply { crudError = ioThrow() }

        val signals = mutableListOf<String>()
        val job = backgroundScope.launch { bus.refreshes.collect { signals += it } }
        runCurrent()

        val result = repo(api, bus).createFolder("/docs", "photos")
        runCurrent()

        assertTrue(result is ApiResult.NetworkError)
        assertTrue(signals.isEmpty())
        job.cancel()
    }

    @Test
    fun createFolder_success_mapsDtoToUnit() = runTest {
        val api = FakeFilesApi()
        val result = repo(api).createFolder("/docs", "photos")
        assertTrue(result is ApiResult.Success)
        // the AND-331 OkRespDto is mapped to Unit by the repository.
        assertEquals(Unit, (result as ApiResult.Success).data)
    }
}
