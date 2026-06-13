package com.testlogon.android.feature.files

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.files.FileSearchDto
import com.testlogon.android.core.model.files.FileTextSearchDto
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.feature.files.data.FileSort
import com.testlogon.android.feature.files.data.FileSortBy
import com.testlogon.android.feature.files.data.FileSortDir
import com.testlogon.android.feature.files.data.FilesRepositoryImpl
import com.testlogon.android.feature.files.data.FolderRefreshBus
import com.testlogon.android.feature.files.data.SearchMode
import kotlinx.coroutines.test.runTest
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import retrofit2.HttpException
import retrofit2.Response

/**
 * AND-332 - [FilesRepositoryImpl] search: the prefix + full-text surfaces map the DTO to domain and
 * sort CLIENT-SIDE per the supplied [FileSort]; a failure folds into an ApiResult error (never throws).
 */
class FilesRepositorySearchTest {

    private val parser = ApiErrorParser(Moshi.Builder().build())

    private fun repo(api: FakeFilesApi) =
        FilesRepositoryImpl(api = api, errorParser = parser, refreshBus = FolderRefreshBus())

    private val nameAsc = FileSort(FileSortBy.NAME, FileSortDir.ASC, foldersFirst = false)

    @Test
    fun prefixSearch_mapsAndSortsClientSide() = runTest {
        val api = FakeFilesApi(
            searchResult = {
                FileSearchDto(
                    prefix = "re",
                    results = listOf(fileEntry("report.txt"), fileEntry("readme.md")),
                )
            },
        )
        val result = repo(api).search("re", SearchMode.PREFIX, nameAsc)

        assertTrue(result is ApiResult.Success)
        val names = (result as ApiResult.Success).data.map { it.name }
        assertEquals(listOf("readme.md", "report.txt"), names) // sorted client-side by name asc
        assertEquals(listOf("re"), api.searchPrefixes)
    }

    @Test
    fun textSearch_usesSearchTextEndpoint() = runTest {
        val api = FakeFilesApi(
            searchTextResult = {
                FileTextSearchDto(query = "todo", results = listOf(fileEntry("notes.txt")))
            },
        )
        val result = repo(api).search("todo", SearchMode.TEXT, nameAsc)

        assertTrue(result is ApiResult.Success)
        assertEquals(listOf("notes.txt"), (result as ApiResult.Success).data.map { it.name })
        assertEquals(listOf("todo"), api.searchTextQueries)
        assertTrue(api.searchPrefixes.isEmpty())
    }

    @Test
    fun descSort_reversesClientSideOrder() = runTest {
        val api = FakeFilesApi(
            searchResult = {
                FileSearchDto(prefix = "a", results = listOf(fileEntry("apple"), fileEntry("zebra")))
            },
        )
        val sort = FileSort(FileSortBy.NAME, FileSortDir.DESC, foldersFirst = false)
        val result = repo(api).search("a", SearchMode.PREFIX, sort)

        assertEquals(listOf("zebra", "apple"), (result as ApiResult.Success).data.map { it.name })
    }

    @Test
    fun httpFailure_becomesApiResultFailure() = runTest {
        val api = FakeFilesApi(
            searchResult = {
                throw HttpException(
                    Response.error<FileSearchDto>(422, "bad".toResponseBody("text/plain".toMediaType())),
                )
            },
        )
        val result = repo(api).search("re", SearchMode.PREFIX, nameAsc)
        assertTrue(result is ApiResult.Failure)
    }
}
