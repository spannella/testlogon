package com.testlogon.android.feature.files

import androidx.paging.PagingSource
import com.testlogon.android.core.model.files.FileListDto
import com.testlogon.android.core.model.files.FileNodeType
import com.testlogon.android.feature.files.data.FileSortBy
import com.testlogon.android.feature.files.data.FileSortDir
import com.testlogon.android.feature.files.data.FilesPagingSource
import kotlinx.coroutines.test.runTest
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import retrofit2.HttpException
import retrofit2.Response
import java.io.IOException

/**
 * AND-332 - direct [FilesPagingSource].load() assertions against a [FakeFilesApi]: a page maps the DTO
 * to domain with nextKey = cursor (and nextKey = null on the last page); HttpException / IOException
 * become LoadResult.Error; the folders-first toggle re-groups the NAME sort.
 */
class FilesPagingSourceTest {

    private fun source(
        api: FakeFilesApi,
        sortBy: FileSortBy = FileSortBy.NAME,
        sortDir: FileSortDir = FileSortDir.ASC,
        foldersFirst: Boolean = false,
    ) = FilesPagingSource(api, path = "/", sortBy = sortBy, sortDir = sortDir, foldersFirst = foldersFirst)

    @Test
    fun refresh_returnsPage_withNextKeyFromCursor() = runTest {
        val api = FakeFilesApi(
            listResult = {
                FileListDto(
                    path = "/",
                    items = listOf(fileEntry("a.txt"), fileEntry("b.txt")),
                    cursor = "c2",
                )
            },
        )
        val result = source(api).load(PagingSource.LoadParams.Refresh(null, 50, false))

        assertTrue(result is PagingSource.LoadResult.Page)
        val page = result as PagingSource.LoadResult.Page
        assertEquals(listOf("a.txt", "b.txt"), page.data.map { it.name })
        assertNull(page.prevKey)
        assertEquals("c2", page.nextKey)
        // The list endpoint received the path + sort params verbatim.
        assertEquals("/", api.listCalls.single().path)
        assertEquals("name", api.listCalls.single().sortBy)
        assertEquals("asc", api.listCalls.single().sortDir)
    }

    @Test
    fun lastPage_hasNullNextKey() = runTest {
        val api = FakeFilesApi(
            listResult = { FileListDto(path = "/", items = listOf(fileEntry("z.txt")), cursor = null) },
        )
        val result = source(api).load(PagingSource.LoadParams.Append("c2", 50, false))

        assertTrue(result is PagingSource.LoadResult.Page)
        val page = result as PagingSource.LoadResult.Page
        assertNull(page.nextKey) // end of pagination
    }

    @Test
    fun foldersFirst_groupsFoldersAheadOfFiles_forNameSort() = runTest {
        val api = FakeFilesApi(
            listResult = {
                FileListDto(
                    path = "/",
                    items = listOf(
                        fileEntry("a.txt"),
                        fileEntry("docs", path = "/docs", type = "folder"),
                        fileEntry("b.txt"),
                    ),
                    cursor = null,
                )
            },
        )
        val page = source(api, foldersFirst = true).load(
            PagingSource.LoadParams.Refresh(null, 50, false),
        ) as PagingSource.LoadResult.Page

        assertEquals(FileNodeType.FOLDER, page.data.first().type)
        assertEquals(listOf("docs", "a.txt", "b.txt"), page.data.map { it.name })
    }

    @Test
    fun httpException_becomesLoadResultError() = runTest {
        val api = FakeFilesApi(
            listResult = {
                throw HttpException(
                    Response.error<FileListDto>(500, "boom".toResponseBody("text/plain".toMediaType())),
                )
            },
        )
        val result = source(api).load(PagingSource.LoadParams.Refresh(null, 50, false))
        assertTrue(result is PagingSource.LoadResult.Error)
    }

    @Test
    fun ioException_becomesLoadResultError() = runTest {
        val api = FakeFilesApi(listResult = { throw IOException("offline") })
        val result = source(api).load(PagingSource.LoadParams.Refresh(null, 50, false))
        assertTrue(result is PagingSource.LoadResult.Error)
    }
}
