package com.testlogon.android.feature.files

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.files.OkRespDto
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.feature.files.data.FilesRepositoryImpl
import com.testlogon.android.feature.files.data.FolderRefreshBus
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import retrofit2.HttpException
import retrofit2.Response

/**
 * AND-337 - [FilesRepositoryImpl] folder CRUD: each verb reuses the AND-331 [FilesApi] CRUD method with
 * the right body / path, maps the DTO to [ApiResult.Success] (Unit) on a 2xx, folds an HTTP error into
 * [ApiResult.Failure], and signals [FolderRefreshBus] for the affected folder on success.
 */
class FilesRepositoryCrudTest {

    private val parser = ApiErrorParser(Moshi.Builder().build())

    private fun repo(api: FakeFilesApi, bus: FolderRefreshBus = FolderRefreshBus()) =
        FilesRepositoryImpl(api = api, errorParser = parser, refreshBus = bus)

    private fun httpError(): () -> Throwable = {
        HttpException(Response.error<OkRespDto>(422, "bad".toResponseBody("text/plain".toMediaType())))
    }

    @Test
    fun createFolder_joinsParentAndName_andMapsToSuccess() = runTest {
        val api = FakeFilesApi()
        val result = repo(api).createFolder("/docs", "photos")

        assertTrue(result is ApiResult.Success)
        assertEquals(listOf("/docs/photos"), api.createFolderBodies.map { it.path })
    }

    @Test
    fun renameFile_vsRenameFolder_routeByFlag() = runTest {
        val api = FakeFilesApi()
        val r = repo(api)

        assertTrue(r.rename("/a.txt", "b.txt", isFolder = false) is ApiResult.Success)
        assertTrue(r.rename("/dir", "dir2", isFolder = true) is ApiResult.Success)

        assertEquals(listOf("/a.txt" to "b.txt"), api.renameFileBodies.map { it.path to it.new_name })
        assertEquals(listOf("/dir" to "dir2"), api.renameFolderBodies.map { it.path to it.new_name })
    }

    @Test
    fun deleteFile_vsDeleteFolder_routeByFlag() = runTest {
        val api = FakeFilesApi()
        val r = repo(api)

        assertTrue(r.delete("/a.txt", isFolder = false) is ApiResult.Success)
        assertTrue(r.delete("/dir", isFolder = true) is ApiResult.Success)

        assertEquals(listOf("/a.txt"), api.deleteFilePaths)
        assertEquals(listOf("/dir"), api.deleteFolderPaths)
    }

    @Test
    fun move_passesSrcAndDst() = runTest {
        val api = FakeFilesApi()
        val result = repo(api).move("/a.txt", "/dst")

        assertTrue(result is ApiResult.Success)
        assertEquals(listOf("/a.txt" to "/dst"), api.moveBodies.map { it.src to it.dst })
    }

    @Test
    fun httpFailure_becomesApiResultFailure() = runTest {
        val api = FakeFilesApi().apply { crudError = httpError() }
        val result = repo(api).createFolder("/docs", "photos")
        assertTrue(result is ApiResult.Failure)
    }

    @Test
    fun success_signalsRefreshBusForParentFolder() = runTest {
        val bus = FolderRefreshBus()
        val api = FakeFilesApi()

        repo(api, bus).createFolder("/docs", "photos")

        // The bus replays its last signal; the affected (parent) folder must be the on-screen one.
        assertEquals("/docs", bus.refreshes.first())
    }

    @Test
    fun failure_doesNotSignalRefreshBus() = runTest {
        val bus = FolderRefreshBus()
        val api = FakeFilesApi().apply { crudError = httpError() }

        val result = repo(api, bus).delete("/a.txt", isFolder = false)
        assertTrue(result is ApiResult.Failure)
    }
}
