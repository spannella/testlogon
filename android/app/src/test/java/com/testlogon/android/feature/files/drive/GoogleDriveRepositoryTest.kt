package com.testlogon.android.feature.files.drive

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.files.DriveCallbackReqDto
import com.testlogon.android.core.model.files.DriveConnectRespDto
import com.testlogon.android.core.model.files.DriveFileDto
import com.testlogon.android.core.model.files.DriveFilesRespDto
import com.testlogon.android.core.model.files.DriveImportReqDto
import com.testlogon.android.core.model.files.DriveImportRespDto
import com.testlogon.android.core.model.files.DriveStatusRespDto
import com.testlogon.android.core.network.drive.GoogleDriveApi
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.feature.files.data.FolderRefreshBus
import com.testlogon.android.feature.files.drive.data.GoogleDriveRepositoryImpl
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import retrofit2.HttpException
import retrofit2.Response

/**
 * AND-336 - [GoogleDriveRepository] tests over a hand-rolled fake [GoogleDriveApi]: status / list /
 * import map DTO to domain; a successful import signals [FolderRefreshBus] for the target; failures fold
 * into an ApiResult error (never throws). Distinct fake-helper names from any other feature fake.
 */
class GoogleDriveRepositoryTest {

    private val parser = ApiErrorParser(Moshi.Builder().build())

    private fun repo(api: FakeDriveApi, bus: FolderRefreshBus = FolderRefreshBus()) =
        GoogleDriveRepositoryImpl(api = api, errorParser = parser, refreshBus = bus)

    /** A hand-rolled fake [GoogleDriveApi] serving configured results + recording arguments. */
    private class FakeDriveApi(
        private val statusResult: () -> DriveStatusRespDto = { DriveStatusRespDto(connected = false) },
        private val connectResult: () -> DriveConnectRespDto = { DriveConnectRespDto(auth_url = "u") },
        private val filesResult: () -> DriveFilesRespDto = { DriveFilesRespDto() },
        private val importResult: () -> DriveImportRespDto = { DriveImportRespDto(ok = true) },
    ) : GoogleDriveApi {
        val importBodies = mutableListOf<DriveImportReqDto>()
        val fileQueries = mutableListOf<Pair<String?, String?>>()

        override suspend fun status(): DriveStatusRespDto = statusResult()
        override suspend fun connect(): DriveConnectRespDto = connectResult()
        override suspend fun files(
            folderId: String?,
            query: String?,
            pageToken: String?,
            pageSize: Int?,
        ): DriveFilesRespDto {
            fileQueries += folderId to query
            return filesResult()
        }

        override suspend fun callback(body: DriveCallbackReqDto): DriveStatusRespDto = statusResult()
        override suspend fun disconnect(): Response<Unit> = Response.success(Unit)
        override suspend fun import(body: DriveImportReqDto): DriveImportRespDto {
            importBodies += body
            return importResult()
        }
    }

    private fun http422(): Nothing = throw HttpException(
        Response.error<Any>(422, "bad".toResponseBody("text/plain".toMediaType())),
    )

    @Test
    fun status_mapsConnectedToDomain() = runTest {
        val api = FakeDriveApi(statusResult = { DriveStatusRespDto(connected = true, email = "a@b.com") })
        val result = repo(api).status()
        assertTrue(result is ApiResult.Success)
        val status = (result as ApiResult.Success).data
        assertTrue(status.connected)
        assertEquals("a@b.com", status.email)
    }

    @Test
    fun listFiles_mapsAndDerivesFolderFlag() = runTest {
        val api = FakeDriveApi(
            filesResult = {
                DriveFilesRespDto(
                    files = listOf(
                        DriveFileDto(id = "1", name = "Reports", is_folder = true),
                        DriveFileDto(id = "2", name = "Photos", mime_type = "application/vnd.google-apps.folder"),
                        DriveFileDto(id = "3", name = "a.txt", mime_type = "text/plain", size = 10L),
                    ),
                    next_page_token = "n1",
                )
            },
        )
        val result = repo(api).listFiles(folderId = "fld", query = "rep")
        assertTrue(result is ApiResult.Success)
        val page = (result as ApiResult.Success).data
        assertEquals("n1", page.nextPageToken)
        assertTrue(page.files[0].isFolder)
        assertTrue(page.files[1].isFolder) // mime discriminator
        assertFalse(page.files[2].isFolder)
        assertEquals(10L, page.files[2].sizeBytes)
        assertEquals("fld" to "rep", api.fileQueries.single())
    }

    @Test
    fun import_success_signalsRefreshBusForTarget() = runTest {
        val bus = FolderRefreshBus()
        val api = FakeDriveApi(importResult = { DriveImportRespDto(ok = true, path = "/docs/x") })

        val result = repo(api, bus).import(fileId = "file_1", targetFolderPath = "/docs")

        assertTrue(result is ApiResult.Success)
        assertEquals("/docs/x", (result as ApiResult.Success).data.path)
        assertEquals(DriveImportReqDto(file_id = "file_1", folder_id = "/docs"), api.importBodies.single())
        // The bus replays the most recent signal (replay = 1) to a late collector.
        assertEquals("/docs", bus.refreshes.first())
    }

    @Test
    fun import_success_noTarget_doesNotSignal() = runTest {
        val api = FakeDriveApi(importResult = { DriveImportRespDto(ok = true) })
        val result = repo(api).import(fileId = "file_1", targetFolderPath = null)
        assertTrue(result is ApiResult.Success)
        assertNull(api.importBodies.single().folder_id)
    }

    @Test
    fun import_httpFailure_becomesApiResultFailure() = runTest {
        val api = FakeDriveApi(importResult = { http422() })
        val result = repo(api).import(fileId = "bad", targetFolderPath = "/docs")
        assertTrue(result is ApiResult.Failure)
    }

    @Test
    fun status_httpFailure_becomesApiResultFailure() = runTest {
        val api = FakeDriveApi(statusResult = { http422() })
        val result = repo(api).status()
        assertTrue(result is ApiResult.Failure)
    }
}
