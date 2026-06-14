package com.testlogon.android.feature.files.drive

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.files.DriveCallbackReqDto
import com.testlogon.android.core.model.files.DriveConnectRespDto
import com.testlogon.android.core.model.files.DriveFilesRespDto
import com.testlogon.android.core.model.files.DriveImportReqDto
import com.testlogon.android.core.model.files.DriveImportRespDto
import com.testlogon.android.core.model.files.DriveStatusRespDto
import com.testlogon.android.core.network.drive.GoogleDriveApi
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.feature.files.data.FolderRefreshBus
import com.testlogon.android.feature.files.drive.data.GoogleDriveRepositoryImpl
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import retrofit2.Response
import java.io.IOException

/**
 * AND-338 - additional [GoogleDriveRepositoryImpl] coverage beyond [GoogleDriveRepositoryTest].
 *
 * These ADD the verbs / error band the AND-336 wave left untested: connectUrl unwraps the auth_url;
 * disconnect maps the empty body to Unit; completeCallback forwards the captured code and maps the
 * resulting status; and a transport IOException folds into [ApiResult.NetworkError] (not Failure).
 * Distinct fake-helper name from the AND-336 FakeDriveApi.
 */
class GoogleDriveRepositoryGapsTest {

    private val parser = ApiErrorParser(Moshi.Builder().build())

    private fun repo(api: GapsDriveApi, bus: FolderRefreshBus = FolderRefreshBus()) =
        GoogleDriveRepositoryImpl(api = api, errorParser = parser, refreshBus = bus)

    /** A hand-rolled fake [GoogleDriveApi] with distinct name; throws [ioOnAll] to exercise NetworkError. */
    private class GapsDriveApi(
        private val connectResult: () -> DriveConnectRespDto = { DriveConnectRespDto(auth_url = "u") },
        private val statusResult: () -> DriveStatusRespDto = { DriveStatusRespDto(connected = true) },
        var ioOnStatus: Boolean = false,
    ) : GoogleDriveApi {
        val callbackBodies = mutableListOf<DriveCallbackReqDto>()
        var disconnectCalls = 0

        override suspend fun status(): DriveStatusRespDto {
            if (ioOnStatus) throw IOException("offline")
            return statusResult()
        }
        override suspend fun connect(): DriveConnectRespDto = connectResult()
        override suspend fun files(
            folderId: String?,
            query: String?,
            pageToken: String?,
            pageSize: Int?,
        ): DriveFilesRespDto = DriveFilesRespDto()

        override suspend fun callback(body: DriveCallbackReqDto): DriveStatusRespDto {
            callbackBodies += body
            return statusResult()
        }

        override suspend fun disconnect(): Response<Unit> {
            disconnectCalls++
            return Response.success(Unit)
        }

        override suspend fun import(body: DriveImportReqDto): DriveImportRespDto =
            DriveImportRespDto(ok = true)
    }

    @Test
    fun connectUrl_unwrapsAuthUrl() = runTest {
        val api = GapsDriveApi(connectResult = { DriveConnectRespDto(auth_url = "https://consent.example/x") })
        val result = repo(api).connectUrl()
        assertTrue(result is ApiResult.Success)
        assertEquals("https://consent.example/x", (result as ApiResult.Success).data)
    }

    @Test
    fun disconnect_mapsEmptyBodyToUnit() = runTest {
        val api = GapsDriveApi()
        val result = repo(api).disconnect()
        assertTrue(result is ApiResult.Success)
        assertEquals(Unit, (result as ApiResult.Success).data)
        assertEquals(1, api.disconnectCalls)
    }

    @Test
    fun completeCallback_forwardsCode_andMapsStatus() = runTest {
        val api = GapsDriveApi(statusResult = { DriveStatusRespDto(connected = true, email = "a@b.com") })
        val result = repo(api).completeCallback(code = "auth-code", state = "st")
        assertTrue(result is ApiResult.Success)
        assertTrue((result as ApiResult.Success).data.connected)
        assertEquals(DriveCallbackReqDto(code = "auth-code", state = "st"), api.callbackBodies.single())
    }

    @Test
    fun status_ioException_becomesNetworkError() = runTest {
        val api = GapsDriveApi(ioOnStatus = true)
        val result = repo(api).status()
        assertTrue(result is ApiResult.NetworkError)
    }
}
