package com.testlogon.android.feature.files.drive.data

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.files.DriveCallbackReqDto
import com.testlogon.android.core.model.files.DriveImportReqDto
import com.testlogon.android.core.network.drive.GoogleDriveApi
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.feature.files.data.FolderRefreshBus
import com.testlogon.android.feature.files.drive.model.DriveFilesPage
import com.testlogon.android.feature.files.drive.model.DriveImportResult
import com.testlogon.android.feature.files.drive.model.DriveStatus
import com.testlogon.android.feature.files.drive.model.toDomain
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
 * AND-336 - data layer for the BACKEND-MEDIATED Google Drive import surface, over the [GoogleDriveApi]
 * (TestLogon's own ui/integrations/google-drive endpoints on the AUTHED Retrofit).
 *
 * Every method maps the wire DTO to a domain type BEFORE folding into a typed [ApiResult] (mirroring the
 * AND-332 FilesRepository call{} / errorParser idiom). On a successful import the repo signals
 * [FolderRefreshBus] for the TestLogon target folder so the AND-332 browse listing re-pages without a
 * manual reload (reusing the AND-333 refresh seam - the file DTOs / upload path are NOT touched).
 *
 * NO Google SDK / Play Services is involved: the consent auth_url is opened externally by the UI and the
 * caller re-polls [status] on return (the backend completes OAuth server-side). The import byte transfer
 * is server-side too, so the client never downloads / re-uploads.
 *
 * An interface (bound to [GoogleDriveRepositoryImpl] in the data module) keeps the VM test fake-able,
 * mirroring the AND-332 FilesRepository idiom.
 */
interface GoogleDriveRepository {
    suspend fun status(): ApiResult<DriveStatus>
    suspend fun connectUrl(): ApiResult<String>
    suspend fun completeCallback(code: String, state: String? = null): ApiResult<DriveStatus>
    suspend fun disconnect(): ApiResult<Unit>
    suspend fun listFiles(
        folderId: String? = null,
        query: String? = null,
        pageToken: String? = null,
    ): ApiResult<DriveFilesPage>
    suspend fun import(fileId: String, targetFolderPath: String? = null): ApiResult<DriveImportResult>
}

@Singleton
class GoogleDriveRepositoryImpl @Inject constructor(
    private val api: GoogleDriveApi,
    private val errorParser: ApiErrorParser,
    private val refreshBus: FolderRefreshBus,
) : GoogleDriveRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    /** Current connection state of the Drive integration. */
    override suspend fun status(): ApiResult<DriveStatus> = withContext(io) {
        call { api.status().toDomain() }
    }

    /** The OAuth consent URL to open externally (the backend completes the redirect server-side). */
    override suspend fun connectUrl(): ApiResult<String> = withContext(io) {
        call { api.connect().auth_url }
    }

    /**
     * SECONDARY path only: forwards a captured OAuth [code] (+ optional [state]) to the backend. The
     * PRIMARY flow needs no code capture - the backend redirect completes OAuth and the app re-polls
     * [status]. Returns the resulting status.
     */
    override suspend fun completeCallback(code: String, state: String?): ApiResult<DriveStatus> =
        withContext(io) {
            call { api.callback(DriveCallbackReqDto(code = code, state = state)).toDomain() }
        }

    /** Disconnects the Drive integration (empty 200 body -> Response<Unit>). */
    override suspend fun disconnect(): ApiResult<Unit> = withContext(io) {
        call { api.disconnect(); Unit }
    }

    /** Lists Drive entries under [folderId] (root when null), optionally filtered by [query]. */
    override suspend fun listFiles(
        folderId: String?,
        query: String?,
        pageToken: String?,
    ): ApiResult<DriveFilesPage> = withContext(io) {
        call { api.files(folderId = folderId, query = query, pageToken = pageToken).toDomain() }
    }

    /**
     * Imports the Drive file [fileId] into the TestLogon [targetFolderPath] (the backend transfers the
     * bytes server-side). On success, signals [FolderRefreshBus] for the target so the browse listing
     * re-pages. The non-idempotent import is NOT auto-retried (the double-send guard lives in the VM).
     */
    override suspend fun import(fileId: String, targetFolderPath: String?): ApiResult<DriveImportResult> =
        withContext(io) {
            val result = call {
                api.import(DriveImportReqDto(file_id = fileId, folder_id = targetFolderPath)).toDomain()
            }
            if (result is ApiResult.Success && result.data.ok && targetFolderPath != null) {
                refreshBus.signal(targetFolderPath)
            }
            result
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
