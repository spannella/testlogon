package com.testlogon.android.feature.files

import com.testlogon.android.core.model.files.CompleteUploadRequest
import com.testlogon.android.core.model.files.CreateFolderRequest
import com.testlogon.android.core.model.files.DeleteFolderDto
import com.testlogon.android.core.model.files.FileEntryDto
import com.testlogon.android.core.model.files.FileListDto
import com.testlogon.android.core.model.files.FileSearchDto
import com.testlogon.android.core.model.files.FileTextSearchDto
import com.testlogon.android.core.model.files.MoveRequest
import com.testlogon.android.core.model.files.MoveResultDto
import com.testlogon.android.core.model.files.OkRespDto
import com.testlogon.android.core.model.files.PresignRequest
import com.testlogon.android.core.model.files.PresignResponse
import com.testlogon.android.core.model.files.RenameRequest
import com.testlogon.android.core.network.files.FilesApi
import okhttp3.ResponseBody.Companion.toResponseBody
import retrofit2.Response

/** AND-332 - one captured argument set from a [FakeFilesApi.list] call. */
data class ListCall(
    val path: String,
    val limit: Int?,
    val cursor: String?,
    val sortBy: String?,
    val sortDir: String?,
)

/**
 * AND-332 - a hand-rolled fake [FilesApi] for the data-layer + paging-source unit tests. The read verbs
 * serve queued / configured results and record their arguments; the mutating verbs throw (this ticket is
 * read-only and never exercises them). Distinct name from any feature fake.
 */
class FakeFilesApi(
    private val listResult: () -> FileListDto = { FileListDto(path = "/", items = emptyList(), cursor = null) },
    private val searchResult: () -> FileSearchDto = { FileSearchDto(prefix = "", results = emptyList()) },
    private val searchTextResult: () -> FileTextSearchDto = { FileTextSearchDto(query = "", results = emptyList()) },
) : FilesApi {

    val listCalls = mutableListOf<ListCall>()
    val searchPrefixes = mutableListOf<String>()
    val searchTextQueries = mutableListOf<String>()

    // AND-337 - CRUD recording for the data-layer CRUD tests. Each verb records its body / path and
    // serves a configurable result; a configured throwable lets a test exercise the failure mapping.
    val createFolderBodies = mutableListOf<CreateFolderRequest>()
    val renameFileBodies = mutableListOf<RenameRequest>()
    val renameFolderBodies = mutableListOf<RenameRequest>()
    val moveBodies = mutableListOf<MoveRequest>()
    val deleteFilePaths = mutableListOf<String>()
    val deleteFolderPaths = mutableListOf<String>()
    var crudError: (() -> Throwable)? = null

    override suspend fun list(
        path: String,
        limit: Int?,
        cursor: String?,
        sortBy: String?,
        sortDir: String?,
    ): FileListDto {
        listCalls += ListCall(path, limit, cursor, sortBy, sortDir)
        return listResult()
    }

    override suspend fun info(path: String): FileEntryDto = error("unused in AND-332 tests")

    // AND-334 - download is unused by the AND-332 browse / search tests; trivial empty-body stub.
    override suspend fun download(path: String): Response<okhttp3.ResponseBody> =
        Response.success(ByteArray(0).toResponseBody())

    override suspend fun search(prefix: String, limit: Int): FileSearchDto {
        searchPrefixes += prefix
        return searchResult()
    }

    override suspend fun searchText(query: String, limit: Int): FileTextSearchDto {
        searchTextQueries += query
        return searchTextResult()
    }

    override suspend fun createFolder(body: CreateFolderRequest): OkRespDto {
        createFolderBodies += body
        crudError?.let { throw it() }
        return OkRespDto(ok = true, path = body.path)
    }

    override suspend fun renameFile(body: RenameRequest): MoveResultDto {
        renameFileBodies += body
        crudError?.let { throw it() }
        return MoveResultDto(ok = true, path = body.path, new_name = body.new_name)
    }

    override suspend fun renameFolder(body: RenameRequest): MoveResultDto {
        renameFolderBodies += body
        crudError?.let { throw it() }
        return MoveResultDto(ok = true, path = body.path, new_name = body.new_name)
    }

    override suspend fun move(body: MoveRequest): MoveResultDto {
        moveBodies += body
        crudError?.let { throw it() }
        return MoveResultDto(ok = true, src = body.src, dst = body.dst)
    }

    val copyBodies = mutableListOf<MoveRequest>()

    override suspend fun copy(body: MoveRequest): MoveResultDto {
        copyBodies += body
        crudError?.let { throw it() }
        return MoveResultDto(ok = true, src = body.src, dst = body.dst)
    }

    override suspend fun deleteFile(path: String): OkRespDto {
        deleteFilePaths += path
        crudError?.let { throw it() }
        return OkRespDto(ok = true, path = path)
    }

    override suspend fun deleteFolder(path: String): DeleteFolderDto {
        deleteFolderPaths += path
        crudError?.let { throw it() }
        return DeleteFolderDto(ok = true, deleted_count = 1)
    }
    override suspend fun presignUpload(body: PresignRequest): PresignResponse = error("read-only ticket")
    override suspend fun completeUpload(body: CompleteUploadRequest): FileEntryDto = error("read-only ticket")
}

/** Builds a wire [FileEntryDto] for tests (file by default; pass type = "folder" for a folder). */
fun fileEntry(
    name: String,
    path: String = "/$name",
    type: String = "file",
    size: Long? = if (type == "file") 100L else null,
    updatedAt: String? = null,
): FileEntryDto = FileEntryDto(
    name = name,
    path = path,
    type = type,
    size = size,
    updated_at = updatedAt,
)
