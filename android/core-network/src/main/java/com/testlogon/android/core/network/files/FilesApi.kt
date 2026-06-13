package com.testlogon.android.core.network.files

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
import okhttp3.ResponseBody
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Query
import retrofit2.http.Streaming

/**
 * AND-331 - Retrofit interface for the path-addressed file-manager surface (transport only).
 *
 * Paths have NO leading slash (relative to the shared Retrofit base URL, matching the rest of the
 * codebase). Entries are addressed by their `path` query/body parameter (NOT by an opaque id); the path
 * VALUE itself uses leading-slash directory notation as the backend expects. All calls are suspend.
 * Mutating verbs carry an explicit JSON Content-Type. Session cookies, Authorization Bearer and
 * X-CSRF-Token are attached by the core-network interceptors.
 *
 * Idempotency: the GETs (list / info / search / search-text) are idempotent. The mutating verbs (POST
 * folder / rename / move / presign / complete, DELETE file / folder) are NON-idempotent and are NOT
 * auto-retried by the shared RetryInterceptor. A 422 surfaces as an HttpException carrying the FastAPI
 * detail body; 401 is handled globally by the SessionAuthenticator.
 *
 * PRESIGN NOTE: presignUpload / completeUpload only DECLARE the typed endpoints here. The actual byte
 * PUT to the signed URL (and any reuse of the existing :app uploader) is AND-333's job. The Presign DTOs
 * are this ticket's own types in core-model (core-network must not depend on :app).
 */
interface FilesApi {

    // ---- Reads (idempotent) ----

    @GET("v1/fs/list")
    suspend fun list(
        @Query("path") path: String = "/",
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
        @Query("sort_by") sortBy: String? = null,
        @Query("sort_dir") sortDir: String? = null,
    ): FileListDto

    @GET("v1/fs/info")
    suspend fun info(@Query("path") path: String): FileEntryDto

    /**
     * AND-334 - streamed authenticated download of the file at [path]. The endpoint advertises an
     * application/json content-type but returns the raw file bytes, so the caller treats the
     * [ResponseBody] as opaque bytes (NOT JSON). @Streaming means Retrofit does NOT buffer the whole
     * body into memory; the caller copies [ResponseBody.byteStream] to disk in chunks on an IO
     * dispatcher. Content-Length may be absent (the download progress total is therefore nullable).
     * Documented errors are 400/401/403/422/429 (no 404/5xx); 401 is handled globally by the
     * SessionAuthenticator. Range/resume is NOT used (restart-from-0 only).
     */
    @Streaming
    @GET("v1/fs/download")
    suspend fun download(@Query("path") path: String): Response<ResponseBody>

    @GET("v1/fs/search")
    suspend fun search(
        @Query("prefix") prefix: String,
        @Query("limit") limit: Int = 50,
    ): FileSearchDto

    @GET("v1/fs/search-text")
    suspend fun searchText(
        @Query("q") query: String,
        @Query("limit") limit: Int = 50,
    ): FileTextSearchDto

    // ---- Mutations (non-idempotent) ----

    @Headers("Content-Type: application/json")
    @POST("v1/fs/folder")
    suspend fun createFolder(@Body body: CreateFolderRequest): OkRespDto

    @Headers("Content-Type: application/json")
    @POST("v1/fs/rename-file")
    suspend fun renameFile(@Body body: RenameRequest): MoveResultDto

    @Headers("Content-Type: application/json")
    @POST("v1/fs/rename-folder")
    suspend fun renameFolder(@Body body: RenameRequest): MoveResultDto

    @Headers("Content-Type: application/json")
    @POST("v1/fs/move")
    suspend fun move(@Body body: MoveRequest): MoveResultDto

    @DELETE("v1/fs/file")
    suspend fun deleteFile(@Query("path") path: String): OkRespDto

    @DELETE("v1/fs/folder")
    suspend fun deleteFolder(@Query("path") path: String): DeleteFolderDto

    // ---- Upload control plane (typed declarations only; byte PUT is AND-333) ----

    @Headers("Content-Type: application/json")
    @POST("v1/fs/presign-upload")
    suspend fun presignUpload(@Body body: PresignRequest): PresignResponse

    @Headers("Content-Type: application/json")
    @POST("v1/fs/complete-upload")
    suspend fun completeUpload(@Body body: CompleteUploadRequest): FileEntryDto
}
