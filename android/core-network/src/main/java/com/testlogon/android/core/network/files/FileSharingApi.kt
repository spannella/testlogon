package com.testlogon.android.core.network.files

import com.testlogon.android.core.model.files.FileEntryDto
import com.testlogon.android.core.model.files.OkRespDto
import com.testlogon.android.core.model.files.ShareFileRequest
import com.testlogon.android.core.model.files.SharedListDto
import com.testlogon.android.core.model.files.SharedWithDto
import com.testlogon.android.core.model.files.SharedWithMeDto
import com.testlogon.android.core.model.files.UnshareFileRequest
import com.testlogon.android.core.model.files.UploadArchiveResultDto
import com.testlogon.android.core.model.files.UsageDailyDto
import com.testlogon.android.core.model.files.UsageStorageDto
import okhttp3.MultipartBody
import okhttp3.ResponseBody
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.Multipart
import retrofit2.http.POST
import retrofit2.http.Part
import retrofit2.http.Query
import retrofit2.http.Streaming

/**
 * FM-SHARE - Retrofit interface for the USER-TO-USER file sharing, archive (zip) and storage-usage
 * endpoints of the `v1/fs` file-manager router (transport only). This is the direct-share sibling of the
 * AND-331 [FilesApi] (path-addressed CRUD) and the AND-335 FileShareLinksApi (public share LINKS); it is
 * kept as its own interface so the existing FilesApi fakes are untouched.
 *
 * Paths have NO leading slash (relative to the shared Retrofit base URL). All calls are suspend. Session
 * cookies, Authorization Bearer and X-CSRF-Token are attached by the core-network interceptors. The
 * GETs (shared-with / shared-with-me / shared-list / shared-info / usage-daily / usage-storage) are
 * idempotent; the POSTs (share / unshare / upload-archive / download-zip) are NOT auto-retried.
 *
 * DEGRADE-ON-404: these surfaces may be disabled per-deployment; a 404/403 surfaces as an HttpException
 * that the repository maps to a "feature unavailable" state (it never crashes the browse surface). A 422
 * carries the FastAPI detail body; 401 is handled globally by the SessionAuthenticator.
 */
interface FileSharingApi {

    // ---- Direct share mutations (non-idempotent) ----

    /** POST v1/fs/share -> { ok } : grant [ShareFileRequest.to_user] access to a node. */
    @Headers("Content-Type: application/json")
    @POST("v1/fs/share")
    suspend fun share(@Body body: ShareFileRequest): OkRespDto

    /** POST v1/fs/unshare -> { ok } : revoke a recipient's access. */
    @Headers("Content-Type: application/json")
    @POST("v1/fs/unshare")
    suspend fun unshare(@Body body: UnshareFileRequest): OkRespDto

    // ---- Share reads (idempotent) ----

    /** GET v1/fs/shared-with : who a node the CALLER owns is shared with. */
    @GET("v1/fs/shared-with")
    suspend fun sharedWith(@Query("path") path: String): SharedWithDto

    /** GET v1/fs/shared-with-me : nodes OTHER users have shared with the caller. */
    @GET("v1/fs/shared-with-me")
    suspend fun sharedWithMe(): SharedWithMeDto

    /** GET v1/fs/shared-list : page a folder inside a share the caller has access to. */
    @GET("v1/fs/shared-list")
    suspend fun sharedList(
        @Query("owner") owner: String,
        @Query("path") path: String = "/",
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
        @Query("sort_by") sortBy: String? = null,
        @Query("sort_dir") sortDir: String? = null,
    ): SharedListDto

    /** GET v1/fs/shared-info : metadata for a single shared node. */
    @GET("v1/fs/shared-info")
    suspend fun sharedInfo(
        @Query("owner") owner: String,
        @Query("path") path: String,
    ): FileEntryDto

    /**
     * GET v1/fs/shared-download : streamed authenticated download of a node shared WITH the caller. The
     * caller treats the [ResponseBody] as opaque bytes and copies [ResponseBody.byteStream] to disk in
     * chunks (Content-Length may be absent). Mirrors [FilesApi.download].
     */
    @Streaming
    @GET("v1/fs/shared-download")
    suspend fun sharedDownload(
        @Query("owner") owner: String,
        @Query("path") path: String,
    ): Response<ResponseBody>

    // ---- Archive (zip) ----

    /**
     * POST v1/fs/upload-archive : upload a zip/archive that the backend extracts into [destFolder]
     * (query). The single file part is named `archive_file`. Returns the created node paths + count.
     */
    @Multipart
    @POST("v1/fs/upload-archive")
    suspend fun uploadArchive(
        @Query("dest_folder") destFolder: String,
        @Part archiveFile: MultipartBody.Part,
    ): UploadArchiveResultDto

    /**
     * POST v1/fs/download-zip : bundle the given [paths] into a streamed zip (application/zip). The body
     * is a RAW JSON array of path strings (the FastAPI route binds `paths: List[str] = Body(...)`, NOT a
     * wrapping object). Treated as opaque bytes; @Streaming so Retrofit does not buffer the whole zip.
     */
    @Streaming
    @Headers("Content-Type: application/json")
    @POST("v1/fs/download-zip")
    suspend fun downloadZip(@Body paths: List<String>): Response<ResponseBody>

    // ---- Storage usage (idempotent) ----

    /** GET v1/fs/usage/daily : per-day upload/download/storage rows within an optional [from]/[to] range. */
    @GET("v1/fs/usage/daily")
    suspend fun usageDaily(
        @Query("from") from: String? = null,
        @Query("to") to: String? = null,
    ): UsageDailyDto

    /** GET v1/fs/usage/storage : current total storage + the heaviest [topN] files. */
    @GET("v1/fs/usage/storage")
    suspend fun usageStorage(@Query("top_n") topN: Int? = null): UsageStorageDto

    companion object {
        /** Retrofit part name the backend expects for the archive upload. */
        const val ARCHIVE_PART_NAME = "archive_file"
    }
}
