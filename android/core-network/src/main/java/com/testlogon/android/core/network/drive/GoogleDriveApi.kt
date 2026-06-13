package com.testlogon.android.core.network.drive

import com.testlogon.android.core.model.files.DriveCallbackReqDto
import com.testlogon.android.core.model.files.DriveConnectRespDto
import com.testlogon.android.core.model.files.DriveFilesRespDto
import com.testlogon.android.core.model.files.DriveImportReqDto
import com.testlogon.android.core.model.files.DriveImportRespDto
import com.testlogon.android.core.model.files.DriveStatusRespDto
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Query

/**
 * AND-336 - Retrofit interface for the BACKEND-MEDIATED Google Drive import surface (transport only).
 *
 * Every call hits TestLogon's OWN endpoints under ui/integrations/google-drive (NOT the Google APIs);
 * the backend performs the OAuth dance and proxies Drive server-side. Paths have NO leading slash
 * (relative to the shared Retrofit base URL, matching the rest of the codebase). Session cookies,
 * Authorization Bearer and X-CSRF-Token are attached by the core-network interceptors (the AUTHED
 * Retrofit) - the Drive picker is authenticated-only. All calls are suspend.
 *
 * Idempotency: status / connect / files are idempotent GETs. callback / import / disconnect are
 * NON-idempotent POSTs and are NOT auto-retried by the shared RetryInterceptor. A 422 surfaces as an
 * HttpException carrying the FastAPI detail body; 401 is handled globally by the SessionAuthenticator.
 *
 * NO Google SDK / Play Services / Credential Manager / androidx.browser is involved: the consent
 * auth_url from [connect] is opened with a plain ACTION_VIEW in the UI layer, and the app re-polls
 * [status] on return (the backend completes OAuth via its own redirect server-side).
 */
interface GoogleDriveApi {

    // ---- Reads (idempotent) ----

    @GET("ui/integrations/google-drive/status")
    suspend fun status(): DriveStatusRespDto

    @GET("ui/integrations/google-drive/connect")
    suspend fun connect(): DriveConnectRespDto

    @GET("ui/integrations/google-drive/files")
    suspend fun files(
        @Query("folder_id") folderId: String? = null,
        @Query("q") query: String? = null,
        @Query("page_token") pageToken: String? = null,
        @Query("page_size") pageSize: Int? = null,
    ): DriveFilesRespDto

    // ---- Mutations (non-idempotent) ----

    @Headers("Content-Type: application/json")
    @POST("ui/integrations/google-drive/callback")
    suspend fun callback(@Body body: DriveCallbackReqDto): DriveStatusRespDto

    @POST("ui/integrations/google-drive/disconnect")
    suspend fun disconnect(): Response<Unit>

    @Headers("Content-Type: application/json")
    @POST("ui/integrations/google-drive/import")
    suspend fun import(@Body body: DriveImportReqDto): DriveImportRespDto
}
