package com.testlogon.android.core.network.files

import com.testlogon.android.core.model.files.DeleteFileMountDto
import com.testlogon.android.core.model.files.FileMountCreateRequest
import com.testlogon.android.core.model.files.FileMountDto
import com.testlogon.android.core.model.files.FileMountUpdateRequest
import com.testlogon.android.core.model.files.FileMountsListDto
import com.testlogon.android.core.model.files.ValidateFileMountDto
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * FM-MOUNTS - Retrofit interface for the file-manager S3 mount CRUD surface (transport only), kept
 * SEPARATE from [FilesApi] on purpose: mounts are a distinct storage-provider concern and a separate
 * interface avoids widening [FilesApi] (which has four fake implementers in the test tree). Mirrors the
 * web contract in frontend/src/api/endpoints/files.ts and the backend app/routers/filemanager.py mount
 * routes.
 *
 * Paths have NO leading slash (relative to the shared Retrofit base URL, matching the rest of the
 * codebase). All calls are suspend. Mutating verbs carry an explicit JSON Content-Type. Session cookies,
 * Authorization Bearer and X-CSRF-Token are attached by the core-network interceptors.
 *
 * Idempotency: the GETs (list) are idempotent. The mutating verbs (POST create, PATCH update, DELETE,
 * POST validate) are NON-idempotent and are NOT auto-retried by the shared RetryInterceptor. A 422
 * surfaces as an HttpException carrying the FastAPI detail body; a 403 feature-gate or 404 (surface not
 * enabled in this environment) is folded to a degrade-empty state in the repository. 401 is handled
 * globally by the SessionAuthenticator.
 */
interface FileMountsApi {

    /** GET v1/fs/mounts -> { items: [...] }. */
    @GET("v1/fs/mounts")
    suspend fun listMounts(): FileMountsListDto

    @Headers("Content-Type: application/json")
    @POST("v1/fs/mounts")
    suspend fun createMount(@Body body: FileMountCreateRequest): FileMountDto

    @Headers("Content-Type: application/json")
    @PATCH("v1/fs/mounts/{id}")
    suspend fun updateMount(
        @Path("id") mountId: String,
        @Body body: FileMountUpdateRequest,
    ): FileMountDto

    @DELETE("v1/fs/mounts/{id}")
    suspend fun deleteMount(@Path("id") mountId: String): DeleteFileMountDto

    /** POST v1/fs/mounts/{id}/validate -> { ok, mount_id, status } (test/connectivity check). */
    @POST("v1/fs/mounts/{id}/validate")
    suspend fun validateMount(@Path("id") mountId: String): ValidateFileMountDto
}
