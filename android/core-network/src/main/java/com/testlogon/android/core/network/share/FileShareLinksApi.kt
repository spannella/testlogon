package com.testlogon.android.core.network.share

import com.testlogon.android.core.model.files.CreateShareLinkRequest
import com.testlogon.android.core.model.files.RevokeShareLinkDto
import com.testlogon.android.core.model.files.ShareLinkListDto
import com.testlogon.android.core.model.files.ShareLinkOutDto
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-335 - Retrofit interface for the OWNER share-link surface (authenticated).
 *
 * These endpoints require the caller's session, so this interface is provided on the SHARED
 * authenticated Retrofit (cookie jar + CSRF + Bearer + 401-refresh all apply), mirroring the AND-331
 * FilesApi wiring. Paths have NO leading slash (relative to the shared Retrofit base URL). All calls are
 * suspend. The mutating POST carries an explicit JSON Content-Type.
 *
 * The list endpoint returns ALL of the caller's links; a per-file view is produced by filtering on
 * file_node_id CLIENT-SIDE in ShareRepository. Revoke is a 200 with a { ok, link_id } body (NOT a 204),
 * so it is typed as a decoded DTO rather than an empty Response. A 401 is handled globally by the
 * SessionAuthenticator; a 422 surfaces as an HttpException carrying the FastAPI detail body.
 */
interface FileShareLinksApi {

    /** GET all of the caller's share links (filtered to a single file CLIENT-SIDE). */
    @GET("ui/files/share-links")
    suspend fun listLinks(): ShareLinkListDto

    /** POST a new share link for a file (201 -> the created link). */
    @Headers("Content-Type: application/json")
    @POST("ui/files/share-links")
    suspend fun createLink(@Body body: CreateShareLinkRequest): ShareLinkOutDto

    /** DELETE (revoke) the link identified by [linkId] (200 -> { ok, link_id }). */
    @DELETE("ui/files/share-links/{link_id}")
    suspend fun revokeLink(@Path("link_id") linkId: String): RevokeShareLinkDto
}
