package com.testlogon.android.core.network.share

import com.testlogon.android.core.model.files.PublicDownloadRequest
import com.testlogon.android.core.model.files.PublicShareDto
import okhttp3.ResponseBody
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Streaming

/**
 * AND-335 - Retrofit interface for the PUBLIC share surface (session-free).
 *
 * CRUCIAL: these endpoints MUST NOT carry the caller's session - a recipient may be a stranger who is
 * signed out, and leaking the owner's cookies/CSRF/Bearer onto a public download would be a security
 * defect. This interface is therefore provided on a SEPARATE, COOKIELESS Retrofit (see
 * ShareNetworkModule.providePublicShareApi) built on a plain OkHttpClient that has NO cookie jar, NO
 * CsrfInterceptor and NO SessionAuthenticator. Only the HostSelectionInterceptor (host targeting),
 * RetryInterceptor and debug logging are shared. The existing authed interceptors are NOT modified.
 *
 * Paths have NO leading slash (relative to the cookieless Retrofit's base URL). The info GET resolves
 * link state via boolean flags (revoked / expired / exhausted) and password_required; there is no
 * download URL in it. The download POST is @Streaming so the bytes are never buffered into memory; the
 * caller copies the ResponseBody stream to MediaStore in chunks. A wrong/missing password yields 401/403
 * (surfaced as a clear, non-leaking error).
 */
interface PublicShareApi {

    /** GET public link metadata + state flags (session-free; no download URL). */
    @GET("public/files/share/{link_id}/info")
    suspend fun resolvePublic(@Path("link_id") linkId: String): PublicShareDto

    /** POST the (optional) password and stream the file bytes back (session-free). */
    @Streaming
    @Headers("Content-Type: application/json")
    @POST("public/files/share/{link_id}/download")
    suspend fun downloadPublic(
        @Path("link_id") linkId: String,
        @Body body: PublicDownloadRequest,
    ): Response<ResponseBody>
}
