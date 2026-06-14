package com.testlogon.android.data.upload

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.suspendCancellableCoroutine
import okhttp3.Call
import okhttp3.Callback
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.Response
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * AND-129 — performs the storage PUT through a COOKIELESS OkHttpClient ([StorageOkHttp]) so the
 * presigned upload (a third-party origin) never carries app session cookies or `X-CSRF-Token`; auth
 * lives entirely in the presigned signature.
 *
 * Coroutine cancellation aborts the in-flight OkHttp [Call] so a user cancel stops the upload
 * immediately (no confirm is sent by the caller in that case).
 */
@Singleton
class StorageUploadClient @Inject constructor(
    @StorageOkHttp private val client: OkHttpClient,
) {

    /** Result of a storage PUT; [success] is true for 2xx, else [httpStatus] carries the code. */
    data class PutResult(val success: Boolean, val httpStatus: Int)

    /**
     * PUTs [body] to [url] with only a `Content-Type` header. Returns the HTTP outcome; throws
     * [IOException] for transport failures (so the caller maps them to NETWORK/TIMEOUT).
     */
    suspend fun put(url: String, contentType: String, body: RequestBody): PutResult {
        val request = Request.Builder()
            .url(url)
            .put(body)
            .header("Content-Type", contentType)
            .build()
        val call = client.newCall(request)
        return suspendCancellableCoroutine { cont ->
            cont.invokeOnCancellation { runCatching { call.cancel() } }
            call.enqueue(object : Callback {
                override fun onFailure(call: Call, e: IOException) {
                    if (call.isCanceled()) {
                        cont.resumeWithException(CancellationException("storage put cancelled"))
                    } else {
                        cont.resumeWithException(e)
                    }
                }

                override fun onResponse(call: Call, response: Response) {
                    response.use {
                        cont.resume(PutResult(success = it.isSuccessful, httpStatus = it.code))
                    }
                }
            })
        }
    }
}
