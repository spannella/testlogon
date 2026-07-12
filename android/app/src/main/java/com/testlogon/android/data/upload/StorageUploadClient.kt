package com.testlogon.android.data.upload

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.suspendCancellableCoroutine
import com.testlogon.android.core.network.SettingsStore
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
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
    private val settingsStore: SettingsStore,
) {

    /** Result of a storage PUT; [success] is true for 2xx, else [httpStatus] carries the code. */
    data class PutResult(val success: Boolean, val httpStatus: Int)

    /**
     * GET raw bytes from a (possibly server-relative) url. Used to fetch encrypted-media ciphertext
     * for client-side decryption. Returns null on any failure. Blocking — call off the main thread.
     */
    fun getBytesBlocking(url: String): ByteArray? {
        val resolved = resolveUploadUrl(url, settingsStore.baseUrl) ?: return null
        return try {
            client.newCall(Request.Builder().url(resolved).get().build()).execute().use { resp ->
                if (resp.isSuccessful) resp.body?.bytes() else null
            }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * PUTs [body] to [url] with only a `Content-Type` header. Returns the HTTP outcome; throws
     * [IOException] for transport failures (so the caller maps them to NETWORK/TIMEOUT).
     */
    suspend fun put(url: String, contentType: String, body: RequestBody): PutResult {
        // The mock-S3 backend returns a RELATIVE, schemeless upload url (e.g. "/mock/s3/..."); resolve
        // it against the configured API origin so okhttp gets an absolute http(s) URL. A schemeless
        // string makes Request.url() throw IllegalArgumentException, which previously crashed the app
        // mid-upload (image/file/voice). Anything unresolvable surfaces as a recoverable IOException.
        val resolvedUrl = resolveUploadUrl(url, settingsStore.baseUrl)
            ?: throw IOException("Invalid upload URL: $url")
        val request = try {
            Request.Builder()
                .url(resolvedUrl)
                .put(body)
                .header("Content-Type", contentType)
                .build()
        } catch (e: IllegalArgumentException) {
            throw IOException("Malformed upload URL: $resolvedUrl", e)
        }
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

/**
 * Resolves a presign `upload_url` to an absolute http(s) URL. Already-absolute urls pass through;
 * relative urls (the mock-S3 "/mock/s3/..." shape) resolve against [baseUrl]'s origin. Returns null
 * when neither yields a valid URL. Pure (no android.net.Uri) so it is JVM-unit-testable.
 */
internal fun resolveUploadUrl(uploadUrl: String, baseUrl: String): String? {
    uploadUrl.toHttpUrlOrNull()?.let { return uploadUrl }
    val base = baseUrl.toHttpUrlOrNull() ?: return null
    return base.resolve(uploadUrl)?.toString()
}
