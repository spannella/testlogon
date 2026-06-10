package com.testlogon.android.data.vod.download

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.suspendCancellableCoroutine
import okhttp3.Call
import okhttp3.Callback
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.io.File
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * AND-195 — streams a watermarked artifact `download_url` to a local file, publishing progress.
 *
 * Uses the shared (session-cookie + CSRF bearing) OkHttpClient since the dev `download_url` is the
 * same authenticated origin. Coroutine cancellation aborts the in-flight call so a user cancel stops
 * the download immediately. The signed `download_url` is NEVER logged (§8/§10).
 */
@Singleton
class WatermarkArtifactClient @Inject constructor(
    private val client: OkHttpClient,
) {

    /** Outcome of streaming the artifact. [httpStatus] carries the code on a non-2xx (e.g. 410 expiry). */
    data class StreamResult(val success: Boolean, val httpStatus: Int, val bytes: Long)

    /**
     * GETs [url] and writes the body to [dest], invoking [onProgress] (bytesRead, totalBytes) as it
     * streams. Throws [IOException] for transport failures; returns a non-success [StreamResult] for a
     * non-2xx response so the caller can detect URL expiry (403/404/410).
     */
    suspend fun stream(
        url: String,
        dest: File,
        onProgress: (Long, Long) -> Unit,
    ): StreamResult {
        val request = Request.Builder().url(url).get().build()
        val call = client.newCall(request)
        return suspendCancellableCoroutine { cont ->
            cont.invokeOnCancellation { runCatching { call.cancel() } }
            call.enqueue(object : Callback {
                override fun onFailure(call: Call, e: IOException) {
                    if (call.isCanceled()) {
                        cont.resumeWithException(CancellationException("artifact stream cancelled"))
                    } else {
                        cont.resumeWithException(e)
                    }
                }

                override fun onResponse(call: Call, response: Response) {
                    response.use { resp ->
                        if (!resp.isSuccessful) {
                            cont.resume(StreamResult(false, resp.code, 0L))
                            return
                        }
                        try {
                            val total = resp.body?.contentLength() ?: -1L
                            var read = 0L
                            dest.parentFile?.mkdirs()
                            resp.body?.byteStream()?.use { input ->
                                dest.outputStream().use { out ->
                                    val buf = ByteArray(BUFFER)
                                    while (true) {
                                        val n = input.read(buf)
                                        if (n < 0) break
                                        out.write(buf, 0, n)
                                        read += n
                                        onProgress(read, total)
                                    }
                                }
                            }
                            cont.resume(StreamResult(true, resp.code, read))
                        } catch (e: IOException) {
                            cont.resumeWithException(e)
                        }
                    }
                }
            })
        }
    }

    private companion object {
        const val BUFFER = 64 * 1024
    }
}
