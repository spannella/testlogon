package com.testlogon.android.feature.messaging.media

import java.net.URLEncoder

/**
 * FE-141 (EPIC E, <- BE-141) — pure, JVM-testable media-CDN + upload-retry decisions. No Android
 * types here so every rule is unit-tested; the runtime render/upload code calls into this.
 *
 * The backend serves uploaded objects one of two ways depending on the environment:
 *  - dev/mock: the list/get endpoints return a server-RELATIVE object url (e.g. "/mock/s3/<bucket>/<key>")
 *    which Coil's RelativeUrlMapper resolves against the API origin.
 *  - prod: the endpoints return an ABSOLUTE CDN url in the DTO's `url` field.
 *
 * [resolveMediaUrl] therefore ALWAYS prefers the API-provided absolute `url`; only when it is blank
 * does it derive one — from a configured CDN base if available, else the mock-relative path so
 * dev/mock behavior is unchanged.
 */
object MediaCdnMath {

    /** Manual retry ceiling for a failed media upload (see [isRetryableUploadStatus]). */
    const val MAX_UPLOAD_RETRIES: Int = 5

    private const val BACKOFF_BASE_MS: Long = 1_000L
    private const val BACKOFF_CAP_MS: Long = 30_000L

    /**
     * Resolves the display/playback url for a media message, mirroring the web client's precedence:
     *  1. a non-blank absolute API [url] wins (prod CDN url, or a signed url);
     *  2. else, if [cdnBase] is a non-blank absolute origin AND we have [bucket]+[key], build
     *     "<cdnBase>/<bucket>/<encoded key>";
     *  3. else fall back to the mock-relative "/mock/s3/<bucket>/<key>" path (bucket-less: "/mock/s3/<key>")
     *     which RelativeUrlMapper absolutizes against the API origin (dev/mock unchanged);
     *  4. null when nothing is derivable.
     *
     * A blank [url] is treated as absent so a prod-blank never shadows the fallback.
     */
    fun resolveMediaUrl(
        url: String?,
        bucket: String?,
        key: String?,
        cdnBase: String?,
    ): String? {
        val absolute = url?.trim().orEmpty()
        if (absolute.isNotEmpty()) return absolute

        val k = key?.trim().orEmpty()
        if (k.isEmpty()) return null
        val b = bucket?.trim().orEmpty()

        val base = cdnBase?.trim().orEmpty()
        if (base.isNotEmpty() && isAbsoluteUrl(base) && b.isNotEmpty()) {
            return base.trimEnd('/') + "/" + b + "/" + encodeMediaKey(k)
        }

        // Mock-relative fallback (dev/mock). The path segments are already gateway-safe.
        return if (b.isEmpty()) "/mock/s3/$k" else "/mock/s3/$b/$k"
    }

    /**
     * Percent-encodes an object key per path segment, keeping the slashes (mirrors the web
     * buildS3ObjectUrl / the upload-side s3ObjectUrl). Spaces become "%20" (not "+").
     */
    fun encodeMediaKey(key: String): String =
        key.split("/").joinToString("/") { segment ->
            URLEncoder.encode(segment, Charsets.UTF_8.name()).replace("+", "%20")
        }

    /**
     * Whether a failed storage PUT / presign / confirm with HTTP [code] is worth retrying:
     * transport failure (0 == no response), 408 request timeout, 429 too-many-requests, or any 5xx.
     * 4xx (except 408/429) are permanent (bad request / auth / expired-presign) and NOT retried here.
     */
    fun isRetryableUploadStatus(code: Int): Boolean = when {
        code == 0 -> true
        code == 408 -> true
        code == 429 -> true
        code in 500..599 -> true
        else -> false
    }

    /**
     * Exponential backoff (base 1s, capped 30s) for retry [attempt] (1-based). attempt<=0 -> 0.
     * attempt 1 -> 1s, 2 -> 2s, 3 -> 4s, 4 -> 8s, 5 -> 16s, then capped at 30s.
     */
    fun uploadBackoffMs(attempt: Int): Long {
        if (attempt <= 0) return 0L
        // Guard the shift so a large attempt never overflows before the cap clamps it.
        val shift = (attempt - 1).coerceAtMost(20)
        val raw = BACKOFF_BASE_MS shl shift
        return raw.coerceIn(0L, BACKOFF_CAP_MS)
    }

    /**
     * Upload progress as an integer percentage 0..100. total<=0 -> 0 (unknown size). Clamped so a
     * loaded>total race never reports >100.
     */
    fun uploadProgressPct(loaded: Long, total: Long): Int {
        if (total <= 0L) return 0
        val pct = (loaded.toDouble() / total.toDouble() * 100.0).toInt()
        return pct.coerceIn(0, 100)
    }

    /** True when [s] is an absolute http(s) origin usable as a CDN base (not a relative path). */
    private fun isAbsoluteUrl(s: String): Boolean =
        s.startsWith("http://", ignoreCase = true) || s.startsWith("https://", ignoreCase = true)
}
