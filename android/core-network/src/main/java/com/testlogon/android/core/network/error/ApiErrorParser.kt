package com.testlogon.android.core.network.error

import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ErrorDetailMapper
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Bridges transport-layer failures into the canonical [ApiError] model, decoding the FastAPI
 * `detail` union with Moshi and normalizing it via [ErrorDetailMapper].
 *
 * Totally failure-proof: malformed/empty/non-JSON bodies degrade to a generic message, never throw.
 */
@Singleton
class ApiErrorParser @Inject constructor(
    moshi: Moshi,
) {
    // detail can be String | List | Map | null -> decode the envelope as Map<String, Any?>.
    private val envelopeAdapter = moshi.adapter<Map<String, Any?>>(
        Types.newParameterizedType(Map::class.java, String::class.java, Any::class.java),
    )

    /** Builds an [ApiError] from a Retrofit [HttpException]. */
    fun from(http: HttpException): ApiError {
        val body = runCatching { http.response()?.errorBody()?.string() }.getOrNull()
        val detail = parseDetail(body)
        return ApiError(
            status = http.code(),
            message = ErrorDetailMapper.normalize(detail),
            code = ErrorDetailMapper.extractCode(detail),
            raw = body,
        )
    }

    /** Builds an [ApiError] from an arbitrary thrown [Throwable]. */
    fun fromThrowable(t: Throwable): ApiError = when (t) {
        is HttpException -> from(t)
        is IOException -> ApiError(
            status = ApiError.STATUS_NETWORK,
            message = ErrorDetailMapper.OFFLINE,
        )
        else -> ApiError(
            status = ApiError.STATUS_PARSE,
            message = ErrorDetailMapper.PARSE,
            raw = t.message,
        )
    }

    /** Decodes the `detail` field of a response body into a loosely-typed value, or null. */
    fun parseDetail(body: String?): Any? {
        if (body.isNullOrBlank()) return null
        return try {
            envelopeAdapter.fromJson(body)?.get("detail")
        } catch (_: Exception) {
            null
        }
    }
}
