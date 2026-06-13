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

    /**
     * AND-373 - extracts the FastAPI 422 validation message whose `loc` tail equals [field], so a composer can
     * surface a field-level error (e.g. loc ["body","body"] -> the message text field). Returns null when the
     * error is not a 422, the body is not a HTTPValidationError {detail:[{loc,msg,type}]}, or no item targets
     * [field]. Additive + total (never throws): existing callers are unaffected. The raw body is read from
     * [ApiError.raw] (populated by [from]).
     */
    fun fieldErrorForLocTail(error: ApiError, field: String): String? {
        if (error.status != HTTP_UNPROCESSABLE_ENTITY) return null
        val detail = parseDetail(error.raw as? String) as? List<*> ?: return null
        for (item in detail) {
            val obj = item as? Map<*, *> ?: continue
            val loc = obj["loc"] as? List<*> ?: continue
            val tail = loc.lastOrNull() as? String ?: continue
            if (tail == field) {
                val msg = obj["msg"] as? String
                if (!msg.isNullOrBlank()) return msg
            }
        }
        return null
    }

    private companion object {
        const val HTTP_UNPROCESSABLE_ENTITY = 422
    }
}
