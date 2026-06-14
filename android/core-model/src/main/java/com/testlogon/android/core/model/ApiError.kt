package com.testlogon.android.core.model

/**
 * Structured representation of a server-side (or transport) error.
 *
 * @param status  HTTP status code (e.g. 401, 422, 500). Sentinels: [STATUS_NETWORK] (0) for
 *                transport/connectivity failures and [STATUS_PARSE] (-1) for decode failures.
 * @param message Best-effort, user-facing message (already normalized by [ErrorDetailMapper]).
 * @param code    Machine-readable application code from FastAPI `detail.{code}`
 *                (e.g. "role_required", "geo_blocked"); null when not coded.
 * @param raw     Unparsed response body / diagnostic payload, retained for logging only.
 *                MUST NOT be rendered in UI.
 */
data class ApiError(
    val status: Int,
    val message: String,
    val code: String? = null,
    val raw: Any? = null,
) {
    val isNetwork: Boolean get() = status == STATUS_NETWORK
    val isParse: Boolean get() = status == STATUS_PARSE
    val isAuth: Boolean get() = status == 401 || status == 403

    companion object {
        /** Sentinel status for transport/connectivity failures (no HTTP response). */
        const val STATUS_NETWORK = 0

        /** Sentinel status for response-decode failures. */
        const val STATUS_PARSE = -1
    }
}
