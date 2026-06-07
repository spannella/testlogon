package com.testlogon.android.core.model

/**
 * Port of the web client's `normalizeErrorDetail` + `mapAuthorizationError`
 * (reference: `src/api/client.ts`).
 *
 * FastAPI's `detail` field is a union of three shapes:
 *  - a plain `String`,
 *  - an array of validation objects, each carrying at least a `msg` (FastAPI 422),
 *  - an object carrying a `code` (application/auth errors such as `role_required`, `geo_blocked`,
 *    `helpdesk_*`) and optionally a `message`.
 *
 * This mapper collapses any of those into a single user-facing string. It is **total** — any
 * unrecognized/malformed input degrades to [fallback] (default [GENERIC]) and never throws.
 *
 * `detail` is accepted as a loosely-typed value (`String | List<*> | Map<*, *> | null`) so the
 * network module can hand it the result of a Moshi `Any?` decode without coupling this pure module
 * to Moshi.
 */
object ErrorDetailMapper {

    const val GENERIC = "Something went wrong. Please try again."
    const val OFFLINE = "Network error — check your connection and try again."
    const val PARSE = "We received an unexpected response. Please try again."

    /** Default English copy for each known application error code (verbatim from `client.ts`). */
    val codeMessages: Map<String, String> = mapOf(
        "role_required" to
            "You don't currently have permission for this action. " +
            "Request temporary elevation or contact a general admin/root operator.",
        "role_required_scope" to
            "You don't currently have permission for this action. " +
            "Request temporary elevation or ask a general admin/root operator to perform it.",
        "role_required_admin_profile_type" to
            "This action requires general admin access. " +
            "Request temporary elevation or ask a general admin/root operator to perform it.",
        "geo_blocked" to "This content is not available in your region.",
        "helpdesk_claim_required" to "Claim this helpdesk conversation before replying.",
        "helpdesk_assignee_required" to
            "Only the currently assigned helpdesk agent can reply in this conversation.",
        "helpdesk_claim_not_available" to
            "You need to be online and available before you can claim and reply.",
    )

    /**
     * Maps a backend `code` to a curated user message, or null when unrecognized.
     * Note: `geo_blocked` is intentionally absent here — it is handled in [normalize] so the
     * backend's own `message` can take precedence before falling back to the curated copy.
     */
    fun mapAuthCode(code: String): String? = when (code) {
        "role_required",
        "role_required_scope",
        "role_required_admin_profile_type",
        "helpdesk_claim_required",
        "helpdesk_assignee_required",
        "helpdesk_claim_not_available",
        -> codeMessages[code]
        else -> null
    }

    /**
     * Collapses a FastAPI `detail` value into a single user-facing string.
     *
     * @param detail   `String`, `List<*>` (validation items), `Map<*, *>` (coded object), or null.
     * @param fallback message used when nothing more specific can be derived.
     */
    fun normalize(detail: Any?, fallback: String = GENERIC): String = when (detail) {
        null -> fallback
        is String -> detail.ifBlank { fallback }
        is List<*> -> normalizeValidation(detail, fallback)
        is Map<*, *> -> normalizeCoded(detail, fallback)
        else -> fallback
    }

    private fun normalizeValidation(items: List<*>, fallback: String): String {
        val messages = items.mapNotNull { item ->
            (item as? Map<*, *>)?.get("msg") as? String
        }.filter { it.isNotBlank() }
        return if (messages.isEmpty()) fallback else messages.joinToString(", ")
    }

    private fun normalizeCoded(obj: Map<*, *>, fallback: String): String {
        val code = obj["code"] as? String
        if (code != null) {
            mapAuthCode(code)?.let { return it }
            if (code == "geo_blocked") {
                val backendMessage = obj["message"] as? String
                return backendMessage?.takeIf { it.isNotBlank() }
                    ?: codeMessages.getValue("geo_blocked")
            }
            return fallback
        }
        // FastAPI-style `{ msg }` object (no code) — the only object form that surfaces its message.
        val msg = obj["msg"] as? String
        return msg?.takeIf { it.isNotBlank() } ?: fallback
    }

    /** The application code carried by a coded `detail` object, if any (for [ApiError.code]). */
    fun extractCode(detail: Any?): String? = (detail as? Map<*, *>)?.get("code") as? String
}
