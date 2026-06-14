package com.testlogon.android.feature.settings

import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

/** Result of validating a user-entered base URL (AND-041). */
sealed interface UrlValidation {
    data class Valid(val normalized: String, val cleartext: Boolean) : UrlValidation
    data class Invalid(val reason: UrlError) : UrlValidation
}

enum class UrlError { BLANK, MALFORMED, BAD_SCHEME, NO_HOST, BAD_PORT }

/**
 * Pure, unit-testable base-URL validator/normalizer (AND-041 §4.2).
 *
 * Parses with OkHttp's `String.toHttpUrlOrNull()` (the OkHttp 4.x extension). Enforces
 * scheme ∈ {http, https}, a non-empty host, and a port in 1..65535. Normalizes to
 * `scheme://host[:port]` (lowercased scheme, explicit non-default port preserved, no trailing
 * slash, whitespace trimmed). `cleartext` is true for `http`.
 */
object BaseUrlValidator {

    fun validate(raw: String): UrlValidation {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return UrlValidation.Invalid(UrlError.BLANK)

        // Reject non-http(s) schemes explicitly so the error is BAD_SCHEME, not MALFORMED.
        val schemeMatch = SCHEME_REGEX.find(trimmed)
        if (schemeMatch != null) {
            val scheme = schemeMatch.groupValues[1].lowercase()
            if (scheme != "http" && scheme != "https") {
                return UrlValidation.Invalid(UrlError.BAD_SCHEME)
            }
        }

        // Validate an explicitly-typed port *before* parsing: OkHttp returns null for port 0 /
        // out-of-range ports, which would otherwise be misclassified as MALFORMED/NO_HOST.
        val explicitPort = explicitPort(trimmed)
        if (explicitPort != null && explicitPort !in 1..65535) {
            return UrlValidation.Invalid(UrlError.BAD_PORT)
        }

        val url = trimmed.toHttpUrlOrNull()
            ?: return UrlValidation.Invalid(classifyParseFailure(trimmed))

        if (url.host.isBlank()) return UrlValidation.Invalid(UrlError.NO_HOST)

        val cleartext = url.scheme == "http"
        val hostPart = if (url.host.contains(':')) "[${url.host}]" else url.host // bracket IPv6
        val portPart = explicitPort?.let { ":$it" } ?: ""
        val normalized = "${url.scheme}://$hostPart$portPart"
        return UrlValidation.Valid(normalized = normalized, cleartext = cleartext)
    }

    private fun classifyParseFailure(trimmed: String): UrlError = when {
        // "http(s)://" with no host (optionally with a port).
        trimmed.matches(Regex("(?i)^https?://(:\\d*)?$")) -> UrlError.NO_HOST
        // Has a valid http(s) scheme prefix but still failed to parse -> missing/invalid host.
        trimmed.matches(Regex("(?i)^https?://.*")) -> UrlError.NO_HOST
        else -> UrlError.MALFORMED
    }

    /** Extracts an explicitly-typed port (the digits after the final `:` in the authority), or null. */
    private fun explicitPort(trimmed: String): Int? {
        val afterScheme = trimmed.substringAfter("://", trimmed)
        val authority = afterScheme.substringBefore('/').substringBefore('?').substringBefore('#')
        // IPv6 literal: port (if any) follows the closing bracket.
        val portStr = if (authority.startsWith("[")) {
            authority.substringAfter(']', "").removePrefix(":").takeIf { it.isNotEmpty() }
        } else {
            val colon = authority.lastIndexOf(':')
            if (colon < 0) null else authority.substring(colon + 1)
        } ?: return null
        return portStr.toIntOrNull() ?: -1 // non-numeric -> out of range -> BAD_PORT
    }

    private val SCHEME_REGEX = Regex("^([a-zA-Z][a-zA-Z0-9+.-]*)://")
}
