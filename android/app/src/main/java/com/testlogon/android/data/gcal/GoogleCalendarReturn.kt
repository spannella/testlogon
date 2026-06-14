package com.testlogon.android.data.gcal

import java.net.URI
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-273 — the parsed result of a Google Calendar OAuth return deep link.
 *
 * The PRIMARY return path is Custom-Tab-return -> refreshStatus() (the verified backend redirect target
 * is the backend's own HTTPS callback). This custom-scheme deep link is the OPTIONAL fallback for the
 * plaintext dev host that cannot serve assetlinks; it mirrors the AND-231 payment-return pattern.
 */
data class GoogleCalendarReturn(
    val code: String?,
    val state: String?,
    val error: String?,
    val cancelled: Boolean,
)

/**
 * AND-273 — PURE return-URL parser (java.net.URI + manual query split, NOT android.net.Uri) so it is
 * fully JVM-unit-testable. Recognizes only the single registered Google-Calendar return shapes:
 *   - custom scheme: `testlogon://calendar-integrations/google/callback?code=&state=&error=`
 *   - App Link prod: `https://<host>/app/calendar/integrations/google/callback?code=&state=&error=`
 *
 * Returns null for any other URL (so other deep-link handlers get their turn). android.net.Uri parsing
 * stays in the Activity layer.
 */
@Singleton
class GoogleCalendarReturnParser @Inject constructor() {

    fun parse(url: String): GoogleCalendarReturn? {
        val uri = runCatching { URI(url) }.getOrNull() ?: return null
        val scheme = uri.scheme?.lowercase() ?: return null
        val path = uri.path ?: ""

        val isCustomScheme = scheme == CUSTOM_SCHEME &&
            (uri.host?.lowercase() == CUSTOM_HOST ||
                url.removePrefix("$scheme://").startsWith("$CUSTOM_HOST/"))
        val isAppLink = (scheme == "https" || scheme == "http") && path.startsWith(APP_LINK_PREFIX)
        if (!isCustomScheme && !isAppLink) return null

        val query = parseQuery(uri.rawQuery)
        val error = query["error"]
        return GoogleCalendarReturn(
            code = query["code"],
            state = query["state"],
            error = error,
            cancelled = error == "access_denied" || query["status"] == "cancel",
        )
    }

    private fun parseQuery(rawQuery: String?): Map<String, String> {
        if (rawQuery.isNullOrBlank()) return emptyMap()
        val out = LinkedHashMap<String, String>()
        for (pair in rawQuery.split('&')) {
            if (pair.isEmpty()) continue
            val eq = pair.indexOf('=')
            val key = if (eq < 0) pair else pair.substring(0, eq)
            val value = if (eq < 0) "" else pair.substring(eq + 1)
            if (key.isNotEmpty()) out[decode(key)] = decode(value)
        }
        return out
    }

    private fun decode(s: String): String {
        val sb = StringBuilder(s.length)
        var i = 0
        while (i < s.length) {
            when (val c = s[i]) {
                '+' -> sb.append(' ')
                '%' -> if (i + 2 < s.length) {
                    val hex = s.substring(i + 1, i + 3)
                    val code = hex.toIntOrNull(16)
                    if (code != null) { sb.append(code.toChar()); i += 2 } else sb.append(c)
                } else sb.append(c)
                else -> sb.append(c)
            }
            i++
        }
        return sb.toString()
    }

    companion object {
        const val CUSTOM_SCHEME = "testlogon"
        const val CUSTOM_HOST = "calendar-integrations"
        const val APP_LINK_PREFIX = "/app/calendar/integrations/google/callback"
    }
}
