package com.testlogon.android.feature.projects.provider

import java.net.URI
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-374 - the parsed result of a project Google Drive OAuth return deep link.
 *
 * The app asks the backend for an authorization URL (start), opens it in a Custom Tab, and the backend
 * completes the exchange and redirects back via a deep link
 * (`testlogon://projects/{projectId}/providers/google_drive/callback?code=&state=&error=`). [projectId] is
 * the project the user was viewing (so the right detail screen resumes). A present [error] (e.g. access_denied)
 * means the user canceled / denied - the app does NOT call the callback endpoint.
 */
data class ProjectDriveReturn(
    val projectId: String,
    val code: String?,
    val state: String?,
    val error: String?,
    val cancelled: Boolean,
)

/**
 * AND-374 - PURE return-URL parser (java.net.URI + manual query split, NOT android.net.Uri) so it is fully
 * JVM-unit-testable. Recognizes only the registered project Drive return shapes:
 *   - custom scheme: `testlogon://projects/{projectId}/providers/google_drive/callback?code=&state=&error=`
 *   - App Link prod: `https://<host>/app/projects/{projectId}/providers/google_drive/callback?...`
 *
 * Returns null for any other URL (so other deep-link handlers get their turn). android.net.Uri parsing stays in
 * the Activity layer. Mirrors the AND-273 GoogleCalendarReturnParser idiom.
 */
@Singleton
class ProjectDriveReturnParser @Inject constructor() {

    fun parse(url: String): ProjectDriveReturn? {
        val uri = runCatching { URI(url) }.getOrNull() ?: return null
        val scheme = uri.scheme?.lowercase() ?: return null

        // For the custom scheme the host is "projects" and the project id is the FIRST path segment; for the
        // App Link the path is /app/projects/{id}/providers/google_drive/callback.
        val projectId: String? = when {
            scheme == CUSTOM_SCHEME && uri.host?.lowercase() == CUSTOM_HOST ->
                segments(uri.path).firstOrNull()?.takeIf {
                    pathMatchesProviderCallback(uri.path, prefixSegments = 1)
                }
            (scheme == "https" || scheme == "http") && (uri.path ?: "").startsWith(APP_LINK_PREFIX) ->
                appLinkProjectId(uri.path)
            else -> null
        }
        if (projectId.isNullOrBlank()) return null

        val query = parseQuery(uri.rawQuery)
        val error = query["error"]
        return ProjectDriveReturn(
            projectId = projectId,
            code = query["code"],
            state = query["state"],
            error = error,
            cancelled = error == "access_denied" || query["status"] == "cancel",
        )
    }

    /** For the custom scheme, after the {id} segment the tail must be providers/google_drive/callback. */
    private fun pathMatchesProviderCallback(path: String?, prefixSegments: Int): Boolean {
        val segs = segments(path)
        if (segs.size < prefixSegments + 3) return false
        return segs[prefixSegments] == "providers" &&
            segs[prefixSegments + 1] == PROVIDER &&
            segs[prefixSegments + 2] == "callback"
    }

    /** For the App Link, the project id is the segment after .../app/projects/ and before /providers/...  */
    private fun appLinkProjectId(path: String?): String? {
        val segs = segments(path)
        // app, projects, {id}, providers, google_drive, callback
        val idx = segs.indexOf("projects")
        if (idx < 0 || segs.size < idx + 5) return null
        val id = segs[idx + 1]
        val ok = segs[idx + 2] == "providers" && segs[idx + 3] == PROVIDER && segs[idx + 4] == "callback"
        return if (ok) id else null
    }

    private fun segments(path: String?): List<String> =
        (path ?: "").split('/').filter { it.isNotEmpty() }

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
        const val CUSTOM_HOST = "projects"
        const val PROVIDER = "google_drive"
        const val APP_LINK_PREFIX = "/app/projects/"
    }
}
