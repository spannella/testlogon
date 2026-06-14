package com.testlogon.android.navigation.applink

import com.testlogon.android.navigation.DonationDest
import com.testlogon.android.navigation.EventDetailDest
import com.testlogon.android.navigation.MainDest
import com.testlogon.android.navigation.PostDetailDest
import com.testlogon.android.navigation.PublicClipDest
import com.testlogon.android.navigation.PublicProfileDest
import com.testlogon.android.navigation.PublicShareDest
import com.testlogon.android.navigation.VideoDetailDest
import java.net.URI
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-396 — pure Uri -> [DeepLink] mapper (FR-3).
 *
 * No navigation, no I/O, no android.net.Uri dependency: parses the URL string with java.net.URI so it
 * is JVM-unit-testable without Robolectric. `parse` is total — every input maps to exactly one
 * [DeepLink] variant; no exception ever escapes (§7).
 */
interface DeepLinkParser {
    /** Pure function: a full URL string -> [DeepLink]. */
    fun parse(url: String?): DeepLink

    /**
     * The logged path TEMPLATE for [url] (e.g. `/videos/{videoId}`), with raw ids and the query
     * string stripped (§10, SEC-5). Returns the literal `/` for the root and `unknown` when the URL
     * is unparseable. Never returns raw ids or query params.
     */
    fun pathTemplate(url: String?): String
}

@Singleton
class DeepLinkParserImpl @Inject constructor(
    @AppLinkHosts private val verifiedHosts: Set<String>,
) : DeepLinkParser {

    override fun parse(url: String?): DeepLink {
        val uri = url?.let { runCatching { URI(it.trim()) }.getOrNull() } ?: return DeepLink.Malformed
        val scheme = uri.scheme?.lowercase()
        // Only HTTP(S) App Links are in scope here; custom schemes are handled by per-feature
        // navDeepLink registrations elsewhere (OQ-2 out of scope).
        if (scheme != "https" && scheme != "http") return DeepLink.Malformed
        val host = uri.host?.lowercase() ?: return DeepLink.Malformed
        // SEC-1: host allowlist. A foreign host (incl. a look-alike like app.testlogon.com.evil.com,
        // whose URI host IS the full attacker domain) never produces a route.
        if (host !in verifiedHosts) return DeepLink.Malformed

        val segments = uri.path.orEmpty()
            .split('/')
            .filter { it.isNotEmpty() }
            .map { decode(it) }

        return mapSegments(segments)
    }

    override fun pathTemplate(url: String?): String {
        val uri = url?.let { runCatching { URI(it.trim()) }.getOrNull() } ?: return UNKNOWN
        val segments = uri.path.orEmpty().split('/').filter { it.isNotEmpty() }
        if (segments.isEmpty()) return "/"
        return templateFor(segments)
    }

    /** Maps validated, decoded path segments onto a [DeepLink]. */
    private fun mapSegments(segments: List<String>): DeepLink {
        if (segments.isEmpty()) {
            // Root -> Home (the authenticated shell start destination). FR-2: `/` -> Home.
            return DeepLink.Resolved(MainDest.Shell.route, requiresAuth = true)
        }
        val head = segments[0]
        val a1 = segments.getOrNull(1)
        return when (head) {
            // Authenticated content detail (FR-2). Web `/videos/{id}` and `/gallery/{id}` both open
            // the shared native video-detail route (AND-190).
            "videos", "gallery" ->
                requireSeg(a1)?.let { DeepLink.Resolved(VideoDetailDest.build(it), requiresAuth = true) }
                    ?: DeepLink.Malformed

            // Web `/posts/{id}` (and the singular `/post/{id}` App Link AND-100) -> post detail.
            "posts", "post" ->
                requireSeg(a1)?.let { DeepLink.Resolved(PostDetailDest.build(it), requiresAuth = true) }
                    ?: DeepLink.Malformed

            // Public, no-auth, ideal shared App Links (FR-2 / claim 10).
            "u" ->
                requireSeg(a1)?.let { DeepLink.Resolved(PublicProfileDest.build(it), requiresAuth = false) }
                    ?: DeepLink.Malformed

            "share" ->
                requireSeg(a1)?.let { DeepLink.Resolved(PublicShareDest.build(it), requiresAuth = false) }
                    ?: DeepLink.Malformed

            "c" ->
                requireSeg(a1)?.let { DeepLink.Resolved(PublicClipDest.build(it), requiresAuth = false) }
                    ?: DeepLink.Malformed

            "donate" ->
                requireSeg(a1)?.let { DeepLink.Resolved(DonationDest.build(it), requiresAuth = false) }
                    ?: DeepLink.Malformed

            // `/event/{calendarId}/{eventId}` (AND-272) — public reduced payload via the deep link.
            "event" -> {
                val calendarId = requireSeg(a1)
                val eventId = requireSeg(segments.getOrNull(2))
                if (calendarId != null && eventId != null) {
                    DeepLink.Resolved(
                        EventDetailDest.build(calendarId, eventId, isPublic = true),
                        requiresAuth = false,
                    )
                } else {
                    DeepLink.Malformed
                }
            }

            // Settings: only the FIXED sub-paths that have a native route (FR-2 correction). The web
            // `/settings/theme` maps to the native appearance screen; unsupported sub-paths fall
            // through to Unhandled.
            "settings" -> when (a1) {
                null -> DeepLink.Resolved(MainDest.Settings.route, requiresAuth = true)
                "privacy" -> DeepLink.Resolved(MainDest.SettingsPrivacy.route, requiresAuth = true)
                "theme" -> DeepLink.Resolved(MainDest.SettingsAppearance.route, requiresAuth = true)
                "security" -> DeepLink.Resolved(MainDest.SettingsSecurity.route, requiresAuth = true)
                "notifications" -> DeepLink.Resolved(MainDest.SettingsNotifications.route, requiresAuth = true)
                "media" -> DeepLink.Resolved(MainDest.SettingsMedia.route, requiresAuth = true)
                "account" -> DeepLink.Resolved(MainDest.SettingsAccount.route, requiresAuth = true)
                "language" -> DeepLink.Resolved(MainDest.SettingsLanguage.route, requiresAuth = true)
                else -> DeepLink.Unhandled
            }

            // Host matched, path unknown (e.g. the fictional `/library`, `/shop/...`, `/clips/...`
            // authed which have no confirmed native route): safe Home fallback (FR-7).
            else -> DeepLink.Unhandled
        }
    }

    /** Returns a path TEMPLATE for the segments (raw ids replaced by `{name}` tokens). */
    private fun templateFor(rawSegments: List<String>): String {
        return when (rawSegments.firstOrNull()) {
            "videos" -> "/videos/{videoId}"
            "gallery" -> "/gallery/{videoId}"
            "posts" -> "/posts/{postId}"
            "post" -> "/post/{postId}"
            "u" -> "/u/{identifier}"
            "share" -> "/share/{linkId}"
            "c" -> "/c/{clipId}"
            "donate" -> "/donate/{fundraiserId}"
            "event" -> "/event/{calendarId}/{eventId}"
            "settings" -> if (rawSegments.size > 1) "/settings/${rawSegments[1]}" else "/settings"
            else -> "/" + rawSegments.first()
        }
    }

    /** A path segment is valid only when non-blank after trimming; trims and validates untrusted input (SEC-3). */
    private fun requireSeg(value: String?): String? =
        value?.trim()?.takeIf { it.isNotEmpty() }

    private fun decode(segment: String): String =
        runCatching { java.net.URLDecoder.decode(segment, Charsets.UTF_8.name()) }.getOrDefault(segment)

    private companion object {
        const val UNKNOWN = "unknown"
    }
}
