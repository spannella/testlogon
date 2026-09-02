package com.testlogon.android.data.alerts

/**
 * Framework-free pure logic for the alert-preference channels (webhook URLs + per-channel event-type
 * sets + push opt-in/opt-out merge). Kept side-effect-free so it is exhaustively JVM-unit-testable and
 * shared by [WebhookAlertRepository] and the AlertPrefs ViewModel.
 *
 * Mirrors the backend contract in app/routers/alerts.py:
 *  - webhook_prefs: { webhook_urls, event_types }  (POST body uses webhook_event_types)
 *  - push_prefs:    (default-ON set) minus (opt-out) plus (explicit opt-in)  [see push.py]
 *  - type-preferences: per-type {enabled,email,push,in_app,sms} toggles
 */
object AlertsPrefsMath {

    /**
     * Normalize a webhook URL list: trim each, drop blanks, and de-duplicate while preserving the
     * first-seen order (case-sensitive — paths/queries are case-sensitive). Does NOT validate scheme;
     * see [isValidWebhookUrl] for the add-guard.
     */
    fun normalizeUrls(urls: List<String>): List<String> {
        val seen = LinkedHashSet<String>()
        for (raw in urls) {
            val u = raw.trim()
            if (u.isNotEmpty()) seen.add(u)
        }
        return seen.toList()
    }

    /**
     * True if [raw] is an acceptable webhook endpoint: a trimmed http(s) URL with a non-empty host.
     * Intentionally permissive (no full RFC parse) — the server is authoritative — but rejects blanks
     * and obviously non-URL text so the Add button can gate.
     */
    fun isValidWebhookUrl(raw: String): Boolean {
        val u = raw.trim()
        if (u.isEmpty()) return false
        val lower = u.lowercase()
        if (!lower.startsWith("http://") && !lower.startsWith("https://")) return false
        val afterScheme = u.substringAfter("://", "")
        val host = afterScheme.substringBefore('/').substringBefore('?').substringBefore('#')
        return host.isNotBlank() && host.contains('.')
    }

    /** Add [rawUrl] to [current] (normalized), if valid and not already present. Returns the new list. */
    fun addUrl(current: List<String>, rawUrl: String): List<String> {
        val u = rawUrl.trim()
        if (!isValidWebhookUrl(u)) return normalizeUrls(current)
        return normalizeUrls(current + u)
    }

    /** Remove [url] from [current] (exact, after trim) and return the normalized remainder. */
    fun removeUrl(current: List<String>, url: String): List<String> =
        normalizeUrls(current.filterNot { it.trim() == url.trim() })

    /**
     * Toggle membership of [eventType] in an event-type selection [current]. Adding preserves order
     * (appended if new); removing drops all matches. Result is de-duplicated/trimmed.
     */
    fun toggleEventType(current: List<String>, eventType: String, enabled: Boolean): List<String> {
        val et = eventType.trim()
        if (et.isEmpty()) return normalizeEventTypes(current)
        val base = normalizeEventTypes(current)
        return if (enabled) {
            if (et in base) base else base + et
        } else {
            base.filterNot { it == et }
        }
    }

    /** Trim + drop-blank + de-dupe an event-type list, order-preserving. */
    fun normalizeEventTypes(types: List<String>): List<String> = normalizeUrls(types)

    /**
     * Resolve which of [candidates] a webhook is subscribed to. An empty [selected] list is treated as
     * "all events" (the server default for webhooks), matching the web behaviour.
     */
    fun isEventSelected(selected: List<String>, eventType: String): Boolean {
        val norm = normalizeEventTypes(selected)
        return norm.isEmpty() || eventType.trim() in norm
    }

    // --- Push opt-in/opt-out merge (mirrors app/services/push.py resolution) ---

    /**
     * The effective push-enabled event set given the server-declared [defaults] (default-ON),
     * the user's [optOut] of those, and [explicitOptIn] for events off by default:
     *   enabled = (defaults - optOut) ∪ explicitOptIn
     */
    fun mergePushEnabled(
        defaults: Set<String>,
        optOut: Set<String>,
        explicitOptIn: Set<String>,
    ): Set<String> = (defaults - optOut) + explicitOptIn

    /** True iff [event] is push-enabled under the opt-in/opt-out model. */
    fun isPushEnabled(
        event: String,
        defaults: Set<String>,
        optOut: Set<String>,
        explicitOptIn: Set<String>,
    ): Boolean = if (event in defaults) event !in optOut else event in explicitOptIn
}
