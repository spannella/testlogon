package com.testlogon.android.data.payments

import java.net.URI
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-231 — PURE return-URL parser. Uses [java.net.URI] + manual query splitting (NOT android.net.Uri)
 * so it is fully JVM-unit-testable and free of any Android framework dependency (gotcha: android.net.Uri
 * parsing lives only in the Activity/handler, never here).
 *
 * Recognized return shapes (app-defined contract; AND-231 §5, finalized by AND-228/229):
 *   - custom scheme dev fallback: `testlogon://payments/return?provider=paypal&intent=...&status=success`
 *   - App Link prod host:         `https://<host>/app/billing/return/<provider>/<success|cancel|failure>?intent=...`
 *
 * Outcome classification (FR-3): a trailing path segment (`success|cancel|pending|failure`) wins; else
 * the `status` query param; else UNKNOWN. The parser is param-tolerant and provider-keyed.
 */
@Singleton
class PaymentReturnParser @Inject constructor(
    private val providers: Set<@JvmSuppressWildcards PaymentProvider>,
) {

    /** Returns null when [url] is not a recognized billing-return URL (so other deep links can run). */
    fun parse(url: String): PaymentReturn? {
        val uri = runCatching { URI(url) }.getOrNull() ?: return null
        val scheme = uri.scheme?.lowercase() ?: return null

        val isCustomScheme = scheme == CUSTOM_SCHEME &&
            (uri.host?.lowercase() == CUSTOM_HOST || url.removePrefix("$scheme://").startsWith("$CUSTOM_HOST/"))
        val isAppLink = (scheme == "https" || scheme == "http") &&
            pathOf(uri).startsWith(APP_LINK_PREFIX)
        if (!isCustomScheme && !isAppLink) return null

        val query = parseQuery(uri.rawQuery)
        val segments = pathOf(uri).split('/').filter { it.isNotBlank() }

        val provider = resolveProvider(segments, query) ?: return null
        val outcome = resolveOutcome(segments, query)

        return PaymentReturn(
            provider = provider,
            outcome = outcome,
            intentId = query["intent"] ?: query["intent_id"] ?: query["session_id"]
                ?: query["checkout_session_id"] ?: query["order_id"],
            state = query["state"],
            providerRef = query["token"] ?: query["tx"] ?: query["correlation_id"]
                ?: query["transaction_id"] ?: query["PayerID"],
            errorCode = query["error"] ?: query["error_code"],
            errorMessage = query["error_description"] ?: query["message"],
            rawUri = url,
        )
    }

    /** The full registered provider set is exposed so AND-228/229 callers build matching return URLs. */
    val registeredProviders: Set<PaymentProvider> get() = providers

    private fun resolveProvider(segments: List<String>, query: Map<String, String>): String? {
        query["provider"]?.let { p -> providers.firstOrNull { it.id == p }?.let { return it.id } }
        // App Link form: .../return/<provider>/<outcome> — provider is the segment after "return".
        val returnIdx = segments.indexOf(RETURN_SEGMENT)
        if (returnIdx >= 0 && returnIdx + 1 < segments.size) {
            val seg = segments[returnIdx + 1]
            providers.firstOrNull { it.id == seg || it.returnPathSegment == seg }?.let { return it.id }
        }
        // Custom scheme form: testlogon://payments/return?provider=... handled above; also accept
        // testlogon://payments/<provider>/<outcome>.
        segments.firstOrNull { seg -> providers.any { it.id == seg } }?.let { return it }
        return null
    }

    private fun resolveOutcome(segments: List<String>, query: Map<String, String>): PaymentOutcome {
        val last = segments.lastOrNull()?.lowercase()
        outcomeFromToken(last)?.let { return it }
        return outcomeFromToken(query["status"]?.lowercase()) ?: PaymentOutcome.UNKNOWN
    }

    private fun outcomeFromToken(token: String?): PaymentOutcome? = when (token) {
        "success", "succeeded", "completed", "approved" -> PaymentOutcome.SUCCESS
        "cancel", "cancelled", "canceled" -> PaymentOutcome.CANCEL
        "pending", "processing", "in_progress" -> PaymentOutcome.PENDING
        "failure", "failed", "declined", "error" -> PaymentOutcome.FAILURE
        else -> null
    }

    private fun pathOf(uri: URI): String = uri.path ?: ""

    /** Manual query split (no android.net.Uri); decodes `+` and `%XX` via a small percent-decoder. */
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
        const val CUSTOM_HOST = "payments"
        const val RETURN_SEGMENT = "return"
        const val APP_LINK_PREFIX = "/app/billing/return"
        /** Canonical custom-scheme return base used by providers to build their return_url. */
        const val RETURN_URL_BASE = "testlogon://payments/return"
    }
}
