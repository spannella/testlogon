package com.testlogon.android.navigation.applink

import android.util.Log
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-396 — structured App Link telemetry seam (§10).
 *
 * Events carry path TEMPLATES (e.g. `/videos/{videoId}`) and host only — NEVER raw ids, query
 * strings, or full URLs at info level (SEC-5). The default implementation logs at debug only; a real
 * analytics backend can replace the Hilt binding later without touching the router.
 */
interface DeepLinkTelemetry {
    /** A VIEW intent arrived. [source] is "cold" or "warm". */
    fun received(host: String?, pathTemplate: String, source: String)

    /** A link resolved to a navigable route. */
    fun resolved(routeName: String, requiredAuth: Boolean)

    /** An authed link was buffered while logged out. */
    fun deferredAuth(pathTemplate: String)

    /** A buffered authed link resumed after a successful session finalize. */
    fun resumedAfterAuth(pathTemplate: String)

    /** Host matched but the path was unknown -> Home fallback. */
    fun unhandled(host: String?, pathTemplate: String)

    /** Not parseable / non-allowlisted host. */
    fun malformed()
}

/** Debug-level no-PII default. Path templates only; never the raw URL/query. */
@Singleton
class LogcatDeepLinkTelemetry @Inject constructor() : DeepLinkTelemetry {
    override fun received(host: String?, pathTemplate: String, source: String) =
        d("received host=$host template=$pathTemplate source=$source")

    override fun resolved(routeName: String, requiredAuth: Boolean) =
        d("resolved route=$routeName requiredAuth=$requiredAuth")

    override fun deferredAuth(pathTemplate: String) = d("deferred_auth template=$pathTemplate")

    override fun resumedAfterAuth(pathTemplate: String) = d("resumed_after_auth template=$pathTemplate")

    override fun unhandled(host: String?, pathTemplate: String) =
        d("unhandled host=$host template=$pathTemplate")

    override fun malformed() = d("malformed")

    private fun d(msg: String) {
        Log.d(TAG, msg)
    }

    private companion object {
        const val TAG = "DeepLinkTelemetry"
    }
}
