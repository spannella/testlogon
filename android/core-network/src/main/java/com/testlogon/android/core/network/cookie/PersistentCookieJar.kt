package com.testlogon.android.core.network.cookie

import android.content.Context
import android.content.SharedPreferences
import dagger.hilt.android.qualifiers.ApplicationContext
import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.HttpUrl
import org.json.JSONException
import org.json.JSONObject
import javax.inject.Inject
import javax.inject.Singleton

/**
 * A persistent [CookieJar] backed by [SharedPreferences].
 *
 * - Captures every `Set-Cookie` ([saveFromResponse]) and replays the matching subset on each
 *   request ([loadForRequest]), delegating RFC 6265 domain/path/secure matching to OkHttp's
 *   [Cookie.matches].
 * - Persists cookies as JSON (name/value/domain/path/expiresAt/secure/httpOnly/hostOnly) and
 *   restores them lazily on first access, so an authenticated session survives process death.
 * - Evicts expired cookies from both memory and storage.
 * - Exposes [clear] for logout and [currentCookie] so the CSRF interceptor can read `ui_csrf`.
 *
 * The store is plaintext SharedPreferences (per scope); encrypting at rest is a follow-up.
 */
@Singleton
class PersistentCookieJar @Inject constructor(
    @ApplicationContext context: Context,
) : CookieJar {

    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    // Keyed by name|domain|path; guarded by `lock`.
    private val cache = LinkedHashMap<String, Cookie>()
    private val lock = Any()

    @Volatile
    private var restored = false

    private fun ensureRestored() {
        if (restored) return
        synchronized(lock) {
            if (restored) return
            val now = System.currentTimeMillis()
            for ((key, raw) in prefs.all) {
                val json = raw as? String ?: continue
                val cookie = decode(json) ?: continue
                if (cookie.expiresAt <= now) {
                    prefs.edit().remove(key).apply()
                } else {
                    cache[key] = cookie
                }
            }
            restored = true
        }
    }

    override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
        ensureRestored()
        val toPersist = mutableMapOf<String, Cookie>()
        val toRemove = mutableListOf<String>()
        synchronized(lock) {
            for (cookie in cookies) {
                val key = keyFor(cookie)
                if (cookie.expiresAt <= System.currentTimeMillis()) {
                    cache.remove(key)
                    toRemove += key
                } else {
                    cache[key] = cookie
                    if (cookie.persistent) toPersist[key] = cookie
                }
            }
        }
        if (toPersist.isNotEmpty() || toRemove.isNotEmpty()) {
            prefs.edit().apply {
                toRemove.forEach { remove(it) }
                toPersist.forEach { (k, c) -> putString(k, encode(c)) }
            }.apply()
        }
    }

    override fun loadForRequest(url: HttpUrl): List<Cookie> {
        ensureRestored()
        val now = System.currentTimeMillis()
        val expiredKeys = mutableListOf<String>()
        val matches: List<Cookie>
        synchronized(lock) {
            val iterator = cache.entries.iterator()
            val out = ArrayList<Cookie>()
            while (iterator.hasNext()) {
                val entry = iterator.next()
                val cookie = entry.value
                if (cookie.expiresAt <= now) {
                    iterator.remove()
                    expiredKeys += entry.key
                    continue
                }
                if (cookie.matches(url)) out += cookie
            }
            matches = out
        }
        if (expiredKeys.isNotEmpty()) {
            prefs.edit().apply { expiredKeys.forEach { remove(it) } }.apply()
        }
        return matches
    }

    /** Returns the live cookie [name] that would be sent for [url], or null. */
    fun currentCookie(name: String, url: HttpUrl): Cookie? =
        loadForRequest(url).firstOrNull { it.name == name }

    /** Wipes all cookies from memory and storage. Synchronous (logout path). */
    fun clear() {
        synchronized(lock) { cache.clear() }
        prefs.edit().clear().commit()
    }

    private fun encode(cookie: Cookie): String = JSONObject().apply {
        put("name", cookie.name)
        put("value", cookie.value)
        put("expiresAt", cookie.expiresAt)
        put("domain", cookie.domain)
        put("path", cookie.path)
        put("secure", cookie.secure)
        put("httpOnly", cookie.httpOnly)
        put("hostOnly", cookie.hostOnly)
    }.toString()

    private fun decode(json: String): Cookie? = try {
        val obj = JSONObject(json)
        val builder = Cookie.Builder()
            .name(obj.getString("name"))
            .value(obj.getString("value"))
            .expiresAt(obj.getLong("expiresAt"))
            .path(obj.getString("path"))
        val domain = obj.getString("domain")
        if (obj.getBoolean("hostOnly")) builder.hostOnlyDomain(domain) else builder.domain(domain)
        if (obj.getBoolean("secure")) builder.secure()
        if (obj.getBoolean("httpOnly")) builder.httpOnly()
        builder.build()
    } catch (_: JSONException) {
        null
    } catch (_: IllegalArgumentException) {
        null
    }

    companion object {
        private const val PREFS_NAME = "tl_cookie_jar"

        fun keyFor(cookie: Cookie): String = "${cookie.name}|${cookie.domain}|${cookie.path}"
    }
}
