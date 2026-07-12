package com.testlogon.android.core.network.host

import com.testlogon.android.core.network.SettingsStore
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.Interceptor
import okhttp3.Response
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Rewrites the scheme/host/port of every outgoing request from the runtime [SettingsStore] base
 * URL, leaving path, query, headers, and body untouched.
 *
 * Retrofit keeps a fixed placeholder base URL forever; this interceptor is the sole authority on
 * where bytes actually go, so changing the stored base URL retargets subsequent requests with no
 * Retrofit/OkHttp rebuild. Reads are synchronous and cheap (SettingsStore is SharedPreferences).
 */
@Singleton
class HostSelectionInterceptor @Inject constructor(
    private val settingsStore: SettingsStore,
) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        val base = settingsStore.baseUrl.toHttpUrlOrNull()
            ?: return chain.proceed(request)

        // Already targeting the configured host/port — nothing to do.
        if (request.url.scheme == base.scheme &&
            request.url.host == base.host &&
            request.url.port == base.port
        ) {
            return chain.proceed(request)
        }

        // A request to the configured HOST but a DIFFERENT port is an intentional call to a co-located
        // service (e.g. the local media server for broadcast WHIP/HLS on :8889/:8888); do not retarget it.
        if (request.url.host == base.host && request.url.port != base.port) {
            return chain.proceed(request)
        }

        val rewritten = request.url.newBuilder()
            .scheme(base.scheme)
            .host(base.host)
            .port(base.port)
            .build()
        return chain.proceed(request.newBuilder().url(rewritten).build())
    }
}
