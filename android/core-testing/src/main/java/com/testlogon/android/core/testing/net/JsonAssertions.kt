package com.testlogon.android.core.testing.net

import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import okhttp3.mockwebserver.RecordedRequest
import org.junit.Assert.assertEquals

private val mapAdapter = Moshi.Builder().build().adapter<Map<String, Any?>>(
    Types.newParameterizedType(Map::class.java, String::class.java, Any::class.java),
)

/** Decodes a recorded request's JSON body into a loosely-typed map (empty map for an empty body). */
fun RecordedRequest.bodyJson(): Map<String, Any?> {
    val raw = body.readUtf8()
    if (raw.isBlank()) return emptyMap()
    return mapAdapter.fromJson(raw) ?: emptyMap()
}

/** Order-insensitive structural JSON equality (parses both via Moshi to a Map). */
fun assertJsonEquals(expected: String, actual: String) {
    assertEquals(mapAdapter.fromJson(expected), mapAdapter.fromJson(actual))
}
