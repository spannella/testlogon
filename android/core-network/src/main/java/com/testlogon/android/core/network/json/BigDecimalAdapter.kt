package com.testlogon.android.core.network.json

import com.squareup.moshi.FromJson
import com.squareup.moshi.JsonReader
import com.squareup.moshi.JsonWriter
import com.squareup.moshi.ToJson
import java.math.BigDecimal

/**
 * AND-218 — Moshi adapter for [BigDecimal]. Moshi has no built-in BigDecimal mapping; the purchases
 * `amount` is a JSON number that must decode losslessly (no Double float drift). Reading the raw token
 * source string preserves the exact wire precision (e.g. 19.995 -> BigDecimal("19.995")). Serializing
 * emits the plain (non-exponent) string as a JSON number value.
 *
 * Registered on the production Moshi in core-network's NetworkModule so every BigDecimal-typed DTO field
 * (purchases transaction `amount`) resolves an adapter at the Retrofit converter.
 */
object BigDecimalAdapter {

    @FromJson
    fun fromJson(reader: JsonReader): BigDecimal {
        // nextSource() yields the exact number token bytes -> no Double round-trip. Closed via use{}.
        val raw = reader.nextSource().use { it.readUtf8() }
        return BigDecimal(raw)
    }

    @ToJson
    fun toJson(writer: JsonWriter, value: BigDecimal) {
        // Emit as a JSON number value (not a quoted string) so round-trips stay number-typed.
        writer.value(value)
    }
}
