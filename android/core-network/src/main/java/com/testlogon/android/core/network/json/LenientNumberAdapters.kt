package com.testlogon.android.core.network.json

import com.squareup.moshi.FromJson
import com.squareup.moshi.JsonQualifier
import com.squareup.moshi.JsonReader
import com.squareup.moshi.JsonWriter
import com.squareup.moshi.ToJson

/**
 * Helpdesk FAIL #3 / #4 (B-HELP-SHAPE) — defensive lenient numeric adapters for the support-ticket media
 * fields (`size_bytes` / `width` / `height`).
 *
 * ROOT CAUSE the app must survive: a Decimal stored in an UNTYPED dict on the backend can be serialized by
 * FastAPI's encoder as a JSON STRING (e.g. `"size_bytes":"10"`). The generated Moshi adapter for a plainly
 * `Long?` / `Int?` field then throws `JsonDataException` (expected a number, was a string) -> the whole
 * `SupportTicketDto` fails to parse -> `GET /tickets` drops EVERY row whenever any ticket carries media, and
 * the `POST /tickets/{id}/close` `{ticket}` envelope is unparseable ("We received an unexpected response").
 *
 * Even though the backend now coerces these to ints, the CLIENT must never empty the whole list / fail an
 * action because a single nested numeric came across as a quoted string (or an empty string). These adapters
 * accept a JSON number, a numeric string, an empty string (-> null), or null; on write they emit a plain
 * number (or null). Applied via the [LenientLong] / [LenientInt] qualifiers on the affected DTO fields and
 * registered on the production Moshi in NetworkModule (before the reflective factory).
 */
@Retention(AnnotationRetention.RUNTIME)
@JsonQualifier
annotation class LenientLong

@Retention(AnnotationRetention.RUNTIME)
@JsonQualifier
annotation class LenientInt

object LenientNumberAdapters {

    @FromJson
    @LenientLong
    fun longFromJson(reader: JsonReader): Long? = readLenientNumber(reader)?.toLong()

    @ToJson
    fun longToJson(writer: JsonWriter, @LenientLong value: Long?) {
        if (value == null) writer.nullValue() else writer.value(value)
    }

    @FromJson
    @LenientInt
    fun intFromJson(reader: JsonReader): Int? = readLenientNumber(reader)?.toInt()

    @ToJson
    fun intToJson(writer: JsonWriter, @LenientInt value: Int?) {
        if (value == null) writer.nullValue() else writer.value(value)
    }

    /**
     * Reads a value that may be a JSON number, a JSON string (possibly empty), or null, and returns a Long
     * or null. Never throws on a string/number mismatch; a non-numeric/blank string -> null. A fractional
     * number is truncated toward zero (size/width/height are whole; tolerate a stray decimal).
     */
    private fun readLenientNumber(reader: JsonReader): Long? {
        return when (reader.peek()) {
            JsonReader.Token.NULL -> {
                reader.nextNull<Unit>()
                null
            }
            JsonReader.Token.NUMBER -> {
                // Read the raw token to tolerate a fractional/large value without Double drift surprises.
                val raw = reader.nextSource().use { it.readUtf8() }.trim()
                raw.toLongOrNull() ?: raw.toDoubleOrNull()?.toLong()
            }
            JsonReader.Token.STRING -> {
                val s = reader.nextString().trim()
                if (s.isEmpty()) null else s.toLongOrNull() ?: s.toDoubleOrNull()?.toLong()
            }
            else -> {
                // Anything unexpected (e.g. a bool/object) is skipped rather than thrown.
                reader.skipValue()
                null
            }
        }
    }
}
