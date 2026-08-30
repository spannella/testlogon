package com.testlogon.android.feature.messaging

import java.util.Locale

/**
 * EPIC D (FE-130, BE-130 post / BE-133 reverse-geocode) - pure, dependency-free model for the
 * location chat card. Kept Android-free so payload build/validate/encode/parse, coord formatting, the
 * maps deep-links, the static-map thumbnail URL and the preview are all JVM-unit-testable in isolation
 * (LocationCardModelTest).
 *
 * TRANSPORT (mirrors EcomCardModel / CryptoTransferModel / TradingCardModel - the 4th chat-card
 * sentinel): the card rides on a NORMAL text message. The structured payload is encoded into the body
 * behind the rare SENTINEL tag; MessageDto.toMedia parses it back to a card and renders it, falling
 * through to a plain text bubble when the body is not a card (so an un-upgraded client just shows text).
 *
 * Encoding: SENTINEL + key=value pairs joined by ";". Reserved chars (";", "=", "%", newline) are
 * percent-escaped so any user-facing value (labels/place names with ";" , "," , unicode) round-trips.
 *
 * Field names match the WEB contract (frontend/src/lib/locationCards.ts): lat/lng/label/place_name +
 * the same maps URLs (keyless OpenStreetMap static map; Google Maps search/directions deep links).
 */
object LocationCardModel {

    const val SENTINEL: String = "TLLOC1:"

    /** A visible location pin marker used in previews (emoji, unicode-escaped for source safety). */
    const val PIN: String = "📍"

    data class LocationCard(
        val lat: Double,
        val lng: Double,
        val label: String?,
        val placeName: String?,
    )

    /** Valid WGS84 coordinate: finite, lat in [-90,90], lng in [-180,180]. */
    fun isValidLatLng(lat: Double, lng: Double): Boolean =
        lat.isFinite() && lng.isFinite() && lat >= -90.0 && lat <= 90.0 && lng >= -180.0 && lng <= 180.0

    fun build(lat: Double, lng: Double, label: String?, placeName: String?): LocationCard =
        LocationCard(
            lat = lat,
            lng = lng,
            label = label?.trim()?.takeIf { it.isNotBlank() },
            placeName = placeName?.trim()?.takeIf { it.isNotBlank() },
        )

    /** e.g. "37.77490, -122.41940" - fixed 5dp (~1.1m precision). */
    fun formatCoords(lat: Double, lng: Double): String =
        String.format(Locale.US, "%.5f, %.5f", lat, lng)

    fun mapsOpenUrl(lat: Double, lng: Double, label: String? = null): String {
        val coords = "$lat,$lng"
        val q = label?.trim()?.takeIf { it.isNotEmpty() }?.let { "$it ($coords)" } ?: coords
        return "https://www.google.com/maps/search/?api=1&query=" + urlEncode(q)
    }

    fun directionsUrl(lat: Double, lng: Double): String =
        "https://www.google.com/maps/dir/?api=1&destination=" + urlEncode("$lat,$lng")

    /** RFC 5870 geo: URI. */
    fun geoUri(lat: Double, lng: Double): String = "geo:$lat,$lng"

    /**
     * Keyless static-map thumbnail URL (OpenStreetMap community service, no API key) with a red marker.
     * The renderer falls back to a pin placeholder onError so an outage / 404 never breaks the card.
     */
    fun staticMapThumbUrl(lat: Double, lng: Double, w: Int = 320, h: Int = 160, zoom: Int = 15): String {
        val center = "$lat,$lng"
        return "https://staticmap.openstreetmap.de/staticmap.php" +
            "?center=$center&zoom=$zoom&size=${w}x$h&markers=$center,red"
    }

    /** Conversation-list / reply preview: pin + label, else pin + "Location". */
    fun locationPreview(label: String?, placeName: String?): String {
        val name = (label?.trim()?.takeIf { it.isNotBlank() } ?: placeName?.trim()?.takeIf { it.isNotBlank() })
        return if (name != null) "$PIN $name" else "$PIN Location"
    }

    fun preview(card: LocationCard): String = locationPreview(card.label, card.placeName)

    fun previewForBody(body: String?): String? = parse(body)?.let { preview(it) }

    fun isCard(body: String?): Boolean = body != null && body.startsWith(SENTINEL)

    fun encode(card: LocationCard): String {
        val sb = StringBuilder(SENTINEL)
        sb.append(kv("lat", card.lat.toString()))
        sb.append(SEP).append(kv("lng", card.lng.toString()))
        card.label?.takeIf { it.isNotBlank() }?.let { sb.append(SEP).append(kv("label", it)) }
        card.placeName?.takeIf { it.isNotBlank() }?.let { sb.append(SEP).append(kv("place", it)) }
        return sb.toString()
    }

    /**
     * Parse a message body into a LocationCard, or null when not a well-formed card. Out-of-range or
     * unparsable coords are rejected (null) so a bad body degrades to a plain text bubble.
     */
    fun parse(body: String?): LocationCard? {
        if (body == null || !body.startsWith(SENTINEL)) return null
        val payload = body.substring(SENTINEL.length)
        val map = HashMap<String, String>()
        for (seg in payload.split(SEP)) {
            val eq = seg.indexOf(EQ)
            if (eq <= 0) continue
            map[unescape(seg.substring(0, eq))] = unescape(seg.substring(eq + 1))
        }
        val lat = map["lat"]?.toDoubleOrNull() ?: return null
        val lng = map["lng"]?.toDoubleOrNull() ?: return null
        if (!isValidLatLng(lat, lng)) return null
        return LocationCard(
            lat = lat,
            lng = lng,
            label = map["label"]?.takeIf { it.isNotBlank() },
            placeName = map["place"]?.takeIf { it.isNotBlank() },
        )
    }

    private const val SEP: Char = ';'
    private const val EQ: Char = '='

    private fun kv(k: String, v: String): String = escape(k) + "=" + escape(v)

    private fun escape(s: String): String {
        val sb = StringBuilder(s.length)
        for (c in s) {
            when (c) {
                '%' -> sb.append("%25")
                ';' -> sb.append("%3B")
                '=' -> sb.append("%3D")
                '\n' -> sb.append("%0A")
                '\r' -> sb.append("%0D")
                else -> sb.append(c)
            }
        }
        return sb.toString()
    }

    private fun unescape(s: String): String {
        if (s.indexOf('%') < 0) return s
        val sb = StringBuilder(s.length)
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c == '%' && i + 2 < s.length) {
                val code = s.substring(i + 1, i + 3).toIntOrNull(16)
                if (code != null) { sb.append(code.toChar()); i += 3; continue }
            }
            sb.append(c); i++
        }
        return sb.toString()
    }

    /** Minimal URL query-component encoder (pure; no android/java.net dependency needed). */
    private fun urlEncode(s: String): String {
        val sb = StringBuilder(s.length)
        for (c in s) {
            when {
                c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || c == '-' || c == '_' || c == '.' || c == '~' ->
                    sb.append(c)
                else -> for (b in c.toString().toByteArray(Charsets.UTF_8)) {
                    sb.append('%').append(String.format(Locale.US, "%02X", b.toInt() and 0xFF))
                }
            }
        }
        return sb.toString()
    }
}
