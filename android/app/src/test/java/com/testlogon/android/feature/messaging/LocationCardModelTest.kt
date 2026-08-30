package com.testlogon.android.feature.messaging

import com.testlogon.android.feature.messaging.LocationCardModel.LocationCard
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** EPIC D (FE-130) - pure validate/build/encode/parse round-trip + URL builders + preview tests. */
class LocationCardModelTest {

    @Test
    fun valid_lat_lng_bounds() {
        assertTrue(LocationCardModel.isValidLatLng(0.0, 0.0))
        assertTrue(LocationCardModel.isValidLatLng(-90.0, 180.0))
        assertTrue(LocationCardModel.isValidLatLng(90.0, -180.0))
        assertFalse(LocationCardModel.isValidLatLng(90.1, 0.0))
        assertFalse(LocationCardModel.isValidLatLng(0.0, 180.1))
        assertFalse(LocationCardModel.isValidLatLng(Double.NaN, 0.0))
        assertFalse(LocationCardModel.isValidLatLng(0.0, Double.POSITIVE_INFINITY))
    }

    @Test
    fun build_collapses_blank_label_and_place() {
        val c = LocationCardModel.build(1.0, 2.0, "   ", "")
        assertNull(c.label)
        assertNull(c.placeName)
        val d = LocationCardModel.build(1.0, 2.0, "  Home  ", "  1 Main St ")
        assertEquals("Home", d.label)
        assertEquals("1 Main St", d.placeName)
    }

    @Test
    fun format_coords_5dp() {
        assertEquals("37.77490, -122.41940", LocationCardModel.formatCoords(37.7749, -122.4194))
        assertEquals("0.00000, 0.00000", LocationCardModel.formatCoords(0.0, 0.0))
    }

    @Test
    fun encode_parse_round_trips_all_fields() {
        val c = LocationCard(37.7749, -122.4194, "Home", "1 Market St, SF")
        val body = LocationCardModel.encode(c)
        assertTrue(body.startsWith(LocationCardModel.SENTINEL))
        val back = LocationCardModel.parse(body)!!
        assertEquals(c.lat, back.lat, 0.0)
        assertEquals(c.lng, back.lng, 0.0)
        assertEquals("Home", back.label)
        assertEquals("1 Market St, SF", back.placeName)
    }

    @Test
    fun encode_parse_round_trips_delimiter_hostile_label() {
        // label + place with the reserved delimiters ; = % and a comma and unicode - must round-trip.
        val c = LocationCard(1.5, -3.25, "a;b=c%d, e", "Cafe; \"El Nino\" = 100% ok")
        val body = LocationCardModel.encode(c)
        val back = LocationCardModel.parse(body)!!
        assertEquals("a;b=c%d, e", back.label)
        assertEquals("Cafe; \"El Nino\" = 100% ok", back.placeName)
    }

    @Test
    fun encode_parse_round_trips_unicode_label() {
        val c = LocationCard(48.8566, 2.3522, "Cafe de Flore", "Paris")
        val back = LocationCardModel.parse(LocationCardModel.encode(c))!!
        assertEquals("Cafe de Flore", back.label)
    }

    @Test
    fun encode_omits_null_label_and_place() {
        val c = LocationCard(10.0, 20.0, null, null)
        val body = LocationCardModel.encode(c)
        assertFalse(body.contains("label="))
        assertFalse(body.contains("place="))
        val back = LocationCardModel.parse(body)!!
        assertNull(back.label)
        assertNull(back.placeName)
    }

    @Test
    fun parse_non_card_body_is_null() {
        assertNull(LocationCardModel.parse(null))
        assertNull(LocationCardModel.parse("hello world"))
        assertNull(LocationCardModel.parse("TLSHOP1:product_card;item=x"))
    }

    @Test
    fun parse_rejects_out_of_range_or_missing_coords() {
        assertNull(LocationCardModel.parse(LocationCardModel.SENTINEL + "lat=99.0;lng=0.0"))
        assertNull(LocationCardModel.parse(LocationCardModel.SENTINEL + "lat=abc;lng=0.0"))
        assertNull(LocationCardModel.parse(LocationCardModel.SENTINEL + "lng=0.0"))
    }

    @Test
    fun is_card_pre_check() {
        assertTrue(LocationCardModel.isCard(LocationCardModel.SENTINEL + "lat=1.0;lng=2.0"))
        assertFalse(LocationCardModel.isCard("nope"))
        assertFalse(LocationCardModel.isCard(null))
    }

    @Test
    fun maps_open_url_uses_coords_when_no_label() {
        assertEquals(
            "https://www.google.com/maps/search/?api=1&query=37.7749%2C-122.4194",
            LocationCardModel.mapsOpenUrl(37.7749, -122.4194),
        )
    }

    @Test
    fun maps_open_url_encodes_label_and_coords() {
        val url = LocationCardModel.mapsOpenUrl(1.0, 2.0, "The Cafe")
        assertTrue(url.startsWith("https://www.google.com/maps/search/?api=1&query="))
        assertTrue(url.contains("The%20Cafe"))
        assertTrue(url.contains("1.0%2C2.0"))
    }

    @Test
    fun directions_and_geo_uri() {
        assertEquals(
            "https://www.google.com/maps/dir/?api=1&destination=1.0%2C2.0",
            LocationCardModel.directionsUrl(1.0, 2.0),
        )
        assertEquals("geo:1.0,2.0", LocationCardModel.geoUri(1.0, 2.0))
    }

    @Test
    fun static_map_thumb_url_defaults_and_marker() {
        val url = LocationCardModel.staticMapThumbUrl(1.5, 2.5)
        assertTrue(url.startsWith("https://staticmap.openstreetmap.de/staticmap.php"))
        assertTrue(url.contains("center=1.5,2.5"))
        assertTrue(url.contains("zoom=15"))
        assertTrue(url.contains("size=320x160"))
        assertTrue(url.contains("markers=1.5,2.5,red"))
    }

    @Test
    fun preview_prefers_label_then_place_then_generic() {
        assertEquals("${LocationCardModel.PIN} Home", LocationCardModel.locationPreview("Home", "1 Main St"))
        assertEquals("${LocationCardModel.PIN} 1 Main St", LocationCardModel.locationPreview(" ", "1 Main St"))
        assertEquals("${LocationCardModel.PIN} Location", LocationCardModel.locationPreview(null, null))
    }

    @Test
    fun preview_for_body_masks_sentinel() {
        val body = LocationCardModel.encode(LocationCard(1.0, 2.0, "Office", null))
        assertEquals("${LocationCardModel.PIN} Office", LocationCardModel.previewForBody(body))
        assertNull(LocationCardModel.previewForBody("plain text"))
    }
}
