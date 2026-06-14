package com.testlogon.android.data.catalog

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.Moshi
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-204 — pure Moshi (de)serialization fidelity for the catalog DTOs: snake_case mapping, money as
 * Long with no float drift (incl. > 2^53), required-field fail-fast, unknown-key tolerance, empty
 * collection defaults, and null next_token.
 */
class CatalogDtoRoundTripTest {

    private val moshi: Moshi = Moshi.Builder().build()
    private val itemAdapter = moshi.adapter(CatalogItemDto::class.java)
    private val categoryAdapter = moshi.adapter(CatalogCategoryDto::class.java)
    private val itemListAdapter = moshi.adapter(CatalogItemListDto::class.java)

    @Test
    fun item_roundTrip_snakeCase_and_money() {
        val json = """
            {"category_id":"c","item_id":"itm_1","name":"Tee","price_cents":1999,"currency":"USD",
             "image_urls":["http://h/1.png"],"attributes":{"size":"M"},
             "created_at":"2026-01-02T10:00:00Z","updated_at":"2026-05-01T00:00:00Z"}
        """.trimIndent()
        val item = itemAdapter.fromJson(json)!!
        assertEquals("itm_1", item.itemId)
        assertEquals(1999L, item.priceCents)
        assertEquals("USD", item.currency)
        val reSerialized = itemAdapter.toJson(item)
        assertTrue(reSerialized.contains("\"price_cents\""))
        assertTrue(reSerialized.contains("\"item_id\""))
        assertTrue(reSerialized.contains("\"image_urls\""))
        // No camelCase wire keys leak.
        assertTrue(!reSerialized.contains("\"priceCents\""))
        assertTrue(!reSerialized.contains("\"itemId\""))
    }

    @Test
    fun money_largeValue_noFloatDrift() {
        val big = 9007199254740993L // > 2^53
        val json = """
            {"category_id":"c","item_id":"i","name":"n","price_cents":$big,"currency":"USD",
             "image_urls":[],"attributes":{},"created_at":"t","updated_at":"t"}
        """.trimIndent()
        val item = itemAdapter.fromJson(json)!!
        assertEquals(big, item.priceCents)
    }

    @Test
    fun missingRequired_throws() {
        val json = """{"category_id":"c","name":"n","price_cents":1,"currency":"USD","image_urls":[],"attributes":{},"created_at":"t","updated_at":"t"}"""
        assertThrows(JsonDataException::class.java) { itemAdapter.fromJson(json) }
    }

    @Test
    fun unknownKeys_tolerated_defaults_applied() {
        val json = """
            {"category_id":"c","item_id":"i","name":"n","price_cents":1,"currency":"USD",
             "created_at":"t","updated_at":"t","unexpected":42}
        """.trimIndent()
        val item = itemAdapter.fromJson(json)!!
        assertTrue(item.imageUrls.isEmpty())
        assertTrue(item.attributes.isEmpty())
        assertEquals("unlimited", item.stockStatus)
        assertEquals(5, item.lowStockThreshold)
    }

    @Test
    fun category_roundTrip_optionalNulls() {
        val json = """{"category_id":"c","name":"Books","created_at":"2026-01-02T03:04:05Z"}"""
        val cat = categoryAdapter.fromJson(json)!!
        assertEquals("c", cat.categoryId)
        assertNull(cat.description)
        assertNull(cat.creatorId)
    }

    @Test
    fun list_emptyItems_and_nullToken() {
        val page = itemListAdapter.fromJson("""{"items":[]}""")!!
        assertTrue(page.items.isEmpty())
        assertNull(page.nextToken)
    }

    // AND-206/209: domain mapping — attributes stringified, null values dropped, order preserved.
    @Test
    fun toDomain_attributes_stringified_nullsDropped_orderPreserved() {
        val json = """
            {"category_id":"c","item_id":"i","name":"n","price_cents":1,"currency":"USD",
             "image_urls":["a.png","b.png"],
             "attributes":{"color":"black","rank":3,"missing":null,"featured":true},
             "stock_count":4,"stock_status":"low_stock","created_at":"t","updated_at":"t"}
        """.trimIndent()
        val domain = itemAdapter.fromJson(json)!!.toDomain()
        // null-valued "missing" dropped; remaining preserved in wire order.
        assertEquals(
            listOf("color" to "black", "rank" to "3.0", "featured" to "true"),
            domain.attributes,
        )
        assertEquals("a.png", domain.thumbnailUrl)
        assertEquals(4, domain.stockCount)
        assertEquals("low_stock", domain.stockStatus)
    }
}
