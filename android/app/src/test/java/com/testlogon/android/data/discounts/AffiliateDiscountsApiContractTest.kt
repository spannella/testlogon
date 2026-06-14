package com.testlogon.android.data.discounts

import com.squareup.moshi.Moshi
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-267/269 — contract tests for [AffiliateDiscountsApi] against MockWebServer (real Retrofit/Moshi).
 *
 * Pins the verified shape (src/api/types.ts:AdAffiliateDiscount): the list GET path/verb with NO query
 * params, the per-creative detail GET, DTO -> domain mapping (epoch-second Longs, nullable codes), and
 * sparse-payload defaults. plain Moshi.Builder().build() — the DTO has no BigDecimal field.
 */
class AffiliateDiscountsApiContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun api(): AffiliateDiscountsApi =
        backend.retrofit(moshi).create(AffiliateDiscountsApi::class.java)

    @Test
    fun listDiscounts_path_verb_noQueryParams() = runTest {
        backend.enqueue(Fixtures.okBody(LIST_FULL))
        api().listDiscounts()
        val recorded = backend.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/ads/affiliate/discounts", recorded.requestUrl?.encodedPath)
        assertTrue(recorded.requestUrl?.querySize == 0)
    }

    @Test
    fun listDiscounts_mapsFields() = runTest {
        backend.enqueue(Fixtures.okBody(LIST_FULL))
        val domain = api().listDiscounts().toDomain()

        assertEquals(2, domain.items.size)
        val first = domain.items[0]
        assertEquals("cr_1", first.creativeId)
        assertEquals("cmp_1", first.campaignId)
        assertEquals("usr_a", first.ownerSub)
        assertEquals("AFF50", first.affiliateCode)
        assertEquals("SAVE10", first.promoCode)
        assertEquals("10% off", first.promoValueDisplay)
        assertEquals("https://shop.com/sale", first.clickThroughUrl)
        assertEquals(42L, first.clickCount)
        assertEquals(7L, first.redemptionCount)
        assertEquals(1717230000L, first.createdAtEpochSeconds)
        assertEquals(1717233600L, first.updatedAtEpochSeconds)
        // promo_code preferred for displayCode; share text is the click-through URL.
        assertEquals("SAVE10", first.displayCode)
        assertEquals("https://shop.com/sale", first.shareText())
    }

    @Test
    fun listDiscounts_nullCodes_fallBackToAffiliateCode_andCodeShare() = runTest {
        backend.enqueue(Fixtures.okBody(LIST_FULL))
        val domain = api().listDiscounts().toDomain()
        val second = domain.items[1]
        assertNull(second.promoCode)
        assertNull(second.promoValueDisplay)
        assertNull(second.clickThroughUrl)
        // No promo code -> displayCode falls back to affiliate_code; no URL -> share the code.
        assertEquals("AFFONLY", second.displayCode)
        assertEquals("AFFONLY", second.shareText())
    }

    @Test
    fun listDiscounts_emptyItems_isEmpty() = runTest {
        backend.enqueue(Fixtures.okBody("""{"items":[]}"""))
        val domain = api().listDiscounts().toDomain()
        assertTrue(domain.isEmpty)
    }

    @Test
    fun listDiscounts_sparsePayload_defaultsTolerated() = runTest {
        backend.enqueue(Fixtures.okBody("""{"items":[{"creative_id":"cr_x"}]}"""))
        val domain = api().listDiscounts().toDomain()
        val item = domain.items.single()
        assertEquals("cr_x", item.creativeId)
        assertEquals("", item.campaignId)
        assertEquals(0L, item.clickCount)
        assertEquals(0L, item.redemptionCount)
        assertNull(item.promoCode)
        assertNull(item.displayCode)
        assertNull(item.shareText())
    }

    @Test
    fun getDiscount_path_verb_keyedByCreativeId() = runTest {
        backend.enqueue(Fixtures.okBody(SINGLE))
        val domain = api().getDiscount("cr_1").toDomain()
        val recorded = backend.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/ads/affiliate/creatives/cr_1/discount", recorded.requestUrl?.encodedPath)
        assertEquals("cr_1", domain.creativeId)
        assertEquals("SAVE10", domain.promoCode)
    }

    private companion object {
        val LIST_FULL = """
            {
              "items": [
                {
                  "creative_id": "cr_1", "campaign_id": "cmp_1", "owner_sub": "usr_a",
                  "affiliate_code": "AFF50", "promo_code": "SAVE10",
                  "promo_value_display": "10% off", "click_through_url": "https://shop.com/sale",
                  "click_count": 42, "redemption_count": 7,
                  "created_at": 1717230000, "updated_at": 1717233600
                },
                {
                  "creative_id": "cr_2", "campaign_id": "cmp_2", "owner_sub": "usr_a",
                  "affiliate_code": "AFFONLY",
                  "click_count": 3, "redemption_count": 0,
                  "created_at": 1717230000, "updated_at": 1717230000
                }
              ]
            }
        """.trimIndent()

        val SINGLE = """
            {
              "creative_id": "cr_1", "campaign_id": "cmp_1", "owner_sub": "usr_a",
              "promo_code": "SAVE10", "promo_value_display": "10% off",
              "click_count": 42, "redemption_count": 7,
              "created_at": 1717230000, "updated_at": 1717233600
            }
        """.trimIndent()
    }
}
