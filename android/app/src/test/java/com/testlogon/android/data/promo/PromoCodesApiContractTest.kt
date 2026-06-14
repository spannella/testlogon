package com.testlogon.android.data.promo

import com.squareup.moshi.Moshi
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-266 — contract tests for [PromoCodesApi] against MockWebServer (real Retrofit/Moshi).
 * Asserts exact paths/verbs/bodies: list (no query), create (PromoCodeCreateIn), redeem ({code_id,...}
 * NOT {code}), deactivate (DELETE /{code_id}).
 */
class PromoCodesApiContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun api(): PromoCodesApi = backend.retrofit(moshi).create(PromoCodesApi::class.java)

    @Test
    fun list_path_verb_noQueryParams() = runTest {
        backend.enqueue(Fixtures.okBody(LIST_RESP))
        val codes = api().list().toDomain()
        val recorded = backend.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/promo-codes", recorded.requestUrl?.encodedPath)
        assertTrue(recorded.requestUrl?.querySize == 0)
        assertEquals(1, codes.size)
        assertEquals("SUMMER25", codes[0].code)
        assertEquals(DiscountType.PERCENTAGE, codes[0].discountType)
        assertEquals(25, codes[0].discountValue)
        assertEquals(12, codes[0].currentUses)
        assertEquals(100, codes[0].maxUses)
    }

    @Test
    fun create_path_verb_body() = runTest {
        backend.enqueue(Fixtures.okBody(CREATE_RESP, code = 201))
        api().create(
            CreatePromoRequestDto(
                code = "SUMMER25",
                discountType = "percentage",
                discountValue = 25,
                maxUses = 100,
            ),
        )
        val recorded = backend.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/promo-codes", recorded.requestUrl?.encodedPath)
        val body = recorded.bodyJson()
        assertEquals("SUMMER25", body["code"])
        assertEquals("percentage", body["discount_type"])
        // numbers decode as Double via the loosely-typed map.
        assertEquals(25.0, body["discount_value"])
    }

    @Test
    fun redeem_path_verb_body_usesCodeIdNotCode() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true,"redeemed_at":1788307200}"""))
        val resp = api().redeem(
            RedeemPromoRequestDto(
                codeId = "pc_1",
                originalPriceCents = 1000,
                finalPriceCents = 750,
                checkoutType = "subscription",
            ),
        ).toDomain()
        val recorded = backend.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/promo-codes/redeem", recorded.requestUrl?.encodedPath)
        val body = recorded.bodyJson()
        assertEquals("pc_1", body["code_id"])
        assertEquals(1000.0, body["original_price_cents"])
        assertEquals("subscription", body["checkout_type"])
        assertNull(body["code"])
        assertTrue(resp.ok)
    }

    @Test
    fun deactivate_path_verb() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true,"code_id":"pc_1","active":false}"""))
        api().deactivate("pc_1")
        val recorded = backend.takeRequest()
        assertEquals("DELETE", recorded.method)
        assertEquals("/ui/promo-codes/pc_1", recorded.requestUrl?.encodedPath)
    }

    private companion object {
        val LIST_RESP = """
            {
              "items": [
                {
                  "code_id": "pc_1", "code": "SUMMER25", "discount_type": "percentage",
                  "discount_value": 25, "free_trial_days": 0, "applies_to": ["subscription"],
                  "min_purchase_cents": 0, "max_uses": 100, "max_uses_per_user": 1,
                  "current_uses": 12, "active": true, "expires_at": 1788307200,
                  "created_at": 1780308000, "creator_user_id": "usr_1"
                }
              ],
              "next_cursor": null
            }
        """.trimIndent()

        val CREATE_RESP = """
            { "code_id": "pc_1", "code": "SUMMER25", "discount_type": "percentage", "discount_value": 25,
              "max_uses": 100, "current_uses": 0, "active": true }
        """.trimIndent()
    }
}
