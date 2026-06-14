package com.testlogon.android.data.subscriptions

import com.squareup.moshi.Moshi
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-234 — pure DTO -> domain mapping + Moshi round-trip + enum fallbacks. */
class SubscriptionMapperTest {

    private val moshi = Moshi.Builder().build()

    @Test
    fun billingInterval_fromWire_fallsBackToUnknown() {
        assertEquals(BillingInterval.MONTH, BillingInterval.fromWire("month"))
        assertEquals(BillingInterval.YEAR, BillingInterval.fromWire("YEAR"))
        assertEquals(BillingInterval.WEEK, BillingInterval.fromWire("week"))
        assertEquals(BillingInterval.UNKNOWN, BillingInterval.fromWire("fortnight"))
        assertEquals(BillingInterval.UNKNOWN, BillingInterval.fromWire(null))
    }

    @Test
    fun subscriptionState_fromWire_fallsBackToUnknown() {
        assertEquals(SubscriptionState.ACTIVE, SubscriptionState.fromWire("active"))
        assertEquals(SubscriptionState.CANCELED, SubscriptionState.fromWire("cancelled"))
        assertEquals(SubscriptionState.UNKNOWN, SubscriptionState.fromWire("frozen"))
    }

    @Test
    fun plan_toDomain_mapsFlatPriceAndPerks() {
        val dto = SubscriptionPlanDto(
            planId = "plan_basic",
            creatorId = "usr_42",
            name = "Supporter",
            description = "Early access",
            priceCents = 499,
            currency = "usd",
            interval = "month",
            annualPriceCents = 4990,
            status = "active",
            assets = listOf(
                PlanAssetDto(name = "Early access"),
                PlanAssetDto(name = "  "), // blank dropped
                PlanAssetDto(name = null), // null dropped
                PlanAssetDto(name = "Q&A"),
            ),
            createdAt = 1749124800,
            updatedAt = 1749124800,
        )
        val tier = dto.toDomain()
        assertEquals(499L, tier.priceCents)
        assertEquals(BillingInterval.MONTH, tier.interval)
        assertEquals(listOf("Early access", "Q&A"), tier.perks)
        assertTrue(tier.isActive)
    }

    @Test
    fun plan_archivedStatus_isNotActive() {
        val dto = SubscriptionPlanDto(
            planId = "p", creatorId = "c", name = "n", priceCents = 0, currency = "usd",
            interval = "month", status = "archived",
        )
        assertTrue(!dto.toDomain().isActive)
    }

    @Test
    fun subscriptionOut_toDomain_mapsStatusAndEpoch() {
        val dto = SubscriptionOutDto(
            subscriptionId = "sub_1",
            planId = "plan_basic",
            creatorId = "usr_42",
            status = "trialing",
            currentPeriodEnd = 1751716800,
            priceCents = 499,
            currency = "usd",
        )
        val sub = dto.toDomain()
        assertEquals(SubscriptionState.TRIALING, sub.status)
        assertEquals(1751716800L, sub.currentPeriodEndEpochSeconds)
        assertEquals("plan_basic", sub.planId)
    }

    @Test
    fun plan_unknownKeysTolerated_andDecodes() {
        val json = """{"plan_id":"p","creator_id":"c","name":"n","price_cents":100,"currency":"usd",
            "interval":"month","status":"active","server_time":"extra","unknown":true}"""
        val dto = moshi.adapter(SubscriptionPlanDto::class.java).fromJson(json)
        requireNotNull(dto)
        assertEquals("p", dto.planId)
        assertEquals(100L, dto.priceCents)
        assertNull(dto.annualPriceCents)
    }

    @Test
    fun subscribeReq_serializesSnakeCase() {
        val json = moshi.adapter(SubscribeReqDto::class.java)
            .toJson(SubscribeReqDto(interval = "month", discountCode = "PROMO10", trialDays = 7))
        assertTrue(json.contains("\"discount_code\":\"PROMO10\""))
        assertTrue(json.contains("\"trial_days\":7"))
    }
}
