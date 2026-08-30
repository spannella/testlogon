package com.testlogon.android.feature.ads.create.campaign

import com.testlogon.android.feature.ads.create.campaign.PromoteTargetingMath.PromoteCampaignDraft
import com.testlogon.android.feature.ads.create.campaign.PromoteTargetingMath.PromoteEntityKind
import com.testlogon.android.feature.ads.create.campaign.PromoteTargetingMath.SelectedSegments
import com.testlogon.android.feature.ads.create.campaign.PromoteTargetingMath.buildPromotePayload
import com.testlogon.android.feature.ads.create.campaign.PromoteTargetingMath.buildTargetingPayload
import com.testlogon.android.feature.ads.create.campaign.PromoteTargetingMath.formatEstimatedReach
import com.testlogon.android.feature.ads.create.campaign.PromoteTargetingMath.summarizeTargeting
import com.testlogon.android.feature.ads.create.campaign.PromoteTargetingMath.validatePromoteCampaign
import com.testlogon.android.feature.ads.create.campaign.PromoteTargetingMath.withPromoteEntity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * FE-162 - pure unit tests for [PromoteTargetingMath], mirroring the web promoteTargeting.test.ts cases
 * (entity kinds, segment presets, opt-in note, payload build + drop-empties, promote descriptor, validation,
 * summary opt-in suffix, reach formatting) plus the Android-only entity-id attach helper.
 */
class PromoteTargetingMathTest {

    @Test
    fun `entity kinds are the three expected with labels`() {
        assertEquals(
            listOf(PromoteEntityKind.MARKET, PromoteEntityKind.CREATOR_TOKEN, PromoteEntityKind.PRODUCT),
            PromoteTargetingMath.PROMOTE_ENTITY_KINDS,
        )
        PromoteTargetingMath.PROMOTE_ENTITY_KINDS.forEach { assertTrue(it.label.isNotBlank()) }
        assertEquals(PromoteEntityKind.MARKET, PromoteEntityKind.fromWire("market"))
        assertEquals(PromoteEntityKind.CREATOR_TOKEN, PromoteEntityKind.fromWire("creator_token"))
        assertNull(PromoteEntityKind.fromWire("nope"))
    }

    @Test
    fun `segment preset lists are non-empty and countries carry code plus label`() {
        assertTrue(PromoteTargetingMath.SEGMENT_AGE_RANGES.isNotEmpty())
        assertTrue(PromoteTargetingMath.SEGMENT_GENDERS.isNotEmpty())
        assertTrue(PromoteTargetingMath.SEGMENT_DEVICE_TYPES.isNotEmpty())
        assertTrue(PromoteTargetingMath.SEGMENT_CONTENT_CATEGORIES.isNotEmpty())
        assertTrue(PromoteTargetingMath.SEGMENT_COUNTRIES.isNotEmpty())
        val us = PromoteTargetingMath.SEGMENT_COUNTRIES.first { it.code == "US" }
        assertEquals("United States", us.label)
    }

    @Test
    fun `opt-in note mentions personalization`() {
        assertTrue(PromoteTargetingMath.RESPECTS_OPT_IN_NOTE.lowercase().contains("opted into personalization"))
    }

    @Test
    fun `buildTargetingPayload drops empty arrays and unset fields`() {
        val body = buildTargetingPayload(
            SelectedSegments(ageRanges = emptyList(), genders = emptyList(), countryCodes = emptyList()),
        )
        assertEquals("Default", body.name)
        assertNull(body.ageRanges)
        assertNull(body.genders)
        assertNull(body.countryCodes)
        assertNull(body.deviceTypes)
        assertNull(body.contentCategories)
        assertEquals(false, body.newUserOnly)
    }

    @Test
    fun `buildTargetingPayload keeps non-empty segments and trims name`() {
        val body = buildTargetingPayload(
            SelectedSegments(
                name = "  Q3 push  ",
                countryCodes = listOf("US", "CA"),
                ageRanges = listOf("18-24"),
                deviceTypes = emptyList(),
                newUserOnly = true,
            ),
        )
        assertEquals("Q3 push", body.name)
        assertEquals(listOf("US", "CA"), body.countryCodes)
        assertEquals(listOf("18-24"), body.ageRanges)
        assertNull(body.deviceTypes)
        assertEquals(true, body.newUserOnly)
    }

    @Test
    fun `buildTargetingPayload omits new_user_only when false and defaults blank name`() {
        val body = buildTargetingPayload(SelectedSegments(name = "   ", newUserOnly = false))
        assertEquals("Default", body.name)
        assertEquals(false, body.newUserOnly)
    }

    @Test
    fun `buildPromotePayload builds descriptor and trims id`() {
        val payload = buildPromotePayload(PromoteEntityKind.MARKET, "  sym-42 ")
        assertEquals("market", payload.promoteKind)
        assertEquals("sym-42", payload.promoteEntityId)
    }

    @Test
    fun `withPromoteEntity attaches id to the matching list`() {
        val base = buildTargetingPayload(SelectedSegments())
        val market = withPromoteEntity(base, PromoteEntityKind.MARKET, " m1 ")
        assertEquals(listOf("m1"), market.marketIds)
        assertNull(market.tokenIds)

        val token = withPromoteEntity(base, PromoteEntityKind.CREATOR_TOKEN, "t1")
        assertEquals(listOf("t1"), token.tokenIds)

        val product = withPromoteEntity(base, PromoteEntityKind.PRODUCT, "p1")
        assertEquals(listOf("p1"), product.productIds)
    }

    @Test
    fun `withPromoteEntity leaves body unchanged for null kind or blank id`() {
        val base = buildTargetingPayload(SelectedSegments())
        assertEquals(base, withPromoteEntity(base, null, "m1"))
        assertEquals(base, withPromoteEntity(base, PromoteEntityKind.MARKET, "   "))
    }

    @Test
    fun `validatePromoteCampaign passes a complete draft`() {
        val errs = validatePromoteCampaign(
            PromoteCampaignDraft(name = "Launch", budgetCents = 5000L, kind = PromoteEntityKind.PRODUCT, entityId = "item-1"),
        )
        assertTrue(errs.isEmpty())
    }

    @Test
    fun `validatePromoteCampaign collects every missing or invalid field`() {
        val errs = validatePromoteCampaign(
            PromoteCampaignDraft(name = "  ", budgetCents = 50L, kind = null, entityId = ""),
        )
        assertEquals(4, errs.size)
        assertTrue(errs.any { it.contains("name", ignoreCase = true) })
        assertTrue(errs.any { it.contains("budget", ignoreCase = true) })
        assertTrue(errs.any { it.contains("promote", ignoreCase = true) })
        assertTrue(errs.any { it.contains("item", ignoreCase = true) })
    }

    @Test
    fun `summarizeTargeting always appends opt-in suffix`() {
        assertEquals("Everyone - opt-in only", summarizeTargeting(null))
        assertEquals("Everyone - opt-in only", summarizeTargeting(buildTargetingPayload(SelectedSegments())))
    }

    @Test
    fun `summarizeTargeting joins the set segments`() {
        val body = buildTargetingPayload(
            SelectedSegments(
                countryCodes = listOf("US"),
                ageRanges = listOf("18-24", "25-34"),
                deviceTypes = listOf("mobile"),
            ),
        )
        assertEquals("US, 18-24, 25-34, mobile - opt-in only", summarizeTargeting(body))
    }

    @Test
    fun `summarizeTargeting includes new users flag`() {
        val body = buildTargetingPayload(SelectedSegments(newUserOnly = true))
        assertEquals("new users - opt-in only", summarizeTargeting(body))
    }

    @Test
    fun `formatEstimatedReach formats small thousands millions`() {
        assertEquals("0", formatEstimatedReach(0))
        assertEquals("999", formatEstimatedReach(999))
        assertEquals("1.2K", formatEstimatedReach(1234))
        assertEquals("2.5M", formatEstimatedReach(2_500_000))
    }

    @Test
    fun `formatEstimatedReach guards against negatives`() {
        assertEquals("0", formatEstimatedReach(-5))
    }
}
