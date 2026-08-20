package com.testlogon.android.feature.markets

import com.testlogon.android.data.exchange.Instrument
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the pure [classesForSymbol] / [matchesTab] classifier that backs the unified,
 * class-filtered symbol picker. No Android or network dependency — pure JVM.
 */
class InstrumentClassTest {

    private fun inst(
        symbol: String = "BTCUSDC",
        id: Int = 1,
        perp: Boolean = false,
        fundingIntervalS: Long = 0,
    ) = Instrument(
        symbol = symbol,
        symbolId = id,
        priceScaler = 1,
        lotSize = 1,
        referencePrice = 0,
        isPerpetual = perp,
        fundingIntervalS = fundingIntervalS,
    )

    @Test
    fun spot_isOnlySpot() {
        val classes = classesForSymbol(inst(perp = false), isPrediction = false)
        assertEquals(setOf(InstrumentClass.SPOT), classes)
    }

    @Test
    fun perp_withFunding_isPerpAndFunding() {
        val classes = classesForSymbol(inst(perp = true, fundingIntervalS = 3600), isPrediction = false)
        assertEquals(setOf(InstrumentClass.PERP, InstrumentClass.FUNDING), classes)
    }

    @Test
    fun perp_withoutFundingInterval_isPerpOnly_notFunding() {
        val classes = classesForSymbol(inst(perp = true, fundingIntervalS = 0), isPrediction = false)
        assertTrue(classes.contains(InstrumentClass.PERP))
        assertFalse(classes.contains(InstrumentClass.FUNDING))
    }

    @Test
    fun predictionFlag_addsPrediction_ontoBaseClass() {
        val spotPm = classesForSymbol(inst(perp = false), isPrediction = true)
        assertEquals(setOf(InstrumentClass.SPOT, InstrumentClass.PREDICTION), spotPm)

        val perpPm = classesForSymbol(inst(perp = true, fundingIntervalS = 28800), isPrediction = true)
        assertEquals(
            setOf(InstrumentClass.PERP, InstrumentClass.FUNDING, InstrumentClass.PREDICTION),
            perpPm,
        )
    }

    @Test
    fun spot_isNeverPerpOrFunding() {
        val classes = classesForSymbol(inst(perp = false, fundingIntervalS = 3600), isPrediction = false)
        // Even if a stray funding interval leaks onto a non-perp, FUNDING is gated on isPerpetual.
        assertFalse(classes.contains(InstrumentClass.PERP))
        assertFalse(classes.contains(InstrumentClass.FUNDING))
    }

    @Test
    fun matchesTab_all_matchesEverything() {
        val spot = inst(perp = false)
        assertTrue(matchesTab(spot, isPrediction = false, MarketClassTab.All))
    }

    @Test
    fun matchesTab_concreteClass_filtersCorrectly() {
        val perp = inst(perp = true, fundingIntervalS = 3600)
        assertTrue(matchesTab(perp, false, MarketClassTab.Of(InstrumentClass.PERP)))
        assertTrue(matchesTab(perp, false, MarketClassTab.Of(InstrumentClass.FUNDING)))
        assertFalse(matchesTab(perp, false, MarketClassTab.Of(InstrumentClass.SPOT)))
        assertFalse(matchesTab(perp, false, MarketClassTab.Of(InstrumentClass.PREDICTION)))
        assertTrue(matchesTab(perp, true, MarketClassTab.Of(InstrumentClass.PREDICTION)))
    }

    @Test
    fun tabRow_hasAllPlusEveryClass_inOrder() {
        assertEquals(1 + InstrumentClass.entries.size, MARKET_CLASS_TABS.size)
        assertTrue(MARKET_CLASS_TABS.first() is MarketClassTab.All)
        val classTabs = MARKET_CLASS_TABS.filterIsInstance<MarketClassTab.Of>().map { it.clazz }
        assertEquals(InstrumentClass.entries.toList(), classTabs)
        assertEquals(listOf("All", "Spot", "Perp", "Prediction", "Funding"), MARKET_CLASS_TABS.map { it.label })
    }
}
