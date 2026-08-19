package com.testlogon.android.data.exchange

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Mapper unit tests for [PricesDto.toDomain] -> [PriceMap], the reference-USD-price map used to
 * FX-normalize Portfolio balances. Covers: string-priced values parsed to Double, key upper-casing +
 * case-insensitive lookup, dropping of non-numeric / non-positive / blank-key entries, the stub flag
 * (explicit and via source=="stub"), the quote default, and the 404 unavailable fallback.
 */
class PriceMapMapperTest {

    @Test
    fun toDomain_parsesStringPricesAndUppercasesKeys() {
        val pm = PricesDto(
            prices = mapOf("btc" to "65000.5", "ETH" to "3200", "usdc" to "1.00"),
            quote = "USD",
            source = "coingecko",
            stub = false,
            note = "live",
        ).toDomain()

        assertTrue(pm.hasPrices)
        assertFalse(pm.unavailable)
        assertFalse(pm.stub)
        assertEquals("USD", pm.quote)
        // keys normalized to upper-case
        assertEquals(65000.5, pm.prices["BTC"]!!, 0.0001)
        assertEquals(3200.0, pm.prices["ETH"]!!, 0.0001)
        // lookup is case-insensitive / trims
        assertEquals(1.0, pm.priceFor(" usdc ")!!, 0.0001)
        assertEquals(65000.5, pm.priceFor("Btc")!!, 0.0001)
        assertNull(pm.priceFor("SOL"))
        assertNull(pm.priceFor(null))
    }

    @Test
    fun toDomain_dropsInvalidNonPositiveAndBlankEntries() {
        val pm = PricesDto(
            prices = mapOf(
                "BTC" to "not-a-number",
                "ETH" to "0",       // non-positive dropped
                "SOL" to "-5",      // negative dropped
                "" to "10",         // blank key dropped
                "USDC" to " 1.0 ",  // trimmed + kept
            ),
        ).toDomain()

        assertEquals(1, pm.prices.size)
        assertEquals(1.0, pm.priceFor("USDC")!!, 0.0001)
        assertNull(pm.priceFor("BTC"))
        assertNull(pm.priceFor("ETH"))
    }

    @Test
    fun toDomain_stubFlaggedByExplicitFlagOrSource() {
        val byFlag = PricesDto(prices = mapOf("BTC" to "1"), stub = true, source = "reference").toDomain()
        assertTrue(byFlag.stub)

        val bySource = PricesDto(prices = mapOf("BTC" to "1"), source = "stub").toDomain()
        assertTrue(bySource.stub)
    }

    @Test
    fun toDomain_defaultsQuoteToUsdWhenMissing() {
        val pm = PricesDto(prices = mapOf("BTC" to "1"), quote = null).toDomain()
        assertEquals("USD", pm.quote)
    }

    @Test
    fun unavailable_hasNoPricesAndFallsBack() {
        val pm = PriceMap.unavailable()
        assertTrue(pm.unavailable)
        assertFalse(pm.hasPrices)
        assertNull(pm.priceFor("BTC"))
    }
}
