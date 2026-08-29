package com.testlogon.android.feature.messaging

import com.testlogon.android.feature.messaging.TradingCardModel.Disclosure
import com.testlogon.android.feature.messaging.TradingCardModel.PositionField
import com.testlogon.android.feature.messaging.TradingCardModel.RawPosition
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** FE-101 / FE-102 — pure disclosure + preview + payload-parse tests (no Android runtime). */
class TradingCardModelTest {

    private fun raw() = RawPosition(
        symbolId = 1,
        symbol = "BTCUSDC",
        owner = "Ada",
        side = "buy",
        qty = 5,
        entryPrice = 60_000,
        markPrice = 61_000,
        liquidationPrice = 45_000,
        unrealizedPnl = 5_000,
        pnlPct = 1.67,
        roiPct = 12.5,
    )

    @Test
    fun full_disclosure_permits_every_field() {
        val f = TradingCardModel.permittedFields(Disclosure.FULL)
        assertEquals(PositionField.values().toSet(), f)
    }

    @Test
    fun pnlPct_disclosure_permits_only_side_and_pnlPct() {
        val f = TradingCardModel.permittedFields(Disclosure.PNL_PCT)
        assertEquals(setOf(PositionField.SIDE, PositionField.PNL_PCT), f)
    }

    @Test
    fun roi_disclosure_permits_only_side_and_roiPct() {
        val f = TradingCardModel.permittedFields(Disclosure.ROI)
        assertEquals(setOf(PositionField.SIDE, PositionField.ROI_PCT), f)
    }

    @Test
    fun project_full_keeps_all_values() {
        val c = TradingCardModel.project(raw(), Disclosure.FULL)
        assertEquals("buy", c.side)
        assertEquals(5L, c.qty)
        assertEquals(60_000L, c.entryPrice)
        assertEquals(61_000L, c.markPrice)
        assertEquals(45_000L, c.liquidationPrice)
        assertEquals(5_000L, c.unrealizedPnl)
        assertEquals(1.67, c.pnlPct!!, 1e-9)
        assertEquals(12.5, c.roiPct!!, 1e-9)
        assertTrue(c.isLong == true)
    }

    @Test
    fun project_pnlPct_withholds_absolute_amounts() {
        val c = TradingCardModel.project(raw(), Disclosure.PNL_PCT)
        // permitted
        assertEquals("buy", c.side)
        assertEquals(1.67, c.pnlPct!!, 1e-9)
        // withheld — must never leak
        assertNull(c.qty)
        assertNull(c.entryPrice)
        assertNull(c.markPrice)
        assertNull(c.liquidationPrice)
        assertNull(c.unrealizedPnl)
        assertNull(c.roiPct)
    }

    @Test
    fun project_roi_withholds_everything_except_side_and_roi() {
        val c = TradingCardModel.project(raw(), Disclosure.ROI)
        assertEquals("buy", c.side)
        assertEquals(12.5, c.roiPct!!, 1e-9)
        assertNull(c.pnlPct)
        assertNull(c.qty)
        assertNull(c.entryPrice)
        assertNull(c.markPrice)
        assertNull(c.liquidationPrice)
        assertNull(c.unrealizedPnl)
    }

    @Test
    fun withheld_fields_are_absent_from_the_encoded_payload() {
        // A ROI share encoded to the wire must not contain entry/qty/liq/upnl keys at all.
        val wire = TradingCardModel.encode(TradingCardModel.project(raw(), Disclosure.ROI))
        assertFalse(wire.contains("entry="))
        assertFalse(wire.contains("qty="))
        assertFalse(wire.contains("liq="))
        assertFalse(wire.contains("upnl="))
        assertFalse(wire.contains("pnlpct="))
        assertTrue(wire.contains("roipct="))
    }

    @Test
    fun market_preview_strings() {
        assertEquals("[Market: BTCUSDC]", TradingCardModel.marketPreview("BTCUSDC"))
        assertEquals("[Position: ETHUSDC]", TradingCardModel.positionPreview("ETHUSDC"))
    }

    @Test
    fun market_card_round_trips_through_encode_parse() {
        val original = TradingCardModel.MarketCard(symbolId = 3, symbol = "SOLUSDC")
        val wire = TradingCardModel.encode(original)
        assertTrue(TradingCardModel.isCard(wire))
        val parsed = TradingCardModel.parse(wire)
        assertEquals(original, parsed)
        assertEquals("[Market: SOLUSDC]", TradingCardModel.previewForBody(wire))
    }

    @Test
    fun position_card_round_trips_and_preserves_disclosure() {
        val original = TradingCardModel.project(raw(), Disclosure.PNL_PCT)
        val wire = TradingCardModel.encode(original)
        val parsed = TradingCardModel.parse(wire) as TradingCardModel.PositionCard
        assertEquals(Disclosure.PNL_PCT, parsed.disclosure)
        assertEquals("Ada", parsed.owner)
        assertEquals("buy", parsed.side)
        assertEquals(1.67, parsed.pnlPct!!, 1e-9)
        assertNull(parsed.entryPrice)
        assertEquals("[Position: BTCUSDC]", TradingCardModel.previewForBody(wire))
    }

    @Test
    fun plain_text_body_is_not_a_card_and_has_no_preview() {
        assertFalse(TradingCardModel.isCard("hello world"))
        assertNull(TradingCardModel.parse("hello world"))
        assertNull(TradingCardModel.previewForBody("hello world"))
        assertNull(TradingCardModel.parse(null))
    }

    @Test
    fun owner_with_reserved_chars_round_trips() {
        // A ; or = in a name must not corrupt the key/value framing.
        val original = TradingCardModel.project(raw().copy(owner = "a;b=c%d"), Disclosure.FULL)
        val parsed = TradingCardModel.parse(TradingCardModel.encode(original)) as TradingCardModel.PositionCard
        assertEquals("a;b=c%d", parsed.owner)
    }

    @Test
    fun malformed_card_body_parses_to_null() {
        assertNull(TradingCardModel.parse(TradingCardModel.SENTINEL + "market_card;sym=BTC")) // no sid
        assertNull(TradingCardModel.parse(TradingCardModel.SENTINEL + "bogus_kind;sid=1;sym=BTC"))
    }

    @Test
    fun disclosure_fromWire_defaults_to_full() {
        assertEquals(Disclosure.FULL, Disclosure.fromWire(null))
        assertEquals(Disclosure.FULL, Disclosure.fromWire("nonsense"))
        assertEquals(Disclosure.ROI, Disclosure.fromWire("roi"))
    }
}
