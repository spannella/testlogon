package com.testlogon.android.feature.messaging

import com.testlogon.android.feature.messaging.CryptoTransferModel.CryptoTransfer
import com.testlogon.android.feature.messaging.CryptoTransferModel.Direction
import com.testlogon.android.feature.messaging.CryptoTransferModel.SendValidation
import com.testlogon.android.feature.messaging.CryptoTransferModel.Status
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** EPIC B (FE-110 / FE-111) — pure validation + fiat + direction + status + encode/parse tests. */
class CryptoTransferModelTest {

    private fun card(
        asset: String = "USDC",
        amount: String = "25",
        fromSub: String = "alice",
        toSub: String = "bob",
        status: Status = Status.PENDING,
        memo: String? = null,
    ) = CryptoTransfer(
        asset = asset,
        amount = amount,
        fromSub = fromSub,
        toSub = toSub,
        fromName = "Alice",
        toName = "Bob",
        status = status,
        memo = memo,
    )

    // ---- validateSend ----

    @Test
    fun validate_ok_when_asset_positive_amount_and_sufficient_balance() {
        assertEquals(SendValidation.OK, CryptoTransferModel.validateSend("USDC", "10", 50.0))
    }

    @Test
    fun validate_no_asset_when_asset_blank_or_null() {
        assertEquals(SendValidation.NO_ASSET, CryptoTransferModel.validateSend(null, "10", 50.0))
        assertEquals(SendValidation.NO_ASSET, CryptoTransferModel.validateSend("  ", "10", 50.0))
    }

    @Test
    fun validate_non_positive_for_zero_negative_or_garbage() {
        assertEquals(SendValidation.NON_POSITIVE, CryptoTransferModel.validateSend("ETH", "0", 5.0))
        assertEquals(SendValidation.NON_POSITIVE, CryptoTransferModel.validateSend("ETH", "-1", 5.0))
        assertEquals(SendValidation.NON_POSITIVE, CryptoTransferModel.validateSend("ETH", "abc", 5.0))
    }

    @Test
    fun validate_insufficient_only_when_balance_known_and_overspent() {
        assertEquals(SendValidation.INSUFFICIENT, CryptoTransferModel.validateSend("ETH", "6", 5.0))
        // Unknown balance never blocks on funds.
        assertEquals(SendValidation.OK, CryptoTransferModel.validateSend("ETH", "6", null))
    }

    @Test
    fun send_validation_ok_flag_matches_enum() {
        assertTrue(SendValidation.OK.ok)
        assertFalse(SendValidation.NO_ASSET.ok)
        assertFalse(SendValidation.NON_POSITIVE.ok)
        assertFalse(SendValidation.INSUFFICIENT.ok)
    }

    // ---- fiatEquivalentCents ----

    @Test
    fun fiat_equivalent_for_stablecoin_is_amount_times_100() {
        assertEquals(2_500L, CryptoTransferModel.fiatEquivalentCents("USDC", "25"))
    }

    @Test
    fun fiat_equivalent_uses_reference_price_and_rounds() {
        // 0.5 ETH * 2500 = 1250.00 -> 125000 cents
        assertEquals(125_000L, CryptoTransferModel.fiatEquivalentCents("ETH", "0.5"))
        // case-insensitive symbol
        assertEquals(125_000L, CryptoTransferModel.fiatEquivalentCents("eth", "0.5"))
    }

    @Test
    fun fiat_equivalent_null_for_unknown_asset_or_bad_amount() {
        assertNull(CryptoTransferModel.fiatEquivalentCents("DOGE", "10"))
        assertNull(CryptoTransferModel.fiatEquivalentCents("USDC", "0"))
        assertNull(CryptoTransferModel.fiatEquivalentCents(null, "10"))
    }

    // ---- direction + status ----

    @Test
    fun direction_is_sent_for_sender_received_otherwise() {
        val c = card(fromSub = "alice", toSub = "bob")
        assertEquals(Direction.SENT, CryptoTransferModel.transferDirection(c, "alice"))
        assertEquals(Direction.RECEIVED, CryptoTransferModel.transferDirection(c, "bob"))
        assertEquals(Direction.RECEIVED, CryptoTransferModel.transferDirection(c, null))
    }

    @Test
    fun status_labels_and_wire_roundtrip() {
        assertEquals("Pending", CryptoTransferModel.statusLabel(Status.PENDING))
        assertEquals("Completed", CryptoTransferModel.statusLabel(Status.COMPLETE))
        assertEquals("Failed", CryptoTransferModel.statusLabel(Status.FAILED))
        assertEquals(Status.COMPLETE, Status.fromWire("complete"))
        assertEquals(Status.PENDING, Status.fromWire("garbage"))
    }

    // ---- preview ----

    @Test
    fun preview_is_directional() {
        val c = card(asset = "USDC", amount = "25", fromSub = "alice", toSub = "bob")
        assertEquals("[Sent 25 USDC]", CryptoTransferModel.preview(c, "alice"))
        assertEquals("[Received 25 USDC]", CryptoTransferModel.preview(c, "bob"))
    }

    @Test
    fun preview_for_body_null_when_not_a_card() {
        assertNull(CryptoTransferModel.previewForBody("just a normal message", "alice"))
        assertNull(CryptoTransferModel.previewForBody(null, "alice"))
    }

    // ---- encode / parse ----

    @Test
    fun encode_then_parse_roundtrips_all_fields() {
        val c = card(asset = "ETH", amount = "1.25", status = Status.COMPLETE, memo = "for lunch")
        val body = CryptoTransferModel.encode(c)
        assertTrue(CryptoTransferModel.isCard(body))
        val parsed = CryptoTransferModel.parse(body)!!
        assertEquals(c, parsed)
    }

    @Test
    fun parse_survives_reserved_characters_in_values() {
        val c = card(memo = "a;b=c%d\ne")
        val parsed = CryptoTransferModel.parse(CryptoTransferModel.encode(c))!!
        assertEquals("a;b=c%d\ne", parsed.memo)
    }

    @Test
    fun parse_returns_null_for_non_card_or_wrong_kind() {
        assertNull(CryptoTransferModel.parse(null))
        assertNull(CryptoTransferModel.parse("hello"))
        // right sentinel, wrong kind
        assertNull(CryptoTransferModel.parse(CryptoTransferModel.SENTINEL + "market_card;asset=X"))
        assertFalse(CryptoTransferModel.isCard("hello"))
    }

    @Test
    fun parse_requires_asset_and_amount() {
        assertNull(CryptoTransferModel.parse(CryptoTransferModel.SENTINEL + "crypto_transfer;from=a;to=b"))
    }

    @Test
    fun crypto_sentinel_is_distinct_from_trading_card_sentinel() {
        // A trading card body must NOT parse as a crypto transfer and vice-versa.
        val trading = TradingCardModel.encode(TradingCardModel.MarketCard(1, "BTCUSDC"))
        assertNull(CryptoTransferModel.parse(trading))
        val xfer = CryptoTransferModel.encode(card())
        assertNull(TradingCardModel.parse(xfer))
    }
}
