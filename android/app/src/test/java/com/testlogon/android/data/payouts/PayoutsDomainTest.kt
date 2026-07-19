package com.testlogon.android.data.payouts

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * AND-258/260 — pure DTO -> domain mapping: full payout maps losslessly (epoch-second Longs, Money
 * cents+currency), every status string folds to the right enum (+ UNKNOWN fallback), method normalizes,
 * balance defaults apply, and list order + nextCursor are preserved.
 */
class PayoutsDomainTest {

    @Test
    fun payoutDto_mapsAllFields_withSuppliedCurrency() {
        val dto = PayoutDto(
            payoutId = "po_1029",
            userId = "usr_77",
            amountCents = 4500,
            method = "bank_transfer",
            status = "completed",
            createdAt = 1_748_628_251,
            updatedAt = 1_748_800_800,
            completedAt = 1_748_800_800,
            notes = "n",
            rejectReason = "",
            approvedBy = "admin_3",
        )
        val domain = dto.toDomain("EUR")
        assertEquals("po_1029", domain.payoutId)
        assertEquals(4500L, domain.amount.cents)
        assertEquals("EUR", domain.amount.currency)
        assertEquals(PayoutStatus.COMPLETED, domain.status)
        assertEquals(1_748_628_251L, domain.createdAtEpochSeconds)
        assertEquals(1_748_800_800L, domain.completedAtEpochSeconds)
        assertEquals("admin_3", domain.approvedBy)
        assertEquals(PayoutMethodType.BANK_TRANSFER, domain.methodType)
        // displayEpochSeconds prefers completed_at.
        assertEquals(1_748_800_800L, domain.displayEpochSeconds)
    }

    @Test
    fun payoutDto_nullCompletedAt_defaultsCurrencyUsd_displayFallsBackToCreated() {
        val dto = PayoutDto(payoutId = "po_1", status = "requested", createdAt = 100, updatedAt = 200, completedAt = null)
        val domain = dto.toDomain()
        assertNull(domain.completedAtEpochSeconds)
        assertEquals("USD", domain.amount.currency)
        assertEquals(100L, domain.displayEpochSeconds)
    }

    @Test
    fun status_mapsEveryKnownVariant_andUnknownFallback() {
        assertEquals(PayoutStatus.REQUESTED, PayoutStatus.from("requested"))
        assertEquals(PayoutStatus.REQUESTED, PayoutStatus.from("pending"))
        assertEquals(PayoutStatus.APPROVED, PayoutStatus.from("approved"))
        assertEquals(PayoutStatus.PROCESSING, PayoutStatus.from("processing"))
        assertEquals(PayoutStatus.COMPLETED, PayoutStatus.from("completed"))
        // PAY: the program split PAID (rail settled) from COMPLETED — "paid"/"succeeded" -> PAID now.
        assertEquals(PayoutStatus.PAID, PayoutStatus.from("paid"))
        assertEquals(PayoutStatus.PAID, PayoutStatus.from("succeeded"))
        assertEquals(PayoutStatus.REJECTED, PayoutStatus.from("rejected"))
        assertEquals(PayoutStatus.CANCELLED, PayoutStatus.from("cancelled"))
        assertEquals(PayoutStatus.CANCELLED, PayoutStatus.from("canceled"))
        assertEquals(PayoutStatus.UNKNOWN, PayoutStatus.from("weird_new_state"))
        assertEquals(PayoutStatus.UNKNOWN, PayoutStatus.from(null))
    }

    @Test
    fun method_normalizes_withUnknownFallback() {
        assertEquals(PayoutMethodType.BANK_TRANSFER, PayoutMethodType.from("bank_transfer"))
        assertEquals(PayoutMethodType.PAYPAL, PayoutMethodType.from("paypal"))
        assertEquals(PayoutMethodType.CARD, PayoutMethodType.from("card"))
        assertEquals(PayoutMethodType.UNKNOWN, PayoutMethodType.from("crypto"))
    }

    @Test
    fun balanceDto_mapsAllSixFields() {
        val balance = PayoutBalanceDto(
            availableCents = 4500,
            pendingCents = 1200,
            totalEarnedCents = 98000,
            holdCents = 0,
            currency = "USD",
            minimumPayoutCents = 1000,
        ).toDomain()
        assertEquals(4500L, balance.availableCents)
        assertEquals(1200L, balance.pendingCents)
        assertEquals(98000L, balance.totalEarnedCents)
        assertEquals(1000L, balance.minimumPayoutCents)
        assertEquals("USD", balance.currency)
    }

    @Test
    fun balanceDto_emptyDefaults() {
        val balance = PayoutBalanceDto().toDomain()
        assertEquals(0L, balance.availableCents)
        assertEquals(1000L, balance.minimumPayoutCents)
        assertEquals("USD", balance.currency)
    }

    @Test
    fun listDto_preservesOrder_andNextCursor() {
        val page = PayoutListDto(
            items = listOf(
                PayoutDto(payoutId = "po_1", status = "completed"),
                PayoutDto(payoutId = "po_2", status = "requested"),
            ),
            nextCursor = "c2",
        ).toDomain()
        assertEquals(listOf("po_1", "po_2"), page.items.map { it.payoutId })
        assertEquals("c2", page.nextCursor)
    }

    @Test
    fun listDto_empty_isSuccessWithNullCursor() {
        val page = PayoutListDto().toDomain()
        assertEquals(0, page.items.size)
        assertNull(page.nextCursor)
    }

    @Test
    fun moneyPrecision_isLong_noFloatLoss() {
        val big = PayoutDto(payoutId = "po", status = "completed", amountCents = 2_147_483_648L).toDomain()
        assertEquals(2_147_483_648L, big.amount.cents)
    }

    @Test
    fun createResp_and_actionResp_map() {
        val create = PayoutCreateRespDto(ok = true, payoutId = "po_1", amountCents = 5000, status = "pending")
            .toDomain("USD")
        assertEquals("po_1", create.payoutId)
        assertEquals(5000L, create.amount.cents)
        assertEquals(PayoutStatus.REQUESTED, create.status)

        val action = PayoutActionRespDto(ok = true, payoutId = "po_1", status = "cancelled").toDomain()
        assertEquals(PayoutStatus.CANCELLED, action.status)
    }
}
