package com.testlogon.android.data.earnings

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** AND-251 — pure mapper + money-invariant tests (no network). */
class EarningsMapperTest {

    @Test
    fun category_lenientMapping_unknownToOther() {
        assertEquals(EarningsCategory.TIP, EarningsCategory.from("tips"))
        assertEquals(EarningsCategory.SUBSCRIPTION, EarningsCategory.from("subscription"))
        assertEquals(EarningsCategory.VOD_PURCHASE, EarningsCategory.from("vod_purchase"))
        assertEquals(EarningsCategory.UNLOCK, EarningsCategory.from("unlocks"))
        assertEquals(EarningsCategory.OTHER, EarningsCategory.from("chargeback"))
        assertEquals(EarningsCategory.OTHER, EarningsCategory.from(null))
    }

    @Test
    fun transactions_mapsAndSurfacesCursor_lastPageNull() {
        val page1 = EarningsTransactionsDto(
            items = listOf(
                EarningsTransactionDto(entryId = "e1", ts = 1746057600, amountCents = 999, category = "tips"),
                EarningsTransactionDto(entryId = "e2", ts = 1746057700, amountCents = 500, category = "weird"),
            ),
            nextCursor = "CUR1",
        ).toDomain()
        assertEquals("CUR1", page1.nextCursor)
        assertEquals(2, page1.items.size)
        assertEquals(EarningsCategory.TIP, page1.items[0].category)
        assertEquals(EarningsCategory.OTHER, page1.items[1].category)
        assertEquals("weird", page1.items[1].rawCategory)
        assertEquals(999L, page1.items[0].amount.cents)

        val lastPage = EarningsTransactionsDto(items = emptyList(), nextCursor = null).toDomain()
        assertNull(lastPage.nextCursor)
    }

    @Test
    fun epochDayParsing_validVsDegraded() {
        assertEquals(20574L, "2026-05-01".toEpochDayOrNull())
        assertNull("2026-W18".toEpochDayOrNull())
        assertNull("2026-05".toEpochDayOrNull())
        assertNull("not-a-date".toEpochDayOrNull())
        assertNull("".toEpochDayOrNull())
    }
}
