package com.testlogon.android.data.licenses

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class LicensesDomainTest {

    // ---- Issued licenses ----

    @Test
    fun issuedLicenseItem_toDomain_mapsKeyFields() {
        val dto = IssuedLicenseItemDto(
            issuedLicenseId = "lic_42",
            contentId = "content_7",
            licenseeId = "user_9",
            licenseMode = "per_user",
            status = "active",
            createdAt = 1_700_000_000L,
        )

        val domain = dto.toDomain()

        assertEquals("lic_42", domain.id)
        assertEquals("content_7", domain.contentId)
        assertEquals("user_9", domain.licenseeId)
        assertEquals("per_user", domain.licenseMode)
        assertEquals("active", domain.status)
        assertEquals(1_700_000_000L, domain.createdAtSeconds)
    }

    @Test
    fun issuedLicenseList_toDomain_mapsItemsAndCursor() {
        val dto = IssuedLicenseListDto(
            items = listOf(
                IssuedLicenseItemDto(issuedLicenseId = "lic_1", contentId = "c1"),
                IssuedLicenseItemDto(issuedLicenseId = "lic_2", contentId = "c2"),
            ),
            nextCursor = "cursor_issued",
        )

        val page = dto.toDomain()

        assertEquals(2, page.items.size)
        assertEquals("lic_1", page.items[0].id)
        assertEquals("lic_2", page.items[1].id)
        assertEquals("cursor_issued", page.nextCursor)
        assertTrue(!page.isEmpty)
    }

    @Test
    fun issuedLicenseList_toDomain_emptyItems_isEmptyTrue() {
        val page = IssuedLicenseListDto(items = emptyList(), nextCursor = null).toDomain()
        assertTrue(page.isEmpty)
        assertNull(page.nextCursor)
    }

    // ---- License requests ----

    @Test
    fun licenseRequest_toDomain_mapsKeyFieldsAndTerms() {
        val dto = LicenseRequestDto(
            requestId = "req_5",
            contentId = "content_8",
            contentType = "video",
            ownerDisplayName = "Owner Name",
            status = "denied",
            proposedTerms = LicenseTermsDto(
                profitSharePct = 12.5,
                fixedCostCents = 2_500L,
                revenueSharePct = 30.0,
            ),
            denialReason = "Not a fit",
            message = "hello",
            createdAt = 1_700_000_300L,
        )

        val domain = dto.toDomain()

        assertEquals("req_5", domain.id)
        assertEquals("content_8", domain.contentId)
        assertEquals("video", domain.contentType)
        assertEquals("Owner Name", domain.ownerDisplayName)
        assertEquals("denied", domain.status)
        assertEquals("Not a fit", domain.denialReason)
        assertEquals("hello", domain.message)
        assertEquals(1_700_000_300L, domain.createdAtSeconds)
        assertEquals(12.5, domain.terms?.profitSharePct ?: -1.0, 0.0001)
        assertEquals(2_500L, domain.terms?.fixedCostCents)
        assertEquals(30.0, domain.terms?.revenueSharePct ?: -1.0, 0.0001)
    }

    @Test
    fun licenseRequest_toDomain_nullTerms_passesNull() {
        val dto = LicenseRequestDto(requestId = "req_6", proposedTerms = null)
        val domain = dto.toDomain()
        assertNull(domain.terms)
    }

    @Test
    fun licenseRequestList_toDomain_mapsItemsAndCursor() {
        val dto = LicenseRequestListDto(
            items = listOf(
                LicenseRequestDto(requestId = "req_1"),
                LicenseRequestDto(requestId = "req_2"),
            ),
            nextCursor = "cursor_req",
        )

        val page = dto.toDomain()

        assertEquals(2, page.items.size)
        assertEquals("req_1", page.items[0].id)
        assertEquals("cursor_req", page.nextCursor)
        assertTrue(!page.isEmpty)
    }

    // ---- Revenue ----

    @Test
    fun revenueSummary_toDomain_mapsTotals() {
        val dto = RevenueSummaryDto(
            totalCents = 99_999L,
            totalTransactions = 7,
            lastTransactionAt = 1_700_000_400L,
            currency = "EUR",
        )

        val domain = dto.toDomain()

        assertEquals(99_999L, domain.totalCents)
        assertEquals(7, domain.totalTransactions)
        assertEquals(1_700_000_400L, domain.lastTransactionAtSeconds)
        assertEquals("EUR", domain.currency)
    }

    @Test
    fun revenueSummary_toDomain_blankCurrency_defaultsToUsd() {
        val domain = RevenueSummaryDto(currency = "").toDomain()
        assertEquals("USD", domain.currency)
    }

    @Test
    fun revenueTransaction_toDomain_mapsKeyFields() {
        val dto = RevenueTransactionDto(
            txnId = "txn_3",
            contentId = "content_9",
            sourceType = "purchase",
            splitAmountCents = 1_250L,
            splitType = "revenue_share",
            currency = "GBP",
            createdAt = 1_700_000_500L,
        )

        val domain = dto.toDomain()

        assertEquals("txn_3", domain.id)
        assertEquals("content_9", domain.contentId)
        assertEquals("purchase", domain.sourceType)
        assertEquals(1_250L, domain.splitAmountCents)
        assertEquals("revenue_share", domain.splitType)
        assertEquals("GBP", domain.currency)
        assertEquals(1_700_000_500L, domain.createdAtSeconds)
    }

    @Test
    fun revenueList_toDomain_mapsSummaryTransactionsAndCursor() {
        val dto = RevenueListDto(
            summary = RevenueSummaryDto(totalCents = 4_200L, totalTransactions = 3),
            transactions = listOf(
                RevenueTransactionDto(txnId = "txn_1", splitAmountCents = 1_000L),
                RevenueTransactionDto(txnId = "txn_2", splitAmountCents = 3_200L),
            ),
            nextCursor = "cursor_rev",
        )

        val page = dto.toDomain()

        assertEquals(4_200L, page.summary.totalCents)
        assertEquals(3, page.summary.totalTransactions)
        assertEquals(2, page.transactions.size)
        assertEquals("txn_1", page.transactions[0].id)
        assertEquals(3_200L, page.transactions[1].splitAmountCents)
        assertEquals("cursor_rev", page.nextCursor)
        assertTrue(!page.isEmpty)
    }

    @Test
    fun revenueList_toDomain_nullSummary_defaultsToZeroUsdSummary() {
        val page = RevenueListDto(
            summary = null,
            transactions = emptyList(),
            nextCursor = null,
        ).toDomain()

        assertEquals(0L, page.summary.totalCents)
        assertEquals(0, page.summary.totalTransactions)
        assertNull(page.summary.lastTransactionAtSeconds)
        assertEquals("USD", page.summary.currency)
        assertTrue(page.isEmpty)
    }
}
