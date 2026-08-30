package com.testlogon.android.feature.tradingdocs

import com.testlogon.android.data.tradingdocs.TradingDocument
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** FE-170 — pure JVM tests for the trading-documents grouping/labelling/filename helpers. */
class TradingDocsMathTest {

    private fun doc(
        docId: String = "d1",
        type: String = "statement",
        title: String? = null,
        taxYear: Int? = null,
        periodStart: Long? = null,
        format: String = "pdf",
        sizeBytes: Long? = null,
        status: String = "ready",
        createdAt: Long? = 100L,
        downloadUrl: String? = null,
    ) = TradingDocument(
        docId = docId,
        type = type,
        rawTitle = title,
        periodStartEpochSeconds = periodStart,
        periodEndEpochSeconds = null,
        taxYear = taxYear,
        format = format,
        sizeBytes = sizeBytes,
        status = status,
        createdAtEpochSeconds = createdAt,
        downloadUrl = downloadUrl,
    )

    @Test
    fun tradingDocTypes_areCanonicalOrder() {
        assertEquals(listOf("statement", "1099", "confirmation", "fills", "pnl"), TRADING_DOC_TYPES)
    }

    @Test
    fun docTypeLabel_knownCodes() {
        assertEquals("Statements", docTypeLabel("statement"))
        assertEquals("1099 Tax Forms", docTypeLabel("1099"))
        assertEquals("Trade Confirmations", docTypeLabel("confirmation"))
        assertEquals("Fills", docTypeLabel("fills"))
        assertEquals("Profit & Loss", docTypeLabel("pnl"))
    }

    @Test
    fun docTypeLabel_unknownCode_titleCasesRaw() {
        assertEquals("Margin", docTypeLabel("margin"))
    }

    @Test
    fun groupDocuments_empty_isEmpty() {
        assertTrue(groupDocuments(emptyList()).isEmpty())
    }

    @Test
    fun groupDocuments_ordersGroupsByCanonicalTypeOrder() {
        val docs = listOf(
            doc(docId = "p", type = "pnl"),
            doc(docId = "s", type = "statement"),
            doc(docId = "t", type = "1099"),
        )
        val groups = groupDocuments(docs)
        assertEquals(listOf("statement", "1099", "pnl"), groups.map { it.type })
    }

    @Test
    fun groupDocuments_newestFirstWithinGroup() {
        val docs = listOf(
            doc(docId = "old", type = "statement", createdAt = 10L),
            doc(docId = "new", type = "statement", createdAt = 99L),
            doc(docId = "mid", type = "statement", createdAt = 50L),
        )
        val group = groupDocuments(docs).single()
        assertEquals(listOf("new", "mid", "old"), group.documents.map { it.docId })
    }

    @Test
    fun groupDocuments_unknownTypesAppendedAlphabetically() {
        val docs = listOf(
            doc(docId = "z", type = "zeta"),
            doc(docId = "a", type = "alpha"),
            doc(docId = "s", type = "statement"),
        )
        val groups = groupDocuments(docs)
        assertEquals(listOf("statement", "alpha", "zeta"), groups.map { it.type })
    }

    @Test
    fun docTitle_prefersServerTitle() {
        assertEquals("Q1 2025 Statement", docTitle(doc(title = "Q1 2025 Statement")))
    }

    @Test
    fun docTitle_derivesFromTypeAndTaxYear_whenNoTitle() {
        assertEquals("1099 Tax Form 2024", docTitle(doc(type = "1099", taxYear = 2024)))
    }

    @Test
    fun docTitle_fallsBackToTypeLabel_singular() {
        assertEquals("Statement", docTitle(doc(type = "statement")))
    }

    @Test
    fun docFilename_safeAndCorrectExtension_pdf() {
        val name = docFilename(doc(title = "Q1/2025: Statement*!", format = "pdf"))
        assertEquals("Q1_2025_Statement.pdf", name)
    }

    @Test
    fun docFilename_csvExtension() {
        val name = docFilename(doc(title = "fills report", format = "csv"))
        assertEquals("fills_report.csv", name)
    }

    @Test
    fun docFilename_blankTitle_fallsBackToTypeAndId() {
        val name = docFilename(doc(docId = "abc", type = "pnl", title = null, format = "pdf"))
        assertEquals("pnl_abc.pdf", name)
    }

    @Test
    fun docFilename_unknownFormat_defaultsToPdf() {
        assertEquals("report.pdf", docFilename(doc(title = "report", format = "xyz")))
    }

    @Test
    fun isDownloadable_falseWhenGenerating() {
        assertFalse(isDownloadable(doc(status = "generating")))
        assertTrue(isDownloadable(doc(status = "ready")))
    }

    @Test
    fun formatDocMeta_readyWithSize() {
        assertEquals("PDF · 1.0 KB", formatDocMeta(doc(format = "pdf", sizeBytes = 1024L)))
    }

    @Test
    fun formatDocMeta_generatingTag() {
        val meta = formatDocMeta(doc(format = "csv", sizeBytes = null, status = "generating"))
        assertEquals("CSV · Generating…", meta)
    }

    @Test
    fun formatSize_units() {
        assertEquals("512 B", formatSize(512L))
        assertEquals("1.0 KB", formatSize(1024L))
        assertEquals("1.5 MB", formatSize((1024L * 1024L * 3L) / 2L))
    }
}
