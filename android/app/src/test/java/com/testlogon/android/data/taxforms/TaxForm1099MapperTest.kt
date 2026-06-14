package com.testlogon.android.data.taxforms

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-247/250 — unit tests for the 1099 DTO -> domain mapper: minor-unit money preservation, epoch
 * handling (0 -> null), status mapping with the correction_count promotion + forward-compatible UNKNOWN,
 * payer-TIN-last4 passthrough, and download_url blank -> null normalization.
 */
class TaxForm1099MapperTest {

    private fun dto(
        taxYear: Int = 2025,
        status: String = "generated",
        correctionCount: Int = 0,
        generatedAt: Long = 1_738_310_400L,
        downloadUrl: String? = null,
    ) = Form1099Dto(
        formId = "tf_1099_x",
        userSub = "auth0|u1",
        taxYear = taxYear,
        totalEarningsCents = 1_284_500,
        qualifies = true,
        status = status,
        correctionCount = correctionCount,
        payerName = "TestLogon, Inc.",
        payerTinLast4 = "6789",
        generatedAt = generatedAt,
        updatedAt = generatedAt,
        downloadUrl = downloadUrl,
    )

    @Test
    fun toDomain_mapsCoreFields_minorUnits_andEpoch() {
        val form = dto().toDomain()
        assertEquals(2025, form.taxYear)
        assertEquals(1_284_500L, form.totalEarnings.cents)
        assertEquals(Form1099Money.USD, form.totalEarnings.currency)
        assertEquals("6789", form.payerTinLast4)
        assertEquals(1_738_310_400L, form.generatedAtEpochSeconds)
        assertEquals(Form1099Status.GENERATED, form.status)
        assertEquals("generated", form.statusRaw)
        assertFalse(form.isCorrected)
    }

    @Test
    fun toDomain_correctionCount_promotesToCorrected() {
        val form = dto(correctionCount = 2, status = "generated").toDomain()
        assertEquals(Form1099Status.CORRECTED, form.status)
        assertTrue(form.isCorrected)
        assertEquals(2, form.correctionCount)
    }

    @Test
    fun toDomain_unknownStatus_isForwardCompatible() {
        val form = dto(status = "amended_xyz").toDomain()
        assertEquals(Form1099Status.UNKNOWN, form.status)
        // The raw string is preserved for display / forward-compat.
        assertEquals("amended_xyz", form.statusRaw)
    }

    @Test
    fun toDomain_zeroEpoch_mapsToNull() {
        val form = dto(generatedAt = 0).toDomain()
        assertNull(form.generatedAtEpochSeconds)
        assertNull(form.updatedAtEpochSeconds)
    }

    @Test
    fun toDomain_blankDownloadUrl_mapsToNull() {
        assertNull(dto(downloadUrl = "").toDomain().downloadUrl)
        assertNull(dto(downloadUrl = null).toDomain().downloadUrl)
        assertEquals("http://x/blob", dto(downloadUrl = "http://x/blob").toDomain().downloadUrl)
    }

    @Test
    fun statusFrom_correctedString_withoutCount_isCorrected() {
        assertEquals(Form1099Status.CORRECTED, Form1099Status.from("corrected", 0))
        assertEquals(Form1099Status.GENERATED, Form1099Status.from("generated", 0))
        assertEquals(Form1099Status.UNKNOWN, Form1099Status.from(null, 0))
    }
}
