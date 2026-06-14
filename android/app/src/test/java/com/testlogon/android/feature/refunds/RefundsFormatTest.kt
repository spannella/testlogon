package com.testlogon.android.feature.refunds

import com.testlogon.android.R
import com.testlogon.android.data.refunds.RefundMoney
import com.testlogon.android.data.refunds.RefundStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.Locale

/** AND-244 — pure formatter tests (money, date-null passthrough, status label mapping). */
class RefundsFormatTest {

    @Test
    fun money_formatsUsdInUsLocale() {
        assertEquals("$12.99", formatRefundMoney(RefundMoney(1299, "usd"), Locale.US))
    }

    @Test
    fun money_unknownCurrency_fallsBack() {
        assertEquals("12.99 ZZZ", formatRefundMoney(RefundMoney(1299, "zzz"), Locale.US))
    }

    @Test
    fun date_nullEpoch_isNull() {
        assertNull(formatRefundDate(null))
    }

    @Test
    fun statusLabel_mapsEveryValue() {
        assertEquals(R.string.refunds_status_pending, refundStatusLabelRes(RefundStatus.PENDING))
        assertEquals(R.string.refunds_status_approved, refundStatusLabelRes(RefundStatus.APPROVED))
        assertEquals(R.string.refunds_status_completed, refundStatusLabelRes(RefundStatus.COMPLETED))
        assertEquals(R.string.refunds_status_denied, refundStatusLabelRes(RefundStatus.DENIED))
        assertEquals(R.string.refunds_status_unknown, refundStatusLabelRes(RefundStatus.UNKNOWN))
    }
}
