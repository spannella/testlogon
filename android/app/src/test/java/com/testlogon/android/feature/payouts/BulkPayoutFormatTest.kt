package com.testlogon.android.feature.payouts

import com.testlogon.android.data.payouts.PayoutBatchStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-261/263 — [payoutBatchStatusLabelRes] returns a distinct, non-zero string-resource id for every
 * [PayoutBatchStatus] (pure Int mapping; JVM-safe — no Android types resolved). Guards against a
 * missing/duplicated branch when the enum grows.
 */
class BulkPayoutFormatTest {

    @Test
    fun everyBatchStatus_hasDistinctNonZeroLabelRes() {
        val ids = PayoutBatchStatus.entries.map { payoutBatchStatusLabelRes(it) }
        assertTrue("all label ids are non-zero", ids.all { it != 0 })
        assertEquals("each status maps to a distinct label res", ids.size, ids.toSet().size)
    }
}
