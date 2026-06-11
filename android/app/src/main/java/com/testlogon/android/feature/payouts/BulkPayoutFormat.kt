package com.testlogon.android.feature.payouts

import com.testlogon.android.R
import com.testlogon.android.data.payouts.PayoutBatchStatus

/**
 * AND-261 — pure, JVM-testable bulk-batch label mapping (no Android types beyond R ids). Reuses the
 * AND-260 money/date formatters ([formatPayoutMoney]/[formatPayoutDate]) for amounts and dates; only
 * the batch-status label needs its own resource map.
 */

/** String-resource id for a [PayoutBatchStatus] chip label (TalkBack reads "Status: <label>"). */
fun payoutBatchStatusLabelRes(status: PayoutBatchStatus): Int = when (status) {
    PayoutBatchStatus.DRAFT -> R.string.bulk_batch_status_draft
    PayoutBatchStatus.PENDING -> R.string.bulk_batch_status_pending
    PayoutBatchStatus.PROCESSING -> R.string.bulk_batch_status_processing
    PayoutBatchStatus.COMPLETED -> R.string.bulk_batch_status_completed
    PayoutBatchStatus.PARTIALLY_FAILED -> R.string.bulk_batch_status_partially_failed
    PayoutBatchStatus.FAILED -> R.string.bulk_batch_status_failed
    PayoutBatchStatus.CANCELED -> R.string.bulk_batch_status_canceled
    PayoutBatchStatus.UNKNOWN -> R.string.bulk_batch_status_unknown
}
