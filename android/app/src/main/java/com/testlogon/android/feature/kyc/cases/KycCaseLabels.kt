package com.testlogon.android.feature.kyc.cases

import com.testlogon.android.R
import com.testlogon.android.core.model.kyc.KycCaseStatus
import com.testlogon.android.feature.kyc.cases.model.TimelineKind

/**
 * AND-329 - shared string-resource resolvers for the KYC case-status & timeline UI (used by both the list and
 * detail screens). Status is conveyed by text (+ icon at the call site), never colour alone, and every token
 * maps to a real R.string.
 */

/** Localized label for an AND-319 [KycCaseStatus] (UNKNOWN-safe). */
fun kycStatusLabel(status: KycCaseStatus): Int = when (status) {
    KycCaseStatus.DRAFT -> R.string.kyc_case_status_draft
    KycCaseStatus.SUBMITTED -> R.string.kyc_case_status_submitted
    KycCaseStatus.UNDER_REVIEW -> R.string.kyc_case_status_under_review
    KycCaseStatus.NEEDS_MORE_INFO -> R.string.kyc_case_status_needs_more_info
    KycCaseStatus.APPROVED -> R.string.kyc_case_status_approved
    KycCaseStatus.REJECTED -> R.string.kyc_case_status_rejected
    KycCaseStatus.EXPIRED -> R.string.kyc_case_status_expired
    KycCaseStatus.UNKNOWN -> R.string.kyc_case_status_unknown
}

/** Localized label for a synthesized timeline-event [kind] (falls back to a generic update label). */
fun timelineKindLabel(kind: String): Int = when (kind) {
    TimelineKind.CREATED -> R.string.kyc_timeline_created
    TimelineKind.DOCUMENTS -> R.string.kyc_timeline_documents
    TimelineKind.SUBMITTED -> R.string.kyc_timeline_submitted
    TimelineKind.DECISION -> R.string.kyc_timeline_decision
    TimelineKind.CURRENT -> R.string.kyc_timeline_current
    else -> R.string.kyc_timeline_updated
}
