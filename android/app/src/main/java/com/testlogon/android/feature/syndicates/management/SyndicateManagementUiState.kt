package com.testlogon.android.feature.syndicates.management

import com.testlogon.android.core.model.syndicates.PlanField

/**
 * Exhaustive UI state for the syndicate MANAGEMENT screen (invites / join-requests / bundle plans / audit).
 * The screen loads three lists (my-invites, join-requests, plans) plus the audit tail for one syndicate;
 * each list degrades to honest-empty on a read failure so the surface stays usable.
 */
sealed interface SyndicateManagementUiState {

    data object Loading : SyndicateManagementUiState

    data class Content(
        val syndicateId: String,
        val invites: List<SyndicateInvite> = emptyList(),
        val requests: List<JoinRequest> = emptyList(),
        val plans: List<BundlePlan> = emptyList(),
        val audit: List<SyndicateAuditEntry> = emptyList(),
        val subscribedPlanIds: Set<String> = emptySet(),
        val isRefreshing: Boolean = false,
        val isStale: Boolean = false,
        /** The plan/user/invite id an inline action is in-flight for (disables just that row). */
        val busyId: String? = null,
        val actionError: String? = null,
        val actionMessage: String? = null,
        val inviteForm: InviteFormState = InviteFormState(),
        val planForm: PlanFormState = PlanFormState(),
        val transferForm: TransferFormState = TransferFormState(),
    ) : SyndicateManagementUiState

    data class Error(val message: String) : SyndicateManagementUiState
}

/** The admin invite-a-member form (dialog). */
data class InviteFormState(
    val visible: Boolean = false,
    val userId: String = "",
    val submitting: Boolean = false,
    val error: String? = null,
) {
    val isValid: Boolean get() = userId.isNotBlank()
}

/** The admin create-a-bundle-plan form (dialog). Price is captured as a raw string, parsed to cents. */
data class PlanFormState(
    val visible: Boolean = false,
    val name: String = "",
    val description: String = "",
    val priceInput: String = "",
    val interval: String = "month",
    val submitting: Boolean = false,
    val fieldErrors: Map<PlanField, String> = emptyMap(),
    val submitError: String? = null,
)

/** The admin transfer-admin form (dialog). */
data class TransferFormState(
    val visible: Boolean = false,
    val newAdminUserId: String = "",
    val submitting: Boolean = false,
    val error: String? = null,
) {
    val isValid: Boolean get() = newAdminUserId.isNotBlank()
}
