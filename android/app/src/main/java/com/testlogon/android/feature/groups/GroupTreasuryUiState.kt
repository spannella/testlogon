package com.testlogon.android.feature.groups

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.groups.Contributor
import com.testlogon.android.core.model.groups.TreasuryBalance
import com.testlogon.android.core.model.groups.TreasuryLedgerEntry

/**
 * AND-355 (sub-pages) - render-ready state for the group TREASURY screen (read-only: balance + ledger +
 * contributors). Spend / set-goal are admin-only at the service layer and are OUT OF SCOPE here.
 */
sealed interface GroupTreasuryUiState {

    data object Loading : GroupTreasuryUiState

    data class Content(
        val balance: TreasuryBalance,
        val ledger: List<TreasuryLedgerEntry>,
        val contributors: List<Contributor>,
    ) : GroupTreasuryUiState

    data class Error(val error: ApiError) : GroupTreasuryUiState
}
