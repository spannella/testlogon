package com.testlogon.android.feature.groups

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.groups.Group

/**
 * AND-355 (sub-pages) - render-ready state for the group SETTINGS screen (an editable form over the group
 * fields -> PATCH updateGroup). Saving is admin-gated at the service layer -> a 403 surfaces a non-fatal
 * snackbar notice. [canEdit] mirrors the group's manage gate (admin) so non-admins see a read-only form.
 */
sealed interface GroupSettingsUiState {

    data object Loading : GroupSettingsUiState

    data class Content(
        val group: Group,
        val canEdit: Boolean,
        val isSaving: Boolean = false,
        val notice: String? = null,
    ) : GroupSettingsUiState

    data class Error(val error: ApiError) : GroupSettingsUiState
}
