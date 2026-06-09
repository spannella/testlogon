package com.testlogon.android.feature.profile.edit

import androidx.annotation.StringRes

/**
 * AND-072 / AND-075 — edit-profile form + state.
 *
 * Editable basics only (no `links`/`bio` — those do not exist in the contract; the long-text field
 * is `description`). All values are trimmed for the dirty/diff check via [normalized].
 */
data class EditProfileForm(
    val displayName: String = "",
    val description: String = "",
    val title: String = "",
    val location: String = "",
) {
    /** Trimmed snapshot used for dirty-tracking so whitespace-only edits aren't "dirty". */
    fun normalized(): EditProfileForm = EditProfileForm(
        displayName = displayName.trim(),
        description = description.trim(),
        title = title.trim(),
        location = location.trim(),
    )
}

data class EditFieldErrors(
    @StringRes val displayName: Int? = null,
    @StringRes val description: Int? = null,
    @StringRes val title: Int? = null,
    @StringRes val location: Int? = null,
) {
    val isEmpty: Boolean get() = displayName == null && description == null && title == null && location == null
}

data class EditProfileUiState(
    val phase: Phase = Phase.Loading,
    val form: EditProfileForm = EditProfileForm(),
    val baseline: EditProfileForm = EditProfileForm(),
    val errors: EditFieldErrors = EditFieldErrors(),
    val isSaving: Boolean = false,
    val saveError: String? = null,
    val loadError: String? = null,
) {
    enum class Phase { Loading, Editing, Error }

    val isDirty: Boolean get() = form.normalized() != baseline.normalized()
    val canSave: Boolean get() = phase == Phase.Editing && errors.isEmpty && isDirty && !isSaving
}

/** One-shot effects (Channel-backed). */
sealed interface EditProfileEffect {
    data object NavigateBack : EditProfileEffect
    data object ConfirmDiscard : EditProfileEffect
    data class ShowMessage(@StringRes val resId: Int) : EditProfileEffect
}
