package com.testlogon.android.feature.profile.edit

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.profile.Profile
import com.testlogon.android.core.model.profile.ProfilePatch
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.profile.ProfileRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-072 / AND-075 — edit-profile state machine.
 *
 * Seeds the form from the cached own profile (or loads it), validates live, tracks dirty state, and
 * saves only changed fields via PATCH /ui/profile (non-idempotent, never auto-retried). Server 422
 * `detail[{loc,msg}]` errors are mapped back onto their fields by the trailing `loc` segment.
 */
@HiltViewModel
class EditProfileViewModel @Inject constructor(
    private val repository: ProfileRepository,
    private val validator: ProfileValidator,
    private val errorParser: ApiErrorParser,
) : ViewModel() {

    private val _uiState = MutableStateFlow(EditProfileUiState())
    val uiState: StateFlow<EditProfileUiState> = _uiState.asStateFlow()

    private val _effects = Channel<EditProfileEffect>(Channel.BUFFERED)
    val effects: Flow<EditProfileEffect> = _effects.receiveAsFlow()

    init {
        load()
    }

    fun onRetryLoad() = load()

    fun onDisplayNameChange(value: String) = updateField { it.copy(displayName = value) }
    fun onDescriptionChange(value: String) = updateField { it.copy(description = value) }
    fun onTitleChange(value: String) = updateField { it.copy(title = value) }
    fun onLocationChange(value: String) = updateField { it.copy(location = value) }

    fun onBackPressed() {
        if (_uiState.value.isDirty) {
            _effects.trySend(EditProfileEffect.ConfirmDiscard)
        } else {
            _effects.trySend(EditProfileEffect.NavigateBack)
        }
    }

    fun onSave() {
        val state = _uiState.value
        if (!state.canSave) return
        val patch = buildPatch(state.baseline.normalized(), state.form.normalized())
        if (patch.isEmpty) return
        _uiState.update { it.copy(isSaving = true, saveError = null) }
        viewModelScope.launch {
            when (val result = repository.updateProfile(patch)) {
                is ApiResult.Success -> {
                    _uiState.update {
                        val seeded = result.data.toForm()
                        it.copy(form = seeded, baseline = seeded, isSaving = false, saveError = null)
                    }
                    _effects.send(EditProfileEffect.NavigateBack)
                }
                is ApiResult.Failure -> reduceSaveFailure(result.error)
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(isSaving = false, saveError = OFFLINE_FALLBACK)
                }
            }
        }
    }

    private fun load() {
        val cached = repository.cachedOwnProfile()
        if (cached != null) {
            seed(cached)
            return
        }
        _uiState.update { it.copy(phase = EditProfileUiState.Phase.Loading, loadError = null) }
        viewModelScope.launch {
            when (val result = repository.getOwnProfile(forceRefresh = false)) {
                is ApiResult.Success -> seed(result.data)
                is ApiResult.Failure -> _uiState.update {
                    it.copy(phase = EditProfileUiState.Phase.Error, loadError = result.error.message)
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(phase = EditProfileUiState.Phase.Error, loadError = OFFLINE_FALLBACK)
                }
            }
        }
    }

    private fun seed(profile: Profile) {
        val form = profile.toForm()
        _uiState.update {
            it.copy(
                phase = EditProfileUiState.Phase.Editing,
                form = form,
                baseline = form,
                errors = EditFieldErrors(),
                loadError = null,
            )
        }
    }

    private inline fun updateField(transform: (EditProfileForm) -> EditProfileForm) {
        _uiState.update { state ->
            val newForm = transform(state.form)
            state.copy(form = newForm, errors = validate(newForm), saveError = null)
        }
    }

    private fun validate(form: EditProfileForm): EditFieldErrors = EditFieldErrors(
        displayName = validator.validateDisplayName(form.displayName).errorRes,
        description = validator.validateDescription(form.description).errorRes,
        title = validator.validateTitle(form.title).errorRes,
        location = validator.validateLocation(form.location).errorRes,
    )

    private fun reduceSaveFailure(error: ApiError) {
        if (error.status == 422) {
            val fieldErrors = mapServerFieldErrors(error)
            if (!fieldErrors.isEmpty) {
                _uiState.update { it.copy(isSaving = false, errors = fieldErrors) }
                return
            }
        }
        _uiState.update { it.copy(isSaving = false, saveError = error.message) }
    }

    /** Routes FastAPI 422 `detail[{loc,msg}]` items to fields by the trailing `loc` segment. */
    private fun mapServerFieldErrors(error: ApiError): EditFieldErrors {
        val detail = (error.raw as? String)?.let { errorParser.parseDetail(it) } as? List<*> ?: return EditFieldErrors()
        var errors = EditFieldErrors()
        for (item in detail) {
            val map = item as? Map<*, *> ?: continue
            val loc = (map["loc"] as? List<*>)?.lastOrNull() as? String ?: continue
            when (loc) {
                "display_name" -> errors = errors.copy(displayName = R.string.profile_edit_error_name_server)
                "description" -> errors = errors.copy(description = R.string.profile_edit_error_description_server)
                "title" -> errors = errors.copy(title = R.string.profile_edit_error_field_server)
                "location" -> errors = errors.copy(location = R.string.profile_edit_error_field_server)
            }
        }
        return errors
    }

    private companion object {
        const val OFFLINE_FALLBACK = "Couldn't reach the server. Try again."
    }
}

/** Builds a patch carrying only the fields whose normalized value changed from [baseline]. */
internal fun buildPatch(baseline: EditProfileForm, current: EditProfileForm): ProfilePatch = ProfilePatch(
    displayName = current.displayName.takeIf { it != baseline.displayName },
    description = current.description.takeIf { it != baseline.description },
    title = current.title.takeIf { it != baseline.title },
    location = current.location.takeIf { it != baseline.location },
)

internal fun Profile.toForm(): EditProfileForm = EditProfileForm(
    displayName = displayName.orEmpty(),
    description = description.orEmpty(),
    title = title.orEmpty(),
    location = location.orEmpty(),
)
