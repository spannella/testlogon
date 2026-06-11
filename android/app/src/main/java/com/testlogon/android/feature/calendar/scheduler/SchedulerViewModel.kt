package com.testlogon.android.feature.calendar.scheduler

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.scheduler.ScheduledAction
import com.testlogon.android.data.scheduler.ScheduledActionCreateInDto
import com.testlogon.android.data.scheduler.ScheduledActionUpdateInDto
import com.testlogon.android.data.scheduler.SchedulerRepository
import com.testlogon.android.feature.calendar.CalendarClock
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.time.Instant
import javax.inject.Inject

/**
 * AND-275 — drives the scheduler create/edit sheet.
 *
 * Create mode starts on an empty (or seeded) [SchedulerForm]; Edit mode loads the action
 * (GET /ui/scheduler/actions/{id}) and hydrates the form. Submit runs [SchedulerValidator] locally first;
 * a valid create POSTs [ScheduledActionCreateInDto], a valid edit PATCHes [ScheduledActionUpdateInDto]
 * (partial — only changed fields; never action_type). Mutations are guarded against double-submit by an
 * in-flight [Job] and are never auto-retried. Form input survives recreation via [SavedStateHandle].
 *
 * `scheduledAt` is an [Instant]; it is serialized to the request as an epoch-SECONDS integer
 * (`scheduled_at`). [CalendarClock] is injected so "now" is deterministic in tests.
 */
@HiltViewModel
class SchedulerViewModel @Inject constructor(
    private val repo: SchedulerRepository,
    private val clock: CalendarClock,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val mode: SchedulerMode = run {
        val actionId = savedState.get<String>(ARG_ACTION_ID)
        if (!actionId.isNullOrBlank()) SchedulerMode.Edit(actionId) else SchedulerMode.Create
    }

    private val _state = MutableStateFlow<SchedulerUiState>(
        if (mode is SchedulerMode.Edit) SchedulerUiState.Loading else SchedulerUiState.Editing(mode, seedForm()),
    )
    val state: StateFlow<SchedulerUiState> = _state.asStateFlow()

    private var submitJob: Job? = null

    init {
        if (mode is SchedulerMode.Edit) loadAction(mode.actionId)
    }

    /** Create-mode seed from optional nav args (a tapped slot / "schedule for later" draft). */
    private fun seedForm(): SchedulerForm {
        val seedSeconds = savedState.get<Long>(ARG_SCHEDULED_AT_SECONDS)
        val seedType = savedState.get<String>(ARG_ACTION_TYPE)
        return SchedulerForm(
            actionType = seedType,
            scheduledAt = seedSeconds?.let(Instant::ofEpochSecond),
        )
    }

    private fun loadAction(actionId: String) {
        viewModelScope.launch {
            when (val r = repo.loadAction(actionId)) {
                is ApiResult.Success -> _state.value = SchedulerUiState.Editing(mode, r.data.toForm())
                is ApiResult.Failure -> _state.value = SchedulerUiState.LoadError(r.error.message, false)
                is ApiResult.NetworkError -> _state.value = SchedulerUiState.LoadError(OFFLINE_MESSAGE, true)
            }
        }
    }

    fun onActionTypeSelected(type: String) = editForm { it.copy(actionType = type) }
    fun onScheduledAtChanged(instant: Instant) = editForm { it.copy(scheduledAt = instant) }
    fun onTitleChanged(title: String) = editForm { it.copy(title = title) }
    fun onDescriptionChanged(text: String) = editForm { it.copy(description = text) }
    fun onNotifyBeforeChanged(seconds: Int) = editForm { it.copy(notifyBeforeSeconds = seconds) }

    fun onDismissError() {
        val editing = _state.value as? SchedulerUiState.Editing ?: return
        _state.value = editing.copy(transientError = null)
    }

    fun onRetry() {
        when (val s = _state.value) {
            is SchedulerUiState.LoadError -> {
                (mode as? SchedulerMode.Edit)?.let {
                    _state.value = SchedulerUiState.Loading
                    loadAction(it.actionId)
                }
            }
            is SchedulerUiState.Editing -> onSubmit()
            else -> Unit
        }
    }

    fun onSubmit() {
        val editing = _state.value as? SchedulerUiState.Editing ?: return
        if (editing.isSubmitting || submitJob?.isActive == true) return

        val errors = SchedulerValidator.validate(editing.form, now())
        if (errors.isNotEmpty()) {
            _state.value = editing.copy(fieldErrors = errors)
            return
        }

        _state.value = editing.copy(isSubmitting = true, fieldErrors = emptyMap(), transientError = null)
        submitJob = viewModelScope.launch {
            val result = when (mode) {
                is SchedulerMode.Create -> repo.create(editing.form.toCreateDto())
                is SchedulerMode.Edit -> repo.reschedule(mode.actionId, editing.form.toUpdateDto())
            }
            _state.update { reduceSubmit(it, result) }
        }
    }

    private fun reduceSubmit(
        current: SchedulerUiState,
        result: ApiResult<ScheduledAction>,
    ): SchedulerUiState {
        val editing = current as? SchedulerUiState.Editing ?: return current
        return when (result) {
            is ApiResult.Success -> SchedulerUiState.Saved(result.data)
            is ApiResult.Failure -> editing.copy(
                isSubmitting = false,
                isOffline = false,
                fieldErrors = mapValidationErrors(result.error.raw),
                transientError = result.error.message,
            )
            is ApiResult.NetworkError -> editing.copy(
                isSubmitting = false,
                isOffline = true,
                transientError = OFFLINE_MESSAGE,
            )
        }
    }

    /** Best-effort 422 loc-path -> field mapping; falls back to a top-level transientError otherwise. */
    private fun mapValidationErrors(raw: Any?): Map<SchedulerField, String> {
        val body = raw as? String ?: return emptyMap()
        val out = LinkedHashMap<SchedulerField, String>()
        if (body.contains("scheduled_at")) out[SchedulerField.ScheduledAt] = "Check the scheduled time"
        if (body.contains("action_type")) out[SchedulerField.ActionType] = "Check the action type"
        if (body.contains("\"title\"")) out[SchedulerField.Title] = "Check the title"
        return out
    }

    private fun editForm(transform: (SchedulerForm) -> SchedulerForm) {
        val editing = _state.value as? SchedulerUiState.Editing ?: return
        val newForm = transform(editing.form)
        _state.value = editing.copy(form = newForm)
        persist(newForm)
    }

    private fun persist(form: SchedulerForm) {
        savedState[ARG_ACTION_TYPE] = form.actionType
        savedState[ARG_SCHEDULED_AT_SECONDS] = form.scheduledAt?.epochSecond
        savedState[KEY_TITLE] = form.title
        savedState[KEY_DESCRIPTION] = form.description
        savedState[KEY_NOTIFY] = form.notifyBeforeSeconds
    }

    private fun now(): Instant = Instant.ofEpochMilli(clock.nowMillis())

    private fun ScheduledAction.toForm(): SchedulerForm = SchedulerForm(
        actionType = actionType,
        scheduledAt = scheduledAt,
        title = title,
        description = description,
        payload = payload,
        notifyBeforeSeconds = notifyBeforeSeconds,
    )

    private fun SchedulerForm.toCreateDto(): ScheduledActionCreateInDto = ScheduledActionCreateInDto(
        actionType = actionType.orEmpty(),
        scheduledAt = scheduledAt?.epochSecond ?: 0L,
        title = title.takeIf { it.isNotBlank() },
        description = description.takeIf { it.isNotBlank() },
        payload = payload.takeIf { it.isNotEmpty() },
        notifyBeforeSeconds = notifyBeforeSeconds.takeIf { it > 0 },
    )

    private fun SchedulerForm.toUpdateDto(): ScheduledActionUpdateInDto = ScheduledActionUpdateInDto(
        scheduledAt = scheduledAt?.epochSecond,
        title = title.takeIf { it.isNotBlank() },
        description = description.takeIf { it.isNotBlank() },
        payload = payload.takeIf { it.isNotEmpty() },
        notifyBeforeSeconds = notifyBeforeSeconds.takeIf { it > 0 },
    )

    companion object {
        const val ARG_ACTION_ID = "actionId"
        const val ARG_SCHEDULED_AT_SECONDS = "scheduledAt"
        const val ARG_ACTION_TYPE = "actionType"
        private const val KEY_TITLE = "scheduler_title"
        private const val KEY_DESCRIPTION = "scheduler_description"
        private const val KEY_NOTIFY = "scheduler_notify"
        private const val OFFLINE_MESSAGE = "You're offline. Try again when connected."
    }
}
