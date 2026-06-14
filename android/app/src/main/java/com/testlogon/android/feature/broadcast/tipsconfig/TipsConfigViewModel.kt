package com.testlogon.android.feature.broadcast.tipsconfig

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.broadcast.BroadcastMonetizationRepository
import com.testlogon.android.data.broadcast.TipConfig
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-315 — presentation logic for the host TIP-CONFIG editor.
 *
 * SCOPE (SMALL): the editor edits ONLY {tipsEnabled, minCents, maxCents}. There is NO tip-menu / currency /
 * goal-linkage. The current values are READ once via [BroadcastMonetizationRepository.getSessionTipConfig]
 * (GET session) and saved via the PATCH tips/config (which returns the persisted full session).
 *
 * [load] runs ONCE on init as a SINGLE non-looping launch (NOT a delay loop) — there is NO poll loop on this
 * surface, so there is nothing to hang runTest's drain. Amounts are edited in DOLLARS (text fields) and
 * converted to cents; client validation (min <= max, each within 100..100000 cents) blocks [onSave].
 */
@HiltViewModel
class TipsConfigViewModel @Inject constructor(
    savedState: SavedStateHandle,
    private val repository: BroadcastMonetizationRepository,
) : ViewModel() {

    val sessionId: String = savedState.get<String>(ARG_SESSION_ID).orEmpty()

    private val _uiState = MutableStateFlow<TipsConfigUiState>(TipsConfigUiState.Loading)
    val uiState: StateFlow<TipsConfigUiState> = _uiState.asStateFlow()

    /** The persisted config (used to compute the `dirty` flag). Null until first loaded. */
    private var persisted: TipConfig? = null

    init {
        if (sessionId.isBlank()) {
            _uiState.value = TipsConfigUiState.Error(NO_SESSION, retryable = false)
        } else {
            load()
        }
    }

    /** A SINGLE non-looping read of the current tip-config. Re-runnable via [onRetry]. */
    fun load() {
        if (sessionId.isBlank()) return
        _uiState.value = TipsConfigUiState.Loading
        viewModelScope.launch {
            when (val result = repository.getSessionTipConfig(sessionId)) {
                is ApiResult.Success -> {
                    persisted = result.data
                    _uiState.value = editingFrom(result.data)
                }
                is ApiResult.Failure -> _uiState.value =
                    TipsConfigUiState.Error(result.error.message, retryable = true)
                is ApiResult.NetworkError -> _uiState.value = TipsConfigUiState.Offline
            }
        }
    }

    fun onEnabledChange(enabled: Boolean) = mutateEditing { it.copy(enabled = enabled) }

    fun onMinChange(minDollars: String) = mutateEditing { it.copy(minDollars = minDollars) }

    fun onMaxChange(maxDollars: String) = mutateEditing { it.copy(maxDollars = maxDollars) }

    /** Validates client-side, then PATCHes. On success the persisted (server) values are reflected back. */
    fun onSave() {
        val editing = _uiState.value as? TipsConfigUiState.Editing ?: return
        val errors = validate(editing)
        if (errors.isNotEmpty()) {
            _uiState.value = editing.copy(fieldErrors = errors)
            return
        }
        _uiState.value = TipsConfigUiState.Saving
        viewModelScope.launch {
            val minCents = dollarsToCents(editing.minDollars)
            val maxCents = dollarsToCents(editing.maxDollars)
            when (
                val result = repository.saveTipConfig(
                    sessionId = sessionId,
                    enabled = editing.enabled,
                    minCents = minCents,
                    maxCents = maxCents,
                )
            ) {
                is ApiResult.Success -> {
                    persisted = result.data
                    _uiState.value = editingFrom(result.data)
                }
                is ApiResult.Failure -> _uiState.value = editing.copy(
                    fieldErrors = emptyMap(),
                    saveError = result.error.message,
                )
                is ApiResult.NetworkError -> _uiState.value = editing.copy(
                    fieldErrors = emptyMap(),
                    saveError = OFFLINE,
                )
            }
        }
    }

    /** Retry a load failure. */
    fun onRetry() = load()

    /** Applies [transform] to the current Editing state (marking it dirty + clearing the save error). */
    private fun mutateEditing(transform: (TipsConfigUiState.Editing) -> TipsConfigUiState.Editing) {
        val editing = _uiState.value as? TipsConfigUiState.Editing ?: return
        val next = transform(editing).copy(saveError = null, fieldErrors = emptyMap())
        _uiState.value = next.copy(dirty = isDirty(next))
    }

    private fun editingFrom(config: TipConfig): TipsConfigUiState.Editing = TipsConfigUiState.Editing(
        enabled = config.tipsEnabled,
        minDollars = config.minCents.centsToDollarsField(),
        maxDollars = config.maxCents.centsToDollarsField(),
        dirty = false,
        fieldErrors = emptyMap(),
        saveError = null,
    )

    private fun isDirty(editing: TipsConfigUiState.Editing): Boolean {
        val base = persisted ?: return true
        return editing.enabled != base.tipsEnabled ||
            dollarsToCents(editing.minDollars) != base.minCents ||
            dollarsToCents(editing.maxDollars) != base.maxCents
    }

    /**
     * Client validation. When tips are enabled BOTH bounds are required, each must parse, fall within
     * [MIN_CENTS]..[MAX_CENTS], and min <= max. When disabled, bounds are not validated (the toggle saves).
     */
    private fun validate(editing: TipsConfigUiState.Editing): Map<TipField, TipFieldError> {
        if (!editing.enabled) return emptyMap()
        val errors = mutableMapOf<TipField, TipFieldError>()
        val min = dollarsToCents(editing.minDollars)
        val max = dollarsToCents(editing.maxDollars)
        if (min == null) {
            errors[TipField.MIN] = TipFieldError.REQUIRED
        } else if (min < MIN_CENTS || min > MAX_CENTS) {
            errors[TipField.MIN] = TipFieldError.OUT_OF_RANGE
        }
        if (max == null) {
            errors[TipField.MAX] = TipFieldError.REQUIRED
        } else if (max < MIN_CENTS || max > MAX_CENTS) {
            errors[TipField.MAX] = TipFieldError.OUT_OF_RANGE
        }
        if (min != null && max != null && !errors.containsKey(TipField.MIN) &&
            !errors.containsKey(TipField.MAX) && min > max
        ) {
            errors[TipField.MAX] = TipFieldError.MIN_GREATER_THAN_MAX
        }
        return errors
    }

    companion object {
        /** Nav arg carrying the broadcast session id. */
        const val ARG_SESSION_ID = "sessionId"

        /** Verified server bounds (cents): $1.00 .. $1000.00. */
        const val MIN_CENTS = 100L
        const val MAX_CENTS = 100_000L

        private const val NO_SESSION = "No broadcast session is available."
        private const val OFFLINE = "Couldn't reach the server. Try again."
    }
}

/** Parses a dollars string (e.g. "5", "5.00") to whole cents, or null when blank / unparseable. */
internal fun dollarsToCents(dollars: String): Long? {
    val trimmed = dollars.trim()
    if (trimmed.isEmpty()) return null
    val value = trimmed.toBigDecimalOrNull() ?: return null
    return value.movePointRight(2).setScale(0, java.math.RoundingMode.HALF_UP).toLong()
}

/** Formats cents to a plain dollars text-field value (e.g. 500 -> "5.00"); null/0-absent -> "". */
internal fun Long?.centsToDollarsField(): String {
    if (this == null) return ""
    return java.math.BigDecimal(this).movePointLeft(2).setScale(2).toPlainString()
}

private fun String.toBigDecimalOrNull(): java.math.BigDecimal? = try {
    java.math.BigDecimal(this)
} catch (_: NumberFormatException) {
    null
}
