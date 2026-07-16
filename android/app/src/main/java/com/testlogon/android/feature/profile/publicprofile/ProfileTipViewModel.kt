package com.testlogon.android.feature.profile.publicprofile

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.data.tip.ProfileTipOutcome
import com.testlogon.android.data.tip.ProfileTipRepository
import com.testlogon.android.data.tip.TipConfig
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * TIPX-C2 - drives the "Tip this creator" bottom sheet on a public profile: Hidden -> Entry ->
 * Submitting -> (Confirmed | Entry(error) | PaymentsUnavailable). A creator tip is money-moving and
 * NEVER optimistic: Confirmed appears only after the repository returns Success. The submit lock
 * (Submitting) ignores further send() taps so exactly one charge is issued on rapid taps.
 */
@HiltViewModel
class ProfileTipViewModel @Inject constructor(
    private val tips: ProfileTipRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<ProfileTipState>(ProfileTipState.Hidden)
    val state: StateFlow<ProfileTipState> = _state.asStateFlow()

    private val _effects = Channel<ProfileTipEffect>(Channel.BUFFERED)
    val effects: Flow<ProfileTipEffect> = _effects.receiveAsFlow()

    /** Open the sheet for the creator identified by [identifier] (a handle or user id). */
    fun open(identifier: String, displayName: String?) {
        _state.value = ProfileTipState.Entry(
            identifier = identifier,
            displayName = displayName,
            config = tips.config(),
            selectedCents = null,
            customAmountText = "",
        )
    }

    fun selectPreset(cents: Int) {
        val entry = currentEntry() ?: return
        _state.value = entry.copy(selectedCents = cents, customAmountText = "", error = null)
    }

    fun setCustomAmount(text: String) {
        val entry = currentEntry() ?: return
        _state.value = entry.copy(customAmountText = text, selectedCents = parseDollarsToCents(text), error = null)
    }

    fun send() {
        val entry = currentEntry() ?: return
        val cents = entry.effectiveCents ?: return
        if (!entry.canSend) return
        _state.value = ProfileTipState.Submitting(entry.identifier, cents)
        viewModelScope.launch {
            when (val outcome = tips.tip(entry.identifier, cents)) {
                is ProfileTipOutcome.Success -> {
                    _state.value = ProfileTipState.Confirmed(cents, outcome.receipt.tipTotalCents)
                    outcome.receipt.tipTotalCents?.let { _effects.trySend(ProfileTipEffect.TotalUpdated(it)) }
                    _effects.trySend(ProfileTipEffect.ShowSnackbar(SNACKBAR_SENT))
                }
                ProfileTipOutcome.PaymentsUnavailable ->
                    _state.value = entry.copy(error = ERR_PAYMENTS_UNAVAILABLE)
                ProfileTipOutcome.Cancelled ->
                    _state.value = entry
                is ProfileTipOutcome.Failure ->
                    _state.value = entry.copy(error = outcome.message)
            }
        }
    }

    fun dismiss() {
        if (_state.value is ProfileTipState.Submitting) return
        _state.value = ProfileTipState.Hidden
    }

    private fun currentEntry(): ProfileTipState.Entry? = _state.value as? ProfileTipState.Entry

    private companion object {
        const val SNACKBAR_SENT = "Tip sent"
        const val ERR_PAYMENTS_UNAVAILABLE = "Payments are unavailable right now."
    }
}

/** TIPX-C2 - profile tip sheet state machine (scoped to one creator). */
sealed interface ProfileTipState {
    data object Hidden : ProfileTipState

    data class Entry(
        val identifier: String,
        val displayName: String?,
        val config: TipConfig,
        val selectedCents: Int?,
        val customAmountText: String,
        val error: String? = null,
    ) : ProfileTipState {
        val effectiveCents: Int? get() = selectedCents
        val canSend: Boolean
            get() {
                val c = effectiveCents ?: return false
                return c in config.minCents..config.maxCents
            }
    }

    data class Submitting(val identifier: String, val amountCents: Int) : ProfileTipState
    data class Confirmed(val amountCents: Int, val tipTotalCents: Int?) : ProfileTipState
}

/** TIPX-C2 - one-shot profile tip effects. */
sealed interface ProfileTipEffect {
    data class ShowSnackbar(val message: String) : ProfileTipEffect
    /** The new running creator tip total; the host updates the profile's rendered support badge. */
    data class TotalUpdated(val tipTotalCents: Int) : ProfileTipEffect
}

/** Parses a user-typed dollar amount ("5", "5.50") to whole cents, or null if invalid/empty. */
internal fun parseDollarsToCents(text: String): Int? {
    val trimmed = text.trim()
    if (trimmed.isEmpty()) return null
    val value = trimmed.toDoubleOrNull() ?: return null
    if (value <= 0.0) return null
    return Math.round(value * 100.0).toInt()
}
