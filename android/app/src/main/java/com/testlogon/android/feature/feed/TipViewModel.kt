package com.testlogon.android.feature.feed

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.data.tip.TipConfig
import com.testlogon.android.data.tip.TipOutcome
import com.testlogon.android.data.tip.TipReactOutcome
import com.testlogon.android.data.tip.TipReceipt
import com.testlogon.android.data.tip.TipRepository
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
 * AND-178 — drives the tip bottom sheet for a single post: Hidden -> Entry -> Submitting ->
 * (Confirmed | Entry(error) | PaymentsUnavailable).
 *
 * A tip is money-moving and NEVER optimistic: the Confirmed state appears only after the repository
 * returns Success. The submit lock (Submitting) ignores further send() taps (FR-8) so exactly one
 * request is issued even on rapid taps. One-shot effects (host snackbar) use Channel + receiveAsFlow.
 */
@HiltViewModel
class TipViewModel @Inject constructor(
    private val tips: TipRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<TipSheetState>(TipSheetState.Hidden)
    val state: StateFlow<TipSheetState> = _state.asStateFlow()

    private val _effects = Channel<TipEffect>(Channel.BUFFERED)
    val effects: Flow<TipEffect> = _effects.receiveAsFlow()

    fun open(postId: String) {
        _state.value = TipSheetState.Entry(
            postId = postId,
            config = tips.config(),
            selectedCents = null,
            customAmountText = "",
        )
    }

    /** TIP-204 - open the tip sheet as a money-REACTION (badge) for [postId] with [emoji]. */
    fun openReaction(postId: String, emoji: String) {
        _state.value = TipSheetState.Entry(
            postId = postId,
            config = tips.config(),
            selectedCents = null,
            customAmountText = "",
            emoji = emoji,
            isReaction = true,
        )
    }

    fun selectPreset(cents: Int) {
        val entry = currentEntry() ?: return
        _state.value = entry.copy(selectedCents = cents, customAmountText = "", error = null)
    }

    fun setCustomAmount(text: String) {
        val entry = currentEntry() ?: return
        val cents = parseDollarsToCents(text)
        _state.value = entry.copy(customAmountText = text, selectedCents = cents, error = null)
    }

    fun send() {
        val entry = currentEntry() ?: return
        val cents = entry.effectiveCents ?: return
        if (!entry.canSend) return
        _state.value = TipSheetState.Submitting(entry.postId, cents)
        viewModelScope.launch {
            if (entry.isReaction) {
                when (val outcome = tips.tipReact(entry.postId, cents, entry.emoji ?: DEFAULT_REACT_EMOJI)) {
                    is TipReactOutcome.Success -> {
                        _effects.trySend(TipEffect.ReactionBadge(entry.postId, outcome.badge))
                        _state.value = TipSheetState.Confirmed(
                            TipReceipt(postId = entry.postId, amountCents = cents, tipTotalCents = outcome.tipTotalCents),
                        )
                        _effects.trySend(TipEffect.ShowSnackbar(SNACKBAR_SENT))
                    }
                    TipReactOutcome.PaymentsUnavailable ->
                        _state.value = entry.copy(error = ERR_PAYMENTS_UNAVAILABLE)
                    TipReactOutcome.Cancelled ->
                        _state.value = entry
                    is TipReactOutcome.Failure ->
                        _state.value = entry.copy(error = outcome.message)
                }
                return@launch
            }
            when (val outcome = tips.tip(entry.postId, cents)) {
                is TipOutcome.Success -> {
                    _state.value = TipSheetState.Confirmed(outcome.receipt)
                    _effects.trySend(TipEffect.ShowSnackbar(SNACKBAR_SENT))
                }
                TipOutcome.PaymentsUnavailable ->
                    _state.value = entry.copy(error = ERR_PAYMENTS_UNAVAILABLE)
                TipOutcome.Cancelled ->
                    _state.value = entry // back to entry, no error
                is TipOutcome.Failure ->
                    _state.value = entry.copy(error = outcome.message)
            }
        }
    }

    /** Dismiss the sheet; blocked while Submitting (FR-10). */
    fun dismiss() {
        if (_state.value is TipSheetState.Submitting) return
        _state.value = TipSheetState.Hidden
    }

    private fun currentEntry(): TipSheetState.Entry? = _state.value as? TipSheetState.Entry

    private companion object {
        const val SNACKBAR_SENT = "Tip sent"
        const val ERR_PAYMENTS_UNAVAILABLE = "Payments are unavailable right now."
        const val DEFAULT_REACT_EMOJI = "💰"
    }
}

/** AND-178 — tip sheet state machine (scoped to one post). */
sealed interface TipSheetState {
    data object Hidden : TipSheetState

    data class Entry(
        val postId: String,
        val config: TipConfig,
        val selectedCents: Int?,
        val customAmountText: String,
        val error: String? = null,
        /** TIP-204 - non-null + [isReaction] when opened as a money-REACTION (badge) not a direct tip. */
        val emoji: String? = null,
        val isReaction: Boolean = false,
    ) : TipSheetState {
        /** The amount that will be sent: a preset or a parsed custom amount. */
        val effectiveCents: Int? get() = selectedCents
        val canSend: Boolean
            get() {
                val c = effectiveCents ?: return false
                return c in config.minCents..config.maxCents
            }
    }

    data class Submitting(val postId: String, val amountCents: Int) : TipSheetState
    data class Confirmed(val receipt: TipReceipt) : TipSheetState
}

/** AND-178 — one-shot tip effects. */
sealed interface TipEffect {
    data class ShowSnackbar(val message: String) : TipEffect
    /** TIP-204 - a successful post tip-reaction; the host forwards the badge to the feed overlay. */
    data class ReactionBadge(val postId: String, val badge: com.testlogon.android.data.feed.TipReactionBadge) : TipEffect
}

/**
 * Parses a user-typed dollar amount ("5", "5.50") to whole cents, or null if invalid/empty.
 * Pure / JVM-unit-testable; locale-agnostic (accepts '.' as the decimal separator).
 */
internal fun parseDollarsToCents(text: String): Int? {
    val trimmed = text.trim()
    if (trimmed.isEmpty()) return null
    val value = trimmed.toDoubleOrNull() ?: return null
    if (value <= 0.0) return null
    return Math.round(value * 100.0).toInt()
}
