package com.testlogon.android.feature.videos.detail

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.BillingAuthorizer
import com.testlogon.android.data.messaging.BillingResult
import com.testlogon.android.data.tip.TipConfig
import com.testlogon.android.data.tip.TipReceipt
import com.testlogon.android.data.videos.VideosRepository
import com.testlogon.android.feature.feed.TipEffect
import com.testlogon.android.feature.feed.TipSheetState
import com.testlogon.android.feature.feed.parseDollarsToCents
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
 * B-VIDSOCIAL2 (#2) — drives the tip bottom sheet for a VIDEO, REUSING the feed's [TipSheetState]
 * machine + [TipSheet] composable so the VOD tip UX is identical to a newsfeed-post tip.
 *
 * Money-moving + NON-optimistic: Confirmed appears only after the backend returns success. The same
 * AND-139 [BillingAuthorizer] seam used by the feed/messaging tips obtains a payment_method_id first
 * (debug builds authorize with a blank id so dev-mode tips complete; release builds surface
 * "payments unavailable" until a real vendor is wired). On success it reports the new running tip
 * total back to the detail screen via [TipResultEffect] so the header updates without a reload.
 */
@HiltViewModel
class VideoTipViewModel @Inject constructor(
    private val repository: VideosRepository,
    private val billing: BillingAuthorizer,
) : ViewModel() {

    private val _state = MutableStateFlow<TipSheetState>(TipSheetState.Hidden)
    val state: StateFlow<TipSheetState> = _state.asStateFlow()

    private val _effects = Channel<TipEffect>(Channel.BUFFERED)
    val effects: Flow<TipEffect> = _effects.receiveAsFlow()

    /** One-shot: the new running tip total to push into the detail header after a confirmed tip. */
    private val _tipTotals = Channel<Int>(Channel.BUFFERED)
    val tipTotals: Flow<Int> = _tipTotals.receiveAsFlow()

    fun open(videoId: String) {
        _state.value = TipSheetState.Entry(
            postId = videoId,
            config = TipConfig(),
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
        _state.value = TipSheetState.Submitting(entry.postId, cents)
        viewModelScope.launch {
            // Authorize via the shared billing seam (debug => blank pm id; release => NotConfigured).
            val pmId: String? = when (val auth = billing.authorize(cents.toLong(), CURRENCY_USD)) {
                is BillingResult.Authorized -> auth.paymentMethodId
                BillingResult.NotConfigured -> { _state.value = entry.copy(error = ERR_UNAVAILABLE); return@launch }
                BillingResult.Cancelled -> { _state.value = entry; return@launch }
                is BillingResult.Declined -> { _state.value = entry.copy(error = auth.reason); return@launch }
                is BillingResult.Failed -> { _state.value = entry.copy(error = ERR_GENERIC); return@launch }
            }
            when (val r = repository.tipVideo(entry.postId, cents, pmId)) {
                is ApiResult.Success -> {
                    _state.value = TipSheetState.Confirmed(
                        TipReceipt(postId = entry.postId, amountCents = r.data.amountCents, tipTotalCents = r.data.tipTotalCents),
                    )
                    _tipTotals.trySend(r.data.tipTotalCents)
                    _effects.trySend(TipEffect.ShowSnackbar(SNACKBAR_SENT))
                }
                is ApiResult.Failure -> _state.value = entry.copy(error = r.error.message)
                is ApiResult.NetworkError -> _state.value = entry.copy(error = ERR_OFFLINE)
            }
        }
    }

    fun dismiss() {
        if (_state.value is TipSheetState.Submitting) return
        _state.value = TipSheetState.Hidden
    }

    private fun currentEntry(): TipSheetState.Entry? = _state.value as? TipSheetState.Entry

    private companion object {
        const val CURRENCY_USD = "USD"
        const val SNACKBAR_SENT = "Tip sent"
        const val ERR_UNAVAILABLE = "Payments are unavailable right now."
        const val ERR_GENERIC = "Couldn't send tip. Try again."
        const val ERR_OFFLINE = "You're offline. Try again."
    }
}
