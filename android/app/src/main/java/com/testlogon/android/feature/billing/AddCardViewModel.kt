package com.testlogon.android.feature.billing

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.data.billing.CardEntryResult
import com.testlogon.android.data.billing.CardTokenizer
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
 * AND-226 — add-card screen state.
 *
 * FLAGGED: the screen never renders raw card-number/CVC fields; card entry is delegated to the
 * [CardTokenizer] seam, which is the [com.testlogon.android.data.billing.StubCardTokenizer] today and
 * returns NotConfigured. So the steady state is [unavailable] = true ("card entry unavailable /
 * payments not configured"). [isPreparing] guards a duplicate submit while the (stub) call runs.
 */
data class AddCardUiState(
    val isPreparing: Boolean = false,
    val unavailable: Boolean = false,
)

/** AND-226 — one-shot effects from the add-card flow. */
sealed interface AddCardEvent {
    /** Card saved (only reachable with a real tokenizer — never from the stub). Triggers a list refresh. */
    data object Saved : AddCardEvent

    /** Payments / card entry not configured (the FLAGGED stub path). */
    data object NotConfigured : AddCardEvent

    data class Failure(val message: String) : AddCardEvent
}

/**
 * AND-226 — add-card presentation logic, wired to the [CardTokenizer] seam (AND-225).
 *
 * STOP-AND-FLAG (Stripe vendor SDK): there is NO Stripe dependency and NO real tokenization. Tapping
 * "Add card" calls [CardTokenizer.addCard]; the bound [StubCardTokenizer] returns
 * [CardEntryResult.NotConfigured], so the flow surfaces a "payments not configured" state and NEVER
 * tokenizes a card, confirms a SetupIntent, or fakes a charge. When the Stripe SDK decision is made,
 * binding the real tokenizer makes the Saved/Failed/Cancelled branches live with no ViewModel change.
 */
@HiltViewModel
class AddCardViewModel @Inject constructor(
    private val tokenizer: CardTokenizer,
) : ViewModel() {

    private val _state = MutableStateFlow(AddCardUiState())
    val uiState: StateFlow<AddCardUiState> = _state.asStateFlow()

    private val _events = Channel<AddCardEvent>(Channel.BUFFERED)
    val events: Flow<AddCardEvent> = _events.receiveAsFlow()

    fun onAddCard() {
        if (_state.value.isPreparing) return
        _state.update { it.copy(isPreparing = true) }
        viewModelScope.launch {
            when (val result = tokenizer.addCard()) {
                is CardEntryResult.NotConfigured -> {
                    _state.update { it.copy(isPreparing = false, unavailable = true) }
                    _events.send(AddCardEvent.NotConfigured)
                }
                is CardEntryResult.Saved -> {
                    _state.update { it.copy(isPreparing = false) }
                    _events.send(AddCardEvent.Saved)
                }
                is CardEntryResult.Cancelled -> _state.update { it.copy(isPreparing = false) }
                is CardEntryResult.Failed -> {
                    _state.update { it.copy(isPreparing = false) }
                    _events.send(AddCardEvent.Failure(result.message))
                }
            }
        }
    }
}
