package com.testlogon.android.feature.checkout.address

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.address.Address
import com.testlogon.android.data.address.AddressDraft
import com.testlogon.android.data.address.AddressRepository
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
 * AND-214 — the address step state.
 *
 * SCOPE (spec sections 1/5/16): shipping quote/option/apply have NO backend support and are NOT
 * modelled here — there is no `ShippingQuoteState`/`ShippingOption`. The buildable slice is: list saved
 * addresses (primary pre-selected), add a new address, select one, and mark it primary (the only
 * backend-supported "apply to order").
 */
sealed interface AddressShippingUiState {
    data object Loading : AddressShippingUiState
    data class Ready(
        val addresses: List<Address>,
        val selectedAddressId: String?,
        val applying: Boolean = false,
    ) : AddressShippingUiState

    data class Error(val message: String, val retryable: Boolean) : AddressShippingUiState
}

/** AND-214 — one-shot effects, delivered over a Channel so rotation cannot replay them. */
sealed interface AddressShippingEvent {
    /** Address marked primary + applied; the route navigates onward to the payment step. */
    data class Applied(val addressId: String) : AddressShippingEvent
    data class ActionFailed(val message: String) : AddressShippingEvent
    /** Inline 422 field errors for the open add-address sheet (loc-path last segment -> message). */
    data class ValidationFailed(val fieldErrors: Map<String, String>) : AddressShippingEvent
}

/**
 * AND-214 — address-step presentation logic.
 *
 * Loads saved addresses (pre-selecting the `is_primary_mailing` one), supports adding a new address
 * (auto-selected on success), and applying the selection by marking it primary
 * (PUT ui/addresses/primary). One-shot outcomes ride a Channel; 422 field errors are projected from the
 * FastAPI `detail` loc-path so the form can show inline messages.
 */
@HiltViewModel
class AddressShippingViewModel @Inject constructor(
    private val repository: AddressRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<AddressShippingUiState>(AddressShippingUiState.Loading)
    val state: StateFlow<AddressShippingUiState> = _state.asStateFlow()

    private val _events = Channel<AddressShippingEvent>(Channel.BUFFERED)
    val events: Flow<AddressShippingEvent> = _events.receiveAsFlow()

    init {
        load()
    }

    fun load() {
        _state.update { AddressShippingUiState.Loading }
        viewModelScope.launch {
            _state.value = when (val r = repository.listAddresses()) {
                is ApiResult.Success -> {
                    val addresses = r.data
                    // Pre-select the primary mailing address when present (web/server-authoritative).
                    val preselected = addresses.firstOrNull { it.isPrimaryMailing }?.addressId
                    AddressShippingUiState.Ready(addresses = addresses, selectedAddressId = preselected)
                }
                is ApiResult.Failure -> AddressShippingUiState.Error(r.error.message, retryable = true)
                is ApiResult.NetworkError -> AddressShippingUiState.Error(OFFLINE_MESSAGE, retryable = true)
            }
        }
    }

    fun retry() = load()

    /** AND-214 — single-choice selection (radio semantics). No shipping re-quote (no endpoint). */
    fun onSelectAddress(addressId: String) {
        val ready = _state.value as? AddressShippingUiState.Ready ?: return
        if (ready.addresses.none { it.addressId == addressId }) return
        _state.value = ready.copy(selectedAddressId = addressId)
    }

    /**
     * AND-214 — creates a new address. On success it is appended + auto-selected; a 422 projects inline
     * field errors; other failures surface a one-shot ActionFailed (the sheet keeps its input).
     */
    fun onAddAddress(draft: AddressDraft) {
        if (!draft.isValid) {
            viewModelScope.launch {
                _events.send(AddressShippingEvent.ValidationFailed(mapOf(FIELD_LINE1 to "Required")))
            }
            return
        }
        viewModelScope.launch {
            when (val r = repository.createAddress(draft)) {
                is ApiResult.Success -> {
                    val created = r.data
                    val ready = _state.value as? AddressShippingUiState.Ready
                    _state.value = if (ready != null) {
                        ready.copy(
                            addresses = ready.addresses + created,
                            selectedAddressId = created.addressId,
                        )
                    } else {
                        AddressShippingUiState.Ready(listOf(created), created.addressId)
                    }
                }
                is ApiResult.Failure -> {
                    val fieldErrors = r.error.fieldErrors()
                    if (fieldErrors.isNotEmpty()) {
                        _events.send(AddressShippingEvent.ValidationFailed(fieldErrors))
                    } else {
                        _events.send(AddressShippingEvent.ActionFailed(r.error.message))
                    }
                }
                is ApiResult.NetworkError ->
                    _events.send(AddressShippingEvent.ActionFailed(OFFLINE_MESSAGE))
            }
        }
    }

    /**
     * AND-214 — applies the selected address by marking it primary (the only backend "apply"). Emits
     * [AddressShippingEvent.Applied] so the route can continue to payment.
     */
    fun onApply() {
        val ready = _state.value as? AddressShippingUiState.Ready ?: return
        val addressId = ready.selectedAddressId ?: return
        if (ready.applying) return
        _state.value = ready.copy(applying = true)
        viewModelScope.launch {
            when (val r = repository.setPrimary(addressId)) {
                is ApiResult.Success -> {
                    // Reflect the new primary in the list + clear the applying flag, then navigate.
                    val updated = r.data
                    val merged = ready.addresses.map {
                        when {
                            it.addressId == updated.addressId -> updated
                            it.isPrimaryMailing -> it.copy(isPrimaryMailing = false)
                            else -> it
                        }
                    }
                    _state.value = ready.copy(
                        addresses = merged,
                        selectedAddressId = updated.addressId,
                        applying = false,
                    )
                    _events.send(AddressShippingEvent.Applied(updated.addressId))
                }
                is ApiResult.Failure -> {
                    _state.value = ready.copy(applying = false)
                    _events.send(AddressShippingEvent.ActionFailed(r.error.message))
                }
                is ApiResult.NetworkError -> {
                    _state.value = ready.copy(applying = false)
                    _events.send(AddressShippingEvent.ActionFailed(OFFLINE_MESSAGE))
                }
            }
        }
    }

    companion object {
        const val FIELD_LINE1 = "line1"
        private const val OFFLINE_MESSAGE = "You're offline"
    }
}

/**
 * Projects a FastAPI 422 `detail` array into per-field messages keyed by the loc-path's last segment
 * (e.g. ["body","line1"] -> "line1"). Non-422 / non-array errors yield an empty map. The original JSON
 * body lives on [com.testlogon.android.core.model.ApiError.raw] (retained for logging) and is the only
 * place the per-field loc paths survive after normalization.
 */
internal fun com.testlogon.android.core.model.ApiError.fieldErrors(): Map<String, String> {
    if (status != 422) return emptyMap()
    val rawBody = raw as? String ?: return emptyMap()
    return parseFieldErrors(rawBody)
}

/** Decodes `{"detail":[{"loc":[...],"msg":"..."}]}` into fieldName -> msg using a tolerant Moshi map. */
private val fieldErrorAdapter by lazy {
    com.squareup.moshi.Moshi.Builder().build().adapter<Map<String, Any?>>(
        com.squareup.moshi.Types.newParameterizedType(
            Map::class.java,
            String::class.java,
            Any::class.java,
        ),
    )
}

internal fun parseFieldErrors(rawBody: String): Map<String, String> {
    val detail = try {
        fieldErrorAdapter.fromJson(rawBody)?.get("detail")
    } catch (_: Exception) {
        null
    }
    val list = detail as? List<*> ?: return emptyMap()
    val out = mutableMapOf<String, String>()
    for (entry in list) {
        val obj = entry as? Map<*, *> ?: continue
        val loc = obj["loc"] as? List<*> ?: continue
        val field = loc.lastOrNull()?.toString() ?: continue
        val msg = obj["msg"]?.toString() ?: continue
        out[field] = msg
    }
    return out
}
