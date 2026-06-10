package com.testlogon.android.feature.messaging.mass

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.PagingData
import androidx.paging.cachedIn
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.Contact
import com.testlogon.android.data.messaging.MessagingRepository
import com.testlogon.android.data.messaging.mass.CampaignMode
import com.testlogon.android.data.messaging.mass.CreateCampaignDraft
import com.testlogon.android.data.messaging.mass.MassCampaign
import com.testlogon.android.data.messaging.mass.MassMessageConfigRepository
import com.testlogon.android.data.messaging.mass.MassMessageRepository
import com.testlogon.android.feature.messaging.thread.debounceCompat
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.UUID
import javax.inject.Inject

/** AND-160 — a selectable recipient (mapped from a [Contact]) in the create sheet. */
data class RecipientUi(
    val conversationId: String,
    val displayName: String,
)

/**
 * AND-160 — create-sheet draft. Recipients are existing conversation ids; the contacts picker maps
 * a Contact's user_id into a conversation id (the explicit conversation_ids model — there is no
 * audience/segment selector). Reuses the SAME contacts search as the group-create member picker.
 */
data class CreateSheetState(
    val visible: Boolean = false,
    val text: String = "",
    val query: String = "",
    val candidates: List<RecipientUi> = emptyList(),
    val selected: List<RecipientUi> = emptyList(),
    val mode: CampaignMode = CampaignMode.IMMEDIATE,
    val sendAtEpochSeconds: Long? = null,
    val isSearching: Boolean = false,
    val submitting: Boolean = false,
    val errorMessage: String? = null,
    val idempotencyKey: String = "",
) {
    val selectedIds: Set<String> get() = selected.mapTo(mutableSetOf()) { it.conversationId }

    /** Submit is enabled with non-blank text in 1..4000, 1..100 recipients, send_at present if scheduled. */
    val canSubmit: Boolean
        get() = text.isNotBlank() &&
            text.length <= MAX_TEXT_LENGTH &&
            selected.size in MIN_RECIPIENTS..MAX_RECIPIENTS &&
            (mode != CampaignMode.SCHEDULED || sendAtEpochSeconds != null) &&
            !submitting

    companion object {
        const val MIN_RECIPIENTS = 1
        const val MAX_RECIPIENTS = 100
        const val MAX_TEXT_LENGTH = 4000
    }
}

data class MassMessagesUiState(
    val isCreator: Boolean = true,
    val createSheet: CreateSheetState = CreateSheetState(),
    val pendingCancelId: String? = null,
    val inFlightCancelIds: Set<String> = emptySet(),
    /** Optimistic/reconciled cancel overlay: campaignId -> new status, applied at render over paged rows. */
    val cancelledOverlay: Map<String, CampaignStatusOverlay> = emptyMap(),
)

/** AND-160 — UI-layer overlay over an immutable paged row while/after a cancel. */
enum class CampaignStatusOverlay { CANCELLING, CANCELLED }

/** One-shot events (snackbar / sheet dismissal). */
sealed interface MassMessagesEvent {
    data class CreatedSnack(val acceptedCount: Int, val rejectedCount: Int) : MassMessagesEvent
    data class CancelledSnack(val cancelledDestinations: Int) : MassMessagesEvent
    data class ErrorSnack(val message: String) : MassMessagesEvent
    data object InvalidateList : MassMessagesEvent
}

/**
 * AND-160 — mass-messages presentation logic.
 *
 * Lists campaigns via Paging 3, creates a campaign (validated draft -> repo.create), and cancels a
 * non-terminal campaign with optimistic + reconciled state. Recipient selection reuses the existing
 * contacts search ([MessagingRepository.searchContacts], AND-153). One-shot effects use Channel +
 * receiveAsFlow. FR-8 gate: [isCreator] reflects messaging_mass_send_enabled.
 */
@HiltViewModel
class MassMessagesViewModel @Inject constructor(
    private val repo: MassMessageRepository,
    private val configRepo: MassMessageConfigRepository,
    private val messagingRepository: MessagingRepository,
) : ViewModel() {

    val campaigns: Flow<PagingData<MassCampaign>> = repo.campaignsPager().cachedIn(viewModelScope)

    private val _ui = MutableStateFlow(MassMessagesUiState())
    val uiState: StateFlow<MassMessagesUiState> = _ui.asStateFlow()

    private val _events = Channel<MassMessagesEvent>(Channel.BUFFERED)
    val events: Flow<MassMessagesEvent> = _events.receiveAsFlow()

    private val queryFlow = MutableStateFlow("")

    init {
        startSearchEngine()
        viewModelScope.launch {
            val enabled = configRepo.isMassSendEnabled()
            _ui.update { it.copy(isCreator = enabled) }
        }
    }

    // ---- create sheet ----

    fun openCreate() {
        _ui.update {
            it.copy(
                createSheet = CreateSheetState(visible = true, idempotencyKey = newIdempotencyKey()),
            )
        }
    }

    fun dismissCreate() {
        _ui.update { it.copy(createSheet = CreateSheetState()) }
        queryFlow.value = ""
    }

    fun onTextChange(value: String) {
        val capped = value.take(CreateSheetState.MAX_TEXT_LENGTH)
        _ui.update { it.copy(createSheet = it.createSheet.copy(text = capped, errorMessage = null)) }
    }

    fun onQueryChange(value: String) {
        val capped = value.take(MAX_QUERY_LENGTH)
        _ui.update { it.copy(createSheet = it.createSheet.copy(query = capped)) }
        if (capped.trim().isEmpty()) {
            _ui.update { it.copy(createSheet = it.createSheet.copy(candidates = emptyList(), isSearching = false)) }
        }
        queryFlow.value = capped
    }

    fun onToggleRecipient(conversationId: String) {
        _ui.update { s ->
            val sheet = s.createSheet
            val next = if (sheet.selectedIds.contains(conversationId)) {
                sheet.copy(selected = sheet.selected.filterNot { it.conversationId == conversationId })
            } else {
                val candidate = sheet.candidates.firstOrNull { it.conversationId == conversationId }
                    ?: return@update s
                if (sheet.selected.size >= CreateSheetState.MAX_RECIPIENTS) return@update s
                sheet.copy(selected = sheet.selected + candidate)
            }
            s.copy(createSheet = next)
        }
    }

    fun onRemoveRecipient(conversationId: String) {
        _ui.update { s ->
            s.copy(
                createSheet = s.createSheet.copy(
                    selected = s.createSheet.selected.filterNot { it.conversationId == conversationId },
                ),
            )
        }
    }

    fun onModeChange(mode: CampaignMode) {
        _ui.update {
            val sheet = it.createSheet
            it.copy(
                createSheet = sheet.copy(
                    mode = mode,
                    sendAtEpochSeconds = if (mode == CampaignMode.SCHEDULED) sheet.sendAtEpochSeconds else null,
                ),
            )
        }
    }

    fun onSendAtChange(epochSeconds: Long?) {
        _ui.update { it.copy(createSheet = it.createSheet.copy(sendAtEpochSeconds = epochSeconds)) }
    }

    fun submitCreate() {
        val sheet = _ui.value.createSheet
        if (!sheet.canSubmit) return
        _ui.update { it.copy(createSheet = it.createSheet.copy(submitting = true, errorMessage = null)) }
        viewModelScope.launch {
            val draft = CreateCampaignDraft(
                text = sheet.text.trim(),
                conversationIds = sheet.selected.map { it.conversationId },
                mode = sheet.mode,
                sendAtEpochSeconds = sheet.sendAtEpochSeconds,
                idempotencyKey = sheet.idempotencyKey,
            )
            when (val r = repo.create(draft)) {
                is ApiResult.Success -> {
                    _ui.update { it.copy(createSheet = CreateSheetState()) }
                    queryFlow.value = ""
                    _events.send(
                        MassMessagesEvent.CreatedSnack(
                            acceptedCount = r.data.acceptedCount,
                            rejectedCount = r.data.rejected.size,
                        ),
                    )
                    _events.send(MassMessagesEvent.InvalidateList)
                }
                is ApiResult.Failure ->
                    _ui.update {
                        it.copy(createSheet = it.createSheet.copy(submitting = false, errorMessage = r.error.message))
                    }
                is ApiResult.NetworkError ->
                    _ui.update {
                        it.copy(createSheet = it.createSheet.copy(submitting = false, errorMessage = OFFLINE_MESSAGE))
                    }
            }
        }
    }

    // ---- cancel ----

    fun requestCancel(id: String) = _ui.update { it.copy(pendingCancelId = id) }

    fun dismissCancel() = _ui.update { it.copy(pendingCancelId = null) }

    fun confirmCancel(id: String, prior: MassCampaign? = null) {
        // Optimistic: show CANCELLING overlay + mark in-flight; clear the dialog.
        _ui.update {
            it.copy(
                pendingCancelId = null,
                inFlightCancelIds = it.inFlightCancelIds + id,
                cancelledOverlay = it.cancelledOverlay + (id to CampaignStatusOverlay.CANCELLING),
            )
        }
        viewModelScope.launch {
            when (val r = repo.cancel(id, prior)) {
                is ApiResult.Success -> {
                    _ui.update {
                        it.copy(
                            inFlightCancelIds = it.inFlightCancelIds - id,
                            cancelledOverlay = it.cancelledOverlay + (id to CampaignStatusOverlay.CANCELLED),
                        )
                    }
                    _events.send(MassMessagesEvent.CancelledSnack(r.data.counters.cancelled))
                    _events.send(MassMessagesEvent.InvalidateList)
                }
                is ApiResult.Failure -> rollbackCancel(id, r.error.message)
                is ApiResult.NetworkError -> rollbackCancel(id, OFFLINE_MESSAGE)
            }
        }
    }

    private suspend fun rollbackCancel(id: String, message: String) {
        _ui.update {
            it.copy(
                inFlightCancelIds = it.inFlightCancelIds - id,
                cancelledOverlay = it.cancelledOverlay - id,
            )
        }
        _events.send(MassMessagesEvent.ErrorSnack(message))
    }

    // ---- contacts search engine (reused pattern from GroupCreateViewModel) ----

    @OptIn(ExperimentalCoroutinesApi::class)
    private fun startSearchEngine() {
        queryFlow
            .debounceCompat(DEBOUNCE_MS)
            .map { it.trim().take(MAX_QUERY_LENGTH) }
            .distinctUntilChanged()
            .flatMapLatest { q ->
                if (q.isEmpty()) {
                    flowOf<SearchEmission>(SearchEmission.Skipped)
                } else {
                    flow<SearchEmission> {
                        emit(SearchEmission.Loading)
                        emit(SearchEmission.Done(messagingRepository.searchContacts(q)))
                    }
                }
            }
            .onEach { applyEmission(it) }
            .launchIn(viewModelScope)
    }

    private fun applyEmission(emission: SearchEmission) {
        when (emission) {
            SearchEmission.Skipped -> Unit
            SearchEmission.Loading ->
                _ui.update { it.copy(createSheet = it.createSheet.copy(isSearching = true)) }
            is SearchEmission.Done -> applyResult(emission.result)
        }
    }

    private fun applyResult(result: ApiResult<List<Contact>>) {
        when (result) {
            is ApiResult.Success ->
                _ui.update {
                    it.copy(
                        createSheet = it.createSheet.copy(
                            isSearching = false,
                            // A Contact's user_id is the conversation id input for the broadcast.
                            candidates = result.data.map { c -> RecipientUi(c.id, c.displayName) },
                        ),
                    )
                }
            is ApiResult.Failure ->
                _ui.update {
                    it.copy(createSheet = it.createSheet.copy(isSearching = false, errorMessage = result.error.message))
                }
            is ApiResult.NetworkError ->
                _ui.update {
                    it.copy(createSheet = it.createSheet.copy(isSearching = false, errorMessage = OFFLINE_MESSAGE))
                }
        }
    }

    private sealed interface SearchEmission {
        data object Skipped : SearchEmission
        data object Loading : SearchEmission
        data class Done(val result: ApiResult<List<Contact>>) : SearchEmission
    }

    companion object {
        const val DEBOUNCE_MS = 300L
        const val MAX_QUERY_LENGTH = 64
        const val OFFLINE_MESSAGE = "You're offline. Try again when you're back online."

        /** Stable client idempotency key (8..128 chars) reused across retries of the same create. */
        fun newIdempotencyKey(): String = UUID.randomUUID().toString().replace("-", "")
    }
}
