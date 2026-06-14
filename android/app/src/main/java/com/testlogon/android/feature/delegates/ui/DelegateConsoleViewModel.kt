package com.testlogon.android.feature.delegates.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.delegates.data.DelegateFeedRepository
import com.testlogon.android.feature.delegates.data.DelegateMessagingRepository
import com.testlogon.android.feature.delegates.data.DelegationContextProvider
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-360 - the focused demonstration ViewModel: in delegate mode it loads the managed creator's delegate
 * feed posts (feed_read) + conversations (chat_read) and offers create-post (feed_post) / send-message
 * (chat_respond), each gated by the delegate repositories. This proves "a delegate can act in delegated
 * surfaces" without retrofitting the mature feed / broadcast / messaging screens.
 *
 * It observes the typed delegation context; when there is no active context the UI shows the enter prompt.
 * The repositories already block a permission-less action WITHOUT calling the API and AUTO-EXIT on a 403,
 * so a blocked / revoked action surfaces a notice and the banner disappears once the context clears.
 */
@HiltViewModel
class DelegateConsoleViewModel @Inject constructor(
    private val contextProvider: DelegationContextProvider,
    private val feedRepository: DelegateFeedRepository,
    private val messagingRepository: DelegateMessagingRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(DelegateConsoleUiState())
    val uiState: StateFlow<DelegateConsoleUiState> = _uiState.asStateFlow()

    init {
        observeContext()
    }

    /** Re-projects the typed context into the base UI state and (re)loads when a context becomes active. */
    private fun observeContext() {
        viewModelScope.launch {
            contextProvider.delegationContext.collect { ctx ->
                if (ctx == null) {
                    _uiState.value = DelegateConsoleUiState(active = false)
                } else {
                    _uiState.value = _uiState.value.copy(
                        active = true,
                        creatorName = ctx.creatorName,
                        canReadFeed = feedRepository.canRead(),
                        canPostFeed = feedRepository.canPost(),
                        canReadChat = messagingRepository.canRead(),
                        canRespond = messagingRepository.canRespond(),
                    )
                    load()
                }
            }
        }
    }

    /** Loads the delegate feed posts + conversations the context is permitted to read. */
    fun load() {
        if (!_uiState.value.active) return
        _uiState.value = _uiState.value.copy(loading = true, loadFailed = false)
        viewModelScope.launch {
            val posts = if (feedRepository.canRead()) {
                (feedRepository.listPosts() as? ApiResult.Success)?.data
            } else {
                emptyList()
            }
            val conversations = if (messagingRepository.canRead()) {
                (messagingRepository.conversations() as? ApiResult.Success)?.data
            } else {
                emptyList()
            }
            _uiState.value = _uiState.value.copy(
                loading = false,
                posts = posts.orEmpty(),
                conversations = conversations.orEmpty(),
                loadFailed = (feedRepository.canRead() && posts == null) ||
                    (messagingRepository.canRead() && conversations == null),
            )
        }
    }

    /** Creates a delegate post (gated by feed_post in the repository); refreshes the feed on success. */
    fun createPost(text: String) {
        if (text.isBlank()) return
        viewModelScope.launch {
            when (feedRepository.createPost(text.trim())) {
                is ApiResult.Success -> load()
                else -> _uiState.value = _uiState.value.copy(notice = NOTICE_ACTION_FAILED)
            }
        }
    }

    /** Sends a delegate message into [conversationId] (gated by chat_respond in the repository). */
    fun sendMessage(conversationId: String, text: String) {
        if (text.isBlank()) return
        viewModelScope.launch {
            when (messagingRepository.send(conversationId, text.trim())) {
                is ApiResult.Success -> _uiState.value = _uiState.value.copy(notice = null)
                else -> _uiState.value = _uiState.value.copy(notice = NOTICE_ACTION_FAILED)
            }
        }
    }

    /** EXIT delegate mode (AND-359 pure-local exit). */
    fun exit() {
        viewModelScope.launch { contextProvider.exit() }
    }

    /** Clears a transient notice after it has been surfaced. */
    fun consumeNotice() {
        if (_uiState.value.notice != null) _uiState.value = _uiState.value.copy(notice = null)
    }

    private companion object {
        const val NOTICE_ACTION_FAILED = "action_failed"
    }
}
