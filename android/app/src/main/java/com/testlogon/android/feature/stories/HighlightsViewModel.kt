package com.testlogon.android.feature.stories

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.feed.CurrentUserRepository
import com.testlogon.android.data.stories.HighlightGroup
import com.testlogon.android.data.stories.HighlightsRepository
import com.testlogon.android.data.stories.StoriesRepository
import com.testlogon.android.data.stories.StorySegment
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
 * PAR-16 - render-ready state for the Story Highlights screen.
 *
 * One immutable data class (content persists across refresh). [isOwner] gates every mutating
 * affordance (create / pin / unpin / delete) - false = read-only viewer of someone else's highlights.
 */
data class HighlightsUiState(
    val phase: Phase = Phase.Loading,
    val groups: List<HighlightGroup> = emptyList(),
    val isOwner: Boolean = false,
    val isRefreshing: Boolean = false,
    val isMutating: Boolean = false,
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Error }

    val isEmpty: Boolean get() = groups.isEmpty()
}

/** One-shot side effects (Channel-backed so they are not replayed on rotation). */
sealed interface HighlightsEffect {
    data class ShowMessage(val message: String) : HighlightsEffect
}

/**
 * PAR-16 - drives [HighlightsUiState] from [HighlightsRepository].
 *
 * The `userId` nav arg may be the [ARG_ME] sentinel (opened from the OWN profile, which does not know
 * its own sub); in that case the current user's `user_sub` is resolved from [CurrentUserRepository]
 * (GET /ui/me) first, and the screen is in owner mode. When a real user id is passed (public profile),
 * owner mode is inferred by comparing it to the signed-in sub. Mutations re-read the groups on success
 * (backend is the source of truth). Pin candidates are the owner's active stories
 * (GET /ui/stories/user/{sub}).
 */
@HiltViewModel
class HighlightsViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val repository: HighlightsRepository,
    private val storiesRepository: StoriesRepository,
    private val currentUserRepository: CurrentUserRepository,
) : ViewModel() {

    private val argUserId: String = savedStateHandle.get<String>(ARG_USER_ID).orEmpty()

    private val _uiState = MutableStateFlow(HighlightsUiState())
    val uiState: StateFlow<HighlightsUiState> = _uiState.asStateFlow()

    private val _effects = Channel<HighlightsEffect>(Channel.BUFFERED)
    val effects: Flow<HighlightsEffect> = _effects.receiveAsFlow()

    /** The resolved real user id whose highlights are shown (never the [ARG_ME] sentinel). */
    private var resolvedUserId: String? = null

    /** The owner's active stories, lazily loaded when the pin sheet is first opened. */
    private val _pinCandidates = MutableStateFlow<List<StorySegment>>(emptyList())
    val pinCandidates: StateFlow<List<StorySegment>> = _pinCandidates.asStateFlow()

    init {
        load(fromUser = false)
    }

    fun onRefresh() = load(fromUser = true)

    fun onRetry() = load(fromUser = true)

    private fun load(fromUser: Boolean) {
        val hasContent = _uiState.value.groups.isNotEmpty()
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else HighlightsUiState.Phase.Loading,
                isRefreshing = fromUser && hasContent,
            )
        }
        viewModelScope.launch {
            // Resolve the target user id + owner flag once.
            val signedInSub = (currentUserRepository.currentUserSub() as? ApiResult.Success)?.data
            val target = when {
                resolvedUserId != null -> resolvedUserId!!
                argUserId == ARG_ME || argUserId.isBlank() -> signedInSub
                else -> argUserId
            }
            if (target.isNullOrBlank()) {
                reduceFailure(ACCOUNT_UNRESOLVED)
                return@launch
            }
            resolvedUserId = target
            val isOwner = signedInSub != null && signedInSub == target
            when (val result = repository.highlights(target)) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        phase = HighlightsUiState.Phase.Content,
                        groups = result.data,
                        isOwner = isOwner,
                        isRefreshing = false,
                        errorMessage = null,
                    )
                }
                is ApiResult.Failure -> reduceFailure(result.error.message)
                is ApiResult.NetworkError -> reduceFailure(OFFLINE_FALLBACK)
            }
        }
    }

    /** Load the owner's active stories to offer as pin candidates (owner-only). */
    fun loadPinCandidates() {
        val target = resolvedUserId ?: return
        if (!_uiState.value.isOwner) return
        viewModelScope.launch {
            when (val r = storiesRepository.loadAuthorStories(target)) {
                is ApiResult.Success -> _pinCandidates.value = r.data
                is ApiResult.Failure -> emit(r.error.message)
                is ApiResult.NetworkError -> emit(OFFLINE_FALLBACK)
            }
        }
    }

    /** Create a new highlight group (owner-only). Re-reads on success. */
    fun createGroup(title: String, coverUrl: String?) {
        val name = title.trim()
        if (name.isEmpty() || !_uiState.value.isOwner) return
        mutate { repository.createGroup(name, coverUrl?.trim()?.ifBlank { null }) }
    }

    /** Delete a highlight group (owner-only). Re-reads on success. */
    fun deleteGroup(groupId: String) {
        if (!_uiState.value.isOwner) return
        mutate { repository.deleteGroup(groupId) }
    }

    /** Pin a story into a group (owner-only). Re-reads on success. */
    fun pin(storyId: String, groupId: String?) {
        if (!_uiState.value.isOwner) return
        mutate { repository.pin(storyId, groupId) }
    }

    /** Unpin a story from highlights (owner-only). Re-reads on success. */
    fun unpin(storyId: String) {
        if (!_uiState.value.isOwner) return
        mutate { repository.unpin(storyId) }
    }

    /** Runs a mutation, surfaces failures as a one-shot message, and re-reads the groups on success. */
    private fun mutate(block: suspend () -> ApiResult<*>) {
        if (_uiState.value.isMutating) return
        _uiState.update { it.copy(isMutating = true) }
        viewModelScope.launch {
            when (val r = block()) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(isMutating = false) }
                    reloadGroups()
                }
                is ApiResult.Failure -> {
                    _uiState.update { it.copy(isMutating = false) }
                    emit(if (r.error.status == HTTP_FORBIDDEN) FORBIDDEN_MESSAGE else r.error.message)
                }
                is ApiResult.NetworkError -> {
                    _uiState.update { it.copy(isMutating = false) }
                    emit(OFFLINE_FALLBACK)
                }
            }
        }
    }

    /** Silent re-read of the groups after a mutation (keeps the current content on failure). */
    private suspend fun reloadGroups() {
        val target = resolvedUserId ?: return
        when (val result = repository.highlights(target)) {
            is ApiResult.Success -> _uiState.update {
                it.copy(phase = HighlightsUiState.Phase.Content, groups = result.data)
            }
            is ApiResult.Failure -> emit(result.error.message)
            is ApiResult.NetworkError -> emit(OFFLINE_FALLBACK)
        }
    }

    private suspend fun reduceFailure(message: String) {
        if (_uiState.value.groups.isNotEmpty()) {
            _uiState.update { it.copy(isRefreshing = false) }
            emit(message)
        } else {
            _uiState.update {
                it.copy(
                    phase = HighlightsUiState.Phase.Error,
                    isRefreshing = false,
                    errorMessage = message,
                )
            }
        }
    }

    private fun emit(message: String) {
        _effects.trySend(HighlightsEffect.ShowMessage(message))
    }

    companion object {
        const val ARG_USER_ID = "userId"

        /** Sentinel passed from the OWN profile (which does not know its own sub). */
        const val ARG_ME = "me"

        private const val HTTP_FORBIDDEN = 403
        private const val OFFLINE_FALLBACK = "You're offline. Pull down to retry."
        private const val ACCOUNT_UNRESOLVED = "Couldn't resolve your account."
        private const val FORBIDDEN_MESSAGE = "You can only highlight your own stories."
    }
}
