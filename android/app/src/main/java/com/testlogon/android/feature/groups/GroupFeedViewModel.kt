package com.testlogon.android.feature.groups

import android.net.Uri
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.PagingData
import androidx.paging.cachedIn
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.groups.GroupFeedPost
import com.testlogon.android.data.feed.CommentImageUploader
import com.testlogon.android.feature.groups.data.GroupsRepository
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
 * Batch-8 (#11) / Batch-9 (#11) - drives the GROUP FEED (list + full-newsfeed compose) for one group.
 *
 * groupId arrives as a nav arg via [SavedStateHandle]. [posts] is a network Paging-3 stream cached in
 * [viewModelScope]. The composer ([composeState]) posts text + 0..n attached images (uploaded via the
 * shared [CommentImageUploader] = POST /uploads/image, the same uploader the main feed comments use) + an
 * optional paid-lock price; on success the box clears and a one-shot [refreshSignal] tells the screen to
 * call LazyPagingItems.refresh() so the new post appears.
 */
@HiltViewModel
class GroupFeedViewModel @Inject constructor(
    private val repository: GroupsRepository,
    private val imageUploader: CommentImageUploader,
    savedState: SavedStateHandle,
) : ViewModel() {

    val groupId: String = checkNotNull(savedState[ARG_GROUP_ID]) { "missing $ARG_GROUP_ID nav arg" }

    val posts: Flow<PagingData<GroupFeedPost>> =
        repository.groupFeedPager(groupId).cachedIn(viewModelScope)

    private val _composeState = MutableStateFlow(GroupComposeState())
    val composeState: StateFlow<GroupComposeState> = _composeState.asStateFlow()

    private val _refreshSignal = Channel<Unit>(Channel.BUFFERED)
    val refreshSignal = _refreshSignal.receiveAsFlow()

    fun onTextChange(value: String) =
        _composeState.update { it.copy(text = value, error = null) }

    /** Sets the paid-lock price in cents (null/<=0 = a free post). */
    fun onPriceChange(cents: Int?) =
        _composeState.update { it.copy(unlockPriceCents = cents?.takeIf { c -> c > 0 }, error = null) }

    /** Uploads a picked image and appends its url to the staged attachments (max 10). */
    fun attachImage(uri: Uri) {
        if (_composeState.value.imageUrls.size >= MAX_IMAGES) return
        _composeState.update { it.copy(uploadingImage = true, error = null) }
        viewModelScope.launch {
            when (val r = imageUploader.uploadImage(uri)) {
                is ApiResult.Success ->
                    _composeState.update { it.copy(imageUrls = it.imageUrls + r.data, uploadingImage = false) }
                is ApiResult.Failure ->
                    _composeState.update { it.copy(uploadingImage = false, error = r.error.message) }
                is ApiResult.NetworkError ->
                    _composeState.update { it.copy(uploadingImage = false, error = OFFLINE_FALLBACK) }
            }
        }
    }

    fun removeImage(url: String) =
        _composeState.update { it.copy(imageUrls = it.imageUrls.filterNot { u -> u == url }) }

    fun submit() {
        val form = _composeState.value
        val text = form.text.trim()
        if ((text.isEmpty() && form.imageUrls.isEmpty()) || form.sending) return
        _composeState.update { it.copy(sending = true, error = null) }
        viewModelScope.launch {
            val result = repository.createGroupPost(
                groupId = groupId,
                // The backend requires text 1..10000; for an image-only post send a single space.
                text = text.ifEmpty { " " },
                imageUrls = form.imageUrls,
                unlockPriceCents = form.unlockPriceCents,
            )
            when (result) {
                is ApiResult.Success -> {
                    _composeState.value = GroupComposeState()
                    _refreshSignal.send(Unit)
                }
                is ApiResult.Failure ->
                    _composeState.update { it.copy(sending = false, error = result.error.message) }
                is ApiResult.NetworkError ->
                    _composeState.update { it.copy(sending = false, error = OFFLINE_FALLBACK) }
            }
        }
    }

    companion object {
        const val ARG_GROUP_ID = "groupId"
        const val MAX_IMAGES = 10
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Please try again."
    }
}

/** Batch-8/9 (#11) - the group-feed composer state (text + staged images + optional paid-lock price). */
data class GroupComposeState(
    val text: String = "",
    val imageUrls: List<String> = emptyList(),
    val unlockPriceCents: Int? = null,
    val uploadingImage: Boolean = false,
    val sending: Boolean = false,
    val error: String? = null,
)
