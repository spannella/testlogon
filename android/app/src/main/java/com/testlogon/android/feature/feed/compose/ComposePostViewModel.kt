package com.testlogon.android.feature.feed.compose

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.groups.Group
import com.testlogon.android.data.feed.FeedRefreshBus
import com.testlogon.android.data.feed.PostComposeRepository
import com.testlogon.android.data.feed.PostVisibility
import com.testlogon.android.data.feed.NewsfeedPollDataReq
import com.testlogon.android.data.feed.NewsfeedPollQuestionReq
import com.testlogon.android.data.feed.NewsfeedPollOptionReq
import com.testlogon.android.core.network.poll.PollInputDto
import com.testlogon.android.feature.common.poll.PollDraft
import com.testlogon.android.data.videos.VideoUploadRepository
import com.testlogon.android.feature.groups.data.GroupsRepository
import com.testlogon.android.navigation.ComposePostDest
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * #2 — one picked video in the composer. [localUri] is shown immediately (real frame + local playback);
 * [videoId] is filled once the VOD upload completes; [uploading] is true while it uploads.
 */
data class PickedVideo(
    val localUri: String,
    val videoId: String? = null,
    val uploading: Boolean = true,
)

/** Compose-a-newsfeed-post screen state. */
data class ComposePostUiState(
    val body: String = "",
    val visibility: PostVisibility = PostVisibility.PUBLIC,
    val lockPriceInput: String = "",
    /** Arbitrary future publish time (epoch seconds); null = publish now. */
    val publishAtEpochSeconds: Long? = null,
    /**
     * #4 (B-GROUPUNIFY) — the audience this post is being shared to. `null` = the user's personal feed
     * (POST /posts); a non-null [Group] routes the post to that group (POST /ui/groups/{id}/posts), which
     * the backend bridges back into the unified feed + my-posts. This is the SAME composer either way —
     * the group is just an audience choice.
     */
    val targetGroup: Group? = null,
    /** The user's groups, offered as audience options. Empty until loaded (or if the user has none). */
    val myGroups: List<Group> = emptyList(),
    /** True when the target group was fixed by the caller (composing FROM a group feed) — not switchable. */
    val groupLocked: Boolean = false,
    /** #2 — uploaded media to attach: image urls (0..n) + 0..n videos. Images AND videos may coexist. */
    val imageUrls: List<String> = emptyList(),
    /** #2 — the picked videos (each with its local uri + uploaded id + uploading flag). */
    val videos: List<PickedVideo> = emptyList(),
    val uploadingMedia: Boolean = false,
    val submitting: Boolean = false,
    val error: String? = null,
    /** Flipped true on a successful post so the screen can pop back. */
    val posted: Boolean = false,
    /** Arbitrary text-option poll: enabled + its draft (question + 2..N options + single/multi + close). */
    val pollEnabled: Boolean = false,
    val pollDraft: PollDraft = PollDraft(),
) {
    /** #2 — video ids of the FULLY-uploaded videos (the ones the post can reference). */
    val uploadedVideoIds: List<String> get() = videos.mapNotNull { it.videoId }

    /** True while ANY picked video is still uploading. */
    val uploadingVideo: Boolean get() = videos.any { it.uploading }

    val pollValid: Boolean get() = pollEnabled && pollDraft.isValid

    val canPost: Boolean
        get() = (body.isNotBlank() || imageUrls.isNotEmpty() || videos.isNotEmpty() || pollValid) &&
            !submitting && !uploadingMedia && !uploadingVideo
}

@HiltViewModel
class ComposePostViewModel @Inject constructor(
    private val repository: PostComposeRepository,
    private val videoUploads: VideoUploadRepository,
    private val feedRefreshBus: FeedRefreshBus,
    private val groupsRepository: GroupsRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    /** Optional nav arg: compose directly into this group (locks the audience to it). */
    private val fixedGroupId: String? =
        savedState.get<String>(ComposePostDest.ARG_GROUP_ID)?.takeIf { it.isNotBlank() }

    private val _state = MutableStateFlow(ComposePostUiState(groupLocked = fixedGroupId != null))
    val state: StateFlow<ComposePostUiState> = _state.asStateFlow()

    init {
        loadGroups()
    }

    /**
     * #4 — load the user's groups so they can be chosen as the post audience. If a [fixedGroupId] nav arg
     * was supplied (composing from a group feed) the matching group is pre-selected and locked.
     */
    private fun loadGroups() {
        viewModelScope.launch {
            when (val r = groupsRepository.listMyGroups()) {
                is ApiResult.Success -> _state.update { s ->
                    val fixed = fixedGroupId?.let { id -> r.data.firstOrNull { it.id == id } }
                    s.copy(
                        myGroups = r.data,
                        // Keep a fixed group selected even if it is not in the list (still post to it).
                        targetGroup = fixed ?: s.targetGroup
                            ?: fixedGroupId?.let { Group(id = it, name = "this group") },
                    )
                }
                // A failure to load groups is non-fatal — the user can still post to their feed.
                is ApiResult.Failure, is ApiResult.NetworkError -> Unit
            }
        }
    }

    /** #4 — choose the post audience: null = personal feed, a [Group] = that group's feed. */
    fun onTargetGroupChange(group: Group?) {
        if (_state.value.groupLocked) return
        _state.update { it.copy(targetGroup = group) }
    }

    fun onBodyChange(text: String) = _state.update { it.copy(body = text, error = null) }
    fun onVisibilityChange(v: PostVisibility) = _state.update { it.copy(visibility = v) }
    fun onLockPriceChange(text: String) = _state.update { it.copy(lockPriceInput = text) }
    fun onScheduleChange(epochSeconds: Long?) = _state.update { it.copy(publishAtEpochSeconds = epochSeconds) }
    fun onPollEnabledChange(enabled: Boolean) = _state.update { it.copy(pollEnabled = enabled, error = null) }
    fun onPollDraftChange(draft: PollDraft) = _state.update { it.copy(pollDraft = draft, error = null) }
    fun removeImage(url: String) = _state.update { it.copy(imageUrls = it.imageUrls - url) }

    /** #2 — remove a picked video by its local uri (works whether or not it finished uploading). */
    fun removeVideo(localUri: String) = _state.update {
        it.copy(videos = it.videos.filterNot { v -> v.localUri == localUri })
    }

    /**
     * #2 / FD8 — pick ANOTHER video; upload it to the VOD pipeline and attach its video_id. Multiple
     * videos (and images) can be attached to one post. The local clip previews/plays immediately while
     * the upload runs in parallel.
     */
    fun onVideoPicked(uri: android.net.Uri?) {
        if (uri == null) return
        val key = uri.toString()
        // Ignore an accidental duplicate pick of the same uri.
        if (_state.value.videos.any { it.localUri == key }) return
        _state.update { it.copy(videos = it.videos + PickedVideo(localUri = key), error = null) }
        viewModelScope.launch {
            val title = _state.value.body.trim().take(80).ifBlank { "Video post" }
            when (val r = videoUploads.upload(uri, title = title, description = "")) {
                is ApiResult.Success -> _state.update { s ->
                    s.copy(videos = s.videos.map { v -> if (v.localUri == key) v.copy(videoId = r.data, uploading = false) else v })
                }
                is ApiResult.Failure -> _state.update { s ->
                    s.copy(videos = s.videos.filterNot { v -> v.localUri == key }, error = r.error.message)
                }
                is ApiResult.NetworkError -> _state.update { s ->
                    s.copy(videos = s.videos.filterNot { v -> v.localUri == key }, error = "Video upload failed.")
                }
            }
        }
    }

    /** Upload picked images (uris) and add their urls to the post. */
    fun onImagesPicked(uris: List<android.net.Uri>) {
        if (uris.isEmpty()) return
        _state.update { it.copy(uploadingMedia = true, error = null) }
        viewModelScope.launch {
            val urls = mutableListOf<String>()
            for (u in uris) {
                when (val r = repository.uploadImage(u)) {
                    is ApiResult.Success -> urls += r.data
                    is ApiResult.Failure -> _state.update { it.copy(error = r.error.message) }
                    is ApiResult.NetworkError -> _state.update { it.copy(error = "Upload failed.") }
                }
            }
            _state.update { it.copy(uploadingMedia = false, imageUrls = it.imageUrls + urls) }
        }
    }

    fun post() {
        val s = _state.value
        if (!s.canPost) return
        _state.update { it.copy(submitting = true, error = null) }
        viewModelScope.launch {
            val cents = parseDollarsToCents(s.lockPriceInput)
            val group = s.targetGroup
            val nowSec = System.currentTimeMillis() / 1000L
            val poll = s.pollDraft.takeIf { s.pollEnabled && it.isValid }
            val choiceMode = if (poll?.multiSelect == true) "multi" else "single"
            val groupPoll: PollInputDto? = poll?.let { d ->
                PollInputDto(
                    question = d.question.trim(),
                    options = d.trimmedOptions,
                    choiceMode = choiceMode,
                    maxSelections = if (d.multiSelect) d.trimmedOptions.size else null,
                    closesAt = d.closesAtOrNull(nowSec),
                    allowWriteIn = d.allowWriteIn,
                )
            }
            val newsfeedPoll: NewsfeedPollDataReq? = poll?.let { d ->
                NewsfeedPollDataReq(
                    questions = listOf(
                        NewsfeedPollQuestionReq(
                            text = d.question.trim(),
                            choiceMode = choiceMode,
                            options = d.trimmedOptions.map { NewsfeedPollOptionReq(it) },
                            maxSelections = if (d.multiSelect) d.trimmedOptions.size else null,
                            allowWriteIn = d.allowWriteIn,
                        ),
                    ),
                    closesAt = d.closesAtOrNull(nowSec),
                    allowWriteIn = d.allowWriteIn,
                )
            }
            // #4 (B-GROUPUNIFY) — a group audience posts to the group store (the backend bridges it into
            // the unified feed + my-posts); the personal feed uses POST /posts. Same composer, same fields.
            val result: ApiResult<Unit> = if (group != null) {
                // The group endpoint requires a non-empty text (1..10000); an image/video-only post
                // sends a single space (matching the existing group composer behavior).
                when (val gr = groupsRepository.createGroupPost(
                    groupId = group.id,
                    text = s.body.trim().ifEmpty { poll?.question?.trim()?.ifEmpty { " " } ?: " " },
                    imageUrls = s.imageUrls,
                    videoId = s.uploadedVideoIds.firstOrNull(),
                    unlockPriceCents = cents?.toInt(),
                    poll = groupPoll,
                )) {
                    is ApiResult.Success -> ApiResult.Success(Unit)
                    is ApiResult.Failure -> ApiResult.Failure(gr.error)
                    is ApiResult.NetworkError -> ApiResult.NetworkError(gr.cause, gr.isTimeout)
                }
            } else {
                val bodyOut = s.body.trim().ifEmpty { if (newsfeedPoll != null) poll?.question?.trim().orEmpty() else "" }
                repository.createPost(bodyOut, s.visibility, cents, s.publishAtEpochSeconds, s.imageUrls, s.uploadedVideoIds, newsfeedPoll)
            }
            when (result) {
                is ApiResult.Success -> {
                    // #18a — make the just-published post appear in the main feed immediately.
                    feedRefreshBus.signal()
                    _state.update { it.copy(submitting = false, posted = true) }
                }
                is ApiResult.Failure -> _state.update { it.copy(submitting = false, error = result.error.message) }
                is ApiResult.NetworkError -> _state.update { it.copy(submitting = false, error = "You're offline. Try again.") }
            }
        }
    }

    private fun parseDollarsToCents(input: String): Long? {
        val t = input.trim()
        if (t.isEmpty()) return null
        val d = t.toDoubleOrNull() ?: return null
        if (d <= 0.0) return null
        return Math.round(d * 100.0)
    }
}
