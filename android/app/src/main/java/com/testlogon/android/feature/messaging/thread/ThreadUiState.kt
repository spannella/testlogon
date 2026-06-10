package com.testlogon.android.feature.messaging.thread

import com.testlogon.android.data.messaging.CustomEmojiUi
import com.testlogon.android.data.messaging.GifResult
import com.testlogon.android.data.messaging.MeetingPoll
import com.testlogon.android.data.messaging.MessageMedia
import com.testlogon.android.data.messaging.SendStatus
import com.testlogon.android.data.messaging.StickerCollectionUi

/**
 * AND-123 / AND-124 — thread (message list) UI state.
 *
 * `messages` is oldest-first (rendered with the newest at the bottom). Each [ThreadMessageUi] knows
 * whether it is the current user's (for sent/received bubble alignment), derived from the current
 * user_sub vs the message sender_id.
 */
data class ThreadUiState(
    val conversationId: String,
    val title: String = "",
    val messages: List<ThreadMessageUi> = emptyList(),
    val isLoadingInitial: Boolean = true,
    val isLoadingOlder: Boolean = false,
    val endOfHistory: Boolean = false,
    val errorMessage: String? = null,
    val composer: ComposerState = ComposerState(),
    /** AND-131 — video-share picker state (hidden until the user taps "share video"). */
    val videoPicker: VideoPickerState = VideoPickerState(),
    /** AND-133 — voice composer (record/preview/sending) overlay state. */
    val voice: VoiceComposerUiState = VoiceComposerUiState.Idle,
    /** AND-132 — per-message file download state, keyed by server message id. */
    val downloads: Map<String, FileDownloadUi> = emptyMap(),
    /** AND-135 — unified GIF/sticker/emoji media picker state (hidden until opened). */
    val mediaPicker: MediaPickerState = MediaPickerState(),
    /** AND-135 — Room-backed custom-emoji catalog (single source for picker + inline render). */
    val customEmoji: List<CustomEmojiUi> = emptyList(),
    /** AND-136 — per-poll card state (counts/my_vote/mutating/error), keyed by poll id. */
    val polls: Map<String, MeetingPollCardUiState> = emptyMap(),
    /** AND-136 — meeting-poll composer sheet (hidden until opened). */
    val pollComposerVisible: Boolean = false,
)

/** AND-135 — the three picker tabs. */
enum class MediaTab { GIF, STICKERS, EMOJI }

/** AND-135 — unified media-picker (GIF / sticker / custom-emoji) state. */
data class MediaPickerState(
    val visible: Boolean = false,
    val tab: MediaTab = MediaTab.GIF,
    val gifQuery: String = "",
    val gifLoading: Boolean = false,
    val gifResults: List<GifResult> = emptyList(),
    val gifError: String? = null,
    val collectionsLoading: Boolean = false,
    val collections: List<StickerCollectionUi> = emptyList(),
    val selectedCollectionId: String? = null,
    val collectionsError: String? = null,
    val emoji: List<CustomEmojiUi> = emptyList(),
)

/** AND-136 — meeting-poll card render + interaction state. */
data class MeetingPollCardUiState(
    val poll: MeetingPoll,
    val isMutating: Boolean = false,
    val inlineError: String? = null,
    val canManage: Boolean = false,
)

/** AND-133 — voice composer UI state (Idle until the user starts recording). */
sealed interface VoiceComposerUiState {
    data object Idle : VoiceComposerUiState
    data class Recording(val elapsedMs: Long, val peaks: List<Float>, val countdownSeconds: Int?) : VoiceComposerUiState
    data class Preview(val durationMs: Long, val peaks: List<Float>) : VoiceComposerUiState
    data class Sending(val progress: Float) : VoiceComposerUiState
    data class PermissionRequired(val permanentlyDenied: Boolean) : VoiceComposerUiState
    data class Failed(val message: String) : VoiceComposerUiState
}

/** AND-132 — file bubble download state. */
sealed interface FileDownloadUi {
    data object NotDownloaded : FileDownloadUi
    data class Downloading(val fraction: Float) : FileDownloadUi
    data class Downloaded(val localPath: String) : FileDownloadUi
    data class Failed(val message: String) : FileDownloadUi
}

/** AND-131 — state of the library-video share picker sheet. */
data class VideoPickerState(
    val visible: Boolean = false,
    val loading: Boolean = false,
    val videos: List<ShareableVideoUi> = emptyList(),
    val errorMessage: String? = null,
)

data class ShareableVideoUi(
    val videoId: String,
    val title: String,
    val thumbnailUrl: String?,
    val durationSeconds: Int?,
)

data class ThreadMessageUi(
    /** Stable list key: server message id when present, else the local clientId. */
    val key: String,
    val text: String,
    val isOwn: Boolean,
    val createdAtEpochSeconds: Long,
    val sendStatus: SendStatus,
    /** AND-130/131 — media payload; [MessageMedia.None] for plain text. */
    val media: MessageMedia = MessageMedia.None,
) {
    val isFailed: Boolean get() = sendStatus == SendStatus.FAILED
    val isSending: Boolean get() = sendStatus == SendStatus.SENDING
    val isImage: Boolean get() = media is MessageMedia.Image
    val isVideo: Boolean get() = media is MessageMedia.VideoShare
    val isFile: Boolean get() = media is MessageMedia.File
    val isVoice: Boolean get() = media is MessageMedia.Voice
    val isVoicemail: Boolean get() = media is MessageMedia.Voicemail
    val isGif: Boolean get() = media is MessageMedia.Gif
    val isSticker: Boolean get() = media is MessageMedia.Sticker
    val isPoll: Boolean get() = media is MessageMedia.MeetingPoll
}

data class ComposerState(
    val draft: String = "",
    val charCount: Int = 0,
    val overLimit: Boolean = false,
) {
    val isSendEnabled: Boolean get() = draft.isNotBlank() && !overLimit

    companion object {
        const val MAX_LENGTH = 4000
    }
}
