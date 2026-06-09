package com.testlogon.android.feature.messaging.thread

import com.testlogon.android.data.messaging.MessageMedia
import com.testlogon.android.data.messaging.SendStatus

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
