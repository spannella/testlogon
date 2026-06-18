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
    /** AND-137 — countdown picker sheet state (hidden until opened). */
    val countdownPicker: CountdownPickerState = CountdownPickerState(),
    /** AND-139 — per-message unlock phase (FIXED or LOTTERY), keyed by message key. */
    val unlocks: Map<String, UnlockUiState> = emptyMap(),
    /** AND-139 — tip sheet state (non-null messageId = open). */
    val tipSheet: TipSheetState = TipSheetState(),
    /** AND-139 — one-shot user-facing confirmation/snackbar text (cleared after shown). */
    val transientMessage: String? = null,
    // ---- AND-140: per-message actions (reactions / pins / edits / delete / revoke / hide) ----
    /** Auxiliary action-sheet + edit-mode state. */
    val actions: MessageActionsUiState = MessageActionsUiState(),
    // ---- AND-141: drafts ----
    /** True when a non-blank draft exists for this conversation (gates "Discard draft"). */
    val hasDraft: Boolean = false,
    /** Last draft sync outcome (non-blocking UX only). */
    val draftSyncState: DraftSyncState = DraftSyncState.Idle,
    // ---- AND-147: read receipts / views ----
    /** Per-own-message receipt state (delivered/seen + viewer roster), keyed by server message id. */
    val receipts: Map<String, com.testlogon.android.data.messaging.realtime.MessageReceipt> = emptyMap(),
    /** Viewer-roster bottom sheet state (non-null messageId = open). */
    val viewerRoster: ViewerRosterUiState = ViewerRosterUiState(),
    /** Whether the send-options (view-once / locked / scheduled) bottom sheet is open. */
    val messageOptionsVisible: Boolean = false,
)

/**
 * AND-147 — viewer-roster ("Seen by") sheet. Non-null [messageId] = open. [viewers] are most-recent
 * first; the network fetch is single-shot (no cursor) but live `message:viewed` events fold in while
 * the sheet is open.
 */
data class ViewerRosterUiState(
    val messageId: String? = null,
    val loading: Boolean = false,
    val viewers: List<com.testlogon.android.data.messaging.realtime.MessageViewer> = emptyList(),
    val error: String? = null,
)

/** AND-140 — generic async loader state for the read sheets (reaction details / pins / edits). */
sealed interface Async<out T> {
    data object Idle : Async<Nothing>
    data object Loading : Async<Nothing>
    data class Success<T>(val data: T) : Async<T>
    data class Error(val message: String) : Async<Nothing>
}

/** AND-141 — non-blocking draft sync indicator. */
enum class DraftSyncState { Idle, Saving, SavedLocal, Synced, Error }

/** AND-140 — the message currently being edited (composer is pre-filled with [originalText]). */
data class EditTarget(val messageId: String, val originalText: String)

/**
 * AND-140 — one-shot intents from the message long-press action surface. Dispatched through
 * [ThreadViewModel.onAction] on viewModelScope.
 */
sealed interface ThreadAction {
    data class ToggleReaction(val messageId: String, val emoji: String) : ThreadAction
    data class OpenReactionDetails(val messageId: String) : ThreadAction
    data class SetPinned(val messageId: String, val pinned: Boolean) : ThreadAction
    data object OpenPinsList : ThreadAction
    data class Reply(val messageId: String) : ThreadAction
    data object CancelReply : ThreadAction
    data class StartEdit(val messageId: String) : ThreadAction
    data class SubmitEdit(val messageId: String, val body: String) : ThreadAction
    data object CancelEdit : ThreadAction
    data class OpenEditHistory(val messageId: String) : ThreadAction
    data class Delete(val messageId: String) : ThreadAction
    data class Revoke(val messageId: String) : ThreadAction
    data class SetHidden(val messageId: String, val hidden: Boolean) : ThreadAction

    /** AND-163 — open the report sheet for a (non-own) message. */
    data class Report(val messageId: String) : ThreadAction
    data object DismissSheets : ThreadAction
}

/**
 * AND-164 — the closed set of client-initiated destructive/mutating message actions, gated centrally so
 * a hold suppresses them all. (Reactions/report are not destructive and are not gated by a hold.)
 */
enum class MessageAction { PIN, EDIT, DELETE, REVOKE, HIDE }

/**
 * AND-164 — actions allowed for a message: none when [ThreadMessageUi.onHold], the full set otherwise.
 * Pure function of UI state so the Compose layer stays dumb and the server is never relied upon to reject.
 */
fun ThreadMessageUi.allowedActions(): Set<MessageAction> =
    if (onHold) emptySet() else MessageAction.entries.toSet()

/** AND-140 — auxiliary state for the action sheets + edit mode + transient errors. */
data class MessageActionsUiState(
    val reactionDetails: Async<List<com.testlogon.android.data.messaging.Reactor>> = Async.Idle,
    val pinned: Async<List<ThreadMessageUi>> = Async.Idle,
    val editHistory: Async<List<com.testlogon.android.data.messaging.MessageEdit>> = Async.Idle,
    /** Non-null while editing one of the user's own messages. */
    val editing: EditTarget? = null,
    /** Whether the pins-list sheet is open. */
    val pinsSheetVisible: Boolean = false,
    /** Whether the reaction-details sheet is open. */
    val reactionDetailsVisible: Boolean = false,
    /** Whether the edit-history sheet is open. */
    val editHistoryVisible: Boolean = false,
    val transientError: String? = null,
)

/** AND-137 — countdown picker draft + inline validation error. */
data class CountdownPickerState(
    val visible: Boolean = false,
    val title: String = "",
    /** Chosen target as UTC epoch seconds; null until a future date/time is picked. */
    val targetEpochSeconds: Long? = null,
    val error: String? = null,
) {
    val isSendEnabled: Boolean
        get() = title.trim().length in 1..200 && targetEpochSeconds != null
}

/** AND-139 — per-message unlock progress. */
enum class UnlockPhase { IDLE, AUTHORIZING, UNLOCKING, FAILED }

data class UnlockUiState(
    val phase: UnlockPhase = UnlockPhase.IDLE,
    val error: String? = null,
)

/** AND-139 — tip sheet (preset/custom amount + optional note). Amounts are integer cents. */
data class TipSheetState(
    /** Non-null = sheet open for this message key. */
    val messageId: String? = null,
    val presetsCents: List<Long> = listOf(100, 500, 1000, 2000),
    val selectedCents: Long? = null,
    val customInput: String = "",
    val note: String = "",
    val amountError: String? = null,
    val submitting: Boolean = false,
) {
    /** Effective amount in cents from the selected preset or the parsed custom input. */
    val amountCents: Long? get() = selectedCents ?: parseDollarsToCents(customInput)

    val isConfirmEnabled: Boolean
        get() = !submitting && amountCents.let { it != null && it in MIN_TIP_CENTS..MAX_TIP_CENTS } &&
            note.length <= MAX_NOTE_LENGTH

    companion object {
        const val MIN_TIP_CENTS = 1L
        const val MAX_TIP_CENTS = 100_000L
        const val MAX_NOTE_LENGTH = 500
    }
}

/**
 * AND-139 — parse a locale-simple dollar string ("7.50") to integer cents, mirroring the web
 * `Math.round(parseFloat(input) * 100)`. Returns null for blank/invalid. Pure / JVM-testable.
 */
fun parseDollarsToCents(input: String): Long? {
    val trimmed = input.trim()
    if (trimmed.isEmpty()) return null
    val dollars = trimmed.toDoubleOrNull() ?: return null
    if (dollars < 0.0) return null
    return Math.round(dollars * 100.0)
}

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
    // AND-140 — moderation / engagement render state.
    val reactions: List<com.testlogon.android.data.messaging.Reaction> = emptyList(),
    val isPinned: Boolean = false,
    val lifecycle: com.testlogon.android.data.messaging.MessageLifecycle =
        com.testlogon.android.data.messaging.MessageLifecycle.ACTIVE,
    val isEdited: Boolean = false,
    /** AND-164 — true when this message is under an active legal hold (suppresses destructive actions). */
    val onHold: Boolean = false,
    /** AND-147 receipt counts (drive the own-message Sent/Delivered/Read indicator). */
    val deliveredCount: Int = 0,
    val seenCount: Int = 0,
    /** Server id of the message this one replies to (null when not a reply). */
    val replyToMessageId: String? = null,
    /** Self-destruct expiry epoch SECONDS (null = never). */
    val expiresAtEpochSeconds: Long? = null,
    /** Server-confirmed expiry flag. */
    val serverExpired: Boolean = false,
) {
    val isFailed: Boolean get() = sendStatus == SendStatus.FAILED
    val isSending: Boolean get() = sendStatus == SendStatus.SENDING
    /** AND-140 — a revoked message renders a tombstone bubble. */
    val isRevoked: Boolean get() = lifecycle == com.testlogon.android.data.messaging.MessageLifecycle.REVOKED
    /** AND-140 — a deleted-for-me message renders a tombstone bubble. */
    val isDeleted: Boolean get() = lifecycle == com.testlogon.android.data.messaging.MessageLifecycle.DELETED
    /** An expiring message whose lifetime has passed: content is redacted. */
    val isExpired: Boolean
        get() = serverExpired ||
            (expiresAtEpochSeconds != null && expiresAtEpochSeconds <= System.currentTimeMillis() / 1000L)
    /** AND-140 — a tombstone (deleted/revoked) or an expired message is rendered specially. */
    val isTombstone: Boolean get() = isRevoked || isDeleted || isExpired
    val isImage: Boolean get() = media is MessageMedia.Image
    val isVideo: Boolean get() = media is MessageMedia.VideoShare
    val isFile: Boolean get() = media is MessageMedia.File
    val isVoice: Boolean get() = media is MessageMedia.Voice
    val isVoicemail: Boolean get() = media is MessageMedia.Voicemail
    val isGif: Boolean get() = media is MessageMedia.Gif
    val isSticker: Boolean get() = media is MessageMedia.Sticker
    val isPoll: Boolean get() = media is MessageMedia.MeetingPoll
    val isCountdown: Boolean get() = media is MessageMedia.Countdown
    val isCalendarEvent: Boolean get() = media is MessageMedia.CalendarEvent
    val isCalendarShare: Boolean get() = media is MessageMedia.CalendarShare
    val isPaid: Boolean get() = media is MessageMedia.Paid
}

/** The message currently being replied to (drives the composer reply banner). */
data class ReplyDraft(
    val messageId: String,
    val preview: String,
    val senderLabel: String,
)

data class ComposerState(
    val draft: String = "",
    val charCount: Int = 0,
    val overLimit: Boolean = false,
    val replyingTo: ReplyDraft? = null,
    /** Optional send-time message options (view-once / locked / scheduled). */
    val options: MessageOptions = MessageOptions(),
) {
    val isSendEnabled: Boolean get() = draft.isNotBlank() && !overLimit

    companion object {
        const val MAX_LENGTH = 4000
    }
}

/**
 * Send-time message options the composer can attach to the next text message. All default to off,
 * giving a plain send. Mutually-sensible combos are allowed (e.g. a scheduled view-once message).
 */
data class MessageOptions(
    /** Self-destruct after first view. */
    val viewOnce: Boolean = false,
    /** Pay-to-unlock price in integer cents; null = not locked. */
    val lockPriceCents: Long? = null,
    val lockDescription: String? = null,
    /** Deliver-at epoch SECONDS in the future; null = send now. */
    val scheduledAtEpochSeconds: Long? = null,
    /** Self-destruct lifetime in seconds after delivery; null = never expires. */
    val expiresInSeconds: Long? = null,
) {
    val isActive: Boolean
        get() = viewOnce || lockPriceCents != null || scheduledAtEpochSeconds != null || expiresInSeconds != null

    /** Short summary chip text, or null when no option is set. */
    val summary: String?
        get() {
            val parts = buildList {
                if (viewOnce) add("View once")
                lockPriceCents?.let { add("Locked $" + "%.2f".format(it / 100.0)) }
                if (scheduledAtEpochSeconds != null) add("Scheduled")
                expiresInSeconds?.let { add("Expires in " + expiryLabel(it)) }
            }
            return parts.takeIf { it.isNotEmpty() }?.joinToString(" · ")
        }
}

/** Human label for a self-destruct lifetime in seconds (e.g. "1h", "1d"). */
fun expiryLabel(seconds: Long): String = when {
    seconds >= 86_400 -> "${seconds / 86_400}d"
    seconds >= 3_600 -> "${seconds / 3_600}h"
    seconds >= 60 -> "${seconds / 60}m"
    else -> "${seconds}s"
}

/** Draft state for the message-options bottom sheet (non-null = open). */
data class MessageOptionsSheetState(
    val visible: Boolean = false,
    val viewOnce: Boolean = false,
    val lockPriceInput: String = "",
    val scheduledAtEpochSeconds: Long? = null,
)
