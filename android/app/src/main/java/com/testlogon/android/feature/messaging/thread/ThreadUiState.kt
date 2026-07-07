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
    val peerUserSub: String? = null,
    /** ID15 - the DM peer's profile photo, resolved lazily once [peerUserSub] is known. */
    val peerPhotoUrl: String? = null,
    /** #15 - the CURRENT user's own profile photo, for the DM overlapping-avatar pair. */
    val myPhotoUrl: String? = null,
    /** #15 - the CURRENT user's display name (monogram fallback for the own avatar circle). */
    val myName: String? = null,
    /** #15 - true for a 1:1 DM (renders the overlapping two-circle avatar in the header). */
    val isDm: Boolean = false,
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
    val textPollComposerVisible: Boolean = false,
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
    // ---- MSG: new in-app composers ----
    /** Lottery composer sheet (hidden until opened). */
    val lotteryComposerVisible: Boolean = false,
    /** Find-a-DateTime ("custom poll") composer sheet (hidden until opened). */
    val findDateTimeComposerVisible: Boolean = false,
    /** Calendar-event share composer (pick a calendar + event). */
    val calendarEventComposer: CalendarPickerState = CalendarPickerState(),
    /** Calendar share composer (pick a calendar + permission). */
    val calendarShareComposer: CalendarPickerState = CalendarPickerState(),
    /** File-manager share composer (pick a file). */
    val fileShareComposer: FilePickerState = FilePickerState(),
    /** MSG — receiver passphrase-unlock dialog for an encrypted message (non-null key = open). */
    val encryptUnlock: EncryptUnlockState = EncryptUnlockState(),
    /** MSG — view-once viewer dialog (non-null key = open, showing the consumed content). */
    val viewOnceViewer: ViewOnceViewerState = ViewOnceViewerState(),
    /** #8 — scheduled-messages manager (list + edit/remove of pending scheduled sends). */
    val scheduledManager: ScheduledManagerUiState = ScheduledManagerUiState(),
)

/**
 * #8 — state for the scheduled-messages manager bottom sheet. [visible] gates the sheet; [items]
 * are the caller's still-pending scheduled messages (sorted by due time). [editing] is non-null
 * while the inline edit dialog for one item is open.
 */
data class ScheduledManagerUiState(
    val visible: Boolean = false,
    val loading: Boolean = false,
    /** One-shot inline error (load/edit/cancel failure), cleared after shown. */
    val error: String? = null,
    val items: List<com.testlogon.android.data.messaging.ScheduledMessage> = emptyList(),
    /** Non-null while the edit dialog for a specific scheduled message is open. */
    val editing: ScheduledEditState? = null,
) {
    val isEmpty: Boolean get() = !loading && items.isEmpty()
}

/** #8/#21/#22 — edit-dialog state for one scheduled message (draft text + draft due time + timezone). */
data class ScheduledEditState(
    val messageId: String,
    /** Whether the body text can be edited (text-kind only). */
    val textEditable: Boolean,
    val draftText: String,
    val draftDeliverAtEpochSeconds: Long,
    /** #21 — IANA zone the draft due-time wall-clock is interpreted in (defaults to the device zone). */
    val timeZoneId: String = java.util.TimeZone.getDefault().id,
    /**
     * #7 (B-SCHED3) — whether THIS scheduled message can have a photo attached. True for a text-only
     * scheduled message (the server promotes it to an image kind) and for an existing image message
     * (replace the photo). False for kinds that can't take a photo via this path (gallery/file/etc).
     */
    val canAttachImage: Boolean = false,
    /** #7 — true while a picked photo is uploading (presign + PUT) before save. */
    val attaching: Boolean = false,
    /** #7 — local content:// uri of the picked photo (for the preview thumbnail), null = none staged. */
    val draftImageLocalUri: String? = null,
    /** #7 — the uploaded photo descriptor sent on save; non-null once the upload succeeds. */
    val draftImage: com.testlogon.android.data.messaging.MessageImageDto? = null,
    /** #4 (B-MSGEDIT) — staged FILE: display name (chip) + the server VFS path sent on save. */
    val draftFileName: String? = null,
    val draftFilePath: String? = null,
    /** #4 (B-MSGEDIT) — staged VIDEO: library video id + a title for the chip. */
    val draftVideoId: String? = null,
    val draftVideoTitle: String? = null,
    val saving: Boolean = false,
    val error: String? = null,
)

/** MSG — passphrase-unlock dialog state for an encrypted message. */
data class EncryptUnlockState(
    /** The message UI key being unlocked; null = dialog closed. */
    val messageKey: String? = null,
    val passphrase: String = "",
    /** Set after a wrong passphrase (GCM tag mismatch). */
    val error: String? = null,
)

/** MSG — view-once popup state (shows the content once; closing consumes it). */
data class ViewOnceViewerState(
    val messageKey: String? = null,
    val text: String = "",
    /** MSG — view-once IMAGE: true while the gated bytes download; the local file once ready. */
    val loading: Boolean = false,
    val imageFile: String? = null,
    val error: Boolean = false,
    /** Dialog title ("View once" or "Encrypted image"). */
    val title: String = "View once",
    /** True for view-once (consume + hide on close); false for an encrypted-image preview. */
    val consumeOnDismiss: Boolean = true,
)

/** MSG — calendar discovery state shared by the calendar-event + calendar-share composers. */
data class CalendarPickerState(
    val visible: Boolean = false,
    val loading: Boolean = false,
    val calendars: List<com.testlogon.android.data.messaging.CalendarAccessUi> = emptyList(),
    val selectedCalendarId: String? = null,
    val eventsLoading: Boolean = false,
    val events: List<com.testlogon.android.data.messaging.CalendarEventUi> = emptyList(),
    val error: String? = null,
)

/** MSG — file-manager discovery state for the file-share composer. */
data class FilePickerState(
    val visible: Boolean = false,
    val loading: Boolean = false,
    val files: List<com.testlogon.android.data.messaging.FileEntryUi> = emptyList(),
    val error: String? = null,
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

/**
 * AND-140 / B-MSGEDIT #5 — the message currently being edited (dialog pre-filled with [originalText]).
 *
 * Beyond the text, the edit dialog now supports full media control: stage a new photo / file / library
 * video to add or replace the message's media (promoting a text message), or [removeMedia] to strip it.
 * Only one media kind can be staged at a time; staging one clears the others.
 */
data class EditTarget(
    val messageId: String,
    val originalText: String,
    /** True if the message already carries media (so "Remove media" is offered). */
    val hasMedia: Boolean = false,
    /** True while a picked photo/file is uploading (presign + PUT) before save. */
    val attaching: Boolean = false,
    /** Staged PHOTO: local content:// uri (preview) + uploaded descriptor (sent on save). */
    val draftImageLocalUri: String? = null,
    val draftImage: com.testlogon.android.data.messaging.MessageImageDto? = null,
    /** Staged FILE: display name (chip) + the server VFS path (sent on save as file_path). */
    val draftFileName: String? = null,
    val draftFilePath: String? = null,
    /** Staged VIDEO: library video id + a title for the chip (sent on save as video_id). */
    val draftVideoId: String? = null,
    val draftVideoTitle: String? = null,
    /** True when the user chose to strip existing media (sent on save as remove_media). */
    val removeMedia: Boolean = false,
    val error: String? = null,
)

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
    /** #32 — IANA zone the chosen target wall-clock is interpreted in (defaults to the device zone). */
    val timeZoneId: String = java.util.TimeZone.getDefault().id,
    /** #31 — optional text revealed when the countdown completes. */
    val revealText: String = "",
    /** #31 — optional image (local uri) revealed when the countdown completes. */
    val revealImageUri: String? = null,
    /** #31 — true while the reveal image is uploading on send. */
    val sending: Boolean = false,
    val error: String? = null,
) {
    val isSendEnabled: Boolean
        get() = !sending && title.trim().length in 1..200 && targetEpochSeconds != null
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
    /** B-MSGEDIT — where a pick is routed: SHARE (compose+send), EDIT or SCHEDULED_EDIT (stage only). */
    val mode: VideoPickMode = VideoPickMode.SHARE,
)

/** B-MSGEDIT — destination for a library-video pick (the same picker serves three call sites). */
enum class VideoPickMode { SHARE, EDIT, SCHEDULED_EDIT }

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
    /** MSG — true when the message was sent encrypted (renders a lock indicator). */
    val isEncrypted: Boolean = false,
    /** MSG — the encryption envelope (for receiver-side passphrase decryption); null if absent. */
    val encryption: com.testlogon.android.data.messaging.MessageEncryption? = null,
    /** MSG — locally-decrypted plaintext after a correct passphrase (transient; never persisted). */
    val decryptedText: String? = null,
    /** MSG — true when this is a view-once message (hidden on the receiver until opened). */
    val viewOnce: Boolean = false,
    /** MSG — true once a view-once message has been consumed (permanently hidden). */
    val consumed: Boolean = false,
    /** R2 — pay-to-unlock price (minor units) when sent locked, else null; drives the own "Locked $X" badge. */
    val lockPriceCents: Long? = null,
    /** R2 — ISO-4217 currency for [lockPriceCents]. */
    val lockCurrency: String = "USD",
    /**
     * #6 (B-COUNTDOWN3) — an optional countdown attached to THIS message (any kind), rendered as an
     * overlay strip below the bubble. Ticks live and reveals its payload at the target.
     */
    val countdown: com.testlogon.android.data.messaging.MessageCountdown? = null,
) {
    val isFailed: Boolean get() = sendStatus == SendStatus.FAILED
    val isSending: Boolean get() = sendStatus == SendStatus.SENDING
    /** AND-140 — a revoked message renders a tombstone bubble. */
    val isRevoked: Boolean get() = lifecycle == com.testlogon.android.data.messaging.MessageLifecycle.REVOKED
    /** AND-140 — a deleted-for-me message renders a tombstone bubble. */
    val isDeleted: Boolean get() = lifecycle == com.testlogon.android.data.messaging.MessageLifecycle.DELETED
    /**
     * G2 — a locked (PPV) message that is now UNLOCKED: its gated payload is present (so it no longer
     * maps to [MessageMedia.Paid]) yet it still carries the lock price. Per the backend expiry-on-locked
     * contract the server REMOVES `expires_at` once a recipient unlocks, so an unlocked locked message
     * must never show a running expiry nor be redacted client-side (a still-cached expiry is stale).
     */
    val isUnlockedLocked: Boolean
        get() = lockPriceCents != null && media !is MessageMedia.Paid
    /** An expiring message whose lifetime has passed: content is redacted. */
    val isExpired: Boolean
        get() = !isUnlockedLocked && (serverExpired ||
            (expiresAtEpochSeconds != null && expiresAtEpochSeconds <= System.currentTimeMillis() / 1000L))
    /** AND-140 — a tombstone (deleted/revoked) or an expired message is rendered specially. */
    val isTombstone: Boolean get() = isRevoked || isDeleted || isExpired
    val isImage: Boolean get() = media is MessageMedia.Image
    val isVideo: Boolean get() = media is MessageMedia.VideoShare || media is MessageMedia.VideoClip
    val isFile: Boolean get() = media is MessageMedia.File
    val isVoice: Boolean get() = media is MessageMedia.Voice
    val isVoicemail: Boolean get() = media is MessageMedia.Voicemail
    val isGif: Boolean get() = media is MessageMedia.Gif
    val isSticker: Boolean get() = media is MessageMedia.Sticker
    val isPoll: Boolean get() = media is MessageMedia.MeetingPoll
    val isFindDateTime: Boolean get() = media is MessageMedia.FindDateTime
    val isCountdown: Boolean get() = media is MessageMedia.Countdown || countdown != null
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

/**
 * #25/#27/#28 — one picked-but-not-yet-sent media item (a photo OR a short video), held in the
 * composer so the user can stage a MIX of photos and videos (and several videos) in ONE message and
 * keep adding more before sending. [localUri] is the content uri; [isVideo] selects the render +
 * upload path.
 */
data class StagedMedia(
    val localUri: String,
    val isVideo: Boolean,
)

/** #29 — a picked-but-not-yet-sent FILE (document), staged so the user adds text/options first. */
data class StagedFile(
    val localUri: String,
    val name: String,
    val sizeBytes: Long,
    val mime: String,
)

data class ComposerState(
    val draft: String = "",
    val charCount: Int = 0,
    val overLimit: Boolean = false,
    val replyingTo: ReplyDraft? = null,
    /** Optional send-time message options (view-once / locked / scheduled). */
    val options: MessageOptions = MessageOptions(),
    /**
     * #25/#27/#28 — picked-but-not-yet-sent media (photos AND short videos, mixed + ordered). The text
     * field becomes the caption. ONE image -> image message; ONE video -> inline video message; any
     * other combination (multiple items, or a mix of photos+videos) -> ONE gallery message.
     */
    val stagedMedia: List<StagedMedia> = emptyList(),
    /** #29 — a picked-but-not-yet-sent file; sent with the typed caption + options on Send. */
    val stagedFile: StagedFile? = null,
) {
    /** Back-compat accessors (the staged photos / a lone staged video) over [stagedMedia]. */
    val stagedImageUris: List<String> get() = stagedMedia.filterNot { it.isVideo }.map { it.localUri }
    val stagedVideoUris: List<String> get() = stagedMedia.filter { it.isVideo }.map { it.localUri }

    val hasStagedMedia: Boolean get() = stagedMedia.isNotEmpty() || stagedFile != null

    val isSendEnabled: Boolean
        get() = (draft.isNotBlank() || hasStagedMedia) && !overLimit &&
            // MSG — an encrypted message needs a passphrase (used to derive the AES key).
            !(options.encrypted && options.encryptionPassphrase.isBlank())

    companion object {
        const val MAX_LENGTH = 4000
        /** Server caps a gallery at 20 free items; cap staged media to keep one message valid. */
        const val MAX_STAGED_MEDIA = 20
    }
}

/**
 * Send-time message options the composer can attach to the next text message. All default to off,
 * giving a plain send. Mutually-sensible combos are allowed (e.g. a scheduled view-once message).
 */
data class MessageOptions(
    /** MSG — encrypt the next text message (sends an encryption envelope, no plaintext). */
    val encrypted: Boolean = false,
    /** MSG — passphrase used to derive the AES key for an encrypted message (never sent to the server). */
    val encryptionPassphrase: String = "",
    /** Self-destruct after first view. */
    val viewOnce: Boolean = false,
    /** Pay-to-unlock price in integer cents; null = not locked. */
    val lockPriceCents: Long? = null,
    val lockDescription: String? = null,
    /** Deliver-at epoch SECONDS in the future; null = send now. */
    val scheduledAtEpochSeconds: Long? = null,
    /** #21 — IANA zone the scheduled wall-clock is expressed in (defaults to the device zone). */
    val scheduledTimeZoneId: String = java.util.TimeZone.getDefault().id,
    /** Self-destruct lifetime in seconds after delivery; null = never expires. */
    val expiresInSeconds: Long? = null,
    // #6 (B-COUNTDOWN3) — an optional countdown attached to the next message (any kind). The reveal
    // image is pre-uploaded when attached, so it ships with the send.
    val countdownTargetEpochSeconds: Long? = null,
    val countdownTitle: String? = null,
    val countdownRevealText: String? = null,
    val countdownRevealImage: com.testlogon.android.data.messaging.LotteryImageRef? = null,
) {
    val isActive: Boolean
        get() = encrypted || viewOnce || lockPriceCents != null || scheduledAtEpochSeconds != null ||
            expiresInSeconds != null || countdownTargetEpochSeconds != null

    /** Short summary chip text, or null when no option is set. */
    val summary: String?
        get() {
            val parts = buildList {
                if (encrypted) add("Encrypted")
                if (viewOnce) add("View once")
                lockPriceCents?.let { add("Locked $" + "%.2f".format(it / 100.0)) }
                if (scheduledAtEpochSeconds != null) add("Scheduled")
                expiresInSeconds?.let { add("Expires in " + expiryLabel(it)) }
                if (countdownTargetEpochSeconds != null) add("Countdown")
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
