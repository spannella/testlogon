package com.testlogon.android.feature.feed

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import androidx.paging.cachedIn
import androidx.paging.insertHeaderItem
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.feed.Comment
import com.testlogon.android.data.feed.CommentsRepository
import com.testlogon.android.data.feed.reactedByMe
import com.testlogon.android.data.feed.toggledReaction
import com.testlogon.android.data.messaging.BillingAuthorizer
import com.testlogon.android.data.messaging.BillingResult
import com.testlogon.android.data.messaging.GifResult
import com.testlogon.android.data.messaging.MessagingRepository
import com.testlogon.android.data.messaging.StickerUi
import com.testlogon.android.feature.common.tip.TipVisibility
import com.testlogon.android.navigation.PostDetailDest
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.UUID
import javax.inject.Inject

/** AND-174 — composer state for the comment input. */
data class ComposerState(
    val text: String = "",
    val replyTo: Comment? = null,
    val sending: Boolean = false,
    /** Non-null while editing an existing comment (its id); send() then PATCHes instead of POSTs. */
    val editingId: String? = null,
    /** #4 — uploaded image URL staged to send ALONGSIDE the text (a text+image comment). */
    val pendingImageUrl: String? = null,
    /** #5 — while editing, the image shown: existing image, a replaced URL, or null after removal. */
    val editImageUrl: String? = null,
    /** #5 — true once the image was changed while editing (replaced/removed) so PATCH sends it. */
    val editImageDirty: Boolean = false,
    /** TIP-302 — an optional tip (cents) ATTACHED to this comment; charged to the post author on send. */
    val tipAmountCents: Int? = null,
) {
    /** Can send with text OR a staged/edited image, and not mid-send. */
    val canSend: Boolean
        get() = !sending && (text.isNotBlank() || pendingImageUrl != null || (isEditing && editImageUrl != null))
    val isEditing: Boolean get() = editingId != null
}

/** AND-174 — one-shot comments UI effects (snackbars). */
sealed interface CommentsEffect {
    data class ShowError(val message: String) : CommentsEffect
    /** Notifies the AND-100 host so it can adjust the post's displayed comment count. */
    data class CommentCountChanged(val delta: Int) : CommentsEffect
}

/**
 * AND-174 — comments presentation logic for a single post.
 *
 * The paged list is a cached Paging 3 stream; locally-originated comments (optimistic + failed) live in
 * a side [pending] StateFlow and are merged ahead of the server page via insertHeaderItem so the differ
 * stays stable. send() inserts an optimistic pending header, clears the composer, and posts; on success
 * the pending entry is removed and the list is refreshed (signalled via [refreshSignal]) so the server
 * entity lands; on failure the entry flips to failed with Retry / Discard. Replies are gated behind
 * [repliesSupported] (false by default — no backend replies endpoint).
 */
/** AND-174 (rich comments) — GIF/sticker picker sheet state. */
data class CommentMediaPickerState(
    val visible: Boolean = false,
    /** 0 = GIF, 1 = Stickers. */
    val tab: Int = 0,
    val gifQuery: String = "",
    val gifLoading: Boolean = false,
    val gifResults: List<GifResult> = emptyList(),
    val stickersLoading: Boolean = false,
    val stickers: List<StickerUi> = emptyList(),
    val error: String? = null,
)

/**
 * TIPX-B2 (F2/F5/F6) — comment tip sheet state machine. Replaces the old preset-only, one-tap-charges
 * sheet with the shared composer flow: Entry (presets + custom amount + visibility + explicit Send) ->
 * Submitting -> Confirmed (in-sheet amount receipt) | NoCard (in-flow add-card, TIPX-B3/F3). Never
 * optimistic: Confirmed appears only after the repository returns Success.
 */
sealed interface CommentTipState {
    /** The comment being tipped, or null when hidden. Drives whether the sheet is shown. */
    val target: Comment? get() = null

    data object Hidden : CommentTipState

    data class Entry(
        override val target: Comment,
        val presetsCents: List<Int> = listOf(100, 500, 1000),
        val selectedCents: Int? = null,
        val customAmountText: String = "",
        val visibility: TipVisibility = TipVisibility.Default,
        val error: String? = null,
        val minCents: Int = 100,
        val maxCents: Int = 5_000_000,
    ) : CommentTipState {
        /** Preset or parsed custom amount. */
        val effectiveCents: Int? get() = selectedCents
        val canSend: Boolean
            get() {
                val c = effectiveCents ?: return false
                return c in minCents..maxCents
            }
    }

    data class Submitting(override val target: Comment, val amountCents: Int) : CommentTipState

    data class Confirmed(
        override val target: Comment,
        val amountCents: Int,
        val visibility: TipVisibility,
    ) : CommentTipState

    /** TIPX-B3 (F3) — empty wallet: the tipper can add a card in-flow and return to [Entry]. */
    data class NoCard(
        override val target: Comment,
        val selectedCents: Int?,
        val customAmountText: String,
        val visibility: TipVisibility,
    ) : CommentTipState
}

@HiltViewModel
class CommentsViewModel @Inject constructor(
    private val repository: CommentsRepository,
    private val stickerCatalog: MessagingRepository,
    private val displayNames: com.testlogon.android.data.profile.DisplayNameResolver,
    private val imageUploader: com.testlogon.android.data.feed.CommentImageUploader,
    private val billing: BillingAuthorizer,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    val postId: String = savedStateHandle.get<String>(PostDetailDest.ARG_POST_ID).orEmpty()

    /** comment author id (email/user_sub) -> display name, resolved lazily for visible comments. */
    val authorNames: StateFlow<Map<String, String>> = displayNames.names

    /** Kick off (cached) resolution of a commenter's display name; UI reads it from [authorNames]. */
    fun resolveAuthor(authorId: String) {
        displayNames.resolve(authorId)
    }

    val repliesSupported: Boolean get() = repository.repliesSupported

    /**
     * #25 — true when the viewer authored the post these comments belong to. Set by the host once the
     * post loads; tipping is then hidden on this post (you can't tip your own content). Drives [showTip].
     */
    private val _isOwnPost = MutableStateFlow(false)
    val isOwnPost: StateFlow<Boolean> = _isOwnPost.asStateFlow()

    fun setOwnPost(own: Boolean) {
        _isOwnPost.value = own
    }

    /** #23 — server-confirmed reaction overrides keyed by comment id, layered over the paged comments. */
    private val _reactionOverrides = MutableStateFlow<Map<String, List<com.testlogon.android.data.feed.ReactionTally>>>(emptyMap())
    val reactionOverrides: StateFlow<Map<String, List<com.testlogon.android.data.feed.ReactionTally>>> =
        _reactionOverrides.asStateFlow()

    private val pending = MutableStateFlow<List<Comment>>(emptyList())

    private val _composer = MutableStateFlow(ComposerState())
    val composer: StateFlow<ComposerState> = _composer.asStateFlow()

    /** Bumped to force the LazyPagingItems to refresh after a successful add/delete reconcile. */
    private val _refreshSignal = MutableStateFlow(0L)
    val refreshSignal: StateFlow<Long> = _refreshSignal.asStateFlow()

    private val _effects = Channel<CommentsEffect>(Channel.BUFFERED)
    val effects: Flow<CommentsEffect> = _effects.receiveAsFlow()

    private val basePager: Flow<PagingData<Comment>> = Pager(
        config = PagingConfig(
            pageSize = PAGE_SIZE,
            initialLoadSize = PAGE_SIZE,
            prefetchDistance = PREFETCH_DISTANCE,
            enablePlaceholders = false,
        ),
        pagingSourceFactory = { CommentsPagingSource(repository, postId) },
    ).flow.cachedIn(viewModelScope)

    /** Server page with not-yet-reconciled local comments prepended (newest at the head). */
    val comments: Flow<PagingData<Comment>> =
        combine(basePager, pending) { page, locals ->
            locals.foldRight(page) { c, acc -> acc.insertHeaderItem(item = c) }
        }

    fun onBodyChange(text: String) {
        _composer.update { it.copy(text = text) }
    }

    /** No-op when replies are unsupported (the default). */
    fun startReply(parent: Comment) {
        if (!repliesSupported) return
        _composer.update { it.copy(replyTo = parent) }
    }

    fun cancelReply() {
        _composer.update { it.copy(replyTo = null) }
    }

    // ---- Rich comments: GIF / sticker picker ----

    private val _picker = MutableStateFlow(CommentMediaPickerState())
    val picker: StateFlow<CommentMediaPickerState> = _picker.asStateFlow()

    private val _tip = MutableStateFlow<CommentTipState>(CommentTipState.Hidden)
    val tip: StateFlow<CommentTipState> = _tip.asStateFlow()

    fun openMediaPicker() {
        _picker.update { it.copy(visible = true, error = null) }
        if (_picker.value.gifResults.isEmpty()) searchGifs("")
        if (_picker.value.stickers.isEmpty()) loadStickers()
    }

    fun closeMediaPicker() {
        _picker.update { it.copy(visible = false) }
    }

    fun setPickerTab(tab: Int) {
        _picker.update { it.copy(tab = tab) }
        if (tab == 1 && _picker.value.stickers.isEmpty() && !_picker.value.stickersLoading) loadStickers()
    }

    fun onGifQueryChange(query: String) {
        _picker.update { it.copy(gifQuery = query) }
        searchGifs(query)
    }

    private fun searchGifs(query: String) {
        viewModelScope.launch {
            _picker.update { it.copy(gifLoading = true, error = null) }
            when (val r = stickerCatalog.searchGifs(query.trim(), limit = 24)) {
                is ApiResult.Success -> _picker.update { it.copy(gifLoading = false, gifResults = r.data) }
                is ApiResult.Failure -> _picker.update { it.copy(gifLoading = false, error = r.error.message) }
                is ApiResult.NetworkError -> _picker.update { it.copy(gifLoading = false, error = OFFLINE_MESSAGE) }
            }
        }
    }

    private fun loadStickers() {
        viewModelScope.launch {
            _picker.update { it.copy(stickersLoading = true) }
            when (val r = stickerCatalog.stickerCollections()) {
                is ApiResult.Success ->
                    _picker.update { it.copy(stickersLoading = false, stickers = r.data.flatMap { c -> c.stickers }) }
                is ApiResult.Failure -> _picker.update { it.copy(stickersLoading = false, error = r.error.message) }
                is ApiResult.NetworkError -> _picker.update { it.copy(stickersLoading = false, error = OFFLINE_MESSAGE) }
            }
        }
    }

    fun pickGif(gif: GifResult) {
        _picker.update { it.copy(visible = false) }
        val parentId = _composer.value.replyTo?.id?.takeIf { repliesSupported }
        _composer.update { it.copy(replyTo = null) }
        val localKey = UUID.randomUUID().toString()
        pending.update {
            listOf(richOptimistic(localKey, parentId, gifUrl = gif.url)) + it
        }
        viewModelScope.launch {
            handleSendResult(localKey, parentId, repository.addGifComment(postId, gif.url, gif.altText, parentId))
        }
    }

    fun pickSticker(sticker: StickerUi) {
        _picker.update { it.copy(visible = false) }
        val parentId = _composer.value.replyTo?.id?.takeIf { repliesSupported }
        _composer.update { it.copy(replyTo = null) }
        val localKey = UUID.randomUUID().toString()
        pending.update {
            listOf(richOptimistic(localKey, parentId, stickerUrl = sticker.url)) + it
        }
        viewModelScope.launch {
            handleSendResult(
                localKey,
                parentId,
                repository.addStickerComment(postId, sticker.stickerId, sticker.collectionId, sticker.url, sticker.altText, parentId),
            )
        }
    }

    private fun richOptimistic(
        localKey: String,
        parentId: String?,
        gifUrl: String? = null,
        stickerUrl: String? = null,
        imageUrl: String? = null,
    ) =
        Comment(
            id = localKey,
            postId = postId,
            parentId = parentId,
            authorId = "",
            body = "",
            createdAtEpochSeconds = System.currentTimeMillis() / 1000L,
            updatedAtEpochSeconds = null,
            gifUrl = gifUrl,
            stickerUrl = stickerUrl,
            imageUrl = imageUrl,
            canDelete = true,
            pending = true,
            localKey = localKey,
        )

    private fun handleSendResult(localKey: String, parentId: String?, result: ApiResult<Comment>) {
        when (result) {
            is ApiResult.Success -> {
                pending.update { list -> list.filterNot { it.localKey == localKey } }
                if (parentId == null) _effects.trySend(CommentsEffect.CommentCountChanged(+1))
                _refreshSignal.value = _refreshSignal.value + 1L
            }
            is ApiResult.Failure -> markFailed(localKey, result.error.message)
            is ApiResult.NetworkError -> markFailed(localKey, OFFLINE_MESSAGE)
        }
    }

    // ---- Comment tipping ----

    fun openTip(comment: Comment) {
        if (comment.pending || comment.failed) return
        _tip.value = CommentTipState.Entry(target = comment)
    }

    fun dismissTip() {
        // Blocked while Submitting (money-moving) so a dismiss can't race a charge.
        if (_tip.value is CommentTipState.Submitting) return
        _tip.value = CommentTipState.Hidden
    }

    /** TIPX-B2 — select a preset amount (clears custom text). */
    fun selectTipPreset(cents: Int) {
        val entry = _tip.value as? CommentTipState.Entry ?: return
        _tip.value = entry.copy(selectedCents = cents, customAmountText = "", error = null)
    }

    /** TIPX-B2 — type a custom dollar amount. */
    fun setTipCustomAmount(text: String) {
        val entry = _tip.value as? CommentTipState.Entry ?: return
        _tip.value = entry.copy(customAmountText = text, selectedCents = parseDollarsToCents(text), error = null)
    }

    /** TIPX-B2 (F5) — toggle public/private visibility. */
    fun setTipVisibility(visibility: TipVisibility) {
        val entry = _tip.value as? CommentTipState.Entry ?: return
        _tip.value = entry.copy(visibility = visibility)
    }

    /**
     * TIPX-B2 — explicit Send. Charges via the shared billing seam; NEVER optimistic. On an empty
     * wallet (NotConfigured) routes to the in-flow add-card state (TIPX-B3/F3) rather than dead-ending.
     */
    fun sendTip() {
        val entry = _tip.value as? CommentTipState.Entry ?: return
        val cents = entry.effectiveCents ?: return
        if (!entry.canSend) return
        val target = entry.target
        val visibility = entry.visibility
        _tip.value = CommentTipState.Submitting(target, cents)
        viewModelScope.launch {
            val pmId: String? = when (val auth = billing.authorize(cents.toLong(), CURRENCY_USD)) {
                is BillingResult.Authorized -> auth.paymentMethodId
                // TIPX-B3 (F3) — empty wallet: offer add-card in-flow instead of a dead-end snackbar.
                BillingResult.NotConfigured -> {
                    _tip.value = CommentTipState.NoCard(target, entry.selectedCents, entry.customAmountText, visibility)
                    return@launch
                }
                BillingResult.Cancelled -> { _tip.value = entry; return@launch }
                is BillingResult.Declined -> { failTip(entry, auth.reason); return@launch }
                is BillingResult.Failed -> { failTip(entry, ERR_GENERIC); return@launch }
            }
            when (val r = repository.tipComment(postId, target.id, cents, pmId)) {
                is ApiResult.Success -> {
                    _tip.value = CommentTipState.Confirmed(target, cents, visibility)
                    _refreshSignal.value = _refreshSignal.value + 1L
                }
                is ApiResult.Failure -> failTip(entry, r.error.message)
                is ApiResult.NetworkError -> failTip(entry, OFFLINE_MESSAGE)
            }
        }
    }

    /**
     * TIPX-B3 (F3) — re-open the composer (Entry) after the tipper returns from add-card, preserving
     * the amount + visibility they had chosen so they can send without re-picking.
     */
    fun resumeTipAfterAddCard() {
        val nc = _tip.value as? CommentTipState.NoCard ?: return
        _tip.value = CommentTipState.Entry(
            target = nc.target,
            selectedCents = nc.selectedCents,
            customAmountText = nc.customAmountText,
            visibility = nc.visibility,
        )
    }

    private fun failTip(entry: CommentTipState.Entry, message: String) {
        // Return to Entry with an inline error (no snackbar loss) so the tipper can retry in-sheet.
        _tip.value = entry.copy(error = message)
    }

    // ---- Comment-CARRYING tip (TIP-302): attach a tip to the comment being written ----

    /** Attach (or clear, with null) a tip amount to the composer; sent with the next comment. */
    fun attachTip(cents: Int?) {
        _composer.update { it.copy(tipAmountCents = cents) }
    }

    // ---- Comment emoji reactions (#23) ----

    /**
     * Optimistically toggle [emoji] on [comment], then call the server. The optimistic tally is stored
     * in [_reactionOverrides] (keyed by the server comment id) so it survives a paging refresh; on
     * failure it rolls back to the pre-toggle tally.
     */
    fun toggleCommentReaction(comment: Comment, emoji: String) {
        val id = comment.id
        if (comment.pending || comment.failed || id.isBlank()) return
        val before = _reactionOverrides.value[id] ?: comment.reactions
        val after = before.toggledReaction(emoji)
        val add = after.reactedByMe(emoji)
        _reactionOverrides.update { it + (id to after) }
        viewModelScope.launch {
            when (val r = repository.setCommentReaction(postId, id, emoji, add)) {
                is ApiResult.Success -> Unit
                is ApiResult.Failure -> {
                    _reactionOverrides.update { it + (id to before) }
                    _effects.trySend(CommentsEffect.ShowError(r.error.message))
                }
                is ApiResult.NetworkError -> {
                    _reactionOverrides.update { it + (id to before) }
                    _effects.trySend(CommentsEffect.ShowError(OFFLINE_MESSAGE))
                }
            }
        }
    }

    // ---- Image comments (#24) ----

    /** True while a picked image is uploading (drives a composer progress affordance). */
    private val _imageUploading = MutableStateFlow(false)
    val imageUploading: StateFlow<Boolean> = _imageUploading.asStateFlow()

    /**
     * #4/#5 — pick an image, upload it via POST /uploads/image, and STAGE the returned platform URL on
     * the composer (instead of sending immediately). Normal mode: rides with the text on the next
     * send() (text+image comment). Edit mode: REPLACES the comment image.
     */
    fun uploadAndStageImage(uri: android.net.Uri) {
        if (_imageUploading.value) return
        _imageUploading.value = true
        viewModelScope.launch {
            when (val up = imageUploader.uploadImage(uri)) {
                is ApiResult.Success -> {
                    _imageUploading.value = false
                    _composer.update {
                        if (it.isEditing) it.copy(editImageUrl = up.data, editImageDirty = true)
                        else it.copy(pendingImageUrl = up.data)
                    }
                }
                is ApiResult.Failure -> {
                    _imageUploading.value = false
                    _effects.trySend(CommentsEffect.ShowError(up.error.message))
                }
                is ApiResult.NetworkError -> {
                    _imageUploading.value = false
                    _effects.trySend(CommentsEffect.ShowError(OFFLINE_MESSAGE))
                }
            }
        }
    }

    /** #4 — drop the staged (not-yet-sent) image before sending a text+image comment. */
    fun clearStagedImage() {
        _composer.update { it.copy(pendingImageUrl = null) }
    }

    /** #5 — remove the image from the comment being edited (PATCH then sends an empty image_url). */
    fun removeEditImage() {
        _composer.update { it.copy(editImageUrl = null, editImageDirty = true) }
    }

    /** Enter edit mode for an own comment: prefill the body and existing image (#5). */
    fun startEdit(comment: Comment) {
        if (!comment.canEdit) return
        _composer.update {
            it.copy(
                text = comment.body,
                editingId = comment.id,
                replyTo = null,
                pendingImageUrl = null,
                editImageUrl = comment.imageUrl,
                editImageDirty = false,
            )
        }
    }

    fun cancelEdit() {
        _composer.update { it.copy(text = "", editingId = null, editImageUrl = null, editImageDirty = false) }
    }

    fun send() {
        val current = _composer.value
        val body = current.text.trim()
        val stagedImage = current.pendingImageUrl
        // Allow text alone, image alone, or text+image (#4).
        if (current.sending) return
        // Edit path: PATCH the existing comment, then refresh the page.
        val editingId = current.editingId
        if (editingId != null) {
            // #5 — only send image_url when the user touched it: empty removes, a URL replaces, null keeps.
            val imageArg = if (current.editImageDirty) current.editImageUrl.orEmpty() else null
            if (body.isEmpty() && current.editImageUrl == null) return
            _composer.value = ComposerState()
            viewModelScope.launch {
                when (val r = repository.editComment(postId, editingId, body, imageArg)) {
                    is ApiResult.Success -> _refreshSignal.value = _refreshSignal.value + 1L
                    is ApiResult.Failure -> _effects.trySend(CommentsEffect.ShowError(r.error.message))
                    is ApiResult.NetworkError -> _effects.trySend(CommentsEffect.ShowError(OFFLINE_MESSAGE))
                }
            }
            return
        }
        if (body.isEmpty() && stagedImage == null) return
        val parentId = current.replyTo?.id?.takeIf { repliesSupported }
        val tipCents = current.tipAmountCents // TIP-302 — carry the attached tip, if any.
        val localKey = UUID.randomUUID().toString()
        val optimistic = Comment(
            id = localKey,
            postId = postId,
            parentId = parentId,
            authorId = "",
            body = body,
            createdAtEpochSeconds = System.currentTimeMillis() / 1000L,
            updatedAtEpochSeconds = null,
            imageUrl = stagedImage,
            canDelete = true,
            pending = true,
            localKey = localKey,
        )
        if (tipCents != null) pendingTips[localKey] = tipCents
        pending.update { listOf(optimistic) + it }
        _composer.value = ComposerState() // clear text + reply + staged image + attached tip, keep sending=false
        postComment(localKey, body, parentId, isReply = parentId != null, imageUrl = stagedImage, tipCents = tipCents)
    }

    fun retry(localKey: String) {
        val entry = pending.value.firstOrNull { it.localKey == localKey } ?: return
        pending.update { list -> list.map { if (it.localKey == localKey) it.copy(pending = true, failed = false) else it } }
        postComment(localKey, entry.body, entry.parentId, isReply = entry.parentId != null, imageUrl = entry.imageUrl, tipCents = pendingTips[localKey])
    }

    fun discard(localKey: String) {
        pendingTips.remove(localKey)
        pending.update { list -> list.filterNot { it.localKey == localKey } }
    }

    fun delete(comment: Comment) {
        if (!comment.canDelete) return
        viewModelScope.launch {
            when (val result = repository.deleteComment(postId, comment.id)) {
                is ApiResult.Success -> {
                    _effects.trySend(CommentsEffect.CommentCountChanged(-1))
                    _refreshSignal.value = _refreshSignal.value + 1L
                }
                is ApiResult.Failure -> _effects.trySend(CommentsEffect.ShowError(result.error.message))
                is ApiResult.NetworkError -> _effects.trySend(CommentsEffect.ShowError(OFFLINE_MESSAGE))
            }
        }
    }

    /** Side-map of localKey -> attached tip cents so a Retry re-charges the same carrying tip (TIP-302). */
    private val pendingTips = mutableMapOf<String, Int>()

    private fun postComment(
        localKey: String,
        body: String,
        parentId: String?,
        isReply: Boolean,
        imageUrl: String? = null,
        tipCents: Int? = null,
    ) {
        viewModelScope.launch {
            // TIP-302 — a carrying tip is money-moving: resolve a PM first. On no-PM / decline the whole
            // action fails (intent preserved, OQ-4) — the comment flips to failed with Retry/Discard.
            var tipPmId: String? = null
            if (tipCents != null) {
                when (val auth = billing.authorize(tipCents.toLong(), CURRENCY_USD)) {
                    is BillingResult.Authorized -> tipPmId = auth.paymentMethodId
                    BillingResult.NotConfigured -> { markFailed(localKey, ERR_PAYMENTS_UNAVAILABLE); return@launch }
                    BillingResult.Cancelled -> {
                        // User backed out of paying: revert to a plain, unsent comment kept in the composer.
                        pendingTips.remove(localKey)
                        pending.update { list -> list.filterNot { it.localKey == localKey } }
                        _composer.update { it.copy(text = body, tipAmountCents = null) }
                        return@launch
                    }
                    is BillingResult.Declined -> { markFailed(localKey, auth.reason); return@launch }
                    is BillingResult.Failed -> { markFailed(localKey, ERR_GENERIC); return@launch }
                }
            }
            when (val result = repository.addComment(postId, body, parentId, imageUrl, tipAmountCents = tipCents, tipPaymentMethodId = tipPmId)) {
                is ApiResult.Success -> {
                    pendingTips.remove(localKey)
                    pending.update { list -> list.filterNot { it.localKey == localKey } }
                    if (!isReply) _effects.trySend(CommentsEffect.CommentCountChanged(+1))
                    _refreshSignal.value = _refreshSignal.value + 1L
                }
                is ApiResult.Failure -> markFailed(localKey, result.error.message)
                is ApiResult.NetworkError -> markFailed(localKey, OFFLINE_MESSAGE)
            }
        }
    }

    private fun markFailed(localKey: String, message: String) {
        pending.update { list ->
            list.map { if (it.localKey == localKey) it.copy(pending = false, failed = true) else it }
        }
        _effects.trySend(CommentsEffect.ShowError(message))
    }

    private companion object {
        const val PAGE_SIZE = 20
        const val PREFETCH_DISTANCE = 5
        const val OFFLINE_MESSAGE = "You're offline. Try again."
        const val CURRENCY_USD = "USD"
        const val ERR_PAYMENTS_UNAVAILABLE = "Payments are unavailable right now."
        const val ERR_GENERIC = "Couldn't send tip. Try again."
    }
}
