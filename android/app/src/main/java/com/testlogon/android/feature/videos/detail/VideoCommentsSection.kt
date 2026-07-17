package com.testlogon.android.feature.videos.detail

import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Flag
import androidx.compose.material.icons.automirrored.filled.Reply
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.AddReaction
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.outlined.Image
import androidx.compose.material.icons.outlined.Paid
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Edit
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import com.testlogon.android.data.report.ReportTarget
import com.testlogon.android.feature.report.ContentReportSheetHost
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import coil.compose.AsyncImage
import com.testlogon.android.BuildConfig
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.BillingAuthorizer
import com.testlogon.android.data.messaging.BillingResult
import com.testlogon.android.data.profile.DisplayNameResolver
import com.testlogon.android.data.videos.VideoComment
import com.testlogon.android.data.videos.VideoCommentsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * #7/#8 — comments surface for the video detail screen with feed-comment parity:
 * REPLY THREADS (parent_comment_id), inline EDIT (PATCH), emoji REACTIONS (counts + my-reactions),
 * and rendering of image comments. All server-backed (GET/POST/PATCH/DELETE + reactions/unreact on
 * /ui/videos/{id}/comments).
 */
@HiltViewModel
class VideoCommentsViewModel @Inject constructor(
    private val repository: VideoCommentsRepository,
    private val displayNames: DisplayNameResolver,
    private val imageUploader: com.testlogon.android.data.feed.CommentImageUploader,
    private val billing: BillingAuthorizer,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val videoId: String = checkNotNull(savedStateHandle[VideoDetailViewModel.ARG_VIDEO_ID])

    data class State(
        val comments: List<VideoComment> = emptyList(),
        val draft: String = "",
        val sending: Boolean = false,
        val loading: Boolean = true,
        // The comment being replied to (null = a new top-level comment).
        val replyingTo: VideoComment? = null,
        // The comment being edited (null = not editing) + the in-flight edit text.
        val editingId: String? = null,
        val editDraft: String = "",
        // #2 feed-parity — an image staged to send ALONGSIDE the comment text, + its upload progress.
        val pendingImageUrl: String? = null,
        val imageUploading: Boolean = false,
        // TIP-305 — the video comment whose tip sheet is open (null = closed), + submit/error state.
        val tipTarget: VideoComment? = null,
        val tipSubmitting: Boolean = false,
        val tipError: String? = null,
        // TIPX-B2/B3 (F2/F5/F6) — shared-composer tip fields: chosen amount, custom text, visibility,
        // an in-sheet confirmed receipt amount, and the empty-wallet add-card state.
        val tipSelectedCents: Int? = null,
        val tipCustomText: String = "",
        val tipVisibility: com.testlogon.android.feature.common.tip.TipVisibility =
            com.testlogon.android.feature.common.tip.TipVisibility.Default,
        val tipConfirmedCents: Int? = null,
        val tipNoCard: Boolean = false,
    ) {
        val tipEffectiveCents: Int? get() = tipSelectedCents
        val tipCanSend: Boolean get() = (tipEffectiveCents ?: 0) in 100..5_000_000
    }

    private val _state = MutableStateFlow(State())
    val state: StateFlow<State> = _state.asStateFlow()
    val authorNames: StateFlow<Map<String, String>> = displayNames.names
    val allowedReactions: List<String> = VideoCommentsRepository.ALLOWED_REACTIONS

    init { load() }

    fun load() {
        viewModelScope.launch {
            _state.update { it.copy(loading = true) }
            val r = repository.list(videoId)
            val items = (r as? ApiResult.Success)?.data
            _state.update { it.copy(loading = false, comments = items ?: it.comments) }
            items?.forEach { displayNames.resolve(it.authorId) }
        }
    }

    fun onDraft(text: String) { _state.update { it.copy(draft = text) } }

    /** #2 feed-parity — pick + upload an image, then STAGE its URL to send with the comment. */
    fun uploadAndStageImage(uri: android.net.Uri) {
        if (_state.value.imageUploading) return
        _state.update { it.copy(imageUploading = true) }
        viewModelScope.launch {
            val r = imageUploader.uploadImage(uri)
            _state.update {
                it.copy(
                    imageUploading = false,
                    pendingImageUrl = (r as? ApiResult.Success)?.data ?: it.pendingImageUrl,
                )
            }
        }
    }

    fun clearStagedImage() { _state.update { it.copy(pendingImageUrl = null) } }
    fun resolveAuthor(id: String) { displayNames.resolve(id) }

    fun startReply(comment: VideoComment) {
        // Replies attach to the THREAD ROOT (the backend stores a single parent level); replying to a
        // reply still threads under its root so the conversation stays one level deep + coherent.
        val root = comment.parentCommentId ?: comment.id
        _state.update {
            it.copy(
                replyingTo = it.comments.firstOrNull { c -> c.id == root } ?: comment,
                editingId = null,
            )
        }
    }

    fun cancelReply() { _state.update { it.copy(replyingTo = null) } }

    fun send() {
        val text = _state.value.draft.trim()
        val image = _state.value.pendingImageUrl
        // A comment may be text-only, image-only, or text+image (feed parity).
        if ((text.isEmpty() && image == null) || _state.value.sending) return
        val parent = _state.value.replyingTo?.id
        _state.update { it.copy(sending = true, draft = "", replyingTo = null, pendingImageUrl = null) }
        viewModelScope.launch {
            val r = repository.add(videoId, text = text.ifEmpty { null }, parentCommentId = parent, imageUrl = image)
            _state.update { it.copy(sending = false) }
            if (r is ApiResult.Success) load()
        }
    }

    fun startEdit(comment: VideoComment) {
        _state.update { it.copy(editingId = comment.id, editDraft = comment.text, replyingTo = null) }
    }

    fun onEditDraft(text: String) { _state.update { it.copy(editDraft = text) } }
    fun cancelEdit() { _state.update { it.copy(editingId = null, editDraft = "") } }

    fun saveEdit() {
        val id = _state.value.editingId ?: return
        val text = _state.value.editDraft.trim()
        if (text.isEmpty()) return
        _state.update { it.copy(editingId = null) }
        viewModelScope.launch {
            if (repository.edit(videoId, id, text) is ApiResult.Success) load()
        }
    }

    /** Toggles a reaction emoji on a comment (un-react when already reacted), then reloads counts. */
    fun toggleReaction(comment: VideoComment, emoji: String) {
        viewModelScope.launch {
            val r = if (emoji in comment.myReactions) {
                repository.unreact(videoId, comment.id, emoji)
            } else {
                repository.react(videoId, comment.id, emoji)
            }
            if (r is ApiResult.Success) {
                // The reaction endpoints return the updated comment; patch it in place (no full reload).
                _state.update { st ->
                    st.copy(comments = st.comments.map { if (it.id == r.data.id) r.data else it })
                }
            }
        }
    }

    fun delete(comment: VideoComment) {
        viewModelScope.launch {
            if (repository.delete(videoId, comment.id) is ApiResult.Success) load()
        }
    }

    // ---- TIP-305 — video-comment tipping (recipient = the comment author) ----

    val tipPresets: List<Int> = listOf(100, 500, 1000)

    fun openTip(comment: VideoComment) {
        _state.update {
            it.copy(
                tipTarget = comment, tipSubmitting = false, tipError = null,
                tipSelectedCents = null, tipCustomText = "",
                tipVisibility = com.testlogon.android.feature.common.tip.TipVisibility.Default,
                tipConfirmedCents = null, tipNoCard = false,
            )
        }
    }

    fun dismissTip() {
        if (_state.value.tipSubmitting) return
        _state.update { it.copy(tipTarget = null, tipSubmitting = false, tipError = null, tipNoCard = false, tipConfirmedCents = null) }
    }

    fun selectTipPreset(cents: Int) {
        _state.update { it.copy(tipSelectedCents = cents, tipCustomText = "", tipError = null) }
    }

    fun setTipCustomAmount(text: String) {
        _state.update {
            it.copy(
                tipCustomText = text,
                tipSelectedCents = com.testlogon.android.feature.feed.parseDollarsToCents(text),
                tipError = null,
            )
        }
    }

    fun setTipVisibility(v: com.testlogon.android.feature.common.tip.TipVisibility) {
        _state.update { it.copy(tipVisibility = v) }
    }

    /** TIPX-B2 — explicit Send; NEVER optimistic. Empty wallet -> in-flow add-card (TIPX-B3). */
    fun sendTip() {
        val s = _state.value
        val target = s.tipTarget ?: return
        val cents = s.tipEffectiveCents ?: return
        if (!s.tipCanSend || s.tipSubmitting) return
        _state.update { it.copy(tipSubmitting = true, tipError = null) }
        viewModelScope.launch {
            val pmId: String? = when (val auth = billing.authorize(cents.toLong(), "USD")) {
                is BillingResult.Authorized -> auth.paymentMethodId
                BillingResult.NotConfigured -> {
                    _state.update { it.copy(tipSubmitting = false, tipNoCard = true) }
                    return@launch
                }
                BillingResult.Cancelled -> { _state.update { it.copy(tipSubmitting = false) }; return@launch }
                is BillingResult.Declined -> { failTip(auth.reason); return@launch }
                is BillingResult.Failed -> { failTip("Couldn't send tip. Try again."); return@launch }
            }
            when (val r = repository.tipComment(videoId, target.id, cents, pmId)) {
                is ApiResult.Success -> {
                    _state.update { it.copy(tipSubmitting = false, tipConfirmedCents = cents) }
                    load()
                }
                is ApiResult.Failure -> failTip(r.error.message)
                is ApiResult.NetworkError -> failTip("You're offline. Try again.")
            }
        }
    }

    /** TIPX-B3 — resume the composer (clearing the add-card state) after returning from add-card. */
    fun resumeTipAfterAddCard() {
        if (_state.value.tipNoCard) _state.update { it.copy(tipNoCard = false) }
    }

    private fun failTip(message: String) {
        _state.update { it.copy(tipSubmitting = false, tipError = message) }
    }
}

@Composable
fun VideoCommentsSection(
    modifier: Modifier = Modifier,
    // TIPX-B3 (F3) — navigate to add-card when an empty-wallet tipper wants to tip a video comment.
    onAddCard: () -> Unit = {},
    viewModel: VideoCommentsViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val names by viewModel.authorNames.collectAsStateWithLifecycle()
    val focusManager = LocalFocusManager.current
    val keyboard = LocalSoftwareKeyboardController.current

    // TIPX-B3 (F3) — resume the tip composer on return from add-card (ON_RESUME clears NoCard).
    val lifecycleOwner = androidx.lifecycle.compose.LocalLifecycleOwner.current
    androidx.compose.runtime.DisposableEffect(lifecycleOwner) {
        val observer = androidx.lifecycle.LifecycleEventObserver { _, event ->
            if (event == androidx.lifecycle.Lifecycle.Event.ON_RESUME) viewModel.resumeTipAfterAddCard()
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }
    // MOD-C2 - video comment report target (reported as video_comment by its id).
    var reportTarget by remember { mutableStateOf<ReportTarget?>(null) }

    Column(
        modifier = modifier
            .fillMaxWidth()
            .testTag("video_comments_section")
            // #9 — tap anywhere in the comments area (outside a field) clears focus + hides the IME so
            // the comment / reply / edit boxes can be dismissed by clicking out.
            .pointerInput(Unit) {
                detectTapGestures(onTap = { focusManager.clearFocus(); keyboard?.hide() })
            },
    ) {
        HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
        Text(
            text = "Comments",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.padding(vertical = 4.dp),
        )

        // Build a thread tree: top-level comments, each with its replies (one level deep).
        val roots = remember(state.comments) { state.comments.filter { !it.isReply } }
        val repliesByParent = remember(state.comments) {
            state.comments.filter { it.isReply }.groupBy { it.parentCommentId }
        }

        when {
            state.loading && state.comments.isEmpty() ->
                Box(Modifier.fillMaxWidth().padding(16.dp), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(modifier = Modifier.size(22.dp))
                }
            state.comments.isEmpty() ->
                Text(
                    text = "No comments yet — be the first.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(vertical = 8.dp),
                )
            else -> roots.forEach { root ->
                CommentRow(
                    comment = root,
                    names = names,
                    state = state,
                    viewModel = viewModel,
                    isReply = false,
                    onReport = { c -> reportTarget = ReportTarget.Content(c.id, "video_comment") },
                )
                repliesByParent[root.id].orEmpty().forEach { reply ->
                    CommentRow(
                        comment = reply,
                        names = names,
                        state = state,
                        viewModel = viewModel,
                        isReply = true,
                        onReport = { c -> reportTarget = ReportTarget.Content(c.id, "video_comment") },
                    )
                }
            }
        }

        // Composer (reply target banner shown above the field when replying).
        state.replyingTo?.let { target ->
            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp).testTag("video_comment_reply_banner"),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = "Replying to ${names[target.authorId]?.takeIf { it.isNotBlank() } ?: target.authorId.ifBlank { "you" }}",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.weight(1f),
                )
                TextButton(onClick = viewModel::cancelReply, modifier = Modifier.testTag("video_comment_reply_cancel")) {
                    Text("Cancel")
                }
            }
        }
        // #2 feed-parity — staged image preview (with remove) above the composer Row.
        state.pendingImageUrl?.let { url ->
            val model = remember(url) {
                if (url.startsWith("/")) BuildConfig.API_BASE_URL.trimEnd('/') + url else url
            }
            Box(modifier = Modifier.padding(top = 8.dp)) {
                AsyncImage(
                    model = model,
                    contentDescription = "Staged comment image",
                    modifier = Modifier.size(96.dp).clip(RoundedCornerShape(8.dp)).testTag("video_comment_staged_image"),
                )
                IconButton(
                    onClick = viewModel::clearStagedImage,
                    modifier = Modifier.size(28.dp).testTag("video_comment_staged_clear"),
                ) {
                    Icon(Icons.Filled.Close, contentDescription = "Remove image", tint = MaterialTheme.colorScheme.error)
                }
            }
        }
        Row(
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            // #2 feed-parity — attach an image to the comment (system photo picker).
            val imagePicker = androidx.activity.compose.rememberLauncherForActivityResult(
                androidx.activity.result.contract.ActivityResultContracts.GetContent(),
            ) { uri -> if (uri != null) viewModel.uploadAndStageImage(uri) }
            IconButton(
                onClick = { imagePicker.launch("image/*") },
                enabled = !state.imageUploading && state.pendingImageUrl == null,
                modifier = Modifier.size(44.dp).testTag("video_comment_attach_image"),
            ) {
                if (state.imageUploading) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp))
                } else {
                    Icon(
                        Icons.Outlined.Image,
                        contentDescription = "Attach image",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            OutlinedTextField(
                value = state.draft,
                onValueChange = viewModel::onDraft,
                modifier = Modifier.weight(1f).testTag("video_comment_input"),
                placeholder = { Text(if (state.replyingTo != null) "Write a reply…" else "Add a comment…") },
                maxLines = 4,
            )
            IconButton(
                onClick = { focusManager.clearFocus(); keyboard?.hide(); viewModel.send() },
                enabled = (state.draft.isNotBlank() || state.pendingImageUrl != null) && !state.sending,
                modifier = Modifier.size(48.dp).testTag("video_comment_send"),
            ) {
                Icon(
                    Icons.AutoMirrored.Filled.Send,
                    contentDescription = "Post comment",
                    tint = if (state.draft.isNotBlank() || state.pendingImageUrl != null) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        // TIP-305 / TIPX-B2 — the video-comment tip sheet (shared composer: presets + custom + explicit
        // Send + confirmed receipt + in-flow add-card).
        if (state.tipTarget != null) {
            VideoCommentTipSheet(
                state = state,
                presets = viewModel.tipPresets,
                onSelectPreset = viewModel::selectTipPreset,
                onCustomAmount = viewModel::setTipCustomAmount,
                onVisibility = viewModel::setTipVisibility,
                onSend = viewModel::sendTip,
                onDismiss = viewModel::dismissTip,
                onAddCard = onAddCard,
            )
        }
    }

    // MOD-C2/C3 - video comment report sheet host (six categories + licensing/IP -> DMCA).
    ContentReportSheetHost(target = reportTarget, onDismiss = { reportTarget = null })
}

@Composable
private fun CommentRow(
    comment: VideoComment,
    names: Map<String, String>,
    state: VideoCommentsViewModel.State,
    viewModel: VideoCommentsViewModel,
    isReply: Boolean,
    onReport: (VideoComment) -> Unit = {},
) {
    LaunchedEffect(comment.authorId) { viewModel.resolveAuthor(comment.authorId) }
    var showReactionPicker by remember { mutableStateOf(false) }
    Column(
        modifier = Modifier
            .fillMaxWidth()
            // Replies are indented one level so the thread reads as nested.
            .padding(start = if (isReply) 28.dp else 0.dp, top = 6.dp)
            .testTag(if (isReply) "video_comment_reply_row" else "video_comment_row"),
    ) {
        Row(verticalAlignment = Alignment.Top) {
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(
                        text = names[comment.authorId]?.takeIf { it.isNotBlank() }
                            ?: comment.authorId.ifBlank { "You" },
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = FontWeight.SemiBold,
                    )
                    if (comment.edited) {
                        Text(
                            text = "edited",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
                // Inline edit field when this comment is being edited; otherwise its content.
                if (state.editingId == comment.id) {
                    OutlinedTextField(
                        value = state.editDraft,
                        onValueChange = viewModel::onEditDraft,
                        modifier = Modifier.fillMaxWidth().padding(top = 4.dp).testTag("video_comment_edit_input"),
                        maxLines = 4,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                        TextButton(onClick = viewModel::cancelEdit) { Text("Cancel") }
                        TextButton(
                            onClick = viewModel::saveEdit,
                            enabled = state.editDraft.isNotBlank(),
                            modifier = Modifier.testTag("video_comment_edit_save"),
                        ) { Text("Save") }
                    }
                } else {
                    if (comment.text.isNotBlank()) {
                        Text(text = comment.text, style = MaterialTheme.typography.bodyMedium)
                    }
                    // #7 — render image comments (kind=image): resolve server-relative urls like the player.
                    comment.imageUrl?.let { url ->
                        val model = remember(url) {
                            if (url.startsWith("/")) BuildConfig.API_BASE_URL.trimEnd('/') + url else url
                        }
                        AsyncImage(
                            model = model,
                            contentDescription = "Comment image",
                            modifier = Modifier
                                .padding(top = 4.dp)
                                .size(160.dp)
                                .clip(RoundedCornerShape(8.dp))
                                .testTag("video_comment_image"),
                        )
                    }
                }
            }
            // Overflow actions: edit (own text comments) + delete (own).
            if (comment.canEdit && state.editingId != comment.id) {
                IconButton(
                    onClick = { viewModel.startEdit(comment) },
                    modifier = Modifier.size(40.dp).testTag("video_comment_edit"),
                ) {
                    Icon(Icons.Outlined.Edit, contentDescription = "Edit comment", tint = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            if (comment.canDelete) {
                IconButton(
                    onClick = { viewModel.delete(comment) },
                    modifier = Modifier.size(40.dp).testTag("video_comment_delete"),
                ) {
                    Icon(Icons.Outlined.Delete, contentDescription = "Delete comment", tint = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
        // Reaction chips + add-reaction + reply affordances.
        Row(
            modifier = Modifier.fillMaxWidth().padding(top = 2.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            comment.reactions.forEach { (emoji, count) ->
                val mine = emoji in comment.myReactions
                Surface(
                    color = if (mine) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.testTag("video_comment_reaction_chip"),
                ) {
                    Text(
                        text = "$emoji $count",
                        style = MaterialTheme.typography.labelMedium,
                        modifier = Modifier
                            .padding(horizontal = 8.dp, vertical = 3.dp)
                            .pointerInput(emoji, comment.id) {
                                detectTapGestures(onTap = { viewModel.toggleReaction(comment, emoji) })
                            },
                    )
                }
            }
            Box {
                IconButton(
                    onClick = { showReactionPicker = true },
                    modifier = Modifier.size(32.dp).testTag("video_comment_react"),
                ) {
                    Icon(
                        Icons.Filled.AddReaction,
                        contentDescription = "Add reaction",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(18.dp),
                    )
                }
                DropdownMenu(expanded = showReactionPicker, onDismissRequest = { showReactionPicker = false }) {
                    Row(Modifier.padding(horizontal = 4.dp)) {
                        viewModel.allowedReactions.forEach { emoji ->
                            TextButton(
                                onClick = { showReactionPicker = false; viewModel.toggleReaction(comment, emoji) },
                                modifier = Modifier.testTag("video_comment_react_$emoji"),
                            ) { Text(emoji, style = MaterialTheme.typography.titleMedium) }
                        }
                    }
                }
            }
            // Reply (only on top-level rows opens a reply targeting this thread).
            IconButton(
                onClick = { viewModel.startReply(comment) },
                modifier = Modifier.size(32.dp).testTag("video_comment_reply"),
            ) {
                Icon(
                    Icons.AutoMirrored.Filled.Reply,
                    contentDescription = "Reply",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(18.dp),
                )
            }
            // TIP-305 — tip this comment's author. Hidden on your OWN comment so you never self-tip
            // (the backend also rejects a self-tip with 400 cannot_tip_self).
            // TIPX-B4 (F7) — gate on real authorship (isOwnAuthor), not the canDelete permission proxy,
            // so a moderator/admin who can delete others' comments still sees the Tip button.
            if (!comment.isOwnAuthor) {
                IconButton(
                    onClick = { viewModel.openTip(comment) },
                    modifier = Modifier.size(32.dp).testTag("tip_video_comment_open"),
                ) {
                    Icon(
                        Icons.Outlined.Paid,
                        contentDescription = "Tip comment",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(18.dp),
                    )
                }
            }
            // MOD-C2 - report another member's video comment (hidden on your own comment).
            if (!comment.canDelete) {
                IconButton(
                    onClick = { onReport(comment) },
                    modifier = Modifier.size(32.dp).testTag("video_comment_report"),
                ) {
                    Icon(
                        Icons.Outlined.Flag,
                        contentDescription = "Report comment",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(18.dp),
                    )
                }
            }
        }
    }
}

/**
 * TIP-305 / TIPX-B2/B3/B4 — VIDEO-comment tip bottom sheet backed by the shared [TipComposerContent]:
 * presets + custom amount + public/private visibility + explicit Send (no one-tap charge) + inline
 * error + an in-sheet amount RECEIPT (with Done) + an in-flow add-card path on an empty wallet.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun VideoCommentTipSheet(
    state: VideoCommentsViewModel.State,
    presets: List<Int>,
    onSelectPreset: (Int) -> Unit,
    onCustomAmount: (String) -> Unit,
    onVisibility: (com.testlogon.android.feature.common.tip.TipVisibility) -> Unit,
    onSend: () -> Unit,
    onDismiss: () -> Unit,
    onAddCard: () -> Unit,
) {
    val submitting = state.tipSubmitting
    ModalBottomSheet(
        onDismissRequest = { if (!submitting) onDismiss() },
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
    ) {
        Column(
            Modifier.fillMaxWidth().padding(horizontal = 24.dp).padding(bottom = 24.dp).testTag("tip_video_comment_sheet"),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                stringResource(com.testlogon.android.R.string.tip_sheet_title),
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.SemiBold,
            )
            when {
                state.tipConfirmedCents != null -> {
                    val amount = "$" + "%.2f".format(state.tipConfirmedCents / 100.0)
                    val label = if (state.tipVisibility.isPrivate) {
                        stringResource(com.testlogon.android.R.string.tip_sent_private) + " · " + amount
                    } else {
                        stringResource(com.testlogon.android.R.string.tip_sent) + " · " + amount
                    }
                    Column(
                        Modifier.fillMaxWidth().testTag("tip_video_comment_confirmed"),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        Icon(
                            Icons.Filled.CheckCircle,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(40.dp),
                        )
                        Text(label, style = MaterialTheme.typography.titleMedium)
                        androidx.compose.material3.Button(
                            onClick = onDismiss,
                            modifier = Modifier.fillMaxWidth().testTag("tip_video_comment_done"),
                        ) { Text(stringResource(com.testlogon.android.R.string.tip_done)) }
                    }
                }
                state.tipNoCard -> {
                    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text(
                            stringResource(com.testlogon.android.R.string.tip_no_card_body),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        androidx.compose.material3.Button(
                            onClick = onAddCard,
                            modifier = Modifier.fillMaxWidth().testTag("tip_video_comment_add_card"),
                        ) { Text(stringResource(com.testlogon.android.R.string.tip_add_card)) }
                    }
                }
                submitting ->
                    androidx.compose.material3.Button(
                        onClick = {},
                        enabled = false,
                        modifier = Modifier.fillMaxWidth().testTag("tip_video_comment_send"),
                    ) { CircularProgressIndicator(modifier = Modifier.size(20.dp)) }
                else ->
                    com.testlogon.android.feature.common.tip.TipComposerContent(
                        presetsCents = presets.map(Int::toLong),
                        selectedCents = state.tipSelectedCents?.toLong(),
                        customText = state.tipCustomText,
                        canSend = state.tipCanSend,
                        inFlight = false,
                        onSelectPreset = { onSelectPreset(it.toInt()) },
                        onCustomAmount = onCustomAmount,
                        onSend = onSend,
                        error = state.tipError,
                        visibility = state.tipVisibility,
                        onVisibility = onVisibility,
                        presetTag = { "tip_video_comment_sheet_${it.toInt()}" },
                        customTag = "tip_video_comment_custom",
                        sendTag = "tip_video_comment_send",
                    )
            }
        }
    }
}
