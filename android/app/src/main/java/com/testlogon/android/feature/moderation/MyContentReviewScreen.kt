@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.moderation

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.moderation.ModerationCase
import com.testlogon.android.data.moderation.ModerationCaseState

/** Stable testTags for the "My content under review" screen. */
object MyContentReviewTestTags {
    const val SCREEN = "moderation_review_screen"
    const val LIST = "moderation_review_list"
    const val LOADING = "moderation_review_loading"
    const val EMPTY = "moderation_review_empty"
    const val ERROR = "moderation_review_error"
    const val CARD_PREFIX = "moderation_review_card_"
    const val RESPOND_PREFIX = "moderation_review_respond_"
    const val CLOSE_PREFIX = "moderation_review_close_"
    const val RESPOND_DIALOG = "moderation_review_respond_dialog"
    const val RESPOND_INPUT = "moderation_review_respond_input"
    const val RESPOND_SUBMIT = "moderation_review_respond_submit"
    const val CLOSE_DIALOG = "moderation_review_close_dialog"
    const val CLOSE_CONFIRM = "moderation_review_close_confirm"
}

@Composable
fun MyContentReviewRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: MyContentReviewViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is ReviewEffect.ShowMessage ->
                    snackbarHostState.showSnackbar(context.getString(effect.resId))
            }
        }
    }

    MyContentReviewScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        onSubmitResponse = viewModel::onSubmitResponse,
        onConfirmClose = viewModel::onConfirmClose,
        snackbarHostState = snackbarHostState,
        modifier = modifier,
    )
}

@Composable
fun MyContentReviewScreen(
    state: MyContentReviewUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onSubmitResponse: (caseId: String, statement: String) -> Unit,
    onConfirmClose: (caseId: String) -> Unit,
    snackbarHostState: SnackbarHostState,
    modifier: Modifier = Modifier,
) {
    // Which case has an open respond / close dialog (null = none).
    var respondFor by remember { mutableStateOf<ModerationCase?>(null) }
    var closeFor by remember { mutableStateOf<ModerationCase?>(null) }

    Scaffold(
        modifier = modifier.testTag(MyContentReviewTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("My content under review") },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("moderation_review_back")) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        Surface(modifier = Modifier.fillMaxSize().padding(padding)) {
            when (state.phase) {
                MyContentReviewUiState.Phase.Loading ->
                    LoadingState(modifier = Modifier.testTag(MyContentReviewTestTags.LOADING))

                MyContentReviewUiState.Phase.Error ->
                    ErrorState(
                        message = "Couldn't load your content review status.",
                        onRetry = onRetry,
                        modifier = Modifier.testTag(MyContentReviewTestTags.ERROR),
                    )

                MyContentReviewUiState.Phase.SessionExpired ->
                    EmptyState(
                        title = "Session expired",
                        body = "Sign in again to view your content review status.",
                        modifier = Modifier.testTag(MyContentReviewTestTags.EMPTY),
                    )

                MyContentReviewUiState.Phase.Empty ->
                    PullToRefreshBox(isRefreshing = state.isRefreshing, onRefresh = onRefresh) {
                        EmptyState(
                            title = "Nothing under review",
                            body = "None of your posts, comments or videos are hidden or under moderation review.",
                            imageVector = Icons.Outlined.Shield,
                            modifier = Modifier.testTag(MyContentReviewTestTags.EMPTY),
                        )
                    }

                MyContentReviewUiState.Phase.Content ->
                    PullToRefreshBox(isRefreshing = state.isRefreshing, onRefresh = onRefresh) {
                        LazyColumn(
                            modifier = Modifier.testTag(MyContentReviewTestTags.LIST).fillMaxSize(),
                            contentPadding = PaddingValues(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            items(state.cases, key = { it.caseId }) { case ->
                                CaseCard(
                                    case = case,
                                    inFlight = state.inFlightCaseId == case.caseId,
                                    onRespond = { respondFor = case },
                                    onClose = { closeFor = case },
                                )
                            }
                        }
                    }
            }
        }
    }

    respondFor?.let { case ->
        RespondDialog(
            case = case,
            onDismiss = { respondFor = null },
            onSubmit = { statement ->
                respondFor = null
                onSubmitResponse(case.caseId, statement)
            },
        )
    }

    closeFor?.let { case ->
        CloseConfirmDialog(
            onDismiss = { closeFor = null },
            onConfirm = {
                closeFor = null
                onConfirmClose(case.caseId)
            },
        )
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun CaseCard(
    case: ModerationCase,
    inFlight: Boolean,
    onRespond: () -> Unit,
    onClose: () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth().testTag(MyContentReviewTestTags.CARD_PREFIX + case.caseId),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = contentTypeLabel(case.contentType),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )

            val status = statusLine(case)
            Text(
                text = status.first,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Medium,
                color = MaterialTheme.colorScheme.primary,
            )
            if (status.second.isNotBlank()) {
                Text(
                    text = status.second,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            if (case.categories.isNotEmpty()) {
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    case.categories.forEach { cat ->
                        AssistChip(onClick = {}, label = { Text(categoryLabel(cat)) })
                    }
                }
            }

            case.posterResponse?.let { resp ->
                Text(
                    text = "Your response: $resp",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            if (case.canRespond || case.canClose) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    if (inFlight) {
                        CircularProgressIndicator(modifier = Modifier.padding(4.dp))
                    }
                    if (case.canRespond) {
                        Button(
                            onClick = onRespond,
                            enabled = !inFlight,
                            modifier = Modifier.testTag(MyContentReviewTestTags.RESPOND_PREFIX + case.caseId),
                        ) { Text("Respond") }
                    }
                    if (case.canClose) {
                        OutlinedButton(
                            onClick = onClose,
                            enabled = !inFlight,
                            modifier = Modifier.testTag(MyContentReviewTestTags.CLOSE_PREFIX + case.caseId),
                        ) { Text("Close & delete") }
                    }
                }
            }
        }
    }
}

@Composable
private fun RespondDialog(
    case: ModerationCase,
    onDismiss: () -> Unit,
    onSubmit: (String) -> Unit,
) {
    var text by rememberSaveable(case.caseId) { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag(MyContentReviewTestTags.RESPOND_DIALOG),
        title = { Text("Respond to the hold") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "Explain why your content should stay up. This goes to a moderator for the final decision. You can respond once.",
                    style = MaterialTheme.typography.bodySmall,
                )
                OutlinedTextField(
                    value = text,
                    onValueChange = { if (it.length <= 2000) text = it },
                    label = { Text("Your statement") },
                    minLines = 3,
                    modifier = Modifier.fillMaxWidth().testTag(MyContentReviewTestTags.RESPOND_INPUT),
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onSubmit(text.trim()) },
                enabled = text.trim().isNotEmpty(),
                modifier = Modifier.testTag(MyContentReviewTestTags.RESPOND_SUBMIT),
            ) { Text("Submit") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun CloseConfirmDialog(
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag(MyContentReviewTestTags.CLOSE_DIALOG),
        title = { Text("Delete this content?") },
        text = {
            Text("Closing your response deletes this content immediately and permanently. This cannot be undone.")
        },
        confirmButton = {
            TextButton(
                onClick = onConfirm,
                modifier = Modifier.testTag(MyContentReviewTestTags.CLOSE_CONFIRM),
            ) { Text("Delete permanently") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

/** Headline + supporting line describing the case state to the poster. */
private fun statusLine(case: ModerationCase): Pair<String, String> = when (case.state) {
    ModerationCaseState.UNDER_REVIEW ->
        "Hidden — pending review" to "Reported and hidden from others while a moderator reviews it."
    ModerationCaseState.HOLD -> {
        val days = case.daysRemaining
        val head = if (days != null) {
            "Violation confirmed — $days ${if (days == 1) "day" else "days"} left to respond"
        } else {
            "Violation confirmed — respond within 30 days"
        }
        head to "Hidden. Respond with a statement or it will be removed when the window ends."
    }
    ModerationCaseState.AWAITING_FINAL ->
        "Awaiting final decision" to "You responded. A moderator is making the final call; your content stays hidden until then."
    ModerationCaseState.UNKNOWN ->
        "Under moderation" to ""
}

private fun contentTypeLabel(t: String): String = when (t) {
    "feed_post" -> "Feed post"
    "feed_comment" -> "Post comment"
    "feed_media" -> "Post media"
    "video" -> "Video"
    "video_comment" -> "Video comment"
    "message", "message_media" -> "Message"
    "profile_photo" -> "Profile photo"
    else -> t.replace('_', ' ').replaceFirstChar { it.uppercase() }
}

private fun categoryLabel(c: String): String = when (c) {
    "spam" -> "Spam"
    "harassment" -> "Harassment"
    "hate" -> "Hate"
    "sexual" -> "Sexual"
    "violence_threats" -> "Violence / threats"
    "licensing_ip" -> "Licensing / IP"
    "other" -> "Other"
    else -> c.replace('_', ' ').replaceFirstChar { it.uppercase() }
}
