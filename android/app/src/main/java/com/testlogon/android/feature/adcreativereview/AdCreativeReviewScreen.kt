@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.adcreativereview

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.PhotoLibrary
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.adcreativereview.PendingCreativeDto
import com.testlogon.android.feature.adminops.adminOpsErrorMessage

object AdCreativeReviewTestTags {
    const val SCREEN = "creative_review_screen"
    const val LIST = "creative_review_list"
    const val EMPTY = "creative_review_empty"
    const val FORBIDDEN = "creative_review_forbidden"
    const val ERROR_RETRY = "creative_review_error_retry"
    const val DIALOG = "creative_review_dialog"
    const val APPROVE = "creative_review_approve"
    const val REJECT = "creative_review_reject"
    fun row(id: String) = "creative_row_$id"
}

@Composable
fun AdCreativeReviewRoute(
    onBack: () -> Unit,
    viewModel: AdCreativeReviewViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    AdCreativeReviewScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onReview = viewModel::review,
        onMessageShown = viewModel::clearActionMessage,
    )
}

@Composable
fun AdCreativeReviewScreen(
    state: CreativeReviewUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onReview: (creativeId: String, decision: String, notes: String?) -> Unit,
    onMessageShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbar = remember { SnackbarHostState() }
    var reviewTarget by remember { mutableStateOf<PendingCreativeDto?>(null) }

    val message = (state as? CreativeReviewUiState.Content)?.actionMessage
    val transient = (state as? CreativeReviewUiState.Content)?.transientError
    LaunchedEffect(message, transient) {
        val text = message ?: transient?.let { adminOpsErrorMessage(it) }
        if (text != null) {
            snackbar.showSnackbar(text)
            onMessageShown()
        }
    }
    // Close the dialog once an action succeeds (row removed / message set).
    LaunchedEffect(message) { if (message != null) reviewTarget = null }

    Scaffold(
        modifier = modifier.testTag(AdCreativeReviewTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Creative review") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        val isRefreshing = (state as? CreativeReviewUiState.Content)?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            when (state) {
                is CreativeReviewUiState.Loading -> LoadingState()
                is CreativeReviewUiState.Empty -> EmptyState(
                    modifier = Modifier.testTag(AdCreativeReviewTestTags.EMPTY),
                    title = "Nothing to review",
                    body = "No creatives are pending review.",
                    imageVector = Icons.Outlined.CheckCircle,
                )
                is CreativeReviewUiState.Forbidden -> EmptyState(
                    modifier = Modifier.testTag(AdCreativeReviewTestTags.FORBIDDEN),
                    title = "Not authorised",
                    body = "You need platform-admin access to review ad creatives.",
                    imageVector = Icons.Outlined.Lock,
                    actionLabel = "Back",
                    onAction = onBack,
                )
                is CreativeReviewUiState.Error -> ErrorState(
                    modifier = Modifier.testTag(AdCreativeReviewTestTags.ERROR_RETRY),
                    message = adminOpsErrorMessage(state.type),
                    onRetry = onRetry,
                )
                is CreativeReviewUiState.Content -> LazyColumn(
                    modifier = Modifier.fillMaxSize().testTag(AdCreativeReviewTestTags.LIST),
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    items(items = state.creatives, key = { it.creativeId }) { cr ->
                        CreativeRow(cr, onClick = { reviewTarget = cr })
                    }
                }
            }
        }
    }

    val target = reviewTarget
    if (target != null) {
        val inFlight = (state as? CreativeReviewUiState.Content)?.actionInFlight == true
        ReviewDialog(
            creative = target,
            actionInFlight = inFlight,
            onDismiss = { if (!inFlight) reviewTarget = null },
            onDecision = { decision, notes -> onReview(target.creativeId, decision, notes) },
        )
    }
}

private fun formatLabel(format: String): String = when (format) {
    "image" -> "Image banner"
    "video" -> "Video ad"
    "native_post" -> "Native post"
    else -> format.ifBlank { "creative" }.replace('_', ' ')
}

@Composable
private fun CreativeRow(cr: PendingCreativeDto, onClick: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(AdCreativeReviewTestTags.row(cr.creativeId))
            .clickable(onClick = onClick),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = cr.title.ifBlank { cr.creativeId },
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = "${formatLabel(cr.format)} · Campaign: ${cr.campaignId}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = "Pending review",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.primary,
            )
        }
    }
}

@Composable
private fun ReviewDialog(
    creative: PendingCreativeDto,
    actionInFlight: Boolean,
    onDismiss: () -> Unit,
    onDecision: (decision: String, notes: String?) -> Unit,
) {
    var notes by remember { mutableStateOf("") }
    Dialog(onDismissRequest = onDismiss) {
        Card(modifier = Modifier.fillMaxWidth().testTag(AdCreativeReviewTestTags.DIALOG)) {
            Column(
                modifier = Modifier.padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(
                    text = "Review: ${creative.title.ifBlank { creative.creativeId }}",
                    style = MaterialTheme.typography.titleMedium,
                )
                DetailLine("Format", formatLabel(creative.format))
                DetailLine("Campaign", creative.campaignId)
                if (creative.width != null && creative.height != null) {
                    DetailLine("Dimensions", "${creative.width}x${creative.height}")
                }
                if (creative.durationSeconds != null) {
                    DetailLine("Duration", "${creative.durationSeconds}s")
                }
                if (creative.rotationWeight != null) {
                    DetailLine("Weight", creative.rotationWeight.toString())
                }
                OutlinedTextField(
                    value = notes,
                    onValueChange = { if (it.length <= 1000) notes = it },
                    label = { Text("Review notes (optional)") },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !actionInFlight,
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End),
                ) {
                    TextButton(
                        onClick = { onDecision("reject", notes) },
                        enabled = !actionInFlight,
                        modifier = Modifier.testTag(AdCreativeReviewTestTags.REJECT),
                    ) { Text("Reject") }
                    Button(
                        onClick = { onDecision("approve", notes) },
                        enabled = !actionInFlight,
                        modifier = Modifier.testTag(AdCreativeReviewTestTags.APPROVE),
                    ) { Text("Approve") }
                }
            }
        }
    }
}

@Composable
private fun DetailLine(label: String, value: String) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
}
