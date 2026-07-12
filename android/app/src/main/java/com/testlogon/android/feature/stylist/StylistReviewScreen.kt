@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.stylist

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.SubcomposeAsyncImage
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.stylist.ReviewIssue
import com.testlogon.android.data.stylist.ReviewScreenshot
import com.testlogon.android.data.stylist.RuleSeverity
import com.testlogon.android.data.stylist.UIReview

object StylistReviewTestTags {
    const val SCREEN = "stylist_review_screen"
    const val LIST = "stylist_review_list"
    const val LOADING = "stylist_review_loading"
    const val ERROR = "stylist_review_error"
    const val OFFLINE = "stylist_review_offline"
    const val SESSION_EXPIRED = "stylist_review_session_expired"
    const val ISSUE_PREFIX = "stylist_review_issue_"
    const val CREATE_TICKET_PREFIX = "stylist_review_create_ticket_"
}

@Composable
fun StylistReviewRoute(
    onBack: () -> Unit,
    onSessionExpired: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: StylistReviewViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is StylistEffect.ShowMessage ->
                    snackbarHostState.showSnackbar(context.getString(effect.resId))
            }
        }
    }
    LaunchedEffect(state.phase) {
        if (state.phase == StylistReviewUiState.Phase.SessionExpired) onSessionExpired()
    }

    StylistReviewScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onCreateTicket = viewModel::onCreateTicket,
        snackbarHostState = snackbarHostState,
        modifier = modifier,
    )
}

@Composable
fun StylistReviewScreen(
    state: StylistReviewUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onCreateTicket: (String) -> Unit,
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    Scaffold(
        modifier = modifier.testTag(StylistReviewTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(state.review?.let { it.pageName.ifBlank { it.pageUrl } } ?: stringResource(R.string.stylist_review_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Box(modifier = Modifier.padding(padding).fillMaxSize()) {
            when (state.phase) {
                StylistReviewUiState.Phase.Loading ->
                    LoadingState(modifier = Modifier.testTag(StylistReviewTestTags.LOADING))
                StylistReviewUiState.Phase.Error ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.stylist_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(StylistReviewTestTags.ERROR),
                    )
                StylistReviewUiState.Phase.Offline ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.stylist_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(StylistReviewTestTags.OFFLINE),
                    )
                StylistReviewUiState.Phase.SessionExpired ->
                    EmptyState(
                        title = stringResource(R.string.stylist_session_expired_title),
                        body = stringResource(R.string.stylist_session_expired_body),
                        modifier = Modifier.testTag(StylistReviewTestTags.SESSION_EXPIRED),
                    )
                StylistReviewUiState.Phase.Content -> {
                    val review = state.review ?: return@Box
                    LazyColumn(
                        modifier = Modifier.testTag(StylistReviewTestTags.LIST).fillMaxSize(),
                        contentPadding = PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        item { ReviewHeader(review) }
                        if (review.screenshots.isNotEmpty()) {
                            item {
                                Text(
                                    stringResource(R.string.stylist_review_screenshots),
                                    style = MaterialTheme.typography.titleMedium,
                                    fontWeight = FontWeight.SemiBold,
                                )
                            }
                            items(review.screenshots, key = { it.url }) { s -> ScreenshotCard(s) }
                        }
                        item {
                            Text(
                                stringResource(R.string.stylist_review_issues, review.issuesFound),
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.SemiBold,
                            )
                        }
                        if (review.issues.isEmpty()) {
                            item {
                                Text(
                                    stringResource(R.string.stylist_review_no_issues),
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        } else {
                            items(review.issues, key = { it.id }) { issue ->
                                IssueCard(
                                    issue = issue,
                                    isCreating = state.creatingTicketIssueId == issue.id,
                                    onCreateTicket = { onCreateTicket(issue.id) },
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ReviewHeader(review: UIReview) {
    Card(modifier = Modifier.fillMaxWidth(), elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)) {
        Column(modifier = Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(review.pageUrl, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            val a11y = review.accessibilityScore?.let { " · " + stringResource(R.string.stylist_gauge_a11y) + " " + String.format("%.1f", it) } ?: ""
            Text(
                text = review.reviewType + " · " + stringResource(R.string.stylist_gauge_design) + " " + String.format("%.1f", review.designScore) + a11y,
                style = MaterialTheme.typography.bodyMedium,
            )
            LabelChip(review.status.ifBlank { "unknown" })
        }
    }
}

@Composable
private fun ScreenshotCard(s: ReviewScreenshot) {
    Card(modifier = Modifier.fillMaxWidth(), elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)) {
        Column(modifier = Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            SubcomposeAsyncImage(
                model = s.url,
                contentDescription = s.label,
                contentScale = ContentScale.FillWidth,
                modifier = Modifier.fillMaxWidth().aspectRatio(1.6f),
                loading = {
                    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        CircularProgressIndicator()
                    }
                },
                error = {
                    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        Text(stringResource(R.string.stylist_screenshot_unavailable), style = MaterialTheme.typography.bodySmall)
                    }
                },
            )
            Text("${s.label} · ${s.viewport}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun IssueCard(issue: ReviewIssue, isCreating: Boolean, onCreateTicket: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth().testTag(StylistReviewTestTags.ISSUE_PREFIX + issue.id),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
    ) {
        Column(modifier = Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp), modifier = Modifier.weight(1f)) {
                    LabelChip(issue.severity.name.lowercase(), isError = issue.severity == RuleSeverity.ERROR)
                    LabelChip(issue.category)
                }
            }
            Text(issue.title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            if (issue.description.isNotBlank()) {
                Text(issue.description, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (issue.suggestion.isNotBlank()) {
                Text(
                    stringResource(R.string.stylist_issue_suggestion, issue.suggestion),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            if (issue.createdTicketId != null) {
                LabelChip(stringResource(R.string.stylist_issue_ticket, issue.createdTicketId))
            } else {
                OutlinedButton(
                    onClick = onCreateTicket,
                    enabled = !isCreating,
                    modifier = Modifier.testTag(StylistReviewTestTags.CREATE_TICKET_PREFIX + issue.id),
                ) {
                    if (isCreating) {
                        CircularProgressIndicator(modifier = Modifier.padding(end = 8.dp))
                    }
                    Text(stringResource(R.string.stylist_issue_create_ticket))
                }
            }
        }
    }
}

@Composable
private fun LabelChip(text: String, isError: Boolean = false) {
    AssistChip(
        onClick = {},
        enabled = false,
        label = { Text(text) },
        colors = AssistChipDefaults.assistChipColors(
            disabledContainerColor = if (isError) MaterialTheme.colorScheme.errorContainer else MaterialTheme.colorScheme.secondaryContainer,
            disabledLabelColor = MaterialTheme.colorScheme.onSurface,
        ),
        border = null,
    )
}
