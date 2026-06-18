@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.ideas

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Lightbulb
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
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
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.data.ideas.Idea
import com.testlogon.android.data.ideas.IdeaStatus

/** Stable testTags for the ideas screen. */
object IdeasTestTags {
    const val SCREEN = "ideas_screen"
    const val LIST = "ideas_list"
    const val LOADING = "ideas_loading"
    const val EMPTY = "ideas_empty"
    const val ERROR = "ideas_error"
    const val OFFLINE = "ideas_offline"
    const val SESSION_EXPIRED = "ideas_session_expired"
    const val NEW = "ideas_new"
    const val FORM = "ideas_submit_form"
    const val FORM_TITLE = "ideas_form_title"
    const val FORM_DESCRIPTION = "ideas_form_description"
    const val FORM_SUBMIT = "ideas_form_submit"
    const val ROW_PREFIX = "ideas_row_"
}

/** Route-level "Ideas" entry (reachable from the More hub). Mirrors the web ideas/submit page. */
@Composable
fun IdeasRoute(
    onBack: () -> Unit,
    onSessionExpired: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: IdeasViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is IdeasEffect.ShowMessage ->
                    snackbarHostState.showSnackbar(context.getString(effect.resId))
            }
        }
    }

    LaunchedEffect(state.phase) {
        if (state.phase == IdeasUiState.Phase.SessionExpired) onSessionExpired()
    }

    IdeasScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        onOpenSubmit = viewModel::onOpenSubmit,
        onDismissSubmit = viewModel::onDismissSubmit,
        onTitleChange = viewModel::onTitleChange,
        onDescriptionChange = viewModel::onDescriptionChange,
        onSubmit = viewModel::onSubmit,
        snackbarHostState = snackbarHostState,
        modifier = modifier,
    )
}

@Composable
fun IdeasScreen(
    state: IdeasUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onOpenSubmit: () -> Unit,
    onDismissSubmit: () -> Unit,
    onTitleChange: (String) -> Unit,
    onDescriptionChange: (String) -> Unit,
    onSubmit: () -> Unit,
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    Scaffold(
        modifier = modifier.testTag(IdeasTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.ideas_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("ideas_back")) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
                actions = {
                    val newCd = stringResource(R.string.ideas_new)
                    IconButton(onClick = onOpenSubmit, modifier = Modifier.testTag(IdeasTestTags.NEW)) {
                        Icon(Icons.Outlined.Add, contentDescription = newCd)
                    }
                },
            )
        },
        floatingActionButton = {
            if (state.phase == IdeasUiState.Phase.Content || state.phase == IdeasUiState.Phase.Empty) {
                FloatingActionButton(onClick = onOpenSubmit) {
                    Icon(Icons.Outlined.Add, contentDescription = stringResource(R.string.ideas_new))
                }
            }
        },
    ) { padding ->
        Box(modifier = Modifier.padding(padding).fillMaxSize()) {
            when (state.phase) {
                IdeasUiState.Phase.Loading ->
                    LoadingState(modifier = Modifier.testTag(IdeasTestTags.LOADING))

                IdeasUiState.Phase.Error ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.ideas_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(IdeasTestTags.ERROR),
                    )

                IdeasUiState.Phase.Offline ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.ideas_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(IdeasTestTags.OFFLINE),
                    )

                IdeasUiState.Phase.SessionExpired ->
                    EmptyState(
                        title = stringResource(R.string.ideas_session_expired_title),
                        body = stringResource(R.string.ideas_session_expired_body),
                        modifier = Modifier.testTag(IdeasTestTags.SESSION_EXPIRED),
                    )

                IdeasUiState.Phase.Empty ->
                    PullToRefreshBox(
                        isRefreshing = state.isRefreshing,
                        onRefresh = onRefresh,
                        modifier = Modifier.fillMaxSize(),
                    ) {
                        EmptyState(
                            title = stringResource(R.string.ideas_empty_title),
                            body = stringResource(R.string.ideas_empty_body),
                            imageVector = Icons.Outlined.Lightbulb,
                            actionLabel = stringResource(R.string.ideas_new),
                            onAction = onOpenSubmit,
                            modifier = Modifier.testTag(IdeasTestTags.EMPTY),
                        )
                    }

                IdeasUiState.Phase.Content -> {
                    val ideas = state.page?.ideas.orEmpty()
                    PullToRefreshBox(
                        isRefreshing = state.isRefreshing,
                        onRefresh = onRefresh,
                        modifier = Modifier.fillMaxSize(),
                    ) {
                        LazyColumn(
                            modifier = Modifier
                                .testTag(IdeasTestTags.LIST)
                                .fillMaxSize(),
                            contentPadding = PaddingValues(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            if (state.isStale) {
                                item { OfflineBanner(onRetry = onRetry) }
                            }
                            items(ideas, key = { it.id }) { idea ->
                                IdeaCard(idea = idea)
                            }
                        }
                    }
                }
            }
        }
    }

    if (state.submit.isOpen) {
        SubmitIdeaDialog(
            form = state.submit,
            onDismiss = onDismissSubmit,
            onTitleChange = onTitleChange,
            onDescriptionChange = onDescriptionChange,
            onSubmit = onSubmit,
        )
    }
}

@Composable
private fun IdeaCard(idea: Idea) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(IdeasTestTags.ROW_PREFIX + idea.id),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = idea.title.ifBlank { stringResource(R.string.ideas_untitled) },
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                StatusChip(status = idea.status)
            }

            if (idea.description.isNotBlank()) {
                Text(
                    text = idea.description,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            val created = idea.formattedCreated()
            if (created.isNotBlank()) {
                Text(
                    text = stringResource(R.string.ideas_submitted_on, created),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            idea.rejectionReason?.let { reason ->
                Text(
                    text = stringResource(R.string.ideas_rejection_reason, reason),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun StatusChip(status: IdeaStatus) {
    val labelRes = when (status) {
        IdeaStatus.SUBMITTED -> R.string.ideas_status_submitted
        IdeaStatus.TRIAGING -> R.string.ideas_status_triaging
        IdeaStatus.ACCEPTED -> R.string.ideas_status_accepted
        IdeaStatus.REJECTED -> R.string.ideas_status_rejected
        IdeaStatus.CONVERTED -> R.string.ideas_status_converted
        IdeaStatus.UNKNOWN -> R.string.ideas_status_unknown
    }
    val container = when (status) {
        IdeaStatus.ACCEPTED, IdeaStatus.CONVERTED -> MaterialTheme.colorScheme.tertiaryContainer
        IdeaStatus.REJECTED -> MaterialTheme.colorScheme.errorContainer
        IdeaStatus.UNKNOWN -> MaterialTheme.colorScheme.surfaceVariant
        else -> MaterialTheme.colorScheme.secondaryContainer
    }
    AssistChip(
        onClick = {},
        enabled = false,
        label = { Text(stringResource(labelRes)) },
        colors = AssistChipDefaults.assistChipColors(
            disabledContainerColor = container,
            disabledLabelColor = MaterialTheme.colorScheme.onSurface,
        ),
        border = null,
    )
}

@Composable
private fun SubmitIdeaDialog(
    form: SubmitFormState,
    onDismiss: () -> Unit,
    onTitleChange: (String) -> Unit,
    onDescriptionChange: (String) -> Unit,
    onSubmit: () -> Unit,
) {
    Dialog(onDismissRequest = onDismiss) {
        Card(
            modifier = Modifier.fillMaxWidth().testTag(IdeasTestTags.FORM),
        ) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(
                    text = stringResource(R.string.ideas_submit_title),
                    style = MaterialTheme.typography.titleLarge,
                )
                Text(
                    text = stringResource(R.string.ideas_submit_helper),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedTextField(
                    value = form.title,
                    onValueChange = onTitleChange,
                    label = { Text(stringResource(R.string.ideas_field_title)) },
                    placeholder = { Text(stringResource(R.string.ideas_field_title_hint)) },
                    singleLine = true,
                    enabled = !form.isSubmitting,
                    modifier = Modifier.fillMaxWidth().testTag(IdeasTestTags.FORM_TITLE),
                )
                OutlinedTextField(
                    value = form.description,
                    onValueChange = onDescriptionChange,
                    label = { Text(stringResource(R.string.ideas_field_description)) },
                    placeholder = { Text(stringResource(R.string.ideas_field_description_hint)) },
                    minLines = 4,
                    enabled = !form.isSubmitting,
                    modifier = Modifier.fillMaxWidth().testTag(IdeasTestTags.FORM_DESCRIPTION),
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                ) {
                    TextButton(onClick = onDismiss, enabled = !form.isSubmitting) {
                        Text(stringResource(R.string.ideas_cancel))
                    }
                    TextButton(
                        onClick = onSubmit,
                        enabled = form.canSubmit,
                        modifier = Modifier.testTag(IdeasTestTags.FORM_SUBMIT),
                    ) {
                        Text(stringResource(R.string.ideas_submit_action))
                    }
                }
            }
        }
    }
}
