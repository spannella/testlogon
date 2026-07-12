@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.bots

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
import androidx.compose.material.icons.outlined.SmartToy
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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.data.bots.Bot
import com.testlogon.android.data.bots.BotStatus

/** Stable testTags for the bots list screen. */
object BotsListTestTags {
    const val SCREEN = "bots_screen"
    const val LIST = "bots_list"
    const val LOADING = "bots_loading"
    const val EMPTY = "bots_empty"
    const val ERROR = "bots_error"
    const val OFFLINE = "bots_offline"
    const val SESSION_EXPIRED = "bots_session_expired"
    const val NEW = "bots_new"
    const val FORM = "bots_create_form"
    const val FORM_NAME = "bots_form_name"
    const val FORM_DESCRIPTION = "bots_form_description"
    const val FORM_PERSONALITY = "bots_form_personality"
    const val FORM_SUBMIT = "bots_form_submit"
    const val ROW_PREFIX = "bots_row_"
}

/** Route-level bots list (reachable from the More hub). Mirrors the web bots page. */
@Composable
fun BotsListRoute(
    onBack: () -> Unit,
    onOpenAutoReply: (String) -> Unit,
    onOpenTemplates: (String) -> Unit,
    onSessionExpired: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: BotsListViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is BotsListEffect.ShowMessage ->
                    snackbarHostState.showSnackbar(context.getString(effect.resId))
            }
        }
    }

    LaunchedEffect(state.phase) {
        if (state.phase == BotsPhase.SessionExpired) onSessionExpired()
    }

    BotsListScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        onOpenCreate = viewModel::onOpenCreate,
        onDismissCreate = viewModel::onDismissCreate,
        onNameChange = viewModel::onNameChange,
        onDescriptionChange = viewModel::onDescriptionChange,
        onPersonalityChange = viewModel::onPersonalityChange,
        onSubmitCreate = viewModel::onSubmitCreate,
        onToggleStatus = viewModel::onToggleStatus,
        onDelete = viewModel::onDelete,
        onOpenAutoReply = onOpenAutoReply,
        onOpenTemplates = onOpenTemplates,
        snackbarHostState = snackbarHostState,
        modifier = modifier,
    )
}

@Composable
fun BotsListScreen(
    state: BotsListUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onOpenCreate: () -> Unit,
    onDismissCreate: () -> Unit,
    onNameChange: (String) -> Unit,
    onDescriptionChange: (String) -> Unit,
    onPersonalityChange: (String) -> Unit,
    onSubmitCreate: () -> Unit,
    onToggleStatus: (String) -> Unit,
    onDelete: (String) -> Unit,
    onOpenAutoReply: (String) -> Unit,
    onOpenTemplates: (String) -> Unit,
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    Scaffold(
        modifier = modifier.testTag(BotsListTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.bots_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("bots_back")) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
                actions = {
                    val newCd = stringResource(R.string.bots_new)
                    IconButton(onClick = onOpenCreate, modifier = Modifier.testTag(BotsListTestTags.NEW)) {
                        Icon(Icons.Outlined.Add, contentDescription = newCd)
                    }
                },
            )
        },
        floatingActionButton = {
            if (state.phase == BotsPhase.Content || state.phase == BotsPhase.Empty) {
                FloatingActionButton(onClick = onOpenCreate) {
                    Icon(Icons.Outlined.Add, contentDescription = stringResource(R.string.bots_new))
                }
            }
        },
    ) { padding ->
        Box(modifier = Modifier.padding(padding).fillMaxSize()) {
            when (state.phase) {
                BotsPhase.Loading ->
                    LoadingState(modifier = Modifier.testTag(BotsListTestTags.LOADING))

                BotsPhase.Error ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.bots_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(BotsListTestTags.ERROR),
                    )

                BotsPhase.Offline ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.bots_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(BotsListTestTags.OFFLINE),
                    )

                BotsPhase.SessionExpired ->
                    EmptyState(
                        title = stringResource(R.string.bots_session_expired_title),
                        body = stringResource(R.string.bots_session_expired_body),
                        modifier = Modifier.testTag(BotsListTestTags.SESSION_EXPIRED),
                    )

                BotsPhase.Empty ->
                    PullToRefreshBox(
                        isRefreshing = state.isRefreshing,
                        onRefresh = onRefresh,
                        modifier = Modifier.fillMaxSize(),
                    ) {
                        EmptyState(
                            title = stringResource(R.string.bots_empty_title),
                            body = stringResource(R.string.bots_empty_body),
                            imageVector = Icons.Outlined.SmartToy,
                            actionLabel = stringResource(R.string.bots_new),
                            onAction = onOpenCreate,
                            modifier = Modifier.testTag(BotsListTestTags.EMPTY),
                        )
                    }

                BotsPhase.Content -> {
                    PullToRefreshBox(
                        isRefreshing = state.isRefreshing,
                        onRefresh = onRefresh,
                        modifier = Modifier.fillMaxSize(),
                    ) {
                        LazyColumn(
                            modifier = Modifier
                                .testTag(BotsListTestTags.LIST)
                                .fillMaxSize(),
                            contentPadding = PaddingValues(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            if (state.isStale) {
                                item { OfflineBanner(onRetry = onRetry) }
                            }
                            items(state.bots, key = { it.id }) { bot ->
                                BotCard(
                                    bot = bot,
                                    isMutating = state.isMutating,
                                    onToggleStatus = { onToggleStatus(bot.id) },
                                    onDelete = { onDelete(bot.id) },
                                    onOpenAutoReply = { onOpenAutoReply(bot.id) },
                                    onOpenTemplates = { onOpenTemplates(bot.id) },
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    if (state.create.isOpen) {
        CreateBotDialog(
            form = state.create,
            onDismiss = onDismissCreate,
            onNameChange = onNameChange,
            onDescriptionChange = onDescriptionChange,
            onPersonalityChange = onPersonalityChange,
            onSubmit = onSubmitCreate,
        )
    }
}

@Composable
private fun BotCard(
    bot: Bot,
    isMutating: Boolean,
    onToggleStatus: () -> Unit,
    onDelete: () -> Unit,
    onOpenAutoReply: () -> Unit,
    onOpenTemplates: () -> Unit,
) {
    var confirmDelete by remember { mutableStateOf(false) }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(BotsListTestTags.ROW_PREFIX + bot.id),
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
                    text = bot.name,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.weight(1f),
                )
                StatusChip(status = bot.status)
            }

            bot.description?.let { desc ->
                Text(
                    text = desc,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                )
            }

            Text(
                text = stringResource(R.string.bots_message_count, bot.messageCount),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                TextButton(onClick = onOpenAutoReply) {
                    Text(stringResource(R.string.bots_action_auto_reply))
                }
                TextButton(onClick = onOpenTemplates) {
                    Text(stringResource(R.string.bots_action_templates))
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                TextButton(onClick = onToggleStatus, enabled = !isMutating) {
                    Text(
                        stringResource(
                            if (bot.isActive) R.string.bots_action_pause else R.string.bots_action_enable,
                        ),
                    )
                }
                TextButton(onClick = { confirmDelete = true }, enabled = !isMutating) {
                    Text(stringResource(R.string.bots_action_delete))
                }
            }
        }
    }

    if (confirmDelete) {
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text(stringResource(R.string.bots_delete_confirm_title)) },
            text = { Text(stringResource(R.string.bots_delete_confirm_body, bot.name)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmDelete = false
                    onDelete()
                }) {
                    Text(stringResource(R.string.bots_action_delete))
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmDelete = false }) {
                    Text(stringResource(R.string.bots_cancel))
                }
            },
        )
    }
}

@Composable
private fun StatusChip(status: BotStatus) {
    val labelRes = when (status) {
        BotStatus.ACTIVE -> R.string.bots_status_active
        BotStatus.PAUSED -> R.string.bots_status_paused
        BotStatus.DISABLED -> R.string.bots_status_disabled
        BotStatus.UNKNOWN -> R.string.bots_status_unknown
    }
    val container = when (status) {
        BotStatus.ACTIVE -> MaterialTheme.colorScheme.secondaryContainer
        BotStatus.PAUSED -> MaterialTheme.colorScheme.tertiaryContainer
        else -> MaterialTheme.colorScheme.surfaceVariant
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
private fun CreateBotDialog(
    form: CreateBotFormState,
    onDismiss: () -> Unit,
    onNameChange: (String) -> Unit,
    onDescriptionChange: (String) -> Unit,
    onPersonalityChange: (String) -> Unit,
    onSubmit: () -> Unit,
) {
    Dialog(onDismissRequest = onDismiss) {
        Card(modifier = Modifier.fillMaxWidth().testTag(BotsListTestTags.FORM)) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(
                    text = stringResource(R.string.bots_create_title),
                    style = MaterialTheme.typography.titleLarge,
                )
                OutlinedTextField(
                    value = form.name,
                    onValueChange = onNameChange,
                    label = { Text(stringResource(R.string.bots_field_name)) },
                    singleLine = true,
                    enabled = !form.isSubmitting,
                    modifier = Modifier.fillMaxWidth().testTag(BotsListTestTags.FORM_NAME),
                )
                OutlinedTextField(
                    value = form.description,
                    onValueChange = onDescriptionChange,
                    label = { Text(stringResource(R.string.bots_field_description)) },
                    minLines = 2,
                    enabled = !form.isSubmitting,
                    modifier = Modifier.fillMaxWidth().testTag(BotsListTestTags.FORM_DESCRIPTION),
                )
                OutlinedTextField(
                    value = form.personality,
                    onValueChange = onPersonalityChange,
                    label = { Text(stringResource(R.string.bots_field_personality)) },
                    singleLine = true,
                    enabled = !form.isSubmitting,
                    modifier = Modifier.fillMaxWidth().testTag(BotsListTestTags.FORM_PERSONALITY),
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                ) {
                    TextButton(onClick = onDismiss, enabled = !form.isSubmitting) {
                        Text(stringResource(R.string.bots_cancel))
                    }
                    TextButton(
                        onClick = onSubmit,
                        enabled = form.canSubmit,
                        modifier = Modifier.testTag(BotsListTestTags.FORM_SUBMIT),
                    ) {
                        Text(stringResource(R.string.bots_create_action))
                    }
                }
            }
        }
    }
}
