@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.groups

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.TextButton
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.flow.collectLatest
import coil.compose.SubcomposeAsyncImage
import coil.request.ImageRequest
import com.testlogon.android.R
import com.testlogon.android.core.model.groups.Group
import com.testlogon.android.core.model.groups.GroupRole
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner

/** AND-355 - stable testTags for the social-groups list screen. */
object GroupsListTestTags {
    const val SCREEN = "groups_list_screen"
    const val ROW_PREFIX = "group_row_"
    const val CREATE_FAB = "groups_create_fab"
    const val CREATE_DIALOG = "groups_create_dialog"
    const val CREATE_NAME = "groups_create_name"
    const val CREATE_DESCRIPTION = "groups_create_description"
    const val CREATE_SUBMIT = "groups_create_submit"
}

/** AND-355 - route-level groups list entry (reachable from the More hub). */
@Composable
fun GroupsListRoute(
    onBack: () -> Unit,
    onOpenGroup: (String) -> Unit,
    viewModel: GroupsListViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val createState by viewModel.createState.collectAsStateWithLifecycle()
    LaunchedEffect(viewModel) {
        viewModel.created.collectLatest { groupId -> onOpenGroup(groupId) }
    }
    GroupsListScreen(
        state = state,
        createState = createState,
        onBack = onBack,
        onRetry = viewModel::load,
        onRefresh = viewModel::refresh,
        onOpenGroup = onOpenGroup,
        onOpenCreate = viewModel::openCreate,
        onDismissCreate = viewModel::dismissCreate,
        onCreateNameChange = viewModel::onCreateNameChange,
        onCreateDescriptionChange = viewModel::onCreateDescriptionChange,
        onCreateVisibilityChange = viewModel::onCreateVisibilityChange,
        onSubmitCreate = viewModel::submitCreate,
    )
}

/** AND-355 - stateless social-groups list screen (discovery). */
@Composable
fun GroupsListScreen(
    state: GroupsListUiState,
    createState: CreateGroupFormState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onRefresh: () -> Unit,
    onOpenGroup: (String) -> Unit,
    onOpenCreate: () -> Unit,
    onDismissCreate: () -> Unit,
    onCreateNameChange: (String) -> Unit,
    onCreateDescriptionChange: (String) -> Unit,
    onCreateVisibilityChange: (Boolean) -> Unit,
    onSubmitCreate: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(GroupsListTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.groups_list_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.groups_back),
                        )
                    }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = onOpenCreate,
                modifier = Modifier.testTag(GroupsListTestTags.CREATE_FAB),
            ) {
                Icon(Icons.Filled.Add, contentDescription = stringResource(R.string.groups_create_title))
            }
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is GroupsListUiState.Loading -> LoadingState()

                is GroupsListUiState.Empty ->
                    EmptyState(
                        title = stringResource(R.string.groups_empty_title),
                        body = stringResource(R.string.groups_empty_body),
                    )

                is GroupsListUiState.Error ->
                    ErrorState(message = state.error.message, onRetry = onRetry)

                is GroupsListUiState.Content ->
                    GroupsListContent(
                        state = state,
                        onRefresh = onRefresh,
                        onRetry = onRetry,
                        onOpenGroup = onOpenGroup,
                    )
            }
        }
    }

    if (createState.visible) {
        CreateGroupDialog(
            form = createState,
            onNameChange = onCreateNameChange,
            onDescriptionChange = onCreateDescriptionChange,
            onVisibilityChange = onCreateVisibilityChange,
            onSubmit = onSubmitCreate,
            onDismiss = onDismissCreate,
        )
    }
}

/** AND-B7 - the create-group dialog (name + description + public/private). */
@Composable
private fun CreateGroupDialog(
    form: CreateGroupFormState,
    onNameChange: (String) -> Unit,
    onDescriptionChange: (String) -> Unit,
    onVisibilityChange: (Boolean) -> Unit,
    onSubmit: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        modifier = Modifier.testTag(GroupsListTestTags.CREATE_DIALOG),
        onDismissRequest = { if (!form.submitting) onDismiss() },
        title = { Text(stringResource(R.string.groups_create_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = form.name,
                    onValueChange = onNameChange,
                    singleLine = true,
                    isError = form.nameError != null,
                    label = { Text(stringResource(R.string.groups_create_name_label)) },
                    modifier = Modifier.fillMaxWidth().testTag(GroupsListTestTags.CREATE_NAME),
                )
                OutlinedTextField(
                    value = form.description,
                    onValueChange = onDescriptionChange,
                    label = { Text(stringResource(R.string.groups_create_description_label)) },
                    modifier = Modifier.fillMaxWidth().testTag(GroupsListTestTags.CREATE_DESCRIPTION),
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(
                        selected = form.isPublic,
                        onClick = { onVisibilityChange(true) },
                        label = { Text(stringResource(R.string.groups_create_visibility_public)) },
                    )
                    FilterChip(
                        selected = !form.isPublic,
                        onClick = { onVisibilityChange(false) },
                        label = { Text(stringResource(R.string.groups_create_visibility_private)) },
                    )
                }
                val err = form.submitError
                if (err != null) {
                    Text(
                        text = err,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = onSubmit,
                enabled = form.isValid && !form.submitting,
                modifier = Modifier.testTag(GroupsListTestTags.CREATE_SUBMIT),
            ) {
                if (form.submitting) {
                    CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                } else {
                    Text(stringResource(R.string.groups_create_submit))
                }
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss, enabled = !form.submitting) {
                Text(stringResource(R.string.groups_create_cancel))
            }
        },
    )
}

@Composable
private fun GroupsListContent(
    state: GroupsListUiState.Content,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onOpenGroup: (String) -> Unit,
) {
    PullToRefreshBox(
        isRefreshing = state.isRefreshing,
        onRefresh = onRefresh,
        modifier = Modifier.fillMaxSize(),
    ) {
        Column(Modifier.fillMaxSize()) {
            if (state.staleError != null) {
                OfflineBanner(message = state.staleError.message, onRetry = onRetry)
            }
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                items(state.groups, key = { it.id }) { group ->
                    GroupRow(group = group, onClick = { onOpenGroup(group.id) })
                }
            }
        }
    }
}

@Composable
private fun GroupRow(
    group: Group,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(GroupsListTestTags.ROW_PREFIX + group.id)
            .clickable(onClick = onClick)
            .padding(vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        GroupCover(group)
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = group.name,
                style = MaterialTheme.typography.titleMedium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            val count = group.memberCount
            if (count != null) {
                Text(
                    text = stringResource(R.string.groups_member_count, count),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        AssistChip(
            onClick = onClick,
            label = { Text(roleLabel(group.myRole)) },
        )
    }
}

@Composable
private fun GroupCover(group: Group) {
    val cd = group.name
    Box(
        modifier = Modifier
            .size(48.dp)
            .clip(RoundedCornerShape(8.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant),
        contentAlignment = Alignment.Center,
    ) {
        val url = group.coverImageUrl
        if (url != null) {
            SubcomposeAsyncImage(
                model = ImageRequest.Builder(LocalContext.current).data(url).crossfade(true).build(),
                contentDescription = cd,
                loading = { Box(Modifier.fillMaxSize().height(48.dp)) },
                modifier = Modifier.fillMaxSize(),
            )
        } else {
            Text(
                text = group.name.take(1).uppercase(),
                style = MaterialTheme.typography.titleMedium,
            )
        }
    }
}

/** Maps a [GroupRole] to its display label (UNKNOWN -> a generic label). */
@Composable
internal fun roleLabel(role: GroupRole): String = stringResource(
    when (role) {
        GroupRole.ADMIN -> R.string.groups_role_admin
        GroupRole.MODERATOR -> R.string.groups_role_moderator
        GroupRole.MEMBER -> R.string.groups_role_member
        GroupRole.UNKNOWN -> R.string.groups_role_unknown
    },
)
