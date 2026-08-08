package com.testlogon.android.feature.stories

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.AsyncImage
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.stories.HighlightGroup
import com.testlogon.android.data.stories.StorySegment

/** PAR-16 - stable test tags for the Story Highlights surface. */
object HighlightsTestTags {
    const val SCREEN = "highlights_screen"
    const val BACK = "highlights_back"
    const val ADD_GROUP = "highlights_add_group"
    const val GRID = "highlights_grid"
    const val EMPTY = "highlights_empty"
    const val GROUP = "highlights_group"
    const val DELETE_GROUP = "highlights_delete_group"
    const val CREATE_DIALOG = "highlights_create_dialog"
    const val CREATE_TITLE = "highlights_create_title"
    const val CREATE_COVER = "highlights_create_cover"
    const val CREATE_CONFIRM = "highlights_create_confirm"
    const val PIN_STORY = "highlights_pin_story"
}

/**
 * PAR-16 - Story Highlights route `stories/highlights/{userId}`. Shows a user's highlight groups; when
 * the resolved user is the signed-in owner it also exposes create-group, pin-story (from the owner's
 * active stories) and delete-group affordances. A read-only viewer (someone else's profile) sees only
 * the groups grid. Errors / forbidden actions surface via the Scaffold snackbar.
 */
@Composable
fun HighlightsRoute(
    onBack: () -> Unit,
    viewModel: HighlightsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val pinCandidates by viewModel.pinCandidates.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is HighlightsEffect.ShowMessage -> snackbarHostState.showSnackbar(effect.message)
            }
        }
    }

    HighlightsScreen(
        state = state,
        pinCandidates = pinCandidates,
        snackbarHostState = snackbarHostState,
        onBack = onBack,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        onCreateGroup = viewModel::createGroup,
        onDeleteGroup = viewModel::deleteGroup,
        onLoadPinCandidates = viewModel::loadPinCandidates,
        onPin = viewModel::pin,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HighlightsScreen(
    state: HighlightsUiState,
    pinCandidates: List<StorySegment>,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onCreateGroup: (title: String, coverUrl: String?) -> Unit,
    onDeleteGroup: (groupId: String) -> Unit,
    onLoadPinCandidates: () -> Unit,
    onPin: (storyId: String, groupId: String?) -> Unit,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    var showCreate by remember { mutableStateOf(false) }
    var pinTarget by remember { mutableStateOf<HighlightGroup?>(null) }

    Scaffold(
        modifier = Modifier.testTag(HighlightsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.highlights_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag(HighlightsTestTags.BACK)) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.highlights_back),
                        )
                    }
                },
                actions = {
                    if (state.isOwner) {
                        IconButton(
                            onClick = { showCreate = true },
                            enabled = !state.isMutating,
                            modifier = Modifier.testTag(HighlightsTestTags.ADD_GROUP),
                        ) {
                            Icon(
                                Icons.Filled.Add,
                                contentDescription = stringResource(R.string.highlights_new_group),
                            )
                        }
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        PullToRefreshBox(
            isRefreshing = state.isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            when (state.phase) {
                HighlightsUiState.Phase.Loading -> LoadingState(modifier = Modifier.fillMaxSize())

                HighlightsUiState.Phase.Error -> ErrorState(
                    message = state.errorMessage.orEmpty(),
                    onRetry = onRetry,
                    modifier = Modifier.fillMaxSize(),
                )

                HighlightsUiState.Phase.Content -> if (state.isEmpty) {
                    EmptyHighlights(isOwner = state.isOwner)
                } else {
                    HighlightsGrid(
                        groups = state.groups,
                        isOwner = state.isOwner,
                        onDeleteGroup = onDeleteGroup,
                        onAddStory = { group ->
                            pinTarget = group
                            onLoadPinCandidates()
                        },
                    )
                }
            }
        }
    }

    if (showCreate) {
        CreateGroupDialog(
            onDismiss = { showCreate = false },
            onConfirm = { title, cover ->
                onCreateGroup(title, cover)
                showCreate = false
            },
        )
    }

    pinTarget?.let { group ->
        PinStoryDialog(
            group = group,
            candidates = pinCandidates,
            onDismiss = { pinTarget = null },
            onPick = { storyId ->
                onPin(storyId, group.id)
                pinTarget = null
            },
        )
    }
}

@Composable
private fun EmptyHighlights(isOwner: Boolean) {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Text(
            text = stringResource(
                if (isOwner) R.string.highlights_empty_owner else R.string.highlights_empty_viewer,
            ),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(32.dp).testTag(HighlightsTestTags.EMPTY),
        )
    }
}

@Composable
private fun HighlightsGrid(
    groups: List<HighlightGroup>,
    isOwner: Boolean,
    onDeleteGroup: (String) -> Unit,
    onAddStory: (HighlightGroup) -> Unit,
) {
    LazyVerticalGrid(
        columns = GridCells.Fixed(3),
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 12.dp)
            .testTag(HighlightsTestTags.GRID),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(vertical = 12.dp),
    ) {
        items(groups, key = { it.id }) { group ->
            HighlightGroupCell(
                group = group,
                isOwner = isOwner,
                onDelete = { onDeleteGroup(group.id) },
                onAddStory = { onAddStory(group) },
            )
        }
    }
}

@Composable
private fun HighlightGroupCell(
    group: HighlightGroup,
    isOwner: Boolean,
    onDelete: () -> Unit,
    onAddStory: () -> Unit,
) {
    Column(
        modifier = Modifier.testTag(HighlightsTestTags.GROUP),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box(contentAlignment = Alignment.TopEnd) {
            AsyncImage(
                model = group.coverFallbackUrl,
                contentDescription = group.title,
                contentScale = ContentScale.Crop,
                modifier = Modifier
                    .aspectRatio(1f)
                    .clip(CircleShape)
                    .background(MaterialTheme.colorScheme.surfaceVariant)
                    .then(if (isOwner) Modifier.clickable { onAddStory() } else Modifier),
            )
            if (isOwner) {
                IconButton(
                    onClick = onDelete,
                    modifier = Modifier
                        .size(28.dp)
                        .testTag(HighlightsTestTags.DELETE_GROUP),
                ) {
                    Icon(
                        Icons.Filled.Delete,
                        contentDescription = stringResource(R.string.highlights_delete_group),
                        tint = MaterialTheme.colorScheme.error,
                        modifier = Modifier.size(18.dp),
                    )
                }
            }
        }
        Text(
            text = group.title,
            style = MaterialTheme.typography.labelMedium,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.padding(top = 6.dp),
        )
        Text(
            text = stringResource(R.string.highlights_story_count, group.storyCount),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun CreateGroupDialog(
    onDismiss: () -> Unit,
    onConfirm: (title: String, coverUrl: String?) -> Unit,
) {
    var title by remember { mutableStateOf("") }
    var cover by remember { mutableStateOf("") }
    AlertDialog(
        modifier = Modifier.testTag(HighlightsTestTags.CREATE_DIALOG),
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.highlights_new_group)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = title,
                    onValueChange = { title = it },
                    modifier = Modifier.fillMaxWidth().testTag(HighlightsTestTags.CREATE_TITLE),
                    label = { Text(stringResource(R.string.highlights_title_label)) },
                    singleLine = true,
                )
                OutlinedTextField(
                    value = cover,
                    onValueChange = { cover = it },
                    modifier = Modifier.fillMaxWidth().testTag(HighlightsTestTags.CREATE_COVER),
                    label = { Text(stringResource(R.string.highlights_cover_label)) },
                    singleLine = true,
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(title.trim(), cover.trim().ifBlank { null }) },
                enabled = title.isNotBlank(),
                modifier = Modifier.testTag(HighlightsTestTags.CREATE_CONFIRM),
            ) {
                Text(stringResource(R.string.highlights_create))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.highlights_cancel)) }
        },
    )
}

@Composable
private fun PinStoryDialog(
    group: HighlightGroup,
    candidates: List<StorySegment>,
    onDismiss: () -> Unit,
    onPick: (storyId: String) -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.highlights_add_to, group.title)) },
        text = {
            if (candidates.isEmpty()) {
                Text(stringResource(R.string.highlights_no_stories))
            } else {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    candidates.take(12).forEach { story ->
                        AsyncImage(
                            model = story.mediaUrl,
                            contentDescription = null,
                            contentScale = ContentScale.Crop,
                            modifier = Modifier
                                .size(56.dp)
                                .clip(RoundedCornerShape(8.dp))
                                .background(MaterialTheme.colorScheme.surfaceVariant)
                                .clickable { onPick(story.storyId) }
                                .testTag(HighlightsTestTags.PIN_STORY),
                        )
                    }
                }
            }
        },
        confirmButton = {},
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.highlights_cancel)) }
        },
    )
}
