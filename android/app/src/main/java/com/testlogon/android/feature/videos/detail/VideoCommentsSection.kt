package com.testlogon.android.feature.videos.detail

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
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

/** AND — comments surface for the video detail screen (GET/POST/DELETE /ui/videos/{id}/comments). */
@HiltViewModel
class VideoCommentsViewModel @Inject constructor(
    private val repository: VideoCommentsRepository,
    private val displayNames: DisplayNameResolver,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val videoId: String = checkNotNull(savedStateHandle[VideoDetailViewModel.ARG_VIDEO_ID])

    data class State(
        val comments: List<VideoComment> = emptyList(),
        val draft: String = "",
        val sending: Boolean = false,
        val loading: Boolean = true,
    )

    private val _state = MutableStateFlow(State())
    val state: StateFlow<State> = _state.asStateFlow()
    val authorNames: StateFlow<Map<String, String>> = displayNames.names

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
    fun resolveAuthor(id: String) { displayNames.resolve(id) }

    fun send() {
        val text = _state.value.draft.trim()
        if (text.isEmpty() || _state.value.sending) return
        _state.update { it.copy(sending = true, draft = "") }
        viewModelScope.launch {
            val r = repository.add(videoId, text)
            _state.update { it.copy(sending = false) }
            if (r is ApiResult.Success) load()
        }
    }

    fun delete(comment: VideoComment) {
        viewModelScope.launch {
            if (repository.delete(videoId, comment.id) is ApiResult.Success) load()
        }
    }
}

@Composable
fun VideoCommentsSection(
    modifier: Modifier = Modifier,
    viewModel: VideoCommentsViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val names by viewModel.authorNames.collectAsStateWithLifecycle()

    Column(modifier = modifier.fillMaxWidth().testTag("video_comments_section")) {
        HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
        Text(
            text = "Comments",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.padding(vertical = 4.dp),
        )
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
            else -> state.comments.forEach { c ->
                LaunchedEffect(c.authorId) { viewModel.resolveAuthor(c.authorId) }
                Row(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp)
                        .testTag("video_comment_row"),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(Modifier.weight(1f)) {
                        Text(
                            text = names[c.authorId]?.takeIf { it.isNotBlank() }
                                ?: c.authorId.ifBlank { "You" },
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.SemiBold,
                        )
                        Text(text = c.text, style = MaterialTheme.typography.bodyMedium)
                    }
                    if (c.canDelete) {
                        IconButton(
                            onClick = { viewModel.delete(c) },
                            modifier = Modifier.size(44.dp).testTag("video_comment_delete"),
                        ) {
                            Icon(
                                Icons.Outlined.Delete,
                                contentDescription = "Delete comment",
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
        }
        Row(
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            OutlinedTextField(
                value = state.draft,
                onValueChange = viewModel::onDraft,
                modifier = Modifier.weight(1f).testTag("video_comment_input"),
                placeholder = { Text("Add a comment…") },
                maxLines = 4,
            )
            IconButton(
                onClick = viewModel::send,
                enabled = state.draft.isNotBlank() && !state.sending,
                modifier = Modifier.size(48.dp).testTag("video_comment_send"),
            ) {
                Icon(
                    Icons.AutoMirrored.Filled.Send,
                    contentDescription = "Post comment",
                    tint = if (state.draft.isNotBlank()) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}
