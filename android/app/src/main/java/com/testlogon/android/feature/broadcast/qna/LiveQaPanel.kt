package com.testlogon.android.feature.broadcast.qna

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.toggleableState
import androidx.compose.ui.state.ToggleableState
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.repeatOnLifecycle
import androidx.compose.runtime.LaunchedEffect
import com.testlogon.android.R
import com.testlogon.android.data.broadcast.qna.QaQuestion

/** AND-284 — stable testTags for the Q&A panel. */
object LiveQaTestTags {
    const val LIST = "qa_list"
    const val COMPOSER = "qa_composer"
    const val SUBMIT = "qa_submit"
    const val FEATURED = "qa_featured"
    const val UPVOTE = "qa_upvote"
    const val RETRY = "qa_retry"
}

/**
 * AND-284 — the live Q&A panel composed into the AND-280 viewer. Drives bounded polling under
 * repeatOnLifecycle(STARTED). Renders a featured banner above an upvotable question list with an ask
 * composer; phase dispatch handles Loading / Content / Error / Disabled. The child VM is an
 * assisted-inject Hilt VM keyed by [sessionId].
 */
@Composable
fun LiveQaPanel(
    sessionId: String,
    modifier: Modifier = Modifier,
    viewModel: LiveQaViewModel = hiltViewModel<LiveQaViewModel, LiveQaViewModel.Factory>(
        key = "live_qa_$sessionId",
        creationCallback = { factory -> factory.create(sessionId) },
    ),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val lifecycleOwner = LocalLifecycleOwner.current

    LaunchedEffect(viewModel, lifecycleOwner) {
        lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
            viewModel.startPolling()
        }
    }

    Surface(modifier = modifier, tonalElevation = 1.dp) {
        Column(modifier = Modifier.fillMaxWidth().padding(8.dp)) {
            Text(stringResource(R.string.qa_title), style = MaterialTheme.typography.titleSmall)
            when (state.phase) {
                LiveQaUiState.Phase.Loading ->
                    QaMessage(stringResource(R.string.qa_loading))
                LiveQaUiState.Phase.Disabled ->
                    QaMessage(stringResource(R.string.qa_disabled))
                LiveQaUiState.Phase.Error ->
                    QaError(onRetry = { viewModel.refresh() })
                LiveQaUiState.Phase.Content -> QaContent(
                    state = state,
                    onUpvote = viewModel::toggleUpvote,
                    onComposerChange = viewModel::onComposerChange,
                    onSubmit = viewModel::submitQuestion,
                )
            }
        }
    }
}

@Composable
private fun QaContent(
    state: LiveQaUiState,
    onUpvote: (String) -> Unit,
    onComposerChange: (String) -> Unit,
    onSubmit: () -> Unit,
) {
    state.featured?.let { featured ->
        FeaturedQuestionBanner(
            question = featured,
            voted = featured.id in state.upvotedIds,
            onUpvote = { onUpvote(featured.id) },
        )
    }
    if (state.questions.isEmpty() && state.featured == null) {
        QaMessage(stringResource(R.string.qa_empty))
    } else {
        LazyColumn(
            modifier = Modifier.fillMaxWidth().heightIn(max = 280.dp).testTag(LiveQaTestTags.LIST),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            items(state.questions, key = { it.id }) { q ->
                QuestionRow(
                    question = q,
                    voted = q.id in state.upvotedIds,
                    onUpvote = { onUpvote(q.id) },
                )
            }
        }
    }
    AskComposer(
        text = state.composerText,
        canSubmit = state.canSubmit,
        onChange = onComposerChange,
        onSubmit = onSubmit,
    )
}

@Composable
private fun FeaturedQuestionBanner(question: QaQuestion, voted: Boolean, onUpvote: () -> Unit) {
    val featuredLabel = stringResource(R.string.qa_featured_label)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.primaryContainer)
            .padding(8.dp)
            .testTag(LiveQaTestTags.FEATURED)
            .semantics(mergeDescendants = true) { },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(featuredLabel, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary)
            Text(question.text, style = MaterialTheme.typography.bodyMedium)
            Text(question.authorDisplayName, style = MaterialTheme.typography.labelSmall)
        }
        UpvoteButton(count = question.upvotes, voted = voted, onClick = onUpvote)
    }
}

@Composable
private fun QuestionRow(question: QaQuestion, voted: Boolean, onUpvote: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(question.text, style = MaterialTheme.typography.bodyMedium)
            Text(question.authorDisplayName, style = MaterialTheme.typography.labelSmall)
        }
        UpvoteButton(count = question.upvotes, voted = voted, onClick = onUpvote)
    }
}

@Composable
private fun UpvoteButton(count: Int, voted: Boolean, onClick: () -> Unit) {
    val cd = stringResource(
        if (voted) R.string.qa_upvoted_cd else R.string.qa_upvote_cd,
        count,
    )
    Row(verticalAlignment = Alignment.CenterVertically) {
        IconButton(
            onClick = onClick,
            modifier = Modifier
                .testTag(LiveQaTestTags.UPVOTE)
                .semantics {
                    role = Role.Button
                    contentDescription = cd
                    toggleableState = if (voted) ToggleableState.On else ToggleableState.Off
                },
        ) {
            Icon(
                Icons.Filled.KeyboardArrowUp,
                contentDescription = null,
                tint = if (voted) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Text(count.toString(), style = MaterialTheme.typography.labelMedium)
    }
}

@Composable
private fun AskComposer(
    text: String,
    canSubmit: Boolean,
    onChange: (String) -> Unit,
    onSubmit: () -> Unit,
) {
    Column(modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
        OutlinedTextField(
            value = text,
            onValueChange = onChange,
            placeholder = { Text(stringResource(R.string.qa_ask_hint)) },
            modifier = Modifier.fillMaxWidth().testTag(LiveQaTestTags.COMPOSER),
        )
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = stringResource(R.string.qa_char_counter, text.length, LiveQaUiState.MAX_LEN),
                style = MaterialTheme.typography.labelSmall,
                color = if (text.length > LiveQaUiState.MAX_LEN) {
                    MaterialTheme.colorScheme.error
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                },
            )
            Button(
                onClick = onSubmit,
                enabled = canSubmit,
                modifier = Modifier.testTag(LiveQaTestTags.SUBMIT),
            ) {
                Text(stringResource(R.string.qa_ask_submit))
            }
        }
    }
}

@Composable
private fun QaMessage(message: String) {
    Box(modifier = Modifier.fillMaxWidth().padding(16.dp), contentAlignment = Alignment.Center) {
        Text(message, style = MaterialTheme.typography.bodyMedium, textAlign = TextAlign.Center)
    }
}

@Composable
private fun QaError(onRetry: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxWidth().padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(stringResource(R.string.qa_error_generic), style = MaterialTheme.typography.bodyMedium)
        TextButton(onClick = onRetry, modifier = Modifier.testTag(LiveQaTestTags.RETRY)) {
            Text(stringResource(R.string.qa_retry))
        }
    }
}
