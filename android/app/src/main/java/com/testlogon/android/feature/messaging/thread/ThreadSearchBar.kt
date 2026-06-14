package com.testlogon.android.feature.messaging.thread

import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import com.testlogon.android.R

/** AND-151 — stable testTags for the in-conversation search affordance. */
object ThreadSearchTestTags {
    const val OPEN = "thread_search_open"
    const val BAR = "thread_search_bar"
    const val INPUT = "thread_search_input"
    const val CLOSE = "thread_search_close"
    const val NEXT = "thread_search_next"
    const val PREV = "thread_search_prev"
    const val STATUS = "thread_search_status"
}

/**
 * AND-151 — the app-bar search input shown when in-conversation search is active. Renders the query
 * field, a live-region status ("M of N" / "0 results" / loading / too-short hint / error), and
 * prev/next match navigation that wraps. The IME "search" action advances to the next match.
 */
@Composable
fun ThreadSearchBar(
    state: ThreadSearchUiState,
    onQueryChange: (String) -> Unit,
    onClose: () -> Unit,
    onNext: () -> Unit,
    onPrev: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Surface(modifier = modifier.fillMaxWidth(), color = MaterialTheme.colorScheme.surface) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp).testTag(ThreadSearchTestTags.BAR),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(onClick = onClose, modifier = Modifier.testTag(ThreadSearchTestTags.CLOSE)) {
                Icon(
                    Icons.AutoMirrored.Filled.ArrowBack,
                    contentDescription = stringResource(R.string.search_close),
                )
            }
            TextField(
                value = state.query,
                onValueChange = onQueryChange,
                singleLine = true,
                modifier = Modifier.weight(1f).testTag(ThreadSearchTestTags.INPUT),
                placeholder = { Text(stringResource(R.string.search_in_conversation)) },
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                keyboardActions = KeyboardActions(onSearch = { onNext() }),
            )
            StatusLabel(state)
            IconButton(
                onClick = onPrev,
                enabled = state.hasMatches,
                modifier = Modifier.testTag(ThreadSearchTestTags.PREV),
            ) {
                Icon(
                    Icons.Filled.KeyboardArrowUp,
                    contentDescription = stringResource(R.string.search_prev_match),
                )
            }
            IconButton(
                onClick = onNext,
                enabled = state.hasMatches,
                modifier = Modifier.testTag(ThreadSearchTestTags.NEXT),
            ) {
                Icon(
                    Icons.Filled.KeyboardArrowDown,
                    contentDescription = stringResource(R.string.search_next_match),
                )
            }
        }
    }
}

@Composable
private fun StatusLabel(state: ThreadSearchUiState) {
    if (state.phase is SearchPhase.Loading) {
        CircularProgressIndicator(modifier = Modifier.size(20.dp).padding(end = 4.dp), strokeWidth = 2.dp)
        return
    }
    val text = when {
        state.tooShort -> stringResource(R.string.search_min_chars)
        state.phase is SearchPhase.Error -> stringResource(R.string.search_error_short)
        state.query.trim().length < ThreadSearchController.MIN_QUERY_LENGTH -> ""
        state.matches.isEmpty() -> stringResource(R.string.search_no_results)
        else -> stringResource(R.string.search_match_cursor, state.activeIndex + 1, state.total)
    }
    if (text.isNotEmpty()) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelMedium,
            modifier = Modifier
                .padding(horizontal = 4.dp)
                .semantics { liveRegion = LiveRegionMode.Polite }
                .testTag(ThreadSearchTestTags.STATUS),
        )
    }
}
