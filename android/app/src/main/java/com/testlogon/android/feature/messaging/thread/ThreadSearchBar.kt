package com.testlogon.android.feature.messaging.thread

import android.text.format.DateUtils
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import com.testlogon.android.data.messaging.MessageSearchMatch

/** AND-151 — stable testTags for the in-conversation search affordance. */
object ThreadSearchTestTags {
    const val OPEN = "thread_search_open"
    const val BAR = "thread_search_bar"
    const val INPUT = "thread_search_input"
    const val CLOSE = "thread_search_close"
    const val CLEAR = "thread_search_clear"
    const val NEXT = "thread_search_next"
    const val PREV = "thread_search_prev"
    const val STATUS = "thread_search_status"
    const val RESULTS = "thread_search_results"
    const val RESULT_ROW = "thread_search_result_row"
}

/**
 * #16/#17 — the in-conversation search surface shown when search is active. It replaces the app bar
 * with a CLEAR search affordance: a back arrow, a rounded pill search field (leading magnifier,
 * trailing clear), an "M of N" counter + prev/next, AND a results list that FILTERS the conversation
 * to just the matching messages. Each result row shows a snippet + its date/time; tapping a row jumps
 * the thread to that message (via [onPickMatch]).
 */
@Composable
fun ThreadSearchBar(
    state: ThreadSearchUiState,
    onQueryChange: (String) -> Unit,
    onClose: () -> Unit,
    onNext: () -> Unit,
    onPrev: () -> Unit,
    modifier: Modifier = Modifier,
    onPickMatch: (MessageSearchMatch) -> Unit = {},
) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        color = MaterialTheme.colorScheme.surface,
        tonalElevation = 3.dp,
        shadowElevation = 3.dp,
    ) {
        Column(modifier = Modifier.fillMaxWidth().testTag(ThreadSearchTestTags.BAR)) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(2.dp),
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
                    leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                    trailingIcon = {
                        if (state.query.isNotEmpty()) {
                            IconButton(
                                onClick = { onQueryChange("") },
                                modifier = Modifier.testTag(ThreadSearchTestTags.CLEAR),
                            ) {
                                Icon(
                                    Icons.Filled.Close,
                                    contentDescription = stringResource(R.string.search_close),
                                )
                            }
                        }
                    },
                    shape = RoundedCornerShape(28.dp),
                    colors = TextFieldDefaults.colors(
                        focusedContainerColor = MaterialTheme.colorScheme.surfaceVariant,
                        unfocusedContainerColor = MaterialTheme.colorScheme.surfaceVariant,
                        focusedIndicatorColor = Color.Transparent,
                        unfocusedIndicatorColor = Color.Transparent,
                        disabledIndicatorColor = Color.Transparent,
                    ),
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

            // #17 — filtered results list (one row per matching message, oldest->newest). Tap to jump.
            if (state.hasMatches) {
                HorizontalDivider()
                // De-duplicate to one row per message (a message can match more than once).
                val rows = remember(state.matches) { state.matches.distinctBy { it.messageId } }
                LazyColumn(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 280.dp)
                        .testTag(ThreadSearchTestTags.RESULTS),
                ) {
                    items(rows, key = { it.messageId }) { match ->
                        val isActive = state.activeMatch?.messageId == match.messageId
                        SearchResultRow(
                            match = match,
                            isActive = isActive,
                            onClick = { onPickMatch(match) },
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun SearchResultRow(
    match: MessageSearchMatch,
    isActive: Boolean,
    onClick: () -> Unit,
) {
    val bg = if (isActive) MaterialTheme.colorScheme.secondaryContainer else Color.Transparent
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(bg)
            .clickable(onClick = onClick)
            .testTag(ThreadSearchTestTags.RESULT_ROW)
            .padding(horizontal = 16.dp, vertical = 10.dp),
    ) {
        val snippet = match.text.ifBlank { stringResource(R.string.search_result_no_text) }
        Text(
            text = snippet,
            style = MaterialTheme.typography.bodyMedium,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
        )
        val context = androidx.compose.ui.platform.LocalContext.current
        Text(
            text = formatMatchDateTime(context, match.createdAtEpochSeconds),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 2.dp),
        )
    }
}

/**
 * #17 — absolute date + time for a match row (e.g. "Jun 24, 10:13 AM"). A real [context] is REQUIRED:
 * DateUtils.formatDateTime -> DateFormat.is24HourFormat NPEs on a null context (crashed on-device).
 */
private fun formatMatchDateTime(context: android.content.Context, epochSeconds: Long): String {
    if (epochSeconds <= 0L) return ""
    val ms = epochSeconds * 1000L
    return DateUtils.formatDateTime(
        context,
        ms,
        DateUtils.FORMAT_SHOW_DATE or DateUtils.FORMAT_ABBREV_ALL or DateUtils.FORMAT_SHOW_TIME,
    )
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
            fontWeight = FontWeight.Medium,
            modifier = Modifier
                .padding(horizontal = 4.dp)
                .semantics { liveRegion = LiveRegionMode.Polite }
                .testTag(ThreadSearchTestTags.STATUS),
        )
    }
}
