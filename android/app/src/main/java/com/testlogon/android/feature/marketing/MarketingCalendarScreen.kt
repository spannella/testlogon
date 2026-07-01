@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.marketing

import androidx.compose.foundation.clickable
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
import androidx.compose.material.icons.outlined.CalendarMonth
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.marketing.CalendarEntry

object MarketingCalendarTestTags {
    const val SCREEN = "marketing_calendar_screen"
    const val LIST = "marketing_calendar_list"
    const val LOADING = "marketing_calendar_loading"
    const val EMPTY = "marketing_calendar_empty"
    const val ERROR = "marketing_calendar_error"
    const val OFFLINE = "marketing_calendar_offline"
    const val SESSION_EXPIRED = "marketing_calendar_session_expired"
    const val PREV = "marketing_calendar_prev"
    const val NEXT = "marketing_calendar_next"
    const val TODAY = "marketing_calendar_today"
    const val MONTH = "marketing_calendar_month"
    const val ENTRY_PREFIX = "marketing_calendar_entry_"
}

@Composable
fun MarketingCalendarRoute(
    onBack: () -> Unit,
    onSessionExpired: () -> Unit,
    onOpenContent: (String) -> Unit,
    modifier: Modifier = Modifier,
    viewModel: MarketingCalendarViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    androidx.compose.runtime.LaunchedEffect(state.phase) {
        if (state.phase == MarketingCalendarUiState.Phase.SessionExpired) onSessionExpired()
    }
    MarketingCalendarScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onPrev = viewModel::onPrevMonth,
        onNext = viewModel::onNextMonth,
        onToday = viewModel::onToday,
        onOpenContent = onOpenContent,
        modifier = modifier,
    )
}

@Composable
fun MarketingCalendarScreen(
    state: MarketingCalendarUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onPrev: () -> Unit,
    onNext: () -> Unit,
    onToday: () -> Unit,
    onOpenContent: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(MarketingCalendarTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.marketing_calendar_title)) },
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
        Column(modifier = Modifier.padding(padding).fillMaxSize()) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(16.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                OutlinedButton(onClick = onPrev, modifier = Modifier.testTag(MarketingCalendarTestTags.PREV)) {
                    Text(stringResource(R.string.marketing_prev))
                }
                Text(
                    text = state.month,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.weight(1f).testTag(MarketingCalendarTestTags.MONTH),
                )
                OutlinedButton(onClick = onNext, modifier = Modifier.testTag(MarketingCalendarTestTags.NEXT)) {
                    Text(stringResource(R.string.marketing_next))
                }
                TextButton(onClick = onToday, modifier = Modifier.testTag(MarketingCalendarTestTags.TODAY)) {
                    Text(stringResource(R.string.marketing_today))
                }
            }
            Box(modifier = Modifier.fillMaxSize()) {
                when (state.phase) {
                    MarketingCalendarUiState.Phase.Loading ->
                        LoadingState(modifier = Modifier.testTag(MarketingCalendarTestTags.LOADING))
                    MarketingCalendarUiState.Phase.Error ->
                        ErrorState(
                            message = state.errorMessage ?: stringResource(R.string.marketing_error_generic),
                            onRetry = onRetry,
                            modifier = Modifier.testTag(MarketingCalendarTestTags.ERROR),
                        )
                    MarketingCalendarUiState.Phase.Offline ->
                        ErrorState(
                            message = state.errorMessage ?: stringResource(R.string.marketing_error_generic),
                            onRetry = onRetry,
                            modifier = Modifier.testTag(MarketingCalendarTestTags.OFFLINE),
                        )
                    MarketingCalendarUiState.Phase.SessionExpired ->
                        EmptyState(
                            title = stringResource(R.string.marketing_session_expired_title),
                            body = stringResource(R.string.marketing_session_expired_body),
                            modifier = Modifier.testTag(MarketingCalendarTestTags.SESSION_EXPIRED),
                        )
                    MarketingCalendarUiState.Phase.Empty ->
                        EmptyState(
                            title = stringResource(R.string.marketing_calendar_empty_title),
                            body = stringResource(R.string.marketing_calendar_empty_body),
                            imageVector = Icons.Outlined.CalendarMonth,
                            modifier = Modifier.testTag(MarketingCalendarTestTags.EMPTY),
                        )
                    MarketingCalendarUiState.Phase.Content ->
                        LazyColumn(
                            modifier = Modifier.testTag(MarketingCalendarTestTags.LIST).fillMaxSize(),
                            contentPadding = PaddingValues(16.dp),
                            verticalArrangement = Arrangement.spacedBy(10.dp),
                        ) {
                            items(state.entries, key = { it.contentId }) { entry ->
                                CalendarEntryRow(entry = entry, onClick = { onOpenContent(entry.contentId) })
                            }
                        }
                }
            }
        }
    }
}

@Composable
private fun CalendarEntryRow(entry: CalendarEntry, onClick: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(MarketingCalendarTestTags.ENTRY_PREFIX + entry.contentId)
            .clickable(onClick = onClick),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(12.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = entry.formattedDate(),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = entry.title,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Medium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f),
            )
            LabelChip(entry.status.name.lowercase())
        }
    }
}
