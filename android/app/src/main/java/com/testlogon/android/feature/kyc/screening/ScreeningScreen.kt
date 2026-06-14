@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.kyc.screening

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.HelpOutline
import androidx.compose.material.icons.filled.HourglassEmpty
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.feature.kyc.screening.model.KycScreenResult
import com.testlogon.android.feature.kyc.screening.model.KycScreenType
import com.testlogon.android.feature.kyc.screening.model.KycScreeningResult
import com.testlogon.android.feature.kyc.screening.model.ScreeningStatus
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import java.util.Locale

/** AND-328 - stable testTags for the screening status screen. */
object ScreeningTestTags {
    const val SCREEN = "screening_screen"
    const val STATUS = "screening_status"
    const val STALE = "screening_stale"
    const val RETRY = "screening_retry"

    /** Per-screen breakdown row tag, suffixed by the screen-type enum name (lowercased). */
    fun result(screenType: KycScreenType): String = "screening_result_${screenType.name.lowercase()}"
}

/**
 * AND-328 - route-level READ-ONLY screening status screen. Sources its state from the VM and forwards only
 * [onBack] (there are no writes / actions besides retry + pull-to-refresh).
 */
@Composable
fun ScreeningRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: ScreeningViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    ScreeningScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        modifier = modifier,
    )
}

@Composable
fun ScreeningScreen(
    state: ScreeningUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(ScreeningTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.screening_title)) },
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
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is ScreeningUiState.Loading ->
                    CircularProgressIndicator(Modifier.align(Alignment.Center))

                is ScreeningUiState.Content -> ContentBody(
                    state = state,
                    onRefresh = onRefresh,
                    onRetry = onRetry,
                )

                is ScreeningUiState.Error -> ErrorBody(
                    message = state.message,
                    retryable = state.retryable,
                    onRetry = onRetry,
                )
            }
        }
    }
}

@Composable
private fun ContentBody(
    state: ScreeningUiState.Content,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
) {
    PullToRefreshBox(
        isRefreshing = state.refreshing,
        onRefresh = onRefresh,
        modifier = Modifier.fillMaxSize(),
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            if (state.isStale) {
                StaleBanner(lastUpdated = state.lastUpdated, onRetry = onRetry)
            }

            StatusCard(state.status)

            if (state.results.isNotEmpty()) {
                HorizontalDivider()
                Text(
                    text = stringResource(R.string.screening_breakdown_heading),
                    style = MaterialTheme.typography.titleSmall,
                )
                state.results.forEach { ScreenResultRow(it) }
            }
        }
    }
}

@Composable
private fun StatusCard(status: ScreeningStatus) {
    val style = statusStyle(status)
    val label = stringResource(style.labelRes)
    Card(modifier = Modifier.fillMaxWidth().testTag(ScreeningTestTags.STATUS)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                // Status is conveyed by icon + text, never colour alone.
                Icon(
                    imageVector = style.icon,
                    contentDescription = null,
                    tint = style.tint(),
                    modifier = Modifier.size(28.dp),
                )
                Text(
                    text = label,
                    style = MaterialTheme.typography.titleLarge,
                    modifier = Modifier.padding(start = 8.dp),
                )
            }
            Text(
                text = stringResource(style.descriptionRes),
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(
                text = stringResource(style.guidanceRes),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun ScreenResultRow(item: KycScreeningResult) {
    val typeLabel = stringResource(screenTypeLabel(item.screenType))
    val resultLabel = stringResource(resultLabel(item.result))
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .testTag(ScreeningTestTags.result(item.screenType)),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(text = typeLabel, style = MaterialTheme.typography.bodyLarge)
        AssistChip(
            onClick = {},
            enabled = false,
            label = { Text(resultLabel) },
            colors = AssistChipDefaults.assistChipColors(),
            modifier = Modifier.clearAndSetSemantics {
                contentDescription = "$typeLabel: $resultLabel"
            },
        )
    }
}

@Composable
private fun StaleBanner(lastUpdated: Instant?, onRetry: () -> Unit) {
    val text = if (lastUpdated != null) {
        stringResource(R.string.screening_stale_with_time, formatTime(lastUpdated))
    } else {
        stringResource(R.string.screening_stale)
    }
    Card(modifier = Modifier.fillMaxWidth().testTag(ScreeningTestTags.STALE)) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Filled.Warning,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp),
                )
                Text(
                    text = text,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(start = 8.dp),
                )
            }
            Button(
                onClick = onRetry,
                modifier = Modifier.heightIn(min = 48.dp).testTag(ScreeningTestTags.RETRY),
            ) {
                Text(stringResource(R.string.screening_retry))
            }
        }
    }
}

@Composable
private fun ErrorBody(message: String, retryable: Boolean, onRetry: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(text = message, style = MaterialTheme.typography.bodyLarge)
        if (retryable) {
            Button(
                onClick = onRetry,
                modifier = Modifier.heightIn(min = 48.dp).testTag(ScreeningTestTags.RETRY),
            ) {
                Text(stringResource(R.string.screening_retry))
            }
        }
    }
}

/** Visual style (icon + tint + copy) for an aggregated [ScreeningStatus]. Colour never carries meaning alone. */
private data class StatusStyle(
    val icon: ImageVector,
    val labelRes: Int,
    val descriptionRes: Int,
    val guidanceRes: Int,
    val tint: @Composable () -> Color,
)

private fun statusStyle(status: ScreeningStatus): StatusStyle = when (status) {
    ScreeningStatus.CLEAR -> StatusStyle(
        icon = Icons.Filled.CheckCircle,
        labelRes = R.string.screening_status_clear,
        descriptionRes = R.string.screening_desc_clear,
        guidanceRes = R.string.screening_guidance_clear,
        tint = { MaterialTheme.colorScheme.primary },
    )
    ScreeningStatus.REVIEW -> StatusStyle(
        icon = Icons.Filled.HourglassEmpty,
        labelRes = R.string.screening_status_review,
        descriptionRes = R.string.screening_desc_review,
        guidanceRes = R.string.screening_guidance_review,
        tint = { MaterialTheme.colorScheme.tertiary },
    )
    ScreeningStatus.HIT -> StatusStyle(
        icon = Icons.Filled.Error,
        labelRes = R.string.screening_status_hit,
        descriptionRes = R.string.screening_desc_hit,
        guidanceRes = R.string.screening_guidance_hit,
        tint = { MaterialTheme.colorScheme.error },
    )
    ScreeningStatus.NOT_STARTED -> StatusStyle(
        icon = Icons.Filled.HelpOutline,
        labelRes = R.string.screening_status_not_started,
        descriptionRes = R.string.screening_desc_not_started,
        guidanceRes = R.string.screening_guidance_not_started,
        tint = { MaterialTheme.colorScheme.onSurfaceVariant },
    )
    ScreeningStatus.UNKNOWN -> StatusStyle(
        icon = Icons.Filled.HelpOutline,
        labelRes = R.string.screening_status_unknown,
        descriptionRes = R.string.screening_desc_unknown,
        guidanceRes = R.string.screening_guidance_unknown,
        tint = { MaterialTheme.colorScheme.onSurfaceVariant },
    )
}

private fun screenTypeLabel(type: KycScreenType): Int = when (type) {
    KycScreenType.SANCTIONS_OFAC -> R.string.screening_type_sanctions_ofac
    KycScreenType.SANCTIONS_EU -> R.string.screening_type_sanctions_eu
    KycScreenType.SANCTIONS_UN -> R.string.screening_type_sanctions_un
    KycScreenType.PEP_CHECK -> R.string.screening_type_pep_check
    KycScreenType.ADVERSE_MEDIA -> R.string.screening_type_adverse_media
    KycScreenType.UNKNOWN -> R.string.screening_type_unknown
}

private fun resultLabel(result: KycScreenResult): Int = when (result) {
    KycScreenResult.CLEAR -> R.string.screening_result_clear
    KycScreenResult.POTENTIAL_MATCH -> R.string.screening_result_potential
    KycScreenResult.CONFIRMED_MATCH -> R.string.screening_result_confirmed
    KycScreenResult.UNKNOWN -> R.string.screening_result_unknown
}

/** Locale-aware short date+time for the stale banner. */
@Composable
private fun formatTime(instant: Instant): String {
    val locale = currentLocale()
    val fmt = DateTimeFormatter
        .ofLocalizedDateTime(FormatStyle.SHORT)
        .withLocale(locale)
        .withZone(ZoneId.systemDefault())
    return fmt.format(instant)
}

@Composable
private fun currentLocale(): Locale {
    val config = LocalConfiguration.current
    return if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N) {
        config.locales[0]
    } else {
        @Suppress("DEPRECATION")
        config.locale
    }
}
