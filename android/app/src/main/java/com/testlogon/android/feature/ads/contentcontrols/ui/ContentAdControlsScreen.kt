@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.ads.contentcontrols.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.text.KeyboardOptions
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.model.ads.AdDensity
import com.testlogon.android.core.model.ads.AdRevenueBreakdown
import com.testlogon.android.core.model.ads.AdvertiserTransparency
import com.testlogon.android.core.model.ads.ContentAdOverride
import com.testlogon.android.core.model.syndicates.formatCents
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** Stable testTags for the content ad-controls screen. */
object ContentAdControlsTestTags {
    const val SCREEN = "content_ad_controls_screen"
    const val CONTENT = "content_ad_controls_content"
    const val ERROR_RETRY = "content_ad_controls_error_retry"
    const val OVERRIDE_CONTENT_ID = "content_ad_controls_override_content_id"
    const val OVERRIDE_SAVE = "content_ad_controls_override_save"
    const val OVERRIDES_EMPTY = "content_ad_controls_overrides_empty"
    const val SHARE_INPUT = "content_ad_controls_share_input"
    const val SHARE_SAVE = "content_ad_controls_share_save"
    const val SHARE_CURRENT = "content_ad_controls_share_current"
    const val BREAKDOWN_TOTAL = "content_ad_controls_breakdown_total"
}

private val DENSITIES = listOf(AdDensity.LOW, AdDensity.STANDARD, AdDensity.HIGH)
private val PERIODS = listOf(7, 30, 90, 365)

@Composable
fun ContentAdControlsRoute(
    onBack: () -> Unit,
    viewModel: ContentAdControlsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    ContentAdControlsScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onUpdateForm = viewModel::updateForm,
        onSaveOverride = viewModel::saveOverride,
        onDeleteOverride = viewModel::deleteOverride,
        onShareInputChanged = viewModel::onShareInputChanged,
        onSaveShare = viewModel::saveRevenueShare,
        onSelectDays = viewModel::selectBreakdownDays,
    )
}

@Composable
fun ContentAdControlsScreen(
    state: ContentAdControlsUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onUpdateForm: ((OverrideForm) -> OverrideForm) -> Unit,
    onSaveOverride: () -> Unit,
    onDeleteOverride: (String) -> Unit,
    onShareInputChanged: (String) -> Unit,
    onSaveShare: () -> Unit,
    onSelectDays: (Int) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(ContentAdControlsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Content ad controls") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is ContentAdControlsUiState.Loading -> LoadingState()
                is ContentAdControlsUiState.Error -> ErrorState(
                    message = state.error.message,
                    onRetry = onRetry,
                    modifier = Modifier.testTag(ContentAdControlsTestTags.ERROR_RETRY),
                )
                is ContentAdControlsUiState.Content -> ContentBody(
                    state = state,
                    onUpdateForm = onUpdateForm,
                    onSaveOverride = onSaveOverride,
                    onDeleteOverride = onDeleteOverride,
                    onShareInputChanged = onShareInputChanged,
                    onSaveShare = onSaveShare,
                    onSelectDays = onSelectDays,
                )
            }
        }
    }
}

@Composable
private fun ContentBody(
    state: ContentAdControlsUiState.Content,
    onUpdateForm: ((OverrideForm) -> OverrideForm) -> Unit,
    onSaveOverride: () -> Unit,
    onDeleteOverride: (String) -> Unit,
    onShareInputChanged: (String) -> Unit,
    onSaveShare: () -> Unit,
    onSelectDays: (Int) -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
            .testTag(ContentAdControlsTestTags.CONTENT),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            text = "Override your global ad settings for specific content, manage your revenue share, and review your ad earnings.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        OverrideEditorCard(state, onUpdateForm, onSaveOverride)
        ActiveOverridesCard(state, onDeleteOverride)
        RevenueShareCard(state, onShareInputChanged, onSaveShare)
        BreakdownCard(state, onSelectDays)
    }
}

@Composable
private fun OverrideEditorCard(
    state: ContentAdControlsUiState.Content,
    onUpdateForm: ((OverrideForm) -> OverrideForm) -> Unit,
    onSaveOverride: () -> Unit,
) {
    val form = state.form
    SectionCard(title = "Per-content override") {
        OutlinedTextField(
            value = form.contentId,
            onValueChange = { v -> onUpdateForm { it.copy(contentId = v) } },
            label = { Text("Content ID (video)") },
            placeholder = { Text("vid_...") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth().testTag(ContentAdControlsTestTags.OVERRIDE_CONTENT_ID),
        )

        ToggleRow("Ads enabled on this content", form.adEnabled) { v -> onUpdateForm { it.copy(adEnabled = v) } }

        Text("Ad density", style = MaterialTheme.typography.titleSmall)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            DENSITIES.forEach { d ->
                FilterChip(
                    selected = form.adDensity == d,
                    onClick = { onUpdateForm { it.copy(adDensity = d) } },
                    label = { Text(d.wire.replaceFirstChar { c -> c.uppercase() }) },
                )
            }
        }

        ToggleRow("Pre-roll enabled", form.preRollEnabled) { v -> onUpdateForm { it.copy(preRollEnabled = v) } }
        ToggleRow("Mid-roll enabled", form.midRollEnabled) { v -> onUpdateForm { it.copy(midRollEnabled = v) } }
        ToggleRow("Ad-free for subscribers", form.adsFreeForSubscribers) { v -> onUpdateForm { it.copy(adsFreeForSubscribers = v) } }

        if (state.saveError != null) {
            Text(state.saveError, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
        }
        if (state.saved) {
            Text("Override saved.", color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.bodyMedium)
        }

        Button(
            onClick = onSaveOverride,
            enabled = form.canSave && !state.saving,
            modifier = Modifier.fillMaxWidth().testTag(ContentAdControlsTestTags.OVERRIDE_SAVE),
        ) {
            if (state.saving) {
                CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(18.dp))
            } else {
                Text("Save override")
            }
        }
    }
}

@Composable
private fun ActiveOverridesCard(
    state: ContentAdControlsUiState.Content,
    onDeleteOverride: (String) -> Unit,
) {
    SectionCard(title = "Active overrides") {
        if (state.overrides.isEmpty()) {
            Text(
                "No per-content overrides yet.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.testTag(ContentAdControlsTestTags.OVERRIDES_EMPTY),
            )
        } else {
            state.overrides.forEach { o ->
                OverrideRow(o, deleting = state.deletingContentId == o.contentId, onDelete = { onDeleteOverride(o.contentId) })
            }
        }
    }
}

@Composable
private fun OverrideRow(override: ContentAdOverride, deleting: Boolean, onDelete: () -> Unit) {
    Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                override.contentId,
                style = MaterialTheme.typography.bodyMedium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                AssistChip(onClick = {}, label = { Text(if (override.adEnabled) "Ads on" else "Ads off") })
                AssistChip(onClick = {}, label = { Text(override.adDensity.wire) })
            }
        }
        if (deleting) {
            CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(18.dp))
        } else {
            IconButton(onClick = onDelete) {
                Icon(Icons.Filled.Delete, contentDescription = "Delete override")
            }
        }
    }
    HorizontalDivider()
}

@Composable
private fun RevenueShareCard(
    state: ContentAdControlsUiState.Content,
    onShareInputChanged: (String) -> Unit,
    onSaveShare: () -> Unit,
) {
    SectionCard(title = "Revenue share") {
        Text(
            text = "Current creator share: ${state.revenueShareBps / 100}%",
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier.testTag(ContentAdControlsTestTags.SHARE_CURRENT),
        )
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
                value = state.shareInput,
                onValueChange = onShareInputChanged,
                label = { Text("New share (%)") },
                placeholder = { Text("70") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.weight(1f).testTag(ContentAdControlsTestTags.SHARE_INPUT),
            )
            Button(
                onClick = onSaveShare,
                enabled = !state.savingShare,
                modifier = Modifier.testTag(ContentAdControlsTestTags.SHARE_SAVE),
            ) {
                if (state.savingShare) {
                    CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(18.dp))
                } else {
                    Text("Update")
                }
            }
        }
        if (state.shareError != null) {
            Text(state.shareError, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun BreakdownCard(
    state: ContentAdControlsUiState.Content,
    onSelectDays: (Int) -> Unit,
) {
    SectionCard(title = "Ad revenue breakdown") {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            PERIODS.forEach { p ->
                if (p == state.breakdownDays) {
                    Button(onClick = { onSelectDays(p) }) { Text("${p}d") }
                } else {
                    OutlinedButton(onClick = { onSelectDays(p) }) { Text("${p}d") }
                }
            }
        }

        if (state.breakdownLoading) {
            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
        }

        val breakdown = state.breakdown
        if (breakdown != null) {
            Text(
                text = formatCents(breakdown.totalAdRevenueCents),
                style = MaterialTheme.typography.headlineMedium,
                modifier = Modifier.testTag(ContentAdControlsTestTags.BREAKDOWN_TOTAL),
            )
            Text(
                text = "over ${breakdown.days} days, ${breakdown.entryCount} events. Your share: ${breakdown.revenueShareBps / 100}%",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            TopContent(breakdown)
        }

        if (state.advertisers.isNotEmpty()) {
            Text("Advertisers on your content", style = MaterialTheme.typography.titleSmall)
            state.advertisers.forEach { AdvertiserRow(it) }
        }
    }
}

@Composable
private fun TopContent(breakdown: AdRevenueBreakdown) {
    Text("Top earning content", style = MaterialTheme.typography.titleSmall)
    if (breakdown.topContent.isEmpty()) {
        Text(
            "No ad revenue yet.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        return
    }
    val max = breakdown.topContent.maxOf { it.revenueCents }.coerceAtLeast(1L)
    breakdown.topContent.forEach { c ->
        Column(modifier = Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(c.contentId, style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
                Text(formatCents(c.revenueCents), style = MaterialTheme.typography.bodySmall)
            }
            LinearProgressIndicator(
                progress = { (c.revenueCents.toFloat() / max.toFloat()).coerceIn(0f, 1f) },
                modifier = Modifier.fillMaxWidth().height(6.dp),
            )
        }
    }
}

@Composable
private fun AdvertiserRow(advertiser: AdvertiserTransparency) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(advertiser.companyName, style = MaterialTheme.typography.bodyMedium)
        Text(
            "${advertiser.totalImpressions} imp - ${formatCents(advertiser.totalRevenueCents)}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun ToggleRow(label: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, style = MaterialTheme.typography.bodyLarge)
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

@Composable
private fun SectionCard(title: String, content: @Composable () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(12.dp)) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            content()
        }
    }
}
