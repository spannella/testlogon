@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.ads.targeting.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.feature.ads.studio.ui.StudioCampaignPicker

/** Stable testTags for the ad targeting editor. */
object AdTargetingTestTags {
    const val SCREEN = "ad_targeting_screen"
    const val FORM = "ad_targeting_form"
    const val EMPTY = "ad_targeting_empty"
    const val ERROR_RETRY = "ad_targeting_error_retry"
    const val NAME = "ad_targeting_name"
    const val COUNTRIES = "ad_targeting_countries"
    const val SAVE = "ad_targeting_save"
    const val ESTIMATE = "ad_targeting_estimate"
}

private val AGE_RANGES = listOf("18-24", "25-34", "35-44", "45-54", "55+")
private val GENDERS = listOf("male", "female", "other")
private val DEVICE_TYPES = listOf("mobile", "desktop", "tablet")
private val CATEGORIES = listOf(
    "gaming", "music", "fitness", "beauty", "tech", "food", "travel",
    "finance", "education", "entertainment", "lifestyle", "sports",
)

@Composable
fun AdTargetingRoute(
    onBack: () -> Unit,
    viewModel: AdTargetingViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val accountsState by viewModel.campaignSelector.accountsState.collectAsStateWithLifecycle()
    val campaignsState by viewModel.campaignSelector.campaignsState.collectAsStateWithLifecycle()
    val selectedAccountId by viewModel.campaignSelector.selectedAccountId.collectAsStateWithLifecycle()
    val selectedCampaignId by viewModel.campaignSelector.selectedCampaignId.collectAsStateWithLifecycle()
    AdTargetingScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onUpdate = viewModel::updateForm,
        onSave = viewModel::save,
        picker = {
            StudioCampaignPicker(
                accountsState = accountsState,
                campaignsState = campaignsState,
                selectedAccountId = selectedAccountId,
                selectedCampaignId = selectedCampaignId,
                onAccountSelected = viewModel::onAccountSelected,
                onCampaignSelected = viewModel::onCampaignSelected,
                enabled = state !is AdTargetingUiState.Loading,
            )
        },
    )
}

@Composable
fun AdTargetingScreen(
    state: AdTargetingUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onUpdate: ((TargetingForm) -> TargetingForm) -> Unit,
    onSave: () -> Unit,
    picker: @androidx.compose.runtime.Composable () -> Unit = {},
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(AdTargetingTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Ad targeting") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) { picker() }
            when (state) {
                is AdTargetingUiState.Loading -> LoadingState()
                is AdTargetingUiState.NoCampaign -> EmptyState(
                    title = "No campaign to target",
                    body = "Create an ad account and a campaign first, then set up targeting.",
                    modifier = Modifier.testTag(AdTargetingTestTags.EMPTY),
                )
                is AdTargetingUiState.Error -> ErrorState(
                    message = state.error.message,
                    onRetry = onRetry,
                    modifier = Modifier.testTag(AdTargetingTestTags.ERROR_RETRY),
                )
                is AdTargetingUiState.Content -> TargetingForm(state, onUpdate, onSave)
            }
        }
    }
}

@Composable
private fun TargetingForm(
    state: AdTargetingUiState.Content,
    onUpdate: ((TargetingForm) -> TargetingForm) -> Unit,
    onSave: () -> Unit,
) {
    val form = state.form
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
            .testTag(AdTargetingTestTags.FORM),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            text = "Campaign: ${state.campaignName}",
            style = MaterialTheme.typography.titleMedium,
        )

        EstimateCard(state)

        OutlinedTextField(
            value = form.name,
            onValueChange = { v -> onUpdate { it.copy(name = v) } },
            label = { Text("Targeting set name") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth().testTag(AdTargetingTestTags.NAME),
        )

        ChipSection("Age ranges", AGE_RANGES, form.ageRanges) { v, sel ->
            onUpdate { it.copy(ageRanges = it.ageRanges.toggle(v, sel)) }
        }
        ChipSection("Genders", GENDERS, form.genders) { v, sel ->
            onUpdate { it.copy(genders = it.genders.toggle(v, sel)) }
        }
        ChipSection("Content categories", CATEGORIES, form.contentCategories) { v, sel ->
            onUpdate { it.copy(contentCategories = it.contentCategories.toggle(v, sel)) }
        }
        ChipSection("Device types", DEVICE_TYPES, form.deviceTypes) { v, sel ->
            onUpdate { it.copy(deviceTypes = it.deviceTypes.toggle(v, sel)) }
        }

        OutlinedTextField(
            value = form.countryCodes.joinToString(", "),
            onValueChange = { v ->
                val codes = v.split(",").map { it.trim().uppercase() }.filter { it.length == 2 }
                onUpdate { it.copy(countryCodes = codes) }
            },
            label = { Text("Country codes (ISO-2, comma-separated)") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(
                capitalization = androidx.compose.ui.text.input.KeyboardCapitalization.Characters,
                imeAction = ImeAction.Done,
            ),
            modifier = Modifier.fillMaxWidth().testTag(AdTargetingTestTags.COUNTRIES),
        )

        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("Active hours (UTC)", style = MaterialTheme.typography.titleSmall)
            FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                (0..23).forEach { hour ->
                    FilterChip(
                        selected = hour in form.activeHours,
                        onClick = {
                            val sel = hour !in form.activeHours
                            onUpdate { it.copy(activeHours = it.activeHours.toggleInt(hour, sel)) }
                        },
                        label = { Text(hour.toString()) },
                    )
                }
            }
        }

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text("New users only", style = MaterialTheme.typography.bodyLarge)
                    Switch(
                        checked = form.newUserOnly,
                        onCheckedChange = { v -> onUpdate { it.copy(newUserOnly = v) } },
                    )
                }
            }
        }

        if (state.actionError != null) {
            Text(
                text = state.actionError,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        if (state.saved) {
            Text(
                text = "Targeting saved.",
                color = MaterialTheme.colorScheme.primary,
                style = MaterialTheme.typography.bodyMedium,
            )
        }

        Button(
            onClick = onSave,
            enabled = !state.saving,
            modifier = Modifier.fillMaxWidth().testTag(AdTargetingTestTags.SAVE),
        ) {
            if (state.saving) {
                CircularProgressIndicator(
                    strokeWidth = 2.dp,
                    modifier = Modifier.size(18.dp),
                )
            } else {
                Text("Save targeting")
            }
        }
    }
}

@Composable
private fun EstimateCard(state: AdTargetingUiState.Content) {
    Card(modifier = Modifier.fillMaxWidth().testTag(AdTargetingTestTags.ESTIMATE)) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("Estimated audience", style = MaterialTheme.typography.titleSmall)
            if (state.estimating) {
                CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(18.dp))
            } else {
                Text(
                    text = state.estimatedReach?.let { "~%,d people".format(it) } ?: "—",
                    style = MaterialTheme.typography.headlineSmall,
                )
            }
        }
    }
}

@Composable
private fun ChipSection(
    title: String,
    options: List<String>,
    selected: Set<String>,
    onToggle: (String, Boolean) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(title, style = MaterialTheme.typography.titleSmall)
        FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            options.forEach { opt ->
                FilterChip(
                    selected = opt in selected,
                    onClick = { onToggle(opt, opt !in selected) },
                    label = { Text(opt) },
                )
            }
        }
    }
}

private fun Set<String>.toggle(value: String, select: Boolean): Set<String> =
    if (select) this + value else this - value

private fun Set<Int>.toggleInt(value: Int, select: Boolean): Set<Int> =
    if (select) this + value else this - value
