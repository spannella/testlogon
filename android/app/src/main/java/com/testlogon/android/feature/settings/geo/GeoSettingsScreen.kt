@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.settings.geo

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** Route-level entry for the geo-blocking settings screen. */
@Composable
fun GeoSettingsRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: GeoSettingsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    GeoSettingsScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::load,
        onModeChanged = viewModel::onModeChanged,
        onCountriesChanged = viewModel::onCountriesChanged,
        onTest = viewModel::test,
        modifier = modifier,
    )
}

@Composable
fun GeoSettingsScreen(
    state: GeoSettingsUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onModeChanged: (String) -> Unit,
    onCountriesChanged: (String) -> Unit,
    onTest: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(GeoSettingsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Geo-Blocking") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        when (state) {
            GeoSettingsUiState.Loading ->
                LoadingState(modifier = Modifier.padding(padding))

            is GeoSettingsUiState.Error ->
                ErrorState(
                    message = state.message,
                    onRetry = onRetry,
                    modifier = Modifier.padding(padding).testTag(GeoSettingsTestTags.ERROR_RETRY),
                )

            is GeoSettingsUiState.Content -> Content(
                state = state,
                padding = padding,
                onModeChanged = onModeChanged,
                onCountriesChanged = onCountriesChanged,
                onTest = onTest,
            )
        }
    }
}

@Composable
private fun Content(
    state: GeoSettingsUiState.Content,
    padding: androidx.compose.foundation.layout.PaddingValues,
    onModeChanged: (String) -> Unit,
    onCountriesChanged: (String) -> Unit,
    onTest: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(padding)
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        // Detected location card.
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text("Your Detected Location", style = MaterialTheme.typography.titleSmall)
                val my = state.myCountry
                if (my?.country != null) {
                    Text(
                        "Country: ${my.country} (${state.myCountryName ?: "Unknown"})",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                } else {
                    Text(
                        "Unable to determine (localhost / private IP)",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
                Text(
                    "IP: ${my?.ip ?: "..."}  |  Source: ${my?.source ?: "..."}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        // Dry-run tester.
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Test Geo Rules", style = MaterialTheme.typography.titleSmall)
                Text(
                    "Run a dry-run check against your current IP to see if a specific geo configuration would block you.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Row(Modifier.selectableGroup()) {
                    ModeChip("No restriction", "", state.testMode, GeoSettingsTestTags.MODE_NONE, onModeChanged)
                    ModeChip("Allow only", "allow", state.testMode, GeoSettingsTestTags.MODE_ALLOW, onModeChanged)
                    ModeChip("Block", "block", state.testMode, GeoSettingsTestTags.MODE_BLOCK, onModeChanged)
                }
                OutlinedTextField(
                    value = state.testCountries,
                    onValueChange = onCountriesChanged,
                    label = { Text("Country codes (e.g. US,CA,GB)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag(GeoSettingsTestTags.COUNTRIES_INPUT),
                )
                OutlinedButton(
                    onClick = onTest,
                    enabled = !state.testing,
                    modifier = Modifier.testTag(GeoSettingsTestTags.TEST_BUTTON),
                ) {
                    Text(if (state.testing) "Checking..." else "Test")
                }
                state.result?.let { r ->
                    val label = buildString {
                        append(if (r.allowed) "Access ALLOWED" else "Access BLOCKED")
                        r.country?.let { append(" (country: $it)") }
                        r.matchedRule?.let { append(" [rule: $it]") }
                    }
                    Text(
                        label,
                        style = MaterialTheme.typography.bodyMedium,
                        color = if (r.allowed) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                        modifier = Modifier.testTag(GeoSettingsTestTags.RESULT),
                    )
                }
                state.resultError?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
            }
        }

        Text(
            "Geo-restrictions are configured per video, broadcast, or catalog item using the editors on each " +
                "content's detail/edit page. ${state.countries.size} countries available.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            fontFamily = FontFamily.Default,
        )
    }
}

@Composable
private fun ModeChip(
    label: String,
    value: String,
    selected: String,
    tag: String,
    onSelect: (String) -> Unit,
) {
    FilterChip(
        selected = selected == value,
        onClick = { onSelect(value) },
        label = { Text(label) },
        modifier = Modifier.padding(end = 8.dp).testTag(tag),
    )
}
