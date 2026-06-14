package com.testlogon.android.feature.settings.appearance

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.network.AppThemeMode
import com.testlogon.android.core.network.AppearancePreferences

/** AND-081 — route-level Appearance settings entry. */
@Composable
fun AppearanceSettingsRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: AppearanceSettingsViewModel = hiltViewModel(),
) {
    val prefs by viewModel.uiState.collectAsStateWithLifecycle()
    AppearanceSettingsScreen(
        prefs = prefs,
        dynamicColorSupported = viewModel.dynamicColorSupported,
        onModeSelected = viewModel::onModeSelected,
        onDynamicColorChanged = viewModel::onDynamicColorChanged,
        onBack = onBack,
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppearanceSettingsScreen(
    prefs: AppearancePreferences,
    dynamicColorSupported: Boolean,
    onModeSelected: (AppThemeMode) -> Unit,
    onDynamicColorChanged: (Boolean) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag("appearance_screen"),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.appearance_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Outlined.ArrowBack,
                            contentDescription = stringResource(R.string.settings_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .selectableGroup(),
        ) {
            Text(
                text = stringResource(R.string.appearance_mode_section),
                style = MaterialTheme.typography.titleSmall,
                modifier = Modifier.padding(start = 16.dp, top = 12.dp, bottom = 4.dp),
            )
            AppThemeMode.entries.forEach { mode ->
                ThemeModeRow(
                    mode = mode,
                    selected = prefs.mode == mode,
                    onSelect = { onModeSelected(mode) },
                )
            }
            if (dynamicColorSupported) {
                HorizontalDivider()
                DynamicColorRow(
                    checked = prefs.dynamicColor,
                    onCheckedChange = onDynamicColorChanged,
                )
            }
        }
    }
}

@Composable
private fun ThemeModeRow(
    mode: AppThemeMode,
    selected: Boolean,
    onSelect: () -> Unit,
) {
    val label = stringResource(
        when (mode) {
            AppThemeMode.LIGHT -> R.string.appearance_mode_light
            AppThemeMode.DARK -> R.string.appearance_mode_dark
            AppThemeMode.SYSTEM -> R.string.appearance_mode_system
        },
    )
    ListItem(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("appearance_mode_${mode.name.lowercase()}")
            .selectable(selected = selected, role = Role.RadioButton, onClick = onSelect),
        headlineContent = { Text(label) },
        leadingContent = { RadioButton(selected = selected, onClick = null) },
    )
}

@Composable
private fun DynamicColorRow(
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    ListItem(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("appearance_dynamic_color")
            .toggleable(value = checked, role = Role.Switch, onValueChange = onCheckedChange),
        headlineContent = { Text(stringResource(R.string.appearance_dynamic_color)) },
        supportingContent = {
            Text(
                stringResource(R.string.appearance_dynamic_color_subtitle),
                style = MaterialTheme.typography.bodySmall,
            )
        },
        trailingContent = { Switch(checked = checked, onCheckedChange = null) },
    )
}
