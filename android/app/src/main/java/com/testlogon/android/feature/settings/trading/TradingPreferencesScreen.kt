package com.testlogon.android.feature.settings.trading

import android.Manifest
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.network.AppThemeMode
import com.testlogon.android.data.exchange.TradingUiPrefsStore
import com.testlogon.android.data.exchange.alerts.TradingAlertKind

/** Route-level Trading preferences entry. */
@Composable
fun TradingPreferencesRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: TradingPreferencesViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    TradingPreferencesScreen(
        state = state,
        onBack = onBack,
        onModeSelected = viewModel::onModeSelected,
        onDefaultMarketSelected = viewModel::onDefaultMarketSelected,
        onAlertKindToggled = viewModel::onAlertKindToggled,
        onRefreshNotifications = viewModel::refreshNotificationState,
        onResetPrefs = viewModel::onResetPrefs,
        onResetShown = viewModel::onResetShown,
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TradingPreferencesScreen(
    state: TradingPreferencesUiState,
    onBack: () -> Unit,
    onModeSelected: (AppThemeMode) -> Unit,
    onDefaultMarketSelected: (Int) -> Unit,
    onAlertKindToggled: (TradingAlertKind, Boolean) -> Unit,
    onRefreshNotifications: () -> Unit,
    onResetPrefs: () -> Unit,
    onResetShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    // POST_NOTIFICATIONS request launcher (no-op pre-33; result refreshes the read state).
    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { onRefreshNotifications() }

    Scaffold(
        modifier = modifier.testTag("trading_prefs_screen"),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.trading_prefs_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("trading_prefs_back")) {
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
                .verticalScroll(rememberScrollState()),
        ) {
            // ---- Theme ----
            SectionHeader(stringResource(R.string.trading_prefs_theme_section))
            AppThemeMode.entries.forEach { mode ->
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
                        .testTag("trading_prefs_theme_${mode.name.lowercase()}")
                        .selectable(
                            selected = state.appearance.mode == mode,
                            role = Role.RadioButton,
                            onClick = { onModeSelected(mode) },
                        ),
                    headlineContent = { Text(label) },
                    leadingContent = {
                        RadioButton(selected = state.appearance.mode == mode, onClick = null)
                    },
                )
            }

            HorizontalDivider()

            // ---- Default market ----
            SectionHeader(stringResource(R.string.trading_prefs_default_market_section))
            DefaultMarketPicker(
                markets = state.markets,
                selectedSymbolId = state.defaultSymbolId,
                onSelected = onDefaultMarketSelected,
            )

            HorizontalDivider()

            // ---- Alert kinds ----
            SectionHeader(stringResource(R.string.trading_prefs_alerts_section))
            TradingAlertKind.entries.forEach { kind ->
                val checked = state.alertPrefs.isEnabled(kind)
                ListItem(
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("trading_prefs_alert_${kind.name.lowercase()}")
                        .toggleable(
                            value = checked,
                            role = Role.Switch,
                            onValueChange = { onAlertKindToggled(kind, it) },
                        ),
                    headlineContent = { Text(stringResource(alertKindLabel(kind))) },
                    trailingContent = { Switch(checked = checked, onCheckedChange = null) },
                )
            }

            HorizontalDivider()

            // ---- Notifications ----
            SectionHeader(stringResource(R.string.trading_prefs_notifications_section))
            ListItem(
                modifier = Modifier.fillMaxWidth().testTag("trading_prefs_notif_status"),
                headlineContent = {
                    Text(
                        stringResource(
                            if (state.notificationsGranted) R.string.trading_prefs_notif_on
                            else R.string.trading_prefs_notif_off,
                        ),
                    )
                },
                supportingContent = {
                    Text(
                        stringResource(R.string.trading_prefs_notif_subtitle),
                        style = MaterialTheme.typography.bodySmall,
                    )
                },
                trailingContent = {
                    if (!state.notificationsGranted) {
                        Button(
                            onClick = {
                                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                                    permissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                                } else {
                                    onRefreshNotifications()
                                }
                            },
                            modifier = Modifier.testTag("trading_prefs_notif_request"),
                        ) {
                            Text(stringResource(R.string.trading_prefs_notif_enable))
                        }
                    }
                },
            )

            HorizontalDivider()

            // ---- Reset ----
            SectionHeader(stringResource(R.string.trading_prefs_reset_section))
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                OutlinedButton(
                    onClick = onResetPrefs,
                    modifier = Modifier.testTag("trading_prefs_reset"),
                ) {
                    Text(stringResource(R.string.trading_prefs_reset_action))
                }
                Text(
                    text = stringResource(R.string.trading_prefs_reset_subtitle),
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(start = 12.dp),
                )
            }

            if (state.resetDone) {
                LaunchedEffect(Unit) { onResetShown() }
                Text(
                    text = stringResource(R.string.trading_prefs_reset_done),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier
                        .padding(horizontal = 16.dp, vertical = 4.dp)
                        .testTag("trading_prefs_reset_done"),
                )
            }
        }
    }
}

@Composable
private fun SectionHeader(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleSmall,
        modifier = Modifier.padding(start = 16.dp, top = 12.dp, bottom = 4.dp),
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DefaultMarketPicker(
    markets: List<MarketChoice>,
    selectedSymbolId: Int,
    onSelected: (Int) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    val selectedLabel = markets.firstOrNull { it.symbolId == selectedSymbolId }?.symbol
        ?: stringResource(R.string.trading_prefs_default_market_none)

    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = it },
        modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
    ) {
        OutlinedTextField(
            value = selectedLabel,
            onValueChange = {},
            readOnly = true,
            label = { Text(stringResource(R.string.trading_prefs_default_market_label)) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor()
                .testTag("trading_prefs_default_market"),
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            // "None" clears the preference.
            DropdownMenuItem(
                text = { Text(stringResource(R.string.trading_prefs_default_market_none)) },
                onClick = {
                    onSelected(TradingUiPrefsStore.NO_DEFAULT)
                    expanded = false
                },
                modifier = Modifier.testTag("trading_prefs_market_none"),
            )
            markets.forEach { market ->
                DropdownMenuItem(
                    text = { Text(market.symbol) },
                    onClick = {
                        onSelected(market.symbolId)
                        expanded = false
                    },
                    modifier = Modifier.testTag("trading_prefs_market_${market.symbolId}"),
                )
            }
        }
    }
}

private fun alertKindLabel(kind: TradingAlertKind): Int = when (kind) {
    TradingAlertKind.FILL -> R.string.trading_prefs_alert_fills
    TradingAlertKind.LIQUIDATION -> R.string.trading_prefs_alert_liquidations
    TradingAlertKind.FUNDING -> R.string.trading_prefs_alert_funding
    TradingAlertKind.MARGIN_DISTRESS -> R.string.trading_prefs_alert_margin
    TradingAlertKind.PM_RESOLVED -> R.string.trading_prefs_alert_pm
}
