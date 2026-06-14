package com.testlogon.android.feature.settings.hub

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.automirrored.outlined.KeyboardArrowRight
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.disabled
import androidx.compose.ui.semantics.semantics
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R

/**
 * AND-077 — route-level Settings hub. [onOpenSection] is wired to the shared NavController; only
 * available rows fire it.
 */
@Composable
fun SettingsHubRoute(
    onOpenSection: (route: String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: SettingsHubViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    SettingsHubScreen(
        state = state,
        onOpenSection = { section -> onOpenSection(section.route) },
        onBack = onBack,
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsHubScreen(
    state: SettingsHubUiState,
    onOpenSection: (SettingsSection) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag("settings_hub_screen"),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.settings_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("settings_back")) {
                        Icon(
                            Icons.AutoMirrored.Outlined.ArrowBack,
                            contentDescription = stringResource(R.string.settings_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding).testTag("settings_hub_list"),
        ) {
            items(state.sections, key = { it.key.name }) { section ->
                SettingsSectionRow(section = section, onClick = { onOpenSection(section) })
            }
        }
    }
}

@Composable
private fun SettingsSectionRow(
    section: SettingsSection,
    onClick: () -> Unit,
) {
    val title = stringResource(section.titleRes)
    val subtitle = when {
        !section.available -> stringResource(COMING_SOON_SUBTITLE)
        section.subtitleRes != null -> stringResource(section.subtitleRes)
        else -> null
    }
    val tag = "settings_row_${section.key.name.lowercase()}"
    val contentDesc = if (subtitle != null) "$title. $subtitle" else title

    val baseModifier = Modifier
        .testTag(tag)
        .then(
            if (section.available) {
                Modifier
                    .clickableRow(onClick)
                    .semantics { contentDescription = contentDesc }
            } else {
                Modifier
                    .alpha(0.5f)
                    .semantics {
                        this.disabled()
                        contentDescription = contentDesc
                    }
            },
        )

    ListItem(
        modifier = baseModifier,
        headlineContent = { Text(title) },
        supportingContent = subtitle?.let { { Text(it, style = MaterialTheme.typography.bodySmall) } },
        leadingContent = { Icon(section.icon, contentDescription = null) },
        trailingContent = {
            if (section.available) {
                Icon(
                    Icons.AutoMirrored.Outlined.KeyboardArrowRight,
                    contentDescription = null,
                )
            }
        },
    )
}

/** Adds a click action via Modifier.clickable, kept separate so disabled rows omit it entirely. */
private fun Modifier.clickableRow(onClick: () -> Unit): Modifier =
    this.clickable(onClick = onClick)
