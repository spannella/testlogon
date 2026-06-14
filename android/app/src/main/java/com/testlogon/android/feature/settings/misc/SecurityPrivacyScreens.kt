package com.testlogon.android.feature.settings.misc

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Devices
import androidx.compose.material.icons.outlined.Download
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import com.testlogon.android.R

/**
 * AND-077 — thin Security subsection: aggregates existing security surfaces (sessions, MFA devices)
 * which are owned by other tickets. This screen only links out.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecuritySettingsScreen(
    onBack: () -> Unit,
    onOpenSessions: () -> Unit,
    onOpenMfaDevices: () -> Unit,
    modifier: Modifier = Modifier,
) {
    SubsectionScaffold(
        title = stringResource(R.string.security_settings_title),
        testTag = "security_settings_screen",
        onBack = onBack,
        modifier = modifier,
    ) {
        SubsectionRow(
            tag = "security_row_sessions",
            icon = Icons.Outlined.Devices,
            title = stringResource(R.string.account_row_sessions),
            onClick = onOpenSessions,
        )
        SubsectionRow(
            tag = "security_row_mfa",
            icon = Icons.Outlined.Security,
            title = stringResource(R.string.account_row_mfa),
            onClick = onOpenMfaDevices,
        )
    }
}

/**
 * AND-082 — Privacy & data-export entry. This screen routes only; the actual export / deletion flows
 * are owned downstream (E50). [onRequestExport] / [onDeleteData] are handoffs.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PrivacySettingsScreen(
    onBack: () -> Unit,
    onRequestExport: () -> Unit,
    onDeleteData: () -> Unit,
    modifier: Modifier = Modifier,
) {
    SubsectionScaffold(
        title = stringResource(R.string.privacy_settings_title),
        testTag = "privacy_settings_screen",
        onBack = onBack,
        modifier = modifier,
    ) {
        SubsectionRow(
            tag = "privacy_row_export",
            icon = Icons.Outlined.Download,
            title = stringResource(R.string.privacy_row_export),
            onClick = onRequestExport,
        )
        SubsectionRow(
            tag = "privacy_row_delete",
            icon = Icons.Outlined.Security,
            title = stringResource(R.string.privacy_row_delete),
            destructive = true,
            onClick = onDeleteData,
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SubsectionScaffold(
    title: String,
    testTag: String,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    Scaffold(
        modifier = modifier.testTag(testTag),
        topBar = {
            TopAppBar(
                title = { Text(title) },
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
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            content()
        }
    }
}

@Composable
private fun SubsectionRow(
    tag: String,
    icon: ImageVector,
    title: String,
    destructive: Boolean = false,
    onClick: () -> Unit,
) {
    val color = if (destructive) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface
    ListItem(
        modifier = Modifier.fillMaxWidth().testTag(tag).clickable(onClick = onClick),
        headlineContent = { Text(title, color = color) },
        leadingContent = { Icon(icon, contentDescription = null, tint = color) },
    )
}
