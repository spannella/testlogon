@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.safety

import androidx.annotation.StringRes
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.automirrored.outlined.KeyboardArrowRight
import androidx.compose.material.icons.outlined.Block
import androidx.compose.material.icons.outlined.Copyright
import androidx.compose.material.icons.outlined.DeleteForever
import androidx.compose.material.icons.outlined.Download
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.ui.unit.dp
import com.testlogon.android.R

/** PAR-27 — stable testTags for the Safety Center hub + its rows. */
object SafetyCenterTestTags {
    const val SCREEN = "safety_center_screen"
    const val LIST = "safety_center_list"
    const val BACK = "safety_center_back"

    fun row(id: String) = "safety_center_row_$id"
}

/**
 * PAR-27 — a Safety Center row descriptor: a section label + icon that navigates to an
 * already-built child screen. [destructive] renders the label/icon in the error colour.
 */
private data class SafetyRow(
    val id: String,
    @StringRes val titleRes: Int,
    @StringRes val subtitleRes: Int,
    val icon: ImageVector,
    val destructive: Boolean = false,
)

/**
 * PAR-27 — the unified Safety Center hub. Aggregation only: every row navigates to a screen that
 * already exists + is already registered in the authenticated graph (blocked users / privacy export /
 * DMCA / account deletion). Mirrors the iOS Safety Center grouping (Safety / Your data / Delete account).
 */
@Composable
fun SafetyCenterRoute(
    onBack: () -> Unit,
    onOpenBlockedUsers: () -> Unit,
    onOpenPrivacyExport: () -> Unit,
    onOpenDmca: () -> Unit,
    onOpenAccountDeletion: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(SafetyCenterTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.safety_center_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag(SafetyCenterTestTags.BACK)) {
                        Icon(
                            Icons.AutoMirrored.Outlined.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding).testTag(SafetyCenterTestTags.LIST),
        ) {
            // Section: Safety.
            item { SectionHeader(R.string.safety_center_section_safety) }
            item {
                SafetyRowItem(
                    row = SafetyRow(
                        id = "blocked_users",
                        titleRes = R.string.safety_center_blocked_users,
                        subtitleRes = R.string.safety_center_blocked_users_subtitle,
                        icon = Icons.Outlined.Block,
                    ),
                    onClick = onOpenBlockedUsers,
                )
            }
            item {
                SafetyRowItem(
                    row = SafetyRow(
                        id = "dmca",
                        titleRes = R.string.safety_center_dmca,
                        subtitleRes = R.string.safety_center_dmca_subtitle,
                        icon = Icons.Outlined.Copyright,
                    ),
                    onClick = onOpenDmca,
                )
            }

            // Section: Your data.
            item { HorizontalDivider() }
            item { SectionHeader(R.string.safety_center_section_data) }
            item {
                SafetyRowItem(
                    row = SafetyRow(
                        id = "privacy_export",
                        titleRes = R.string.safety_center_privacy_export,
                        subtitleRes = R.string.safety_center_privacy_export_subtitle,
                        icon = Icons.Outlined.Download,
                    ),
                    onClick = onOpenPrivacyExport,
                )
            }

            // Section: Delete account (destructive).
            item { HorizontalDivider() }
            item { SectionHeader(R.string.safety_center_section_delete) }
            item {
                SafetyRowItem(
                    row = SafetyRow(
                        id = "account_deletion",
                        titleRes = R.string.safety_center_account_deletion,
                        subtitleRes = R.string.safety_center_account_deletion_subtitle,
                        icon = Icons.Outlined.DeleteForever,
                        destructive = true,
                    ),
                    onClick = onOpenAccountDeletion,
                )
            }
            item {
                Text(
                    text = stringResource(R.string.safety_center_delete_footer),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                )
            }
        }
    }
}

@Composable
private fun SectionHeader(@StringRes titleRes: Int) {
    Text(
        text = stringResource(titleRes),
        style = MaterialTheme.typography.labelLarge,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(start = 16.dp, end = 16.dp, top = 16.dp, bottom = 4.dp),
    )
}

@Composable
private fun SafetyRowItem(row: SafetyRow, onClick: () -> Unit) {
    val title = stringResource(row.titleRes)
    val subtitle = stringResource(row.subtitleRes)
    val tint = if (row.destructive) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface
    ListItem(
        modifier = Modifier
            .clickable(onClick = onClick)
            .testTag(SafetyCenterTestTags.row(row.id)),
        headlineContent = { Text(title, color = tint) },
        supportingContent = { Text(subtitle, style = MaterialTheme.typography.bodySmall) },
        leadingContent = {
            Icon(
                row.icon,
                contentDescription = null,
                tint = if (row.destructive) {
                    MaterialTheme.colorScheme.error
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                },
            )
        },
        trailingContent = {
            Icon(Icons.AutoMirrored.Outlined.KeyboardArrowRight, contentDescription = null)
        },
    )
}
