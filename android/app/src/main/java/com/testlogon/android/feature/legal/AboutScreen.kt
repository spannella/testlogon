@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.legal

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.testlogon.android.R

/** PAR-29 — resolves the human-readable app name + version for the About screen. */
private fun appVersionLabel(context: android.content.Context): String {
    return try {
        val pm = context.packageManager
        val info = pm.getPackageInfo(context.packageName, 0)
        val name = context.applicationInfo.loadLabel(pm).toString()
        val version = info.versionName ?: ""
        if (version.isBlank()) name else "$name $version"
    } catch (_: Exception) {
        context.packageName
    }
}

/**
 * PAR-29 — the About screen. Static content plus the live app name/version resolved from the
 * PackageManager. Mirrors the iOS About page.
 */
@Composable
fun AboutScreen(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val versionLabel = appVersionLabel(context)
    Scaffold(
        modifier = modifier.testTag("about_screen"),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.legal_about_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("about_back")) {
                        Icon(
                            Icons.AutoMirrored.Outlined.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
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
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = versionLabel,
                style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.testTag("about_version"),
            )
            Text(
                text = stringResource(R.string.legal_terms_version, LegalConstants.CURRENT_TERMS_VERSION),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = stringResource(R.string.legal_about_body),
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}
