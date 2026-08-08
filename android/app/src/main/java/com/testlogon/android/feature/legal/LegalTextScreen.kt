@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.legal

import androidx.annotation.StringRes
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
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.testlogon.android.R

/**
 * PAR-29 — shared scaffold for a static legal text screen (title + scrollable body). Reused by the Terms
 * and Community Guidelines screens so the chrome + scroll behaviour stay identical.
 */
@Composable
private fun LegalTextScreen(
    @StringRes titleRes: Int,
    @StringRes bodyRes: Int,
    testTagPrefix: String,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    @StringRes versionRes: Int? = null,
    version: String? = null,
) {
    Scaffold(
        modifier = modifier.testTag("${testTagPrefix}_screen"),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(titleRes)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("${testTagPrefix}_back")) {
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
            if (versionRes != null && version != null) {
                Text(
                    text = stringResource(versionRes, version),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Text(
                text = stringResource(bodyRes),
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}

/** PAR-29 — the Terms of Service screen (static, versioned). */
@Composable
fun TermsScreen(onBack: () -> Unit, modifier: Modifier = Modifier) {
    LegalTextScreen(
        titleRes = R.string.legal_terms_title,
        bodyRes = R.string.legal_terms_body,
        testTagPrefix = "terms",
        onBack = onBack,
        modifier = modifier,
        versionRes = R.string.legal_terms_version,
        version = LegalConstants.CURRENT_TERMS_VERSION,
    )
}

/** PAR-29 — the Community Guidelines screen (static). */
@Composable
fun CommunityGuidelinesScreen(onBack: () -> Unit, modifier: Modifier = Modifier) {
    LegalTextScreen(
        titleRes = R.string.legal_guidelines_title,
        bodyRes = R.string.legal_guidelines_body,
        testTagPrefix = "guidelines",
        onBack = onBack,
        modifier = modifier,
    )
}
