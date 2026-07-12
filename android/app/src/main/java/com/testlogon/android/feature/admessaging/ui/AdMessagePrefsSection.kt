package com.testlogon.android.feature.admessaging.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R

/** ADV2-511/601 — stable testTags for the ad-messages opt-out section. */
object AdMessagePrefsTestTags {
    const val SECTION = "admsg_prefs_section"
    const val SWITCH = "admsg_prefs_switch"
}

/**
 * ADV2-511/601 — the self-contained "Allow promotional messages" opt-out Card dropped onto the Message-
 * Privacy settings screen. Hosts its own [AdMessagePrefsViewModel] via hiltViewModel so it never touches
 * the existing pay-to-message form/VM.
 */
@Composable
fun AdMessagePrefsSection(
    modifier: Modifier = Modifier,
    viewModel: AdMessagePrefsViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    Card(modifier = modifier.fillMaxWidth().testTag(AdMessagePrefsTestTags.SECTION)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(
                stringResource(R.string.admsg_prefs_title),
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                stringResource(R.string.admsg_prefs_body),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            when (val s = state) {
                is AdMessagePrefsViewModel.State.Loading ->
                    CircularProgressIndicator()

                is AdMessagePrefsViewModel.State.Error ->
                    Text(
                        s.message,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )

                is AdMessagePrefsViewModel.State.Loaded -> {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Switch(
                            checked = s.allow,
                            onCheckedChange = viewModel::onToggle,
                            enabled = !s.saving,
                            modifier = Modifier.testTag(AdMessagePrefsTestTags.SWITCH),
                        )
                        Text(
                            stringResource(R.string.admsg_prefs_switch_label),
                            modifier = Modifier.padding(start = 12.dp),
                        )
                    }
                    s.error?.let {
                        Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    }
                }
            }
        }
    }
}
