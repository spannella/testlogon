@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.kyc.eidv

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.selection.selectable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.feature.kyc.eidv.model.EidAssuranceLevel
import com.testlogon.android.feature.kyc.eidv.model.EidAuthFlow
import com.testlogon.android.feature.kyc.eidv.model.EidDiscrepancy
import com.testlogon.android.feature.kyc.eidv.model.EidDiscrepancySeverity
import com.testlogon.android.feature.kyc.eidv.model.EidScheme
import com.testlogon.android.feature.kyc.eidv.model.SchemeInfo

/** AND-325 - stable testTags for the eIDV screen. */
object EidvTestTags {
    const val SCREEN = "eidv_screen"
    const val START = "eidv_start"
    const val AWAITING = "eidv_awaiting"
    const val REOPEN = "eidv_reopen"
    const val CHECK_STATUS = "eidv_check_status"
    const val RESULT = "eidv_result"
    const val EXPIRED = "eidv_expired"
    const val RESTART = "eidv_restart"
    const val ERROR = "eidv_error"

    /** Per-scheme row tag: [SCHEME_PREFIX] + scheme wire token. */
    const val SCHEME_PREFIX = "eidv_scheme_"

    /** Per-discrepancy row tag: [DISCREPANCY_PREFIX] + field. */
    const val DISCREPANCY_PREFIX = "eidv_discrepancy_"

    fun scheme(scheme: EidScheme): String = SCHEME_PREFIX + scheme.wire
    fun discrepancy(field: String): String = DISCREPANCY_PREFIX + field
}

/**
 * AND-325 - route-level eIDV screen. A draft KYC case is ensured lazily by the VM (REUSING AND-319
 * KycApi.createCase) or resumed from an optional `caseId` nav arg.
 *
 * REAL REST REDIRECT eIDV: on entering [EidvUiState.AwaitingProvider] (keyed on sessionId) the route opens
 * the returned redirect_url EXTERNALLY via ACTION_VIEW (Custom Tab / browser); the "Reopen" action does the
 * same. NO PII is submitted, NO vendor / ML / CameraX SDK, NO camera / permission / manifest change.
 */
@Composable
fun EidvRoute(
    onBack: () -> Unit,
    onDone: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: EidvViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current

    // Open the provider redirect EXTERNALLY when a session is started (keyed on sessionId so a restart with
    // a new session re-opens). The poll is owned by the VM.
    val awaiting = state as? EidvUiState.AwaitingProvider
    LaunchedEffect(awaiting?.sessionId) {
        awaiting?.let { openExternalUrl(context, it.redirectUrl) }
    }

    EidvScreen(
        state = state,
        onBack = onBack,
        onSchemeSelected = viewModel::onSchemeSelected,
        onStart = viewModel::start,
        onReopen = { (state as? EidvUiState.AwaitingProvider)?.let { openExternalUrl(context, it.redirectUrl) } },
        onCheckStatus = viewModel::onProviderReturned,
        onDone = onDone,
        onRestart = viewModel::restart,
        onRetry = viewModel::retry,
        modifier = modifier,
    )
}

/**
 * AND-325 - stateless eIDV screen: scheme selection (single-select rows with assurance level, auth flow,
 * countries, description), an awaiting-provider state (reopen + manual check-status + spinner), a result
 * (verified summary + discrepancy list, critical flagged), an expired state (restart), and an error state
 * (retry per kind).
 */
@Composable
fun EidvScreen(
    state: EidvUiState,
    onBack: () -> Unit,
    onSchemeSelected: (EidScheme) -> Unit,
    onStart: () -> Unit,
    onReopen: () -> Unit,
    onCheckStatus: () -> Unit,
    onDone: () -> Unit,
    onRestart: () -> Unit,
    onRetry: (EidvUiState.Retry) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(EidvTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.eidv_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is EidvUiState.Loading ->
                    CircularProgressIndicator(modifier = Modifier.align(Alignment.Center))

                is EidvUiState.SchemeSelection -> SchemeSelectionContent(
                    state = state,
                    onSchemeSelected = onSchemeSelected,
                    onStart = onStart,
                )

                is EidvUiState.AwaitingProvider -> AwaitingContent(
                    state = state,
                    onReopen = onReopen,
                    onCheckStatus = onCheckStatus,
                )

                is EidvUiState.Result -> ResultContent(state = state, onDone = onDone)

                is EidvUiState.Expired -> ExpiredContent(onRestart = onRestart)

                is EidvUiState.Error -> ErrorContent(state = state, onRetry = onRetry)
            }
        }
    }
}

@Composable
private fun SchemeSelectionContent(
    state: EidvUiState.SchemeSelection,
    onSchemeSelected: (EidScheme) -> Unit,
    onStart: () -> Unit,
) {
    Column(modifier = Modifier.fillMaxSize()) {
        LazyColumn(
            modifier = Modifier.weight(1f).fillMaxWidth(),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item {
                Text(
                    text = stringResource(R.string.eidv_scheme_heading),
                    style = MaterialTheme.typography.titleMedium,
                )
            }
            items(items = state.schemes, key = { it.scheme.wire + it.name }) { scheme ->
                SchemeRow(
                    scheme = scheme,
                    selected = state.selected == scheme.scheme,
                    onSelected = { onSchemeSelected(scheme.scheme) },
                )
            }
        }

        Button(
            onClick = onStart,
            enabled = state.canStart,
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
                .heightIn(min = 48.dp)
                .testTag(EidvTestTags.START),
        ) {
            if (state.starting) {
                CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.heightIn(min = 20.dp))
            } else {
                Text(stringResource(R.string.eidv_start_button))
            }
        }
    }
}

@Composable
private fun SchemeRow(
    scheme: SchemeInfo,
    selected: Boolean,
    onSelected: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .selectable(selected = selected, onClick = onSelected)
            .heightIn(min = 48.dp)
            .testTag(EidvTestTags.scheme(scheme.scheme)),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            RadioButton(selected = selected, onClick = onSelected)
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = scheme.name,
                        style = MaterialTheme.typography.bodyLarge,
                        modifier = Modifier.weight(1f),
                    )
                    AssistChip(
                        onClick = {},
                        enabled = false,
                        label = { Text(stringResource(assuranceLabel(scheme.assuranceLevel))) },
                    )
                }
                Text(
                    text = stringResource(authFlowLabel(scheme.authFlow)),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (scheme.countries.isNotEmpty()) {
                    Text(
                        text = stringResource(
                            R.string.eidv_countries_value,
                            scheme.countries.joinToString(", "),
                        ),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                scheme.description?.let { description ->
                    Text(text = description, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

@Composable
private fun AwaitingContent(
    state: EidvUiState.AwaitingProvider,
    onReopen: () -> Unit,
    onCheckStatus: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp).testTag(EidvTestTags.AWAITING),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
    ) {
        Text(
            text = stringResource(R.string.eidv_awaiting_heading),
            style = MaterialTheme.typography.titleMedium,
        )
        Text(
            text = stringResource(R.string.eidv_awaiting_body),
            style = MaterialTheme.typography.bodyMedium,
        )
        if (state.polling) {
            CircularProgressIndicator()
        }
        Button(
            onClick = onCheckStatus,
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag(EidvTestTags.CHECK_STATUS),
        ) {
            Text(stringResource(R.string.eidv_check_status_button))
        }
        OutlinedButton(
            onClick = onReopen,
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag(EidvTestTags.REOPEN),
        ) {
            Text(stringResource(R.string.eidv_reopen_button))
        }
    }
}

@Composable
private fun ResultContent(
    state: EidvUiState.Result,
    onDone: () -> Unit,
) {
    Column(modifier = Modifier.fillMaxSize().testTag(EidvTestTags.RESULT)) {
        LazyColumn(
            modifier = Modifier.weight(1f).fillMaxWidth(),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item {
                Text(
                    text = stringResource(R.string.eidv_result_heading),
                    style = MaterialTheme.typography.titleMedium,
                )
            }
            item {
                Text(
                    text = stringResource(
                        R.string.eidv_result_assurance,
                        stringResource(assuranceLabel(state.verification.assuranceLevel)),
                    ),
                    style = MaterialTheme.typography.bodyLarge,
                )
            }
            if (state.autoTierUpgrade) {
                item {
                    Text(
                        text = stringResource(R.string.eidv_tier_upgraded),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
            if (state.hasCriticalDiscrepancy) {
                item {
                    Text(
                        text = stringResource(R.string.eidv_critical_warning),
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
            if (state.verification.discrepancies.isNotEmpty()) {
                item {
                    Text(
                        text = stringResource(R.string.eidv_discrepancies_heading),
                        style = MaterialTheme.typography.titleSmall,
                    )
                }
                items(items = state.verification.discrepancies, key = { it.field }) { discrepancy ->
                    DiscrepancyRow(discrepancy = discrepancy)
                }
            }
        }
        Button(
            onClick = onDone,
            modifier = Modifier.fillMaxWidth().padding(16.dp).heightIn(min = 48.dp),
        ) {
            Text(stringResource(R.string.eidv_continue_button))
        }
    }
}

@Composable
private fun DiscrepancyRow(discrepancy: EidDiscrepancy) {
    Card(
        modifier = Modifier.fillMaxWidth().testTag(EidvTestTags.discrepancy(discrepancy.field)),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    text = discrepancy.field,
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.weight(1f),
                )
                AssistChip(
                    onClick = {},
                    enabled = false,
                    label = { Text(stringResource(severityLabel(discrepancy.severity))) },
                )
            }
            Text(
                text = stringResource(
                    R.string.eidv_discrepancy_profile,
                    discrepancy.profileValue ?: stringResource(R.string.eidv_value_absent),
                ),
                style = MaterialTheme.typography.bodySmall,
            )
            Text(
                text = stringResource(
                    R.string.eidv_discrepancy_eid,
                    discrepancy.eidValue ?: stringResource(R.string.eidv_value_absent),
                ),
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

@Composable
private fun ExpiredContent(onRestart: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp).testTag(EidvTestTags.EXPIRED),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(
            text = stringResource(R.string.eidv_expired_message),
            style = MaterialTheme.typography.bodyLarge,
        )
        Button(
            onClick = onRestart,
            modifier = Modifier.padding(top = 16.dp).heightIn(min = 48.dp).testTag(EidvTestTags.RESTART),
        ) {
            Text(stringResource(R.string.eidv_restart_button))
        }
    }
}

@Composable
private fun ErrorContent(
    state: EidvUiState.Error,
    onRetry: (EidvUiState.Retry) -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp).testTag(EidvTestTags.ERROR),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(text = state.message, style = MaterialTheme.typography.bodyLarge)
        Button(
            onClick = { onRetry(state.retry) },
            modifier = Modifier.padding(top = 16.dp).heightIn(min = 48.dp),
        ) {
            Text(stringResource(R.string.eidv_retry_button))
        }
    }
}

private fun assuranceLabel(level: EidAssuranceLevel): Int = when (level) {
    EidAssuranceLevel.LOW -> R.string.eidv_assurance_low
    EidAssuranceLevel.SUBSTANTIAL -> R.string.eidv_assurance_substantial
    EidAssuranceLevel.HIGH -> R.string.eidv_assurance_high
    EidAssuranceLevel.UNKNOWN -> R.string.eidv_assurance_unknown
}

private fun authFlowLabel(flow: EidAuthFlow): Int = when (flow) {
    EidAuthFlow.BROWSER_REDIRECT -> R.string.eidv_flow_browser_redirect
    EidAuthFlow.MOBILE_APP_QR -> R.string.eidv_flow_mobile_app_qr
    EidAuthFlow.OTP_BIOMETRIC -> R.string.eidv_flow_otp_biometric
    EidAuthFlow.UNKNOWN -> R.string.eidv_flow_unknown
}

private fun severityLabel(severity: EidDiscrepancySeverity): Int = when (severity) {
    EidDiscrepancySeverity.MATCH -> R.string.eidv_severity_match
    EidDiscrepancySeverity.WARNING -> R.string.eidv_severity_warning
    EidDiscrepancySeverity.CRITICAL -> R.string.eidv_severity_critical
    EidDiscrepancySeverity.UNKNOWN -> R.string.eidv_severity_unknown
}

/** Opens [url] in an external browser / Custom Tab via ACTION_VIEW (best-effort). Reuses the AND-324 idiom. */
internal fun openExternalUrl(context: Context, url: String) {
    val intent = Intent(Intent.ACTION_VIEW, url.toUri()).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    try {
        context.startActivity(intent)
    } catch (_: ActivityNotFoundException) {
        // No browser available; the CTA is best-effort.
    }
}
