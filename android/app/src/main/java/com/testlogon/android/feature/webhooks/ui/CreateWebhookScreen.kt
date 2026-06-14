@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.webhooks.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.error
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.webhooks.WebhookEventType

/** AND-398 - stable testTags for the create-webhook screen. */
object CreateWebhookTestTags {
    const val SCREEN = "webhooks_create_screen"
    const val URL_FIELD = "webhooks_create_url"
    const val SUBMIT = "webhooks_create_submit"
    const val EVENTS_LOADING = "webhooks_create_events_loading"

    fun chip(type: String) = "webhooks_create_chip_$type"
}

/**
 * AND-398 - route-level entry for the LIGHT create screen (screen 3). Collects the form, wires
 * CreateSucceeded to a back-pop (the list refreshes on re-entry) and NavigateToLogin to the re-auth handoff.
 * The one-time signing secret (if any) is surfaced to the caller via [onCreated] for one-time in-session
 * display (never persisted / logged).
 */
@Composable
fun CreateWebhookRoute(
    onBack: () -> Unit,
    onCreated: (secret: String?) -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: CreateWebhookViewModel = hiltViewModel(),
) {
    val form by viewModel.form.collectAsStateWithLifecycle()

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is WebhooksEffect.CreateSucceeded -> onCreated(effect.secret)
                is WebhooksEffect.NavigateToLogin -> onNavigateToLogin()
            }
        }
    }

    CreateWebhookScreen(
        form = form,
        onBack = onBack,
        onUrlChange = viewModel::onUrlChange,
        onToggleEvent = viewModel::toggleEvent,
        onSubmit = viewModel::submit,
    )
}

/** AND-398 - stateless LIGHT create (URL field + event-type FilterChip multi-select + gated submit). */
@Composable
fun CreateWebhookScreen(
    form: CreateWebhookForm,
    onBack: () -> Unit,
    onUrlChange: (String) -> Unit,
    onToggleEvent: (String) -> Unit,
    onSubmit: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(CreateWebhookTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.webhooks_create_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.webhooks_back),
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
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            UrlField(form = form, onUrlChange = onUrlChange)

            EventSelector(
                eventTypes = form.eventTypes,
                selected = form.selectedEvents,
                loading = form.eventTypesLoading,
                onToggle = onToggleEvent,
            )

            if (form.submitError != null) {
                Text(
                    text = form.submitError,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error,
                )
            }

            Button(
                onClick = onSubmit,
                enabled = form.canSubmit && !form.submitting,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(CreateWebhookTestTags.SUBMIT),
            ) {
                if (form.submitting) {
                    CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.heightIn(max = 20.dp))
                } else {
                    Text(stringResource(R.string.webhooks_create_submit))
                }
            }
        }
    }
}

@Composable
private fun UrlField(form: CreateWebhookForm, onUrlChange: (String) -> Unit) {
    val errorText = form.urlError
    OutlinedTextField(
        value = form.url,
        onValueChange = onUrlChange,
        label = { Text(stringResource(R.string.webhooks_create_url_label)) },
        placeholder = { Text(stringResource(R.string.webhooks_create_url_placeholder)) },
        singleLine = true,
        isError = errorText != null,
        supportingText = {
            if (errorText != null) {
                Text(errorText)
            } else {
                Text(stringResource(R.string.webhooks_create_url_hint))
            }
        },
        keyboardOptions = KeyboardOptions(
            keyboardType = KeyboardType.Uri,
            imeAction = ImeAction.Done,
        ),
        modifier = Modifier
            .fillMaxWidth()
            .testTag(CreateWebhookTestTags.URL_FIELD)
            .then(
                if (errorText != null) Modifier.semantics { error(errorText) } else Modifier,
            ),
    )
}

@Composable
private fun EventSelector(
    eventTypes: List<WebhookEventType>,
    selected: Set<String>,
    loading: Boolean,
    onToggle: (String) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            text = stringResource(R.string.webhooks_create_events_label),
            style = MaterialTheme.typography.labelLarge,
        )
        when {
            loading ->
                CircularProgressIndicator(
                    strokeWidth = 2.dp,
                    modifier = Modifier
                        .heightIn(max = 24.dp)
                        .testTag(CreateWebhookTestTags.EVENTS_LOADING),
                )

            eventTypes.isEmpty() ->
                Text(
                    text = stringResource(R.string.webhooks_create_events_unavailable),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

            else ->
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    eventTypes.forEach { event ->
                        val isSelected = event.type in selected
                        FilterChip(
                            selected = isSelected,
                            onClick = { onToggle(event.type) },
                            label = { Text(event.type) },
                            modifier = Modifier
                                .heightIn(min = 48.dp)
                                .testTag(CreateWebhookTestTags.chip(event.type))
                                .semantics { role = Role.Checkbox },
                        )
                    }
                }
        }
    }
}
