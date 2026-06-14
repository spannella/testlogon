@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.syndicates.ui

import android.text.format.DateUtils
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Policy
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.syndicates.LicensingContentType
import com.testlogon.android.core.model.syndicates.OpenLicensingContent
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import kotlinx.coroutines.launch

/** AND-357 - stable testTags for the open-licensing sub-screen + its register form. */
object OpenLicensingTestTags {
    const val SCREEN = "open_licensing_screen"
    const val REGISTER = "ol_register"
    const val FORM = "ol_form"
    const val CONTENT_ID = "ol_content_id"
    const val CONTENT_TYPE = "ol_content_type"
    const val SUBMIT = "ol_submit"
    const val EMPTY = "ol_empty"
    const val RESULT = "ol_result"

    fun contentRow(contentId: String) = "ol_content_row_$contentId"
}

/**
 * AND-357 - route-level open-licensing entry; collects the [OpenLicensingUiState] and binds the form
 * callbacks to the [OpenLicensingViewModel].
 */
@Composable
fun OpenLicensingRoute(
    onBack: () -> Unit,
    viewModel: OpenLicensingViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    OpenLicensingScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onRefresh = viewModel::refresh,
        onOpenForm = viewModel::openForm,
        onDismissForm = viewModel::dismissForm,
        onContentIdChange = viewModel::onContentIdChange,
        onContentTypeChange = viewModel::onContentTypeChange,
        onSubmit = viewModel::submit,
        onResultShown = viewModel::consumeResult,
    )
}

/** AND-357 - stateless open-licensing list + register form (a sub-surface of the AND-356 overview). */
@Composable
fun OpenLicensingScreen(
    state: OpenLicensingUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onRefresh: () -> Unit,
    onOpenForm: () -> Unit,
    onDismissForm: () -> Unit,
    onContentIdChange: (String) -> Unit,
    onContentTypeChange: (LicensingContentType) -> Unit,
    onSubmit: () -> Unit,
    onResultShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()

    // Surface the licenses_created success feedback once, then consume it.
    val result = state.form.lastResult
    val resultCd = if (result != null) {
        stringResource(R.string.open_licensing_result, result)
    } else {
        null
    }
    LaunchedEffect(result) {
        if (result != null && resultCd != null) {
            scope.launch { snackbarHostState.showSnackbar(resultCd) }
            onResultShown()
        }
    }

    Scaffold(
        modifier = modifier.testTag(OpenLicensingTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.open_licensing_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.open_licensing_back),
                        )
                    }
                },
            )
        },
        floatingActionButton = {
            if (state is OpenLicensingUiState.Content) {
                FloatingActionButton(
                    onClick = onOpenForm,
                    modifier = Modifier.testTag(OpenLicensingTestTags.REGISTER),
                ) {
                    Icon(
                        Icons.Outlined.Add,
                        contentDescription = stringResource(R.string.open_licensing_register_cta),
                    )
                }
            }
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            // The licenses_created success line (also rendered for assertion / accessibility).
            if (resultCd != null) {
                Surface(
                    color = MaterialTheme.colorScheme.secondaryContainer,
                    contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag(OpenLicensingTestTags.RESULT),
                ) {
                    Text(
                        text = resultCd,
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                    )
                }
            }

            when (state) {
                is OpenLicensingUiState.Loading -> LoadingState()

                is OpenLicensingUiState.Error ->
                    ErrorState(message = state.error.message, onRetry = onRetry)

                is OpenLicensingUiState.Empty ->
                    EmptyState(
                        title = stringResource(R.string.open_licensing_empty_title),
                        body = stringResource(R.string.open_licensing_empty_body),
                        imageVector = Icons.Outlined.Policy,
                        actionLabel = stringResource(R.string.open_licensing_register_cta),
                        onAction = onOpenForm,
                        modifier = Modifier.testTag(OpenLicensingTestTags.EMPTY),
                    )

                is OpenLicensingUiState.Content ->
                    ContentList(state = state, onRefresh = onRefresh)
            }
        }
    }

    if (state.form.visible) {
        RegisterDialog(
            form = state.form,
            onDismiss = onDismissForm,
            onContentIdChange = onContentIdChange,
            onContentTypeChange = onContentTypeChange,
            onSubmit = onSubmit,
        )
    }
}

@Composable
private fun ContentList(
    state: OpenLicensingUiState.Content,
    onRefresh: () -> Unit,
) {
    PullToRefreshBox(
        isRefreshing = state.isRefreshing,
        onRefresh = onRefresh,
        modifier = Modifier.fillMaxSize(),
    ) {
        LazyColumn(modifier = Modifier.fillMaxSize()) {
            items(state.items, key = { it.contentId }) { item ->
                ContentRow(item)
            }
        }
    }
}

@Composable
private fun ContentRow(item: OpenLicensingContent) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(OpenLicensingTestTags.contentRow(item.contentId))
            .padding(horizontal = 16.dp, vertical = 12.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column(
            modifier = Modifier.padding(end = 12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(text = item.contentId, style = MaterialTheme.typography.titleSmall)
            Text(
                text = contentTypeLabel(item.contentType),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            val creator = item.creatorId
            if (!creator.isNullOrBlank()) {
                Text(
                    text = stringResource(R.string.open_licensing_creator, creator),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            val relative = relativeSeconds(item.registeredAt)
            if (relative.isNotBlank()) {
                Text(
                    text = relative,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        val exemptLabel = if (item.exempt) {
            stringResource(R.string.open_licensing_exempt)
        } else {
            stringResource(R.string.open_licensing_auto_licensed)
        }
        AssistChip(
            onClick = {},
            enabled = false,
            label = { Text(exemptLabel) },
            colors = AssistChipDefaults.assistChipColors(),
        )
    }
}

@Composable
private fun RegisterDialog(
    form: RegisterFormState,
    onDismiss: () -> Unit,
    onContentIdChange: (String) -> Unit,
    onContentTypeChange: (LicensingContentType) -> Unit,
    onSubmit: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag(OpenLicensingTestTags.FORM),
        title = { Text(stringResource(R.string.open_licensing_form_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = form.contentId,
                    onValueChange = onContentIdChange,
                    label = { Text(stringResource(R.string.open_licensing_content_id_label)) },
                    singleLine = true,
                    isError = form.contentIdError != null,
                    supportingText = form.contentIdError?.let { msg -> { Text(msg) } },
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag(OpenLicensingTestTags.CONTENT_ID),
                )
                ContentTypePicker(
                    selected = form.contentType,
                    error = form.contentTypeError,
                    onSelect = onContentTypeChange,
                )
                val submitError = form.submitError
                if (submitError != null) {
                    Text(
                        text = submitError,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        },
        confirmButton = {
            TlButton(
                text = stringResource(R.string.open_licensing_submit),
                onClick = onSubmit,
                enabled = form.isValid && !form.submitting,
                loading = form.submitting,
                modifier = Modifier.testTag(OpenLicensingTestTags.SUBMIT),
            )
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.open_licensing_cancel))
            }
        },
    )
}

/** AND-357 - content_type picker over the fixed 6 wire values (UNKNOWN is never offerable). */
@Composable
private fun ContentTypePicker(
    selected: LicensingContentType?,
    error: String?,
    onSelect: (LicensingContentType) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    val label = selected?.let { contentTypeLabel(it) }
        ?: stringResource(R.string.open_licensing_content_type_placeholder)
    val pickerCd = stringResource(R.string.open_licensing_content_type_label)
    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = it },
        modifier = Modifier
            .fillMaxWidth()
            .testTag(OpenLicensingTestTags.CONTENT_TYPE)
            .semantics { contentDescription = pickerCd },
    ) {
        OutlinedTextField(
            value = label,
            onValueChange = {},
            readOnly = true,
            label = { Text(stringResource(R.string.open_licensing_content_type_label)) },
            isError = error != null,
            supportingText = error?.let { msg -> { Text(msg) } },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor(),
        )
        ExposedDropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
        ) {
            LicensingContentType.WIRE_VALUES.forEach { option ->
                DropdownMenuItem(
                    text = { Text(contentTypeLabel(option)) },
                    onClick = {
                        expanded = false
                        onSelect(option)
                    },
                )
            }
        }
    }
}

@Composable
private fun contentTypeLabel(type: LicensingContentType): String = stringResource(
    when (type) {
        LicensingContentType.VIDEO -> R.string.open_licensing_type_video
        LicensingContentType.MUSIC -> R.string.open_licensing_type_music
        LicensingContentType.IMAGE -> R.string.open_licensing_type_image
        LicensingContentType.POST -> R.string.open_licensing_type_post
        LicensingContentType.BROADCAST -> R.string.open_licensing_type_broadcast
        LicensingContentType.CLIP -> R.string.open_licensing_type_clip
        LicensingContentType.UNKNOWN -> R.string.open_licensing_type_unknown
    },
)

/**
 * AND-357 - relative-time copy from a nullable INTEGER epoch-SECONDS value. UI-only
 * (android.text.format), returns "" for null / unknown / epoch timestamps. Mirrors the AND-356 helper.
 */
private fun relativeSeconds(epochSeconds: Long?, nowMs: Long = System.currentTimeMillis()): String {
    if (epochSeconds == null || epochSeconds <= 0L) return ""
    return DateUtils.getRelativeTimeSpanString(
        epochSeconds * 1000L,
        nowMs,
        DateUtils.MINUTE_IN_MILLIS,
    ).toString()
}
