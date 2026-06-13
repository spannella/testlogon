@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.questionnaire.respond

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.QuestionnaireField
import com.testlogon.android.feature.questionnaire.render.SectionFieldList
import com.testlogon.android.feature.questionnaire.respond.data.QuestionnairePdfOpener
import dagger.hilt.android.EntryPointAccessors

/** AND-349 - Hilt entry point so the route can resolve the singleton PDF opener in a composable. */
@dagger.hilt.EntryPoint
@dagger.hilt.InstallIn(dagger.hilt.components.SingletonComponent::class)
interface QuestionnairePdfOpenerEntryPoint {
    fun questionnairePdfOpener(): QuestionnairePdfOpener
}

/** AND-349 - stable testTags for the public respondent submit + PDF screen. */
object RespondTestTags {
    const val SCREEN = "respond_screen"
    const val SUBMIT = "respond_submit"
    const val PROGRESS = "respond_progress"
    const val CONFIRMATION = "respond_confirmation"
    const val SESSION_ID = "respond_session_id"
    const val DOWNLOAD_PDF = "respond_download_pdf"
    const val ERROR_RETRY = "respond_error_retry"
}

/**
 * AND-349 - route-level public respondent surface. Hosts the AND-347 dynamic form bound to the VM,
 * collects the one-shot [RespondEffect.OpenPdf] effect and hands the cached PDF to the system chooser via
 * [QuestionnairePdfOpener] (FileProvider ACTION_VIEW, reusing AND-334 OpenWithLauncher).
 *
 * [fields] is the schema question order to render. AND-349 owns submit + PDF + the deep link; the schema
 * fetch/paging is a sibling concern, so the route passes the fields it has (empty until wired) and binds
 * answers / fieldErrors / onAnswerChanged from the VM. The VM is also told the [fields] order so a
 * rejected submit can scroll to the first errored question.
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */
@Composable
fun RespondRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    fields: List<QuestionnaireField> = emptyList(),
    viewModel: RespondentSessionViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val opener: QuestionnairePdfOpener = remember(context) {
        EntryPointAccessors.fromApplication(
            context.applicationContext,
            QuestionnairePdfOpenerEntryPoint::class.java,
        ).questionnairePdfOpener()
    }
    LaunchedEffect(viewModel, fields) {
        viewModel.fieldOrder = fields.map { it.questionId }
    }
    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is RespondEffect.OpenPdf -> opener.open(context, effect.file)
                is RespondEffect.ShowError -> Unit // surfaced inline via state.syncState
            }
        }
    }
    RespondScreen(
        state = state,
        fields = fields,
        onAnswerChanged = viewModel::onAnswerChanged,
        onSubmit = viewModel::onSubmit,
        onDownloadPdf = viewModel::onDownloadPdf,
        onRetry = viewModel::onReload,
        onReloadSchema = viewModel::onReloadSchema,
        onFirstErrorConsumed = viewModel::onFirstErrorConsumed,
        onBack = onBack,
        modifier = modifier,
    )
}

/**
 * AND-349 - the STATELESS respondent screen. Renders the AND-347 [SectionFieldList] (disabled once
 * submitting), a Submit button gated on canSubmit + a real sessionId, the terminal Submitted confirmation
 * (response_session_id + status + Download PDF), and a retryable error surface. On a validation failure it
 * scrolls the first errored field into view.
 */
@Composable
fun RespondScreen(
    state: RespondentSessionUiState,
    fields: List<QuestionnaireField>,
    onAnswerChanged: (String, AnswerValue) -> Unit,
    onSubmit: () -> Unit,
    onDownloadPdf: () -> Unit,
    onRetry: () -> Unit,
    onReloadSchema: () -> Unit,
    onFirstErrorConsumed: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val backDescription = stringResource(R.string.respond_back)
    Scaffold(
        modifier = modifier.testTag(RespondTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.respond_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.size(48.dp)) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = backDescription,
                        )
                    }
                },
            )
        },
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding),
        ) {
            when (state) {
                is RespondentSessionUiState.Loading -> CenteredProgress(RespondTestTags.PROGRESS)
                is RespondentSessionUiState.SchemaChanged -> SchemaChangedBody(onReloadSchema)
                is RespondentSessionUiState.Error -> ErrorBody(state, onRetry)
                is RespondentSessionUiState.Active -> ActiveBody(
                    state = state,
                    fields = fields,
                    onAnswerChanged = onAnswerChanged,
                    onSubmit = onSubmit,
                    onFirstErrorConsumed = onFirstErrorConsumed,
                )
                is RespondentSessionUiState.Submitted -> SubmittedBody(state, onDownloadPdf)
            }
        }
    }
}

@Composable
private fun ActiveBody(
    state: RespondentSessionUiState.Active,
    fields: List<QuestionnaireField>,
    onAnswerChanged: (String, AnswerValue) -> Unit,
    onSubmit: () -> Unit,
    onFirstErrorConsumed: () -> Unit,
) {
    val listState = rememberLazyListState()
    // AND-349: scroll the first errored field into view after a rejected submit, then clear the marker.
    LaunchedEffect(state.firstErrorQuestionId) {
        val target = state.firstErrorQuestionId ?: return@LaunchedEffect
        val index = fields.indexOfFirst { it.questionId == target }
        if (index >= 0) {
            listState.animateScrollToItem(index)
        }
        onFirstErrorConsumed()
    }
    val canSubmit = state.canSubmit && state.session.sessionId.isNotBlank() && !state.submitting
    Column(modifier = Modifier.fillMaxSize()) {
        LazyColumn(
            state = listState,
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            if (fields.isEmpty()) {
                item { Text(stringResource(R.string.respond_empty_form)) }
            } else {
                item {
                    SectionFieldList(
                        fields = fields,
                        answers = state.answers,
                        enabled = !state.submitting,
                        errors = state.fieldErrors,
                        onAnswerChanged = onAnswerChanged,
                    )
                }
            }
        }
        Button(
            onClick = onSubmit,
            enabled = canSubmit,
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
                .testTag(RespondTestTags.SUBMIT),
        ) {
            if (state.submitting) {
                CircularProgressIndicator(
                    modifier = Modifier
                        .size(20.dp)
                        .testTag(RespondTestTags.PROGRESS),
                    strokeWidth = 2.dp,
                )
            } else {
                Text(stringResource(R.string.respond_submit))
            }
        }
    }
}

@Composable
private fun SubmittedBody(
    state: RespondentSessionUiState.Submitted,
    onDownloadPdf: () -> Unit,
) {
    val downloading = state.pdfState is PdfState.Downloading
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp)
            .testTag(RespondTestTags.CONFIRMATION),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
    ) {
        Icon(
            imageVector = Icons.Filled.CheckCircle,
            contentDescription = null,
            modifier = Modifier.size(48.dp),
        )
        Text(
            text = stringResource(R.string.respond_confirmation_title),
            style = MaterialTheme.typography.headlineSmall,
        )
        Text(stringResource(R.string.respond_confirmation_body))
        // No submission_id on the wire: the confirmation shows the response_session_id + status.
        Text(
            text = stringResource(R.string.respond_session_id_label, state.sessionId),
            modifier = Modifier.testTag(RespondTestTags.SESSION_ID),
        )
        Text(stringResource(R.string.respond_status_label, state.sessionStatus.name))
        if (state.pdfState is PdfState.Error) {
            Text(
                text = state.pdfState.message,
                color = MaterialTheme.colorScheme.error,
            )
        }
        Button(
            onClick = onDownloadPdf,
            enabled = !downloading,
            modifier = Modifier
                .fillMaxWidth()
                .testTag(RespondTestTags.DOWNLOAD_PDF),
        ) {
            if (downloading) {
                CircularProgressIndicator(
                    modifier = Modifier.size(20.dp),
                    strokeWidth = 2.dp,
                )
            } else {
                Text(stringResource(R.string.respond_download_pdf))
            }
        }
    }
}

@Composable
private fun SchemaChangedBody(onReloadSchema: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
    ) {
        Text(stringResource(R.string.respond_schema_changed))
        Button(onClick = onReloadSchema, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.respond_schema_reload))
        }
    }
}

@Composable
private fun ErrorBody(
    state: RespondentSessionUiState.Error,
    onRetry: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
    ) {
        Text(
            text = stringResource(R.string.respond_error_title),
            style = MaterialTheme.typography.titleMedium,
        )
        Text(state.error.message)
        OutlinedButton(
            onClick = onRetry,
            modifier = Modifier.testTag(RespondTestTags.ERROR_RETRY),
        ) {
            Text(stringResource(R.string.respond_error_retry))
        }
    }
}

@Composable
private fun CenteredProgress(tag: String) {
    val loadingDescription = stringResource(R.string.respond_loading)
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        CircularProgressIndicator(
            modifier = Modifier
                .testTag(tag)
                .semantics { contentDescription = loadingDescription },
        )
    }
}
