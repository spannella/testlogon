package com.testlogon.android.feature.questionnaire.respond.publicentry

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** AND-395 - stable testTags for the public-entry shim states. */
object PublicRespondTestTags {
    const val LOADING = "public_respond_loading"
    const val NOT_FOUND = "public_respond_not_found"
    const val ERROR = "public_respond_error"
}

/**
 * AND-395 - the public (UNAUTHENTICATED) respondent ENTRY shim (epic E51). Resolves the published
 * [slug] + an anonymous session via [PublicRespondViewModel], then forwards to AND-349's RespondScreen:
 * a non-terminal session via [onSessionReady]; an already-submitted (terminal) session straight to the
 * Submitted confirmation via [onSubmittedSession] (FR-3). This screen renders NO form - the renderer is
 * AND-347/349's.
 *
 * The hand-off is a one-shot navigation effect keyed on the session id (not re-fired on
 * recomposition / rotation); the route registration pops this entry off the back stack so Back from the
 * form does not return to the loading shim (FR-4 / §6). Loading / NotFound / Error use the core-ui
 * AND-021 state composables (liveRegion + a ≥48dp Retry target inherited from ErrorState).
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */
@Composable
fun PublicRespondScreen(
    slug: String,
    onSessionReady: (sessionId: String) -> Unit,
    onSubmittedSession: (sessionId: String) -> Unit,
    modifier: Modifier = Modifier,
    viewModel: PublicRespondViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    PublicRespondContent(
        state = state,
        onSessionReady = onSessionReady,
        onSubmittedSession = onSubmittedSession,
        onRetry = viewModel::retry,
        modifier = modifier,
    )
}

/**
 * AND-395 - the STATELESS public-entry surface (testable without Hilt). Renders the loading / not-found
 * / error shim and fires the one-shot hand-off effect for a [PublicEntryState.Ready] session.
 */
@Composable
fun PublicRespondContent(
    state: PublicEntryState,
    onSessionReady: (sessionId: String) -> Unit,
    onSubmittedSession: (sessionId: String) -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    when (val s = state) {
        PublicEntryState.Loading ->
            LoadingState(
                modifier = modifier.testTag(PublicRespondTestTags.LOADING),
                message = stringResource(R.string.public_respond_opening),
            )

        is PublicEntryState.Ready ->
            // One-shot hand-off keyed on the session id; pops the entry route (see route registration).
            LaunchedEffect(s.sessionId, s.terminal) {
                if (s.terminal) onSubmittedSession(s.sessionId) else onSessionReady(s.sessionId)
            }

        PublicEntryState.NotFound ->
            EmptyState(
                title = stringResource(R.string.public_respond_not_found_title),
                body = stringResource(R.string.public_respond_not_found_body),
                modifier = modifier.testTag(PublicRespondTestTags.NOT_FOUND),
            )

        is PublicEntryState.Error ->
            ErrorState(
                message = s.message,
                onRetry = onRetry,
                modifier = modifier.testTag(PublicRespondTestTags.ERROR),
            )
    }
}
