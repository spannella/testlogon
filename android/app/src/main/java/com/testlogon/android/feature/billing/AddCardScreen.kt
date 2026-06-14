package com.testlogon.android.feature.billing

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.CreditCardOff
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState

/** Stable testTags for the Add Card screen (AND-226). */
object AddCardTestTags {
    const val SCREEN = "add_card_screen"
    const val UNAVAILABLE = "add_card_unavailable"
    const val ADD = "add_card_button"
}

/**
 * AND-226 — route-level Add Card entry, reached from the Payment Methods "Add" CTA.
 *
 * FLAGGED: card entry is delegated to the [com.testlogon.android.data.billing.CardTokenizer] seam,
 * which is the stub today (NotConfigured). The screen NEVER renders raw card-number/CVC fields. On
 * [AddCardEvent.Saved] (only with a real tokenizer) it asks the caller to refresh + close via
 * [onCardSaved]; the stub path surfaces a "card entry unavailable / payments not configured" state.
 */
@Composable
fun AddCardRoute(
    onBack: () -> Unit,
    onCardSaved: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: AddCardViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val notConfiguredMsg = stringResource(R.string.add_card_not_configured)

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is AddCardEvent.Saved -> onCardSaved()
                is AddCardEvent.NotConfigured -> snackbarHostState.showSnackbar(notConfiguredMsg)
                is AddCardEvent.Failure -> snackbarHostState.showSnackbar(event.message)
            }
        }
    }

    // Attempt card entry immediately so the FLAGGED stub surfaces the unavailable state on open.
    LaunchedEffect(Unit) { viewModel.onAddCard() }

    AddCardScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onRetry = viewModel::onAddCard,
        onBack = onBack,
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AddCardScreen(
    state: AddCardUiState,
    snackbarHostState: SnackbarHostState,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(AddCardTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.add_card_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("add_card_back")) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            // FLAGGED steady state: payments not configured. No raw card fields are ever shown.
            EmptyState(
                title = stringResource(R.string.add_card_unavailable_title),
                body = stringResource(R.string.add_card_unavailable_body),
                imageVector = Icons.Outlined.CreditCardOff,
                actionLabel = if (state.isPreparing) null else stringResource(R.string.add_card_button),
                onAction = if (state.isPreparing) null else onRetry,
                modifier = Modifier.testTag(AddCardTestTags.UNAVAILABLE),
            )
        }
    }
}
