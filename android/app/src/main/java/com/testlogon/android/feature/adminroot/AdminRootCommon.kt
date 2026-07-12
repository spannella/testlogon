@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.adminroot

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/**
 * Shared bits for the ROOT/ADMIN governance screens added for web /admin parity
 * (tenants / SSO / root-roles / subscription-tier manager / billing-config write ops).
 * Each screen self-gates on a backend 403 -> Forbidden state (our admin account drives the ADMIN
 * subscription-tier manager; the ROOT-only surfaces render Forbidden).
 */
enum class AdminRootErrorType { NETWORK, SERVER, AUTH }

internal fun adminRootErrorMessage(type: AdminRootErrorType): String = when (type) {
    AdminRootErrorType.AUTH -> "Your session expired. Please sign in again."
    AdminRootErrorType.SERVER -> "Something went wrong on the server. Try again."
    AdminRootErrorType.NETWORK -> "You appear to be offline. Check your connection."
}

internal fun adminRootErrorFor(status: Int): AdminRootErrorType =
    if (status == 401) AdminRootErrorType.AUTH else AdminRootErrorType.SERVER

/** Maps an [ApiResult] failure to a normalized error kind; 403 is signalled separately (Forbidden). */
internal fun ApiResult<*>.adminRootErrorType(): AdminRootErrorType = when (this) {
    is ApiResult.NetworkError -> AdminRootErrorType.NETWORK
    is ApiResult.Failure -> adminRootErrorFor(error.status)
    is ApiResult.Success -> AdminRootErrorType.SERVER
}

internal fun ApiResult<*>.isForbidden(): Boolean =
    this is ApiResult.Failure && error.status == 403

/** Simplified branch descriptor for the shared scaffold, mirroring the B6 admin-ops pattern. */
internal sealed interface AdminRootBranch {
    val isRefreshing: Boolean get() = false
    data object Loading : AdminRootBranch
    data class Content(override val isRefreshing: Boolean = false) : AdminRootBranch
    data object Forbidden : AdminRootBranch
    data class Error(val type: AdminRootErrorType) : AdminRootBranch
}

@Composable
internal fun AdminRootScaffold(
    title: String,
    branch: AdminRootBranch,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
    screenTag: String = "",
    forbiddenTag: String = "",
    retryTag: String = "",
    forbiddenBody: String = "You need root access to manage this.",
    actions: @Composable () -> Unit = {},
    content: @Composable () -> Unit,
) {
    Scaffold(
        modifier = modifier.let { if (screenTag.isNotEmpty()) it.testTag(screenTag) else it },
        topBar = {
            TopAppBar(
                title = { Text(title) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = { actions() },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxWidth().padding(padding)) {
            androidx.compose.material3.pulltorefresh.PullToRefreshBox(
                isRefreshing = branch.isRefreshing,
                onRefresh = onRefresh,
                modifier = Modifier.fillMaxSize(),
            ) {
                when (branch) {
                    is AdminRootBranch.Loading -> LoadingState()
                    is AdminRootBranch.Forbidden -> EmptyState(
                        modifier = if (forbiddenTag.isNotEmpty()) Modifier.testTag(forbiddenTag) else Modifier,
                        title = "Not authorised",
                        body = forbiddenBody,
                        imageVector = Icons.Outlined.Lock,
                        actionLabel = "Back",
                        onAction = onBack,
                    )
                    is AdminRootBranch.Error -> ErrorState(
                        modifier = if (retryTag.isNotEmpty()) Modifier.testTag(retryTag) else Modifier,
                        message = adminRootErrorMessage(branch.type),
                        onRetry = onRetry,
                    )
                    is AdminRootBranch.Content -> content()
                }
            }
        }
    }
}

@Composable
internal fun AdminRootSectionCard(title: String, content: @Composable () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
            )
            content()
        }
    }
}

@Composable
internal fun AdminRootStatRow(label: String, value: String) {
    androidx.compose.foundation.layout.Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(end = 12.dp),
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium,
        )
    }
}
