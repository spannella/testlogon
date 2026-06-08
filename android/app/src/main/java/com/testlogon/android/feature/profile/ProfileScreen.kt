package com.testlogon.android.feature.profile

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.core.ui.input.TlButtonVariant

/** Authenticated Profile tab: shows the current principal and a Logout action (AND-032). */
@Composable
fun ProfileScreen(
    modifier: Modifier = Modifier,
    viewModel: ProfileViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(24.dp)
            .testTag("me_placeholder"),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
    ) {
        Text("Profile", style = MaterialTheme.typography.headlineSmall)
        Text(
            text = state.userSub?.let { "Signed in as $it" } ?: "Signed in",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        TlButton(
            text = "Log out",
            onClick = viewModel::onLogout,
            variant = TlButtonVariant.Secondary,
            loading = state.loggingOut,
            modifier = Modifier.testTag("profile_logout"),
        )
    }
}
