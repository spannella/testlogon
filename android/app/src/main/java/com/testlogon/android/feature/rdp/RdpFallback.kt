@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.rdp

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Lan
import androidx.compose.material3.Card
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.rdp.RdpFallbackDto
import com.testlogon.android.data.rdp.RdpRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * B7 Remote-Access: RDP browser transport, Phase-1 FALLBACK ONLY. This is a connection-info VIEW for a
 * registered Windows/RDP host — there is NO interactive rendering on mobile (native in-browser RDP is a
 * deferred milestone behind a server gate; POST /api/rdp/session returns 503/501). It mirrors the web
 * rdp.ts `fallback` surface and lives beside the VNC remote-desktop broker on the same screen.
 *
 * Degrade-on-404: an unknown/foreign host_id fails closed server-side (RDP_TARGET_NOT_FOUND) and renders
 * an honest "not found / unavailable" line rather than crashing.
 */
object RdpFallbackTestTags {
    const val CARD = "rdp_fallback_card"
    const val HOST_FIELD = "rdp_fallback_host"
    const val LOOKUP = "rdp_fallback_lookup"
    const val DETAILS = "rdp_fallback_details"
    const val COPY_ADDRESS = "rdp_fallback_copy_address"
}

data class RdpFallbackUiState(
    val hostId: String = "",
    val loading: Boolean = false,
    val result: RdpFallbackDto? = null,
    val notFound: Boolean = false,
    val errorMessage: String? = null,
)

@HiltViewModel
class RdpFallbackViewModel @Inject constructor(
    private val repo: RdpRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(RdpFallbackUiState())
    val state: StateFlow<RdpFallbackUiState> = _state.asStateFlow()

    fun setHost(id: String) {
        _state.value = _state.value.copy(hostId = id, notFound = false, errorMessage = null)
    }

    fun lookup() {
        val cur = _state.value
        if (cur.loading || cur.hostId.isBlank()) return
        _state.value = cur.copy(loading = true, result = null, notFound = false, errorMessage = null)
        viewModelScope.launch {
            when (val r = repo.fallback(cur.hostId)) {
                is ApiResult.Success ->
                    _state.value = _state.value.copy(loading = false, result = r.data)
                is ApiResult.Failure ->
                    _state.value = _state.value.copy(
                        loading = false,
                        notFound = r.error.status == 404,
                        errorMessage = when (r.error.status) {
                            404 -> null
                            401 -> "Your session expired. Please sign in again."
                            403 -> "You are not authorized to access this RDP host."
                            else -> "Could not load RDP connection details. Try again."
                        },
                    )
                is ApiResult.NetworkError ->
                    _state.value = _state.value.copy(
                        loading = false,
                        errorMessage = "You appear to be offline. Check your connection.",
                    )
            }
        }
    }
}

@Composable
fun RdpFallbackCard(
    modifier: Modifier = Modifier,
    viewModel: RdpFallbackViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    RdpFallbackCardContent(
        state = state,
        onSetHost = viewModel::setHost,
        onLookup = viewModel::lookup,
        modifier = modifier,
    )
}

@Composable
private fun RdpFallbackCardContent(
    state: RdpFallbackUiState,
    onSetHost: (String) -> Unit,
    onLookup: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val clipboard = LocalClipboardManager.current
    Card(modifier = modifier.fillMaxWidth().testTag(RdpFallbackTestTags.CARD)) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Icon(Icons.Outlined.Lan, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                Text("RDP connection info", style = MaterialTheme.typography.titleMedium)
            }
            Text(
                "Look up copy-ready connection details for a registered Windows/RDP host. In-app RDP " +
                    "rendering is not available on mobile — use a native RDP client with the details below.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = state.hostId,
                onValueChange = onSetHost,
                label = { Text("Host ID") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().testTag(RdpFallbackTestTags.HOST_FIELD),
            )
            OutlinedButton(
                onClick = onLookup,
                enabled = !state.loading && state.hostId.isNotBlank(),
                modifier = Modifier.fillMaxWidth().testTag(RdpFallbackTestTags.LOOKUP),
            ) { Text(if (state.loading) "Looking up..." else "Look up connection details") }

            state.errorMessage?.let {
                Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            }
            if (state.notFound) {
                Row(verticalAlignment = Alignment.Top, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Icon(Icons.Outlined.Info, contentDescription = null, tint = MaterialTheme.colorScheme.tertiary)
                    Text(
                        "No RDP host found for that ID, or it is not an RDP target.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            val result = state.result
            if (result != null) {
                HorizontalDivider()
                Column(
                    modifier = Modifier.testTag(RdpFallbackTestTags.DETAILS),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Text(RdpFallbackMath.displayLabel(result), style = MaterialTheme.typography.titleSmall)
                    if (RdpFallbackMath.isConnectable(result)) {
                        val address = RdpFallbackMath.connectionAddress(result)
                        Text("Address:", style = MaterialTheme.typography.labelMedium)
                        Text(address, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                        if (result.username.isNotBlank()) {
                            Text("Username: ${result.username}", style = MaterialTheme.typography.bodySmall)
                        }
                        if (result.instructions.isNotBlank()) {
                            Text(result.instructions, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        Text(
                            RdpFallbackMath.nativeClientsHint(result),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        OutlinedButton(
                            onClick = { clipboard.setText(AnnotatedString(address)) },
                            modifier = Modifier.fillMaxWidth().testTag(RdpFallbackTestTags.COPY_ADDRESS),
                        ) { Text("Copy address") }
                    } else {
                        Text(
                            "This host is not currently available for RDP.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }
    }
}
