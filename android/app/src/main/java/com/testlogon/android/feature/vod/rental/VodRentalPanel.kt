package com.testlogon.android.feature.vod.rental

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import com.testlogon.android.data.vod.rental.VodRentalApi

/** AND-192 — stable test tags for the rental affordance. */
object VodRentalTestTags {
    const val PANEL = "vod_rental_panel"
    const val RENT = "vod_rental_rent"
    const val PLAY = "vod_rental_play"
    const val COUNTDOWN = "vod_rental_countdown"
}

/**
 * AND-192 — the rent / play affordance + live countdown for the VOD detail screen.
 *
 * Stateless: it renders [VodRentalUiState] and hoists the rent/play callbacks. The countdown exposes a
 * natural-language contentDescription (distinct from the compact HH:MM:SS) and announces re-lock via a
 * live region. Buttons meet the 48dp minimum touch target via the Material 3 Button defaults.
 */
@Composable
fun VodRentalPanel(
    state: VodRentalUiState,
    onRent: (tier: String) -> Unit,
    onPlay: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp)
            .testTag(VodRentalTestTags.PANEL),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        when (state) {
            VodRentalUiState.Loading -> CircularProgressIndicator(modifier = Modifier.size(24.dp))

            is VodRentalUiState.Locked -> {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = { onRent(VodRentalApi.TIER_RENTAL) },
                        enabled = !state.isRenting,
                        modifier = Modifier.testTag(VodRentalTestTags.RENT),
                    ) {
                        Text(
                            text = if (state.isRenting) {
                                stringResource(R.string.vod_rental_renting)
                            } else {
                                stringResource(R.string.vod_rent)
                            },
                        )
                    }
                    OutlinedButton(
                        onClick = { onRent(VodRentalApi.TIER_VIEW_ONCE) },
                        enabled = !state.isRenting,
                    ) {
                        Text(stringResource(R.string.vod_view_once))
                    }
                }
            }

            is VodRentalUiState.Active -> {
                Button(
                    onClick = onPlay,
                    enabled = !state.isStartingPlayback,
                    modifier = Modifier.testTag(VodRentalTestTags.PLAY),
                ) {
                    Text(
                        text = if (state.isStartingPlayback) {
                            stringResource(R.string.vod_rental_starting_playback)
                        } else {
                            stringResource(R.string.vod_rent_play)
                        },
                    )
                }
                val cd = stringResource(R.string.vod_rental_countdown_cd, state.countdownA11y)
                Text(
                    text = stringResource(R.string.vod_rental_expires_in, state.countdownLabel),
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier
                        .testTag(VodRentalTestTags.COUNTDOWN)
                        .semantics {
                            contentDescription = cd
                            liveRegion = LiveRegionMode.Polite
                        },
                )
            }

            is VodRentalUiState.Error -> {
                Text(text = state.message, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}
