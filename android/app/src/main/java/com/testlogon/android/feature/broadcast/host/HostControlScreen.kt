@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.broadcast.host

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DatePicker
import androidx.compose.material3.DatePickerDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TimePicker
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.rememberDatePickerState
import androidx.compose.material3.rememberTimePickerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.data.broadcast.BroadcastSession
import com.testlogon.android.feature.broadcast.host.ads.AdControlViewModel
import com.testlogon.android.feature.broadcast.host.livecommerce.LiveCommerceHostSection
import com.testlogon.android.feature.broadcast.chat.LiveChatPanel
import com.testlogon.android.data.broadcast.BroadcastSessionStatus
import com.testlogon.android.data.broadcast.HealthLevel
import com.testlogon.android.data.broadcast.HostHealthReport
import com.testlogon.android.core.webrtc.ui.LocalVideoPreview
import com.testlogon.android.core.webrtc.ui.PlaceholderVideoRenderer
import com.testlogon.android.core.webrtc.ui.VideoRenderer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import kotlinx.coroutines.delay
import java.text.NumberFormat
import java.time.Duration
import java.time.Instant
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.LocalTime
import java.time.ZoneId
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

/** AND-309 — stable testTags for the host LIVE control surface. */
object HostControlTestTags {
    const val SCREEN = "host_screen"
    const val START = "host_start"
    const val STOP = "host_stop"
    const val RESUME = "host_resume"
    const val RESCHEDULE = "host_reschedule"
    const val HEALTH_CARD = "host_health_card"
    const val STALE_BANNER = "host_stale_banner"
    const val STOP_CONFIRM = "host_stop_confirm"
    const val STATUS_CHIP = "host_status_chip"

    /** AND-310 — opens the inputs-management surface. */
    const val MANAGE_INPUTS = "host_manage_inputs"

    /** AND-311 — opens the layout-management surface. */
    const val MANAGE_LAYOUT = "host_manage_layout"

    /** AND-312 — opens the guest-management surface. */
    const val MANAGE_GUESTS = "host_manage_guests"

    /** AND-313 — opens the chat-moderation log surface. */
    const val MODERATION = "host_moderation"

    /** AND-314 — opens the goals + products authoring surface. */
    const val MANAGE_GOALS_PRODUCTS = "host_manage_goals_products"

    /** AND-315 — opens the tip-config editor. */
    const val MANAGE_TIPS = "host_manage_tips"

    /** AND-315 — opens the private-show lifecycle surface. */
    const val PRIVATE_SHOWS = "host_private_shows"

    /** AND-316 — opens the ad-break / ad-config surface. */
    const val MANAGE_ADS = "host_manage_ads"
    const val MANAGE_QA = "host_manage_qa"

    /** ADV2-106 - the primary-screen Start ad break / End early control + its countdown card. */
    const val AD_BREAK_CARD = "host_ad_break_card"
    const val AD_BREAK_START = "host_ad_break_start"
    const val AD_BREAK_END = "host_ad_break_end"

    /** #7c — the live self-view PIP of the host's own camera while managing. */
    const val SELF_VIEW = "host_self_view"

    /** Bidirectional host live-chat read/compose panel. */
    const val LIVE_CHAT = "host_live_chat"
}

/**
 * AND-309 — host control entry. Collects the ViewModel state and delegates rendering to the stateless
 * [HostControlScreen]. Reached from the host create/ingest flow after Start (BroadcastHostControlDest).
 */
@Composable
fun HostControlRoute(
    onBack: () -> Unit,
    // AND-310 — open the inputs-management surface (list / activate / make-live) for this session.
    onManageInputs: () -> Unit = {},
    // AND-311 — open the layout-management surface (mode chooser) for this session.
    onManageLayout: () -> Unit = {},
    // AND-312 — open the guest-management surface (invite / promote / mute / remove) for this session.
    onManageGuests: () -> Unit = {},
    // AND-313 — open the chat-moderation log surface; receives the broadcast's creator id (delegate routing).
    onModeration: (String) -> Unit = {},
    // AND-314 — open the goals + products authoring surface for this session.
    onManageGoalsProducts: () -> Unit = {},
    // AND-315 — open the tip-config editor for this session.
    onManageTips: () -> Unit = {},
    // AND-315 — open the private-show lifecycle surface for this session.
    onPrivateShows: () -> Unit = {},
    // AND-316 — open the ad-break / ad-config surface for this session.
    onManageAds: () -> Unit = {},
    onManageQa: () -> Unit = {},
    viewModel: HostControlViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    // Drive health polling only while the surface is composed (paused -> stop, resumed -> start).
    DisposableEffect(viewModel) {
        viewModel.startHealthPolling()
        onDispose { viewModel.stopHealthPolling() }
    }
    HostControlScreen(
        state = state,
        videoRenderer = viewModel.videoRenderer,
        // Bidirectional live chat for the host: the SAME viewer LiveChatPanel + LiveChatViewModel,
        // keyed by this broadcast session id, so the host can READ the live chat and POST messages
        // (not just moderate). Only shown once the session id resolves.
        chatPanel = { state.session?.id?.let { sid -> HostLiveChatSection(sessionId = sid) } },
        // ADV2-106 - Start ad break (+ countdown / End early) on the PRIMARY live screen. Shares the host
        // route's NavBackStackEntry (same sessionId arg) so AdControlViewModel resolves without extra wiring.
        adBreakControls = { HostAdBreakSection() },
        // LIVECOM L5 - "Feature/Pin product" (shop this stream) control. Shares the host route's
        // NavBackStackEntry (same sessionId arg) so LiveCommerceHostViewModel resolves without extra wiring.
        liveCommerceControls = { LiveCommerceHostSection() },
        onStart = viewModel::onStart,
        onStop = viewModel::onStop,
        onConfirmStop = viewModel::onConfirmStopDialog,
        onResume = viewModel::onResume,
        onReschedule = viewModel::onReschedule,
        onRetryHealth = viewModel::retryHealth,
        onManageInputs = onManageInputs,
        onManageLayout = onManageLayout,
        onManageGuests = onManageGuests,
        onModeration = onModeration,
        onManageGoalsProducts = onManageGoalsProducts,
        onManageTips = onManageTips,
        onPrivateShows = onPrivateShows,
        onManageAds = onManageAds,
        onManageQa = onManageQa,
        onBack = onBack,
    )
}

/**
 * AND-309 — stateless host control surface: a status header (name + status chip + LIVE timer derived from
 * startedAt), a [HealthReportCard] (bitrate / fps / dropped% / viewers + a stale banner), and a control bar
 * with Start / Stop / Resume / Reschedule gated by [HostControlPolicy]. Stop is a two-step AlertDialog; the
 * whole bar is disabled while an action is in flight (the in-flight button shows a spinner).
 */
@Composable
fun HostControlScreen(
    state: HostControlUiState,
    onStart: () -> Unit,
    // #7c — the native-WebRTC renderer for the live self-view PIP. Defaulted to the placeholder so
    // existing call sites / tests are unaffected.
    videoRenderer: VideoRenderer = PlaceholderVideoRenderer,
    // Bidirectional live-chat panel slot (host read + compose). Defaulted empty so existing call
    // sites / Compose tests that render the stateless surface without Hilt are unaffected.
    chatPanel: @Composable () -> Unit = {},
    // ADV2-106 - the Start ad break / countdown / End early control slot on the primary live screen.
    adBreakControls: @Composable () -> Unit = {},
    // LIVECOM L5 - the "Feature/Pin product" (shop this stream) control slot. Defaulted empty so existing
    // call sites / Compose tests that render the stateless surface without Hilt are unaffected.
    liveCommerceControls: @Composable () -> Unit = {},
    onStop: () -> Unit,
    onConfirmStop: (Boolean) -> Unit,
    onResume: () -> Unit,
    onReschedule: (Long) -> Unit,
    onRetryHealth: () -> Unit,
    onBack: () -> Unit,
    // AND-310 — open the inputs-management surface; defaulted so existing call sites/tests are unaffected.
    onManageInputs: () -> Unit = {},
    // AND-311 — open the layout-management surface; defaulted so existing call sites/tests are unaffected.
    onManageLayout: () -> Unit = {},
    // AND-312 — open the guest-management surface; defaulted so existing call sites/tests are unaffected.
    onManageGuests: () -> Unit = {},
    // AND-313 — open the chat-moderation log; receives creator id, defaulted so existing tests are unaffected.
    onModeration: (String) -> Unit = {},
    // AND-314 — open the goals + products authoring surface; defaulted so existing tests are unaffected.
    onManageGoalsProducts: () -> Unit = {},
    // AND-315 — open the tip-config editor; defaulted so existing call sites/tests are unaffected.
    onManageTips: () -> Unit = {},
    // AND-315 — open the private-show lifecycle surface; defaulted so existing call sites/tests are unaffected.
    onPrivateShows: () -> Unit = {},
    // AND-316 — open the ad-break / ad-config surface; defaulted so existing call sites/tests are unaffected.
    onManageAds: () -> Unit = {},
    onManageQa: () -> Unit = {},
) {
    Scaffold(
        modifier = Modifier.testTag(HostControlTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.host_control_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.broadcast_go_live_back_cd),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            StatusHeader(session = state.session)

            // #7c — live self-view PIP of the host's own camera while managing the broadcast. Renders the
            // running local track (published by the ingest preview/publisher) via the native renderer; the
            // renderer paints its own placeholder when no track is present yet.
            LocalVideoPreview(
                modifier = Modifier
                    .fillMaxWidth()
                    .aspectRatio(16f / 9f)
                    .testTag(HostControlTestTags.SELF_VIEW),
                hasTrack = true,
                renderer = videoRenderer,
            )

            HealthReportCard(
                health = state.health,
                stale = state.healthStale,
                onRetry = onRetryHealth,
            )

            state.transientError?.let { message ->
                Text(
                    text = message,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }

            HostControlBar(
                state = state,
                onStart = onStart,
                onStop = onStop,
                onResume = onResume,
                onReschedule = onReschedule,
            )

            // ADV2-106 - Start ad break (+ live countdown / End early) on the PRIMARY live host screen.
            adBreakControls()

            // LIVECOM L5 - "Feature/Pin product" (shop this stream): pick own OR affiliate any product,
            // show the pinned list + unpin.
            liveCommerceControls()

            // Bidirectional live chat (read + compose) for the host, alongside the moderation controls.
            chatPanel()

            // AND-310 — manage this broadcast's inputs (list / activate / promote to live program).
            OutlinedButton(
                onClick = onManageInputs,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag(HostControlTestTags.MANAGE_INPUTS),
            ) {
                Text(stringResource(R.string.host_control_manage_inputs))
            }

            // AND-311 — manage this broadcast's composition layout (single / side_by_side / pip / grid).
            OutlinedButton(
                onClick = onManageLayout,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag(HostControlTestTags.MANAGE_LAYOUT),
            ) {
                Text(stringResource(R.string.host_control_manage_layout))
            }

            // AND-312 — manage this broadcast's co-broadcast guests (invite / promote / mute / remove).
            OutlinedButton(
                onClick = onManageGuests,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag(HostControlTestTags.MANAGE_GUESTS),
            ) {
                Text(stringResource(R.string.host_control_manage_guests))
            }

            // AND-313 — moderate this broadcast's chat (mute / ban / delete / pin) + view the moderation log.
            OutlinedButton(
                onClick = { onModeration(state.session?.createdBy.orEmpty()) },
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag(HostControlTestTags.MODERATION),
            ) {
                Text(stringResource(R.string.host_control_moderation))
            }

            // AND-314 — manage this broadcast's tip goals + featured products (create / add / price / reorder).
            OutlinedButton(
                onClick = onManageGoalsProducts,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag(HostControlTestTags.MANAGE_GOALS_PRODUCTS),
            ) {
                Text(stringResource(R.string.host_control_manage_goals_products))
            }

            // AND-315 — edit this broadcast's tip-config (allow tips + min/max bounds).
            OutlinedButton(
                onClick = onManageTips,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag(HostControlTestTags.MANAGE_TIPS),
            ) {
                Text(stringResource(R.string.host_control_manage_tips))
            }

            // AND-315 — manage incoming private-show requests + the active private show.
            OutlinedButton(
                onClick = onPrivateShows,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag(HostControlTestTags.PRIVATE_SHOWS),
            ) {
                Text(stringResource(R.string.host_control_private_shows))
            }

            // AND-316 — trigger / end ad breaks + edit the ad-config (pre-roll + mid-roll bounds).
            OutlinedButton(
                onClick = onManageAds,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag(HostControlTestTags.MANAGE_ADS),
            ) {
                Text(stringResource(R.string.host_control_manage_ads))
            }

            // Live Q&A host console: toggle Q&A mode, moderate the question queue (feature / answer /
            // dismiss / pin / remove), view engagement stats.
            OutlinedButton(
                onClick = onManageQa,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag(HostControlTestTags.MANAGE_QA),
            ) {
                Text(stringResource(R.string.host_control_manage_qa))
            }
        }
    }

    if (state.showStopConfirm) {
        AlertDialog(
            modifier = Modifier.testTag(HostControlTestTags.STOP_CONFIRM),
            onDismissRequest = { onConfirmStop(false) },
            title = { Text(stringResource(R.string.host_control_stop_confirm_title)) },
            text = { Text(stringResource(R.string.host_control_stop_confirm_body)) },
            confirmButton = {
                TextButton(onClick = { onConfirmStop(true) }) {
                    Text(stringResource(R.string.host_control_stop_confirm_yes))
                }
            },
            dismissButton = {
                TextButton(onClick = { onConfirmStop(false) }) {
                    Text(stringResource(R.string.host_control_stop_confirm_no))
                }
            },
        )
    }
}

/** Status header: name + a status chip + a 1s-ticking LIVE timer derived from startedAt. */
@Composable
private fun StatusHeader(session: BroadcastSession?) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            text = session?.name ?: stringResource(R.string.host_control_untitled),
            style = MaterialTheme.typography.titleLarge,
        )
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            val status = session?.status ?: BroadcastSessionStatus.UNKNOWN
            AssistChip(
                onClick = {},
                modifier = Modifier.testTag(HostControlTestTags.STATUS_CHIP),
                label = { Text(status.label()) },
            )
            val startedAt = session?.startedAt
            if (status == BroadcastSessionStatus.LIVE && startedAt != null) {
                LiveTimer(startedAt = startedAt)
            }
        }
    }
}

/** A 1s-tick elapsed timer (HH:MM:SS) since [startedAt], driven by a produceState loop. */
@Composable
private fun LiveTimer(startedAt: Instant) {
    val now by produceState(initialValue = Instant.now(), startedAt) {
        while (true) {
            value = Instant.now()
            delay(1_000)
        }
    }
    val elapsed = Duration.between(startedAt, now).coerceAtLeast(Duration.ZERO)
    val text = "%02d:%02d:%02d".format(elapsed.toHours(), elapsed.toMinutesPart(), elapsed.toSecondsPart())
    Text(
        text = stringResource(R.string.host_control_live_for, text),
        style = MaterialTheme.typography.bodyMedium,
    )
}

/** Maps a lifecycle status to a localized chip label. */
@Composable
private fun BroadcastSessionStatus.label(): String = stringResource(
    when (this) {
        BroadcastSessionStatus.DRAFT -> R.string.host_control_status_draft
        BroadcastSessionStatus.SCHEDULED -> R.string.host_control_status_scheduled
        BroadcastSessionStatus.PROVISIONING -> R.string.host_control_status_provisioning
        BroadcastSessionStatus.READY -> R.string.host_control_status_ready
        BroadcastSessionStatus.LIVE -> R.string.host_control_status_live
        BroadcastSessionStatus.STOPPING -> R.string.host_control_status_stopping
        BroadcastSessionStatus.STOPPED -> R.string.host_control_status_stopped
        BroadcastSessionStatus.CANCELLED -> R.string.host_control_status_cancelled
        BroadcastSessionStatus.ERROR -> R.string.host_control_status_error
        BroadcastSessionStatus.UNKNOWN -> R.string.host_control_status_unknown
    },
)

/**
 * Health card: bitrate / fps / dropped% / viewer count + a health badge, with a "stale as of <updatedAt>"
 * banner when [stale]. The metrics region is an aria-live Polite region so screen readers announce updates.
 */
@Composable
private fun HealthReportCard(
    health: HostHealthReport?,
    stale: Boolean,
    onRetry: () -> Unit,
) {
    Card(modifier = Modifier
        .fillMaxWidth()
        .testTag(HostControlTestTags.HEALTH_CARD)) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = stringResource(R.string.host_control_health_title),
                style = MaterialTheme.typography.titleMedium,
            )

            if (health == null) {
                Text(
                    text = stringResource(R.string.host_control_health_none),
                    style = MaterialTheme.typography.bodyMedium,
                )
            } else {
                val numberFormat = remember { NumberFormat.getInstance() }
                val percentFormat = remember {
                    NumberFormat.getPercentInstance().apply { maximumFractionDigits = 1 }
                }
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .semantics { liveRegion = LiveRegionMode.Polite },
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Text(stringResource(R.string.host_control_health_badge, health.level.label()))
                    Text(
                        stringResource(
                            R.string.host_control_health_bitrate,
                            numberFormat.format(health.ingestBitrateKbps),
                        ),
                    )
                    Text(
                        stringResource(
                            R.string.host_control_health_fps,
                            numberFormat.format(health.ingestFramerate),
                        ),
                    )
                    Text(
                        stringResource(
                            R.string.host_control_health_dropped,
                            percentFormat.format(health.droppedFramesPct / 100.0),
                        ),
                    )
                    Text(
                        stringResource(
                            R.string.host_control_health_viewers,
                            numberFormat.format(health.viewerCount),
                        ),
                    )
                }

                if (stale) {
                    val formatter = remember {
                        DateTimeFormatter.ofLocalizedDateTime(FormatStyle.SHORT)
                            .withZone(ZoneId.systemDefault())
                    }
                    Text(
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag(HostControlTestTags.STALE_BANNER),
                        text = stringResource(
                            R.string.host_control_health_stale,
                            formatter.format(health.updatedAt),
                        ),
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                    TextButton(onClick = onRetry) {
                        Text(stringResource(R.string.host_control_health_retry))
                    }
                }
            }
        }
    }
}

/** Maps a [HealthLevel] to a localized label. */
@Composable
private fun HealthLevel.label(): String = stringResource(
    when (this) {
        HealthLevel.HEALTHY -> R.string.host_control_level_healthy
        HealthLevel.DEGRADED -> R.string.host_control_level_degraded
        HealthLevel.UNHEALTHY -> R.string.host_control_level_unhealthy
        HealthLevel.UNKNOWN -> R.string.host_control_level_unknown
    },
)

/**
 * The control bar: Start / Stop / Resume / Reschedule. Each button's enablement comes from
 * [HostControlPolicy] for the current status; the WHOLE bar is disabled while an action is in flight, and
 * the in-flight button shows a [CircularProgressIndicator].
 */
@Composable
private fun HostControlBar(
    state: HostControlUiState,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onResume: () -> Unit,
    onReschedule: (Long) -> Unit,
) {
    val status = state.session?.status ?: BroadcastSessionStatus.UNKNOWN
    val barEnabled = state.inFlight == null
    var showReschedulePicker by remember { mutableStateOf(false) }

    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        ActionButton(
            tag = HostControlTestTags.START,
            label = stringResource(R.string.host_control_start),
            cd = stringResource(R.string.host_control_start_cd),
            enabled = barEnabled && HostControlPolicy.canStart(status),
            loading = state.inFlight == HostAction.START,
            onClick = onStart,
        )
        ActionButton(
            tag = HostControlTestTags.STOP,
            label = stringResource(R.string.host_control_stop),
            cd = stringResource(R.string.host_control_stop_cd),
            enabled = barEnabled && HostControlPolicy.canStop(status),
            loading = state.inFlight == HostAction.STOP,
            outlined = true,
            onClick = onStop,
        )
        ActionButton(
            tag = HostControlTestTags.RESUME,
            label = stringResource(R.string.host_control_resume),
            cd = stringResource(R.string.host_control_resume_cd),
            enabled = barEnabled && HostControlPolicy.canResume(status, state.resumable),
            loading = state.inFlight == HostAction.RESUME,
            onClick = onResume,
        )
        ActionButton(
            tag = HostControlTestTags.RESCHEDULE,
            label = stringResource(R.string.host_control_reschedule),
            cd = stringResource(R.string.host_control_reschedule_cd),
            enabled = barEnabled && HostControlPolicy.canReschedule(status),
            loading = state.inFlight == HostAction.RESCHEDULE,
            outlined = true,
            onClick = { showReschedulePicker = true },
        )
    }

    if (showReschedulePicker) {
        RescheduleDialog(
            onDismiss = { showReschedulePicker = false },
            onConfirm = { epochSeconds ->
                showReschedulePicker = false
                onReschedule(epochSeconds)
            },
        )
    }
}

/** A single 48dp-min control button with a content description and an optional in-flight spinner. */
@Composable
private fun ActionButton(
    tag: String,
    label: String,
    cd: String,
    enabled: Boolean,
    loading: Boolean,
    outlined: Boolean = false,
    onClick: () -> Unit,
) {
    val modifier = Modifier
        .fillMaxWidth()
        .heightIn(min = 48.dp)
        .testTag(tag)
        .semantics { contentDescription = cd }
    val content: @Composable () -> Unit = {
        if (loading) {
            CircularProgressIndicator(modifier = Modifier.size(20.dp))
        } else {
            Text(label)
        }
    }
    if (outlined) {
        OutlinedButton(onClick = onClick, enabled = enabled, modifier = modifier) { content() }
    } else {
        Button(onClick = onClick, enabled = enabled, modifier = modifier) { content() }
    }
}

/**
 * A DatePicker + TimePicker pair that resolves to a Unix epoch-SECOND instant (local zone). Two-stage: pick
 * the date, then the time; confirming the time emits the combined epoch seconds.
 */
@Composable
private fun RescheduleDialog(
    onDismiss: () -> Unit,
    onConfirm: (Long) -> Unit,
) {
    var pickedDate by remember { mutableStateOf<LocalDate?>(null) }
    val datePickerState = rememberDatePickerState()
    val timePickerState = rememberTimePickerState(is24Hour = false)

    if (pickedDate == null) {
        DatePickerDialog(
            onDismissRequest = onDismiss,
            confirmButton = {
                TextButton(
                    onClick = {
                        val millis = datePickerState.selectedDateMillis
                        if (millis != null) {
                            pickedDate = Instant.ofEpochMilli(millis)
                                .atZone(ZoneOffset.UTC)
                                .toLocalDate()
                        }
                    },
                ) { Text(stringResource(R.string.host_control_reschedule_next)) }
            },
            dismissButton = {
                TextButton(onClick = onDismiss) {
                    Text(stringResource(R.string.host_control_stop_confirm_no))
                }
            },
        ) {
            DatePicker(state = datePickerState)
        }
    } else {
        val date = pickedDate!!
        DatePickerDialog(
            onDismissRequest = onDismiss,
            confirmButton = {
                TextButton(
                    onClick = {
                        val dateTime = LocalDateTime.of(
                            date,
                            LocalTime.of(timePickerState.hour, timePickerState.minute),
                        )
                        val epochSeconds = dateTime.atZone(ZoneId.systemDefault()).toEpochSecond()
                        onConfirm(epochSeconds)
                    },
                ) { Text(stringResource(R.string.host_control_reschedule_confirm)) }
            },
            dismissButton = {
                TextButton(onClick = onDismiss) {
                    Text(stringResource(R.string.host_control_stop_confirm_no))
                }
            },
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                TimePicker(state = timePickerState)
            }
        }
    }
}


/**
 * Host live-chat section: a labelled LiveChatPanel keyed by the broadcast [sessionId]. Reuses the exact
 * viewer panel + LiveChatViewModel so the host reads the live chat and posts messages through the same
 * send path (attributed to the host = session creator). The panel poll backstop keeps it usable even
 * when the SSE will not connect on-device.
 */
@Composable
private fun HostLiveChatSection(sessionId: String) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            text = stringResource(R.string.live_chat_title),
            style = MaterialTheme.typography.titleMedium,
        )
        LiveChatPanel(
            sessionId = sessionId,
            isHost = true,
            modifier = Modifier
                .fillMaxWidth()
                .testTag(HostControlTestTags.LIVE_CHAT),
        )
    }
}

/**
 * ADV2-106 - the "Start ad break" control (+ live countdown / End early) surfaced on the PRIMARY live host
 * screen, reusing [AdControlViewModel.triggerAdBreak]/[endAdBreak]. The VM shares the host route's
 * NavBackStackEntry (same "sessionId" arg), so no extra nav wiring is needed. Backend guardrails (min
 * interval + max breaks/session, ADV2-104) surface as a transient error under the button.
 */
@Composable
private fun HostAdBreakSection(vm: AdControlViewModel = hiltViewModel()) {
    val s by vm.uiState.collectAsStateWithLifecycle()
    Card(modifier = Modifier.fillMaxWidth().testTag(HostControlTestTags.AD_BREAK_CARD)) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = stringResource(R.string.host_ad_break_title),
                style = MaterialTheme.typography.titleMedium,
            )
            if (s.adBreakActive) {
                Text(
                    text = stringResource(R.string.host_ad_break_active, s.remainingSeconds),
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                )
                OutlinedButton(
                    onClick = vm::endAdBreak,
                    enabled = !s.mutationInFlight,
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .testTag(HostControlTestTags.AD_BREAK_END),
                ) {
                    if (s.mutationInFlight) {
                        CircularProgressIndicator(modifier = Modifier.size(20.dp))
                    } else {
                        Text(stringResource(R.string.host_ad_break_end))
                    }
                }
            } else {
                Button(
                    onClick = vm::triggerAdBreak,
                    enabled = !s.mutationInFlight && !s.loading,
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .testTag(HostControlTestTags.AD_BREAK_START),
                ) {
                    if (s.mutationInFlight) {
                        CircularProgressIndicator(modifier = Modifier.size(20.dp))
                    } else {
                        Text(stringResource(R.string.host_ad_break_start))
                    }
                }
            }
            s.error?.let { msg ->
                Text(
                    text = msg,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}
