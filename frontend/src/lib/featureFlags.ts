const env = (import.meta as any).env ?? {};

const toBool = (value: unknown, fallback = false): boolean => {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (["1", "true", "yes", "on"].includes(normalized)) return true;
    if (["0", "false", "no", "off"].includes(normalized)) return false;
  }
  return fallback;
};

/**
 * Feature toggle for password-encrypted messaging UI.
 * Default is OFF unless explicitly enabled per environment.
 */
export const messagingEncryptedMessagesEnabled = toBool(env.VITE_MESSAGING_ENCRYPTED_MESSAGES_ENABLED, false);

/**
 * Emergency kill switch to disable encrypted messaging behavior without redeploying code.
 */
export const messagingEncryptedMessagesKillSwitch = toBool(env.VITE_MESSAGING_ENCRYPTED_MESSAGES_KILL_SWITCH, false);

export const isMessagingEncryptionEnabled = () =>
  messagingEncryptedMessagesEnabled && !messagingEncryptedMessagesKillSwitch;


export const messagingGalleryEnabled = toBool(env.VITE_MESSAGING_GALLERY_ENABLED, true);
export const messagingGalleryKillSwitch = toBool(env.VITE_MESSAGING_GALLERY_KILL_SWITCH, false);
export const isMessagingGalleryEnabled = () => messagingGalleryEnabled && !messagingGalleryKillSwitch;
export const messagingDmLotteryEnabled = toBool(env.VITE_MESSAGING_DM_LOTTERY_ENABLED, false);
export const messagingDmLotteryKillSwitch = toBool(env.VITE_MESSAGING_DM_LOTTERY_KILL_SWITCH, false);
export const isMessagingDmLotteryEnabled = () => messagingDmLotteryEnabled && !messagingDmLotteryKillSwitch;

// Messenger Voice & AI (MVA). These mirror the server-side feature flags
// (messaging_translation_enabled / messaging_transcription_enabled /
// messaging_tts_enabled). They gate whether the UI shows the action; the
// server still authoritatively 404s the endpoint when its flag is off, which
// the UI surfaces as a toast. Translation defaults on (server default true);
// transcription/TTS default off (server default false until keys configured).
export const messagingTranslationEnabled = toBool(env.VITE_MESSAGING_TRANSLATION_ENABLED, true);
export const isMessagingTranslationEnabled = () => messagingTranslationEnabled;
export const messagingTranscriptionEnabled = toBool(env.VITE_MESSAGING_TRANSCRIPTION_ENABLED, false);
export const isMessagingTranscriptionEnabled = () => messagingTranscriptionEnabled;
export const messagingTtsEnabled = toBool(env.VITE_MESSAGING_TTS_ENABLED, false);
export const isMessagingTtsEnabled = () => messagingTtsEnabled;
// Default target language for one-click translate (BCP-47).
export const messagingTranslationDefaultLang = String(
  env.VITE_MESSAGING_TRANSLATION_DEFAULT_LANG ?? "en",
).trim() || "en";

export const messagingWebrtcDirectCallEnabled = toBool(env.VITE_MESSAGING_WEBRTC_DIRECT_CALL_ENABLED, false);
export const messagingWebrtcDirectCallKillSwitch = toBool(env.VITE_MESSAGING_WEBRTC_DIRECT_CALL_KILL_SWITCH, false);
export const messagingWebrtcDirectCallMode = String(env.VITE_MESSAGING_WEBRTC_DIRECT_CALL_MODE ?? "enabled").trim().toLowerCase();

const csvSet = (value: unknown): Set<string> => {
  if (typeof value !== "string") return new Set<string>();
  return new Set(
    value
      .split(",")
      .map((part) => part.trim())
      .filter((part) => part.length > 0),
  );
};

const webrtcEnabledTenantIds = csvSet(env.VITE_MESSAGING_WEBRTC_DIRECT_CALL_ENABLED_TENANT_IDS);
const webrtcInternalTenantIds = csvSet(env.VITE_MESSAGING_WEBRTC_DIRECT_CALL_INTERNAL_TENANT_IDS ?? "internal");
const webrtcEnabledCohorts = new Set(Array.from(csvSet(env.VITE_MESSAGING_WEBRTC_DIRECT_CALL_ENABLED_COHORTS)).map((v) => v.toLowerCase()));

export const isMessagingWebrtcDirectCallEnabled = (params?: { tenantId?: string | null; cohort?: string | null }) => {
  if (!messagingWebrtcDirectCallEnabled || messagingWebrtcDirectCallKillSwitch) return false;

  if (["enabled", "on", "true", "1"].includes(messagingWebrtcDirectCallMode)) return true;
  if (["disabled", "off", "false", "0", ""].includes(messagingWebrtcDirectCallMode)) return false;

  const tenantId = (params?.tenantId ?? env.VITE_TENANT_ID ?? "").toString().trim();
  const cohort = (params?.cohort ?? env.VITE_ROLLOUT_COHORT ?? "").toString().trim().toLowerCase();

  if (["internal", "pilot_internal"].includes(messagingWebrtcDirectCallMode)) {
    return tenantId.length > 0 && webrtcInternalTenantIds.has(tenantId);
  }

  if (["selective", "tenant", "cohort"].includes(messagingWebrtcDirectCallMode)) {
    const tenantAllowed = tenantId.length > 0 && webrtcEnabledTenantIds.has(tenantId);
    const cohortAllowed = cohort.length > 0 && webrtcEnabledCohorts.has(cohort);

    if (webrtcEnabledTenantIds.size > 0 && webrtcEnabledCohorts.size > 0) {
      return tenantAllowed || cohortAllowed;
    }
    if (webrtcEnabledTenantIds.size > 0) return tenantAllowed;
    if (webrtcEnabledCohorts.size > 0) return cohortAllowed;
    return false;
  }

  return false;
};
export const messagingOnceMediaComposerEnabled = toBool(env.VITE_CLIENT_ONCE_MEDIA_COMPOSER_ENABLED, true);
export const messagingOnceMediaImageEnabled = toBool(env.VITE_MESSAGING_ONCE_MEDIA_IMAGE_ENABLED, true);
export const messagingOnceMediaVideoEnabled = toBool(env.VITE_MESSAGING_ONCE_MEDIA_VIDEO_ENABLED, true);
export const messagingOnceMediaAudioEnabled = toBool(env.VITE_MESSAGING_ONCE_MEDIA_AUDIO_ENABLED, true);

export const isMessagingOnceMediaComposerEnabled = () => messagingOnceMediaComposerEnabled;
export const isMessagingViewOnceImageEnabled = () => isMessagingOnceMediaComposerEnabled() && messagingOnceMediaImageEnabled;
export const isMessagingViewOnceVideoEnabled = () => isMessagingOnceMediaComposerEnabled() && messagingOnceMediaVideoEnabled;
export const isMessagingListenOnceAudioEnabled = () => isMessagingOnceMediaComposerEnabled() && messagingOnceMediaAudioEnabled;

export const messagingDraftsEnabled = toBool(env.VITE_MESSAGING_DRAFTS_ENABLED, true);
export const messagingDraftsKillSwitch = toBool(env.VITE_MESSAGING_DRAFTS_KILL_SWITCH, false);
export const isMessagingDraftsEnabled = () => messagingDraftsEnabled && !messagingDraftsKillSwitch;


export const devtoolsLogUiEnabled = toBool(env.VITE_ENABLE_DEVTOOLS_LOG_UI, false);
export const isDevtoolsLogUiEnabled = () => devtoolsLogUiEnabled;

export const newsfeedMarkdownEnabled = toBool(env.VITE_NEWSFEED_MARKDOWN_ENABLED, false);
export const newsfeedRichtextEnabled = toBool(env.VITE_NEWSFEED_RICHTEXT_ENABLED, false);
export const newsfeedDraftsEnabled = toBool(env.VITE_NEWSFEED_DRAFTS_ENABLED, true);
export const newsfeedDraftsKillSwitch = toBool(env.VITE_NEWSFEED_DRAFTS_KILL_SWITCH, false);
export const isNewsfeedDraftsEnabled = () => newsfeedDraftsEnabled && !newsfeedDraftsKillSwitch;
export const newsfeedSchedulingUiEnabled = toBool(env.VITE_NEWSFEED_SCHEDULING_UI_ENABLED, true);

// NRS-011: "For You" ranked-feed tab. Gates the visible tab bar in the newsfeed.
// Defaults OFF so removing the flag reverts cleanly to the chronological feed.
// The server still authoritatively falls back to chronological when
// NEWSFEED_RECSYS_ENABLED is off (the For You request never errors).
export const newsfeedRecsysUiEnabled = toBool(env.VITE_NEWSFEED_RECSYS_UI_ENABLED, false);
export const isNewsfeedRecsysUiEnabled = () => newsfeedRecsysUiEnabled;
export const profilePostsFeedEnabled = toBool(env.VITE_PROFILE_POSTS_FEED_ENABLED, true);
export const profilePostsFeedKillSwitch = toBool(env.VITE_PROFILE_POSTS_FEED_KILL_SWITCH, false);
export const isProfilePostsFeedEnabled = () => profilePostsFeedEnabled && !profilePostsFeedKillSwitch;

export const canonicalProfileNavigationEnabled = toBool(env.VITE_CANONICAL_PROFILE_NAVIGATION_ENABLED, false);
export const isCanonicalProfileNavigationEnabled = () => canonicalProfileNavigationEnabled;

export const vncRemoteDesktopEnabled = toBool(env.VITE_VNC_REMOTE_DESKTOP_ENABLED, true);
export const vncRemoteDesktopKillSwitch = toBool(env.VITE_VNC_REMOTE_DESKTOP_KILL_SWITCH, false);
export const isVncRemoteDesktopEnabled = () => vncRemoteDesktopEnabled && !vncRemoteDesktopKillSwitch;

// Browser SSH terminal (xterm) — the interactive in-browser SSH page (CTI).
export const browserSshEnabled = toBool(env.VITE_BROWSER_SSH_ENABLED, true);
export const isBrowserSshEnabled = () => browserSshEnabled;

// Agent SSH QA actions panel (ADR-003 / AQA). Default OFF — mirrors the backend
// AGENT_SSH_QA_ENABLED master flag. With it off the QA Actions page/route/nav
// entry are hidden and the backend router is not registered.
export const agentSshQaEnabled = toBool(env.VITE_AGENT_SSH_QA_ENABLED, false);
export const isAgentSshQaEnabled = () => agentSshQaEnabled;

// RDP browser transport (ADR-004 / CTI-005). Phase 1 ships only the fallback
// /remote/rdp instructions page; native in-browser RDP is a future milestone.
// Default OFF — mirrors backend RDP_REMOTE_DESKTOP_ENABLED. With it off the
// page shows "RDP not available — use VNC/SSH"; the fallback metadata surface
// is always available so Windows hosts never dead-end in the SSH form.
export const rdpRemoteDesktopEnabled = toBool(env.VITE_RDP_REMOTE_DESKTOP_ENABLED, false);
export const isRdpRemoteDesktopEnabled = () => rdpRemoteDesktopEnabled;

export const broadcastNavigationEnabled = toBool(env.VITE_BROADCAST_NAVIGATION_ENABLED, true);
export const broadcastNavigationKillSwitch = toBool(env.VITE_BROADCAST_NAVIGATION_KILL_SWITCH, false);
export const isBroadcastNavigationEnabled = () =>
  broadcastNavigationEnabled && !broadcastNavigationKillSwitch;

export const googleCalendarSyncEnabled = toBool(env.VITE_GOOGLE_CALENDAR_SYNC_ENABLED, false);
export const googleCalendarWritebackEnabled = toBool(env.VITE_GOOGLE_CALENDAR_WRITEBACK_ENABLED, false);
export const isGoogleCalendarSyncEnabled = () => googleCalendarSyncEnabled;
export const isGoogleCalendarWritebackEnabled = () =>
  isGoogleCalendarSyncEnabled() && googleCalendarWritebackEnabled;

export const callRecordingEnabled = toBool(env.VITE_CALL_RECORDING_ENABLED, false);
export const isCallRecordingEnabled = () => callRecordingEnabled;

export const groupCallsEnabled = toBool(env.VITE_GROUP_CALLS_ENABLED, true);
export const groupCallsKillSwitch = toBool(env.VITE_GROUP_CALLS_KILL_SWITCH, false);
export const isGroupCallsEnabled = () => groupCallsEnabled && !groupCallsKillSwitch;

// PWA Install Prompt
export const pwaInstallPromptEnabled = toBool(env.VITE_PWA_INSTALL_PROMPT_ENABLED, true);
export const pwaInstallPromptKillSwitch = toBool(env.VITE_PWA_INSTALL_PROMPT_KILL_SWITCH, false);
export const isPwaInstallPromptEnabled = () =>
  pwaInstallPromptEnabled && !pwaInstallPromptKillSwitch;
