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


export const vncRemoteDesktopEnabled = toBool(env.VITE_VNC_REMOTE_DESKTOP_ENABLED, true);
export const vncRemoteDesktopKillSwitch = toBool(env.VITE_VNC_REMOTE_DESKTOP_KILL_SWITCH, false);
export const isVncRemoteDesktopEnabled = () => vncRemoteDesktopEnabled && !vncRemoteDesktopKillSwitch;

export const googleCalendarSyncEnabled = toBool(env.VITE_GOOGLE_CALENDAR_SYNC_ENABLED, false);
export const googleCalendarWritebackEnabled = toBool(env.VITE_GOOGLE_CALENDAR_WRITEBACK_ENABLED, false);
export const isGoogleCalendarSyncEnabled = () => googleCalendarSyncEnabled;
export const isGoogleCalendarWritebackEnabled = () =>
  isGoogleCalendarSyncEnabled() && googleCalendarWritebackEnabled;
