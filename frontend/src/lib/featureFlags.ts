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
