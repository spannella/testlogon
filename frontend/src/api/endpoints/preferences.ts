import { api } from "@/api/client";

export interface UiPreferences {
  theme?: "system" | "light" | "dark";
  sidebar_collapsed?: boolean;
}

/**
 * Fetch server-side UI preferences for the current user.
 * Returns an empty object if no preferences have been set.
 */
export const getPreferences = async (): Promise<UiPreferences> => {
  const resp = await api.get<{ preferences: UiPreferences }>("/ui/settings/preferences");
  return resp.preferences;
};

/**
 * Merge-update UI preferences on the server.
 * Fire-and-forget -- the frontend does not wait for this to complete
 * before applying the preference locally.
 */
export const patchPreferences = async (prefs: Partial<UiPreferences>): Promise<void> => {
  await api.patch("/ui/settings/preferences", prefs);
};
