import { api } from "@/api/client";

export type AccentColor = "blue" | "purple" | "green" | "orange" | "pink" | "red" | "teal" | "custom";
export type FontSize = "small" | "default" | "large" | "xlarge";
export type Density = "compact" | "comfortable" | "spacious";

export interface UiPreferences {
  theme?: "system" | "light" | "dark";
  sidebar_collapsed?: boolean;
  accent_color?: AccentColor;
  custom_accent_hex?: string;
  font_size?: FontSize;
  density?: Density;
  high_contrast?: boolean;
}

export interface ValidateColorResponse {
  valid: boolean;
  contrast_light: number;
  contrast_dark: number;
  wcag_aa: boolean;
  wcag_aaa: boolean;
  suggestion: string | null;
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

/**
 * Validate a custom accent color hex and get contrast information.
 */
export const validateColor = async (hex: string): Promise<ValidateColorResponse> => {
  return api.post<ValidateColorResponse>("/ui/settings/validate-color", { hex });
};
