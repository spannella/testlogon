import { api } from "@/api/client";
import type {
  ThemeConfig,
  ThemeConfigPatch,
  ThemeConfigResponse,
} from "@/api/types";

/**
 * PLATFORM-013: Per-user theme customization API.
 *
 * Backend: /ui/theme (require_ui_session; CSRF for non-GET cookie requests).
 * Distinct from the legacy /ui/settings/preferences (UX-001) endpoints.
 */

/** Fetch the current user's saved theme config (server returns defaults if unset). */
export const getThemeCustomization = async (): Promise<ThemeConfig> => {
  const resp = await api.get<ThemeConfigResponse>("/ui/theme");
  return resp.theme;
};

/** Merge-update the theme config; returns the full resulting config. */
export const patchThemeCustomization = async (
  patch: ThemeConfigPatch,
): Promise<ThemeConfig> => {
  const resp = await api.patch<ThemeConfigResponse>("/ui/theme", patch);
  return resp.theme;
};

/** Reset the theme config to server defaults. */
export const resetThemeCustomization = async (): Promise<ThemeConfig> => {
  const resp = await api.del<ThemeConfigResponse>("/ui/theme");
  return resp.theme;
};
