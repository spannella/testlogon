import { api } from "@/api/client";
import type { MediaPreferencesIn, MediaPreferencesOut } from "@/api/types";

export const getMediaPreferences = () =>
  api.get<MediaPreferencesOut>("/ui/media/preferences");

export const saveMediaPreferences = (body: MediaPreferencesIn) =>
  api.put<MediaPreferencesOut>("/ui/media/preferences", body);
