// Custom Emojis API (MSG-007)
import { api } from "@/api/client";
import type {
  CustomEmoji,
  CustomEmojiListOut,
  ResolveShortcodesOut,
} from "@/api/types";

export interface UploadCustomEmojiBody {
  shortcode: string;
  name: string;
  alt_text?: string;
  category?: string;
  file: File;
}

function buildForm(body: UploadCustomEmojiBody): FormData {
  const fd = new FormData();
  fd.append("shortcode", body.shortcode);
  fd.append("name", body.name);
  fd.append("alt_text", body.alt_text ?? "");
  fd.append("category", body.category ?? "Uncategorized");
  fd.append("file", body.file);
  return fd;
}

// ---- Personal emojis ----

export const uploadCustomEmoji = (body: UploadCustomEmojiBody) =>
  api.upload<CustomEmoji>("/ui/emojis/custom", buildForm(body));

export const listMyCustomEmojis = () =>
  api.get<CustomEmojiListOut>("/ui/emojis/custom");

export const deleteCustomEmoji = (emojiId: string) =>
  api.del<{ ok: boolean; emoji_id: string }>(`/ui/emojis/custom/${emojiId}`);

export const resolveCustomShortcodes = (codes: string[]) =>
  api.get<ResolveShortcodesOut>("/ui/emojis/custom/resolve", {
    codes: codes.join(","),
  });

// ---- Admin (global) emojis ----

export const uploadGlobalEmoji = (body: UploadCustomEmojiBody) =>
  api.upload<CustomEmoji>("/v1/admin/emojis", buildForm(body));

export const listGlobalEmojis = () =>
  api.get<CustomEmojiListOut>("/v1/admin/emojis");

export const deleteGlobalEmoji = (emojiId: string) =>
  api.del<{ ok: boolean; emoji_id: string }>(`/v1/admin/emojis/${emojiId}`);
