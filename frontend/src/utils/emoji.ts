// MSG-006: Emoji utilities — shortcode replacement + emoji-only detection.
// These are pure string operations with no side effects, safe to call on every
// message send / render. The shortcode map is derived from the static emoji
// dataset (see frontend/src/data/emoji-data.ts).

import { SHORTCODE_MAP } from "@/data/emoji-data";

/**
 * Replace `:shortcode:` tokens in `text` with their Unicode emoji equivalents.
 * Unknown shortcodes are preserved verbatim. Called on the frontend before a
 * message/post is sent so the backend only ever sees Unicode characters.
 */
export function replaceShortcodes(text: string): string {
  if (!text) return text;
  return text.replace(/:([a-z0-9_+-]+):/gi, (match, code: string) => {
    return SHORTCODE_MAP.get(code.toLowerCase()) ?? match;
  });
}

// MSG-007: custom emoji shortcode helpers.
// A custom shortcode looks like `:my_cat:` where the inner text is [a-z0-9_]{2,32}.
const CUSTOM_SHORTCODE_RE = /:([a-z0-9_]{2,32}):/g;

/**
 * Extract the unique set of `:shortcode:` tokens present in `text` whose inner
 * value does NOT correspond to a built-in Unicode emoji. These are candidate
 * custom-emoji shortcodes that must be resolved server-side.
 */
export function extractCustomShortcodes(text: string | null | undefined): string[] {
  if (!text) return [];
  const out = new Set<string>();
  let m: RegExpExecArray | null;
  CUSTOM_SHORTCODE_RE.lastIndex = 0;
  while ((m = CUSTOM_SHORTCODE_RE.exec(text)) !== null) {
    const code = m[1].toLowerCase();
    if (!SHORTCODE_MAP.has(code)) out.add(code);
  }
  return Array.from(out);
}

export type CustomEmojiTextPart =
  | { type: "text"; value: string }
  | { type: "emoji"; shortcode: string; url: string };

/**
 * Split `text` into a sequence of plain-text and resolved custom-emoji parts.
 * `customEmojiMap` maps a shortcode -> image URL. Shortcodes not present in the
 * map are kept verbatim as text.
 */
export function splitCustomEmojiText(
  text: string,
  customEmojiMap: Record<string, string>,
): CustomEmojiTextPart[] {
  const parts: CustomEmojiTextPart[] = [];
  if (!text) return parts;
  let lastIndex = 0;
  let m: RegExpExecArray | null;
  CUSTOM_SHORTCODE_RE.lastIndex = 0;
  while ((m = CUSTOM_SHORTCODE_RE.exec(text)) !== null) {
    const code = m[1].toLowerCase();
    const url = customEmojiMap[code];
    if (!url) continue;
    if (m.index > lastIndex) {
      parts.push({ type: "text", value: text.slice(lastIndex, m.index) });
    }
    parts.push({ type: "emoji", shortcode: code, url });
    lastIndex = m.index + m[0].length;
  }
  if (lastIndex < text.length) {
    parts.push({ type: "text", value: text.slice(lastIndex) });
  }
  if (parts.length === 0) parts.push({ type: "text", value: text });
  return parts;
}

// Matches a single emoji "cluster" (base emoji + optional ZWJ-joined parts +
// optional variation selectors / skin-tone modifiers). The `u` flag enables
// Unicode property escapes.
const EMOJI_CLUSTER =
  "(?:\\p{Extended_Pictographic}(?:\\uFE0F|[\\u{1F3FB}-\\u{1F3FF}])?(?:\\u200D\\p{Extended_Pictographic}(?:\\uFE0F|[\\u{1F3FB}-\\u{1F3FF}])?)*)";

const EMOJI_SPLIT = new RegExp(EMOJI_CLUSTER, "gu");

/**
 * True when `text` consists solely of 1-3 emoji (with only whitespace allowed
 * between them). Used by MessageBubble / PostCard to render such messages at a
 * larger ("jumbo") size, matching mainstream messengers.
 */
export function isEmojiOnly(text: string | null | undefined): boolean {
  if (!text) return false;
  const trimmed = text.trim();
  if (!trimmed) return false;
  const emojis = trimmed.match(EMOJI_SPLIT);
  if (!emojis) return false;
  // Strip all emoji clusters; whatever remains must be empty (whitespace only).
  const remainder = trimmed.replace(EMOJI_SPLIT, "").trim();
  return remainder === "" && emojis.length >= 1 && emojis.length <= 3;
}
