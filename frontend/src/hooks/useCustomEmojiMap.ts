// MSG-007: Resolve custom emoji shortcodes found in a piece of text to image
// URLs. Caches per-text in React Query (staleTime 10m).
import { useQuery } from "@tanstack/react-query";
import { resolveCustomShortcodes } from "@/api/endpoints/customEmojis";
import { extractCustomShortcodes } from "@/utils/emoji";

export function useCustomEmojiMap(text: string | null | undefined): Record<string, string> {
  const codes = extractCustomShortcodes(text);
  const key = codes.slice().sort().join(",");
  const { data } = useQuery({
    queryKey: ["custom-emoji-resolve", key],
    queryFn: () => resolveCustomShortcodes(codes),
    enabled: codes.length > 0,
    staleTime: 10 * 60 * 1000,
  });
  return data?.resolved ?? {};
}
