// MSG-007: Render a single reaction key. Custom emoji reactions use the key
// format `custom:shortcode` and render as an inline <img>; Unicode reactions
// render as plain text.
import { useQuery } from "@tanstack/react-query";
import { resolveCustomShortcodes } from "@/api/endpoints/customEmojis";

export const CUSTOM_REACTION_PREFIX = "custom:";

export function isCustomReaction(key: string): boolean {
  return key.startsWith(CUSTOM_REACTION_PREFIX);
}

export function customReactionShortcode(key: string): string {
  return key.slice(CUSTOM_REACTION_PREFIX.length).toLowerCase();
}

export interface ReactionEmojiProps {
  reactionKey: string;
  className?: string;
}

export function ReactionEmoji({ reactionKey, className }: ReactionEmojiProps) {
  const custom = isCustomReaction(reactionKey);
  const shortcode = custom ? customReactionShortcode(reactionKey) : "";

  const { data } = useQuery({
    queryKey: ["custom-emoji-resolve", shortcode],
    queryFn: () => resolveCustomShortcodes([shortcode]),
    enabled: custom && shortcode.length > 0,
    staleTime: 10 * 60 * 1000,
  });

  if (!custom) {
    return <span className={className}>{reactionKey}</span>;
  }

  const url = data?.resolved?.[shortcode];
  if (!url) {
    // Unresolved (e.g. deleted) — show fallback text.
    return (
      <span className={className} data-custom-reaction-fallback={shortcode}>
        :{shortcode}:
      </span>
    );
  }
  return (
    <img
      src={url}
      alt={`:${shortcode}:`}
      title={`:${shortcode}:`}
      data-custom-reaction={shortcode}
      className="inline-block h-4 w-4 align-text-bottom"
    />
  );
}

export default ReactionEmoji;
