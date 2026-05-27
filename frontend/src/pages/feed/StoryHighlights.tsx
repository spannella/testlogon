import { useQuery } from "@tanstack/react-query";
import { getUserHighlights } from "@/api/endpoints/stories";
import type { StoryHighlightGroup } from "@/api/types";

interface StoryHighlightsProps {
  userId: string;
}

export function StoryHighlights({ userId }: StoryHighlightsProps) {
  const { data, isLoading } = useQuery({
    queryKey: ["stories", "highlights", userId],
    queryFn: () => getUserHighlights(userId),
  });

  const groups = data?.groups ?? [];

  if (isLoading || groups.length === 0) return null;

  return (
    <div className="space-y-3" data-testid="story-highlights">
      <h3 className="text-sm font-medium text-muted-foreground">Highlights</h3>
      <div className="flex gap-4 overflow-x-auto pb-2">
        {groups.map((group) => (
          <HighlightGroupItem key={group.highlight_group_id} group={group} />
        ))}
      </div>
    </div>
  );
}

function HighlightGroupItem({ group }: { group: StoryHighlightGroup }) {
  const coverUrl = group.cover_url || group.stories?.[0]?.media_url;

  return (
    <div className="flex shrink-0 flex-col items-center gap-1">
      <div className="h-16 w-16 overflow-hidden rounded-full border-2 border-muted bg-muted">
        {coverUrl ? (
          <img
            src={coverUrl}
            alt={group.title}
            className="h-full w-full object-cover"
          />
        ) : (
          <div className="flex h-full w-full items-center justify-center text-xs text-muted-foreground">
            {group.title.charAt(0).toUpperCase()}
          </div>
        )}
      </div>
      <span className="max-w-[64px] truncate text-xs text-muted-foreground">
        {group.title}
      </span>
    </div>
  );
}
