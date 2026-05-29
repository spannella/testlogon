import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getMyAchievements,
  setDisplayBadges,
} from "@/api/endpoints/achievements";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { Check } from "lucide-react";
import { toast } from "sonner";

const RARITY_COLORS: Record<string, string> = {
  common: "bg-gray-100 text-gray-700 border-gray-300",
  uncommon: "bg-green-100 text-green-700 border-green-400",
  rare: "bg-blue-100 text-blue-700 border-blue-400",
  epic: "bg-purple-100 text-purple-700 border-purple-400",
  legendary: "bg-amber-100 text-amber-700 border-amber-400",
};

export function BadgeGrid() {
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["achievements", "mine"],
    queryFn: () => getMyAchievements(),
  });

  const displayMut = useMutation({
    mutationFn: (ids: string[]) => setDisplayBadges(ids),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["achievements"] });
      toast.success("Display badges updated");
    },
  });

  if (isLoading)
    return <div className="text-muted-foreground">Loading badges...</div>;

  const achievements = data?.achievements ?? [];

  const toggleDisplay = (achId: string) => {
    const current = achievements.filter((a) => a.displayed).map((a) => a.achievement_id);
    if (current.includes(achId)) {
      displayMut.mutate(current.filter((id) => id !== achId));
    } else if (current.length < 3) {
      displayMut.mutate([...current, achId]);
    } else {
      toast.error("Maximum 3 display badges");
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="text-sm text-muted-foreground">
          {data?.achievement_count ?? 0} badges earned /{" "}
          {data?.total_points ?? 0} total points
        </div>
      </div>

      {achievements.length === 0 ? (
        <p className="text-muted-foreground text-sm">No badges earned yet.</p>
      ) : (
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-4">
          {achievements.map((ach) => (
            <Card
              key={ach.achievement_id}
              className={cn(
                "cursor-pointer transition-all hover:shadow-md",
                ach.displayed && "ring-2 ring-primary",
              )}
              onClick={() => toggleDisplay(ach.achievement_id)}
            >
              <CardContent className="flex flex-col items-center p-4 text-center">
                <div className="h-12 w-12 mb-2 flex items-center justify-center text-2xl">
                  {ach.icon_url ? (
                    <img
                      src={ach.icon_url}
                      alt={ach.label}
                      className="h-12 w-12"
                    />
                  ) : (
                    "\u{1F3C6}"
                  )}
                </div>
                <span className="text-sm font-medium">{ach.label}</span>
                <Badge
                  className={cn("mt-1 text-xs", RARITY_COLORS[ach.rarity])}
                >
                  {ach.rarity}
                </Badge>
                <span className="text-xs text-muted-foreground mt-1">
                  +{ach.points} pts
                </span>
                {ach.displayed && (
                  <Check className="h-4 w-4 text-primary mt-1" />
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
