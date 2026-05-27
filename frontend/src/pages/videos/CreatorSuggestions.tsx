import { useQuery } from "@tanstack/react-query";
import { Loader2, UserPlus } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { getCreatorSuggestions } from "@/api/endpoints/recommendations";

export default function CreatorSuggestions() {
  const q = useQuery({
    queryKey: ["recommendations", "creators"],
    queryFn: () => getCreatorSuggestions(10),
    staleTime: 30 * 60_000,
  });

  const creators = q.data?.creators ?? [];

  if (q.isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Creators You Might Like</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center py-4">
            <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
          </div>
        </CardContent>
      </Card>
    );
  }

  if (creators.length === 0) {
    return null;
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Creators You Might Like</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {creators.map((c) => (
          <div key={c.user_id} className="flex items-center gap-3">
            <Avatar className="h-10 w-10">
              {c.avatar_url && <AvatarImage src={c.avatar_url} alt={c.display_name} />}
              <AvatarFallback>{c.display_name.charAt(0).toUpperCase()}</AvatarFallback>
            </Avatar>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium truncate">{c.display_name}</p>
              <p className="text-xs text-muted-foreground">
                {c.subscriber_count} subscriber{c.subscriber_count !== 1 ? "s" : ""}
              </p>
            </div>
            <Button size="sm" variant="outline" className="gap-1">
              <UserPlus className="h-3 w-3" />
              Subscribe
            </Button>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
