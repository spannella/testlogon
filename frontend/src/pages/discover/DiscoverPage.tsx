import { useState, useCallback } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { FollowButton } from "@/components/shared/FollowButton";
import { EmptyState } from "@/components/shared/EmptyState";
import { Compass, Hash, Search, TrendingUp, Users } from "lucide-react";
import {
  searchDiscoverUsers,
  getSuggestedUsers,
  getTrendingCreators,
  getTrendingTags,
  type DiscoveryUser,
} from "@/api/endpoints/discovery";

function UserCard({ user }: { user: DiscoveryUser }) {
  const initials = (user.display_name || user.user_id)
    .split(" ")
    .map((w) => w[0])
    .join("")
    .toUpperCase()
    .slice(0, 2);

  return (
    <div className="flex items-center gap-3 rounded-lg border p-3">
      <Avatar className="h-10 w-10">
        {user.profile_photo_url && <AvatarImage src={user.profile_photo_url} />}
        <AvatarFallback>{initials}</AvatarFallback>
      </Avatar>
      <div className="flex-1 min-w-0">
        <p className="font-medium text-sm truncate">{user.display_name}</p>
        {user.description && (
          <p className="text-xs text-muted-foreground truncate">{user.description}</p>
        )}
        <p className="text-xs text-muted-foreground">
          {user.follower_count.toLocaleString()} followers
        </p>
      </div>
      <FollowButton
        targetUserId={user.user_id}
        isFollowing={user.is_following}
        size="sm"
      />
    </div>
  );
}


export default function DiscoverPage() {
  const [query, setQuery] = useState("");
  const [debouncedQuery, setDebouncedQuery] = useState("");

  const handleQueryChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const v = e.target.value;
    setQuery(v);
    if (window.__discoverTimeout) clearTimeout(window.__discoverTimeout);
    window.__discoverTimeout = setTimeout(() => setDebouncedQuery(v.trim()), 300);
  }, []);

  const searchEnabled = debouncedQuery.length >= 1;

  const { data: searchResults, isLoading: searchLoading } = useQuery({
    queryKey: ["discover-search", debouncedQuery],
    queryFn: () => searchDiscoverUsers(debouncedQuery),
    enabled: searchEnabled,
  });

  const { data: suggested } = useQuery({
    queryKey: ["discover-suggested"],
    queryFn: () => getSuggestedUsers(12),
  });

  const { data: trending } = useQuery({
    queryKey: ["discover-trending"],
    queryFn: () => getTrendingCreators(20),
  });

  const { data: trendingTags } = useQuery({
    queryKey: ["discover", "trending-tags"],
    queryFn: () => getTrendingTags(20),
    staleTime: 300_000,
  });

  return (
    <div className="container max-w-3xl py-6 space-y-6">
      <div className="flex items-center gap-2">
        <Compass className="h-6 w-6" />
        <h1 className="text-2xl font-bold">Discover</h1>
      </div>

      <div className="relative">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder="Search users..."
          value={query}
          onChange={handleQueryChange}
          className="pl-10"
        />
      </div>

      {searchEnabled ? (
        <Card>
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Search className="h-4 w-4" />
              Search Results
            </CardTitle>
          </CardHeader>
          <CardContent>
            {searchLoading ? (
              <p className="text-sm text-muted-foreground">Searching...</p>
            ) : searchResults?.items.length ? (
              <div className="space-y-2">
                {searchResults.items.map((user) => (
                  <UserCard key={user.user_id} user={user} />
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">No users found</p>
            )}
          </CardContent>
        </Card>
      ) : (
        <>
          {(trendingTags?.tags ?? []).length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Hash className="h-4 w-4" />
                  Trending Tags
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-2">
                  {(trendingTags?.tags ?? []).map((t) => (
                    <Link key={t.tag} to={`/discover/tags/${t.tag}`}>
                      <Badge variant="outline" className="cursor-pointer hover:bg-accent">
                        #{t.tag} ({t.count})
                      </Badge>
                    </Link>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Users className="h-4 w-4" />
                Suggested For You
              </CardTitle>
            </CardHeader>
            <CardContent>
              {suggested?.items.length ? (
                <div className="space-y-2">
                  {suggested.items.map((user) => (
                    <UserCard key={user.user_id} user={user} />
                  ))}
                </div>
              ) : (
                <EmptyState
                  icon={<Users className="h-7 w-7" />}
                  title="No suggestions yet"
                  description="Follow creators and engage with posts to get personalized suggestions."
                  className="py-10"
                />
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <TrendingUp className="h-4 w-4" />
                Trending Creators
              </CardTitle>
            </CardHeader>
            <CardContent>
              {trending?.items.length ? (
                <div className="space-y-2">
                  {trending.items.map((user) => (
                    <UserCard key={user.user_id} user={user} />
                  ))}
                </div>
              ) : (
                <EmptyState
                  icon={<TrendingUp className="h-7 w-7" />}
                  title="No trending creators yet"
                  description="Trending creators appear here as the community grows — check back soon."
                  className="py-10"
                />
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}

declare global {
  interface Window {
    __discoverTimeout?: ReturnType<typeof setTimeout>;
  }
}
