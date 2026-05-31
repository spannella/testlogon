import { useState } from "react";
import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getActivityFeed,
  getActivityFeedFiltered,
  markActivitiesRead,
  getActivityUnreadCount,
} from "@/api/endpoints/activityFeed";
import { useQuery } from "@tanstack/react-query";
import type { ActivityItem } from "@/api/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Activity,
  UserPlus,
  Heart,
  MessageCircle,
  FileText,
  AtSign,
  Share2,
  DollarSign,
  CheckCheck,
  Loader2,
} from "lucide-react";

const ACTIVITY_TYPE_LABELS: Record<string, string> = {
  follow: "Follow",
  like: "Like",
  comment: "Comment",
  post: "Post",
  mention: "Mention",
  share: "Share",
  tip: "Tip",
};

const FILTER_TABS = [
  { key: "all", label: "All" },
  { key: "follow", label: "Follows" },
  { key: "like", label: "Likes" },
  { key: "comment", label: "Comments" },
  { key: "post", label: "Posts" },
  { key: "mention", label: "Mentions" },
  { key: "share", label: "Shares" },
  { key: "tip", label: "Tips" },
];

function activityIcon(type: string) {
  switch (type) {
    case "follow":
      return <UserPlus className="h-4 w-4 text-blue-500" />;
    case "like":
      return <Heart className="h-4 w-4 text-red-500" />;
    case "comment":
      return <MessageCircle className="h-4 w-4 text-green-500" />;
    case "post":
      return <FileText className="h-4 w-4 text-purple-500" />;
    case "mention":
      return <AtSign className="h-4 w-4 text-orange-500" />;
    case "share":
      return <Share2 className="h-4 w-4 text-cyan-500" />;
    case "tip":
      return <DollarSign className="h-4 w-4 text-yellow-500" />;
    default:
      return <Activity className="h-4 w-4 text-muted-foreground" />;
  }
}

function formatTimestamp(ts: number): string {
  if (!ts) return "";
  const d = new Date(ts * 1000);
  const now = Date.now();
  const diff = now - d.getTime();
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return d.toLocaleDateString();
}

function ActivityRow({ item }: { item: ActivityItem }) {
  const meta = item.metadata as Record<string, string>;
  const description =
    meta?.description || meta?.title || `${item.activity_type} on ${item.target_type || "item"}`;

  return (
    <div
      className={`flex items-start gap-3 rounded-lg border p-3 ${
        item.read ? "opacity-70" : "bg-accent/30"
      }`}
      data-testid="activity-item"
      data-activity-type={item.activity_type}
      data-read={String(item.read)}
    >
      <div className="mt-0.5 flex-shrink-0">{activityIcon(item.activity_type)}</div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium">{item.actor_id}</span>
          <Badge variant="outline" className="text-xs">
            {ACTIVITY_TYPE_LABELS[item.activity_type] || item.activity_type}
          </Badge>
          {!item.read && (
            <Badge variant="default" className="text-xs">
              New
            </Badge>
          )}
        </div>
        <p className="mt-0.5 text-sm text-muted-foreground">{description}</p>
        <span className="text-xs text-muted-foreground">{formatTimestamp(item.created_at)}</span>
      </div>
    </div>
  );
}

export default function ActivityFeedPage() {
  const [activeFilter, setActiveFilter] = useState("all");
  const queryClient = useQueryClient();

  const feedQuery = useInfiniteQuery({
    queryKey: ["activity-feed", activeFilter],
    queryFn: ({ pageParam }) => {
      if (activeFilter === "all") {
        return getActivityFeed({ limit: 20, cursor: pageParam ?? undefined });
      }
      return getActivityFeedFiltered(activeFilter, {
        limit: 20,
        cursor: pageParam ?? undefined,
      });
    },
    getNextPageParam: (last) => last.next_cursor,
    initialPageParam: null as string | null,
  });

  const unreadQuery = useQuery({
    queryKey: ["activity-feed-unread"],
    queryFn: getActivityUnreadCount,
  });

  const markReadMut = useMutation({
    mutationFn: () => markActivitiesRead(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["activity-feed"] });
      queryClient.invalidateQueries({ queryKey: ["activity-feed-unread"] });
    },
  });

  const allItems = feedQuery.data?.pages.flatMap((p) => p.items) ?? [];
  const unreadCount = unreadQuery.data?.count ?? 0;

  return (
    <div className="mx-auto max-w-3xl space-y-4 p-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="flex items-center gap-2 text-xl">
            <Activity className="h-5 w-5" />
            Activity Feed
            {unreadCount > 0 && (
              <Badge variant="destructive" data-testid="unread-badge">
                {unreadCount}
              </Badge>
            )}
          </CardTitle>
          <Button
            variant="outline"
            size="sm"
            onClick={() => markReadMut.mutate()}
            disabled={markReadMut.isPending || unreadCount === 0}
            data-testid="mark-all-read-btn"
          >
            <CheckCheck className="mr-1 h-4 w-4" />
            Mark all read
          </Button>
        </CardHeader>
        <CardContent>
          {/* Filter tabs */}
          <div className="mb-4 flex flex-wrap gap-1" data-testid="filter-tabs">
            {FILTER_TABS.map((tab) => (
              <Button
                key={tab.key}
                variant={activeFilter === tab.key ? "default" : "outline"}
                size="sm"
                onClick={() => setActiveFilter(tab.key)}
                data-testid={`filter-${tab.key}`}
              >
                {tab.label}
              </Button>
            ))}
          </div>

          {/* Feed items */}
          {feedQuery.isLoading ? (
            <div className="flex justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : allItems.length === 0 ? (
            <div className="py-8 text-center text-muted-foreground" data-testid="empty-feed">
              No activity yet
            </div>
          ) : (
            <div className="space-y-2" data-testid="activity-list">
              {allItems.map((item) => (
                <ActivityRow key={item.activity_id} item={item} />
              ))}
            </div>
          )}

          {/* Load more */}
          {feedQuery.hasNextPage && (
            <div className="mt-4 flex justify-center">
              <Button
                variant="outline"
                size="sm"
                onClick={() => feedQuery.fetchNextPage()}
                disabled={feedQuery.isFetchingNextPage}
                data-testid="load-more-btn"
              >
                {feedQuery.isFetchingNextPage ? (
                  <Loader2 className="mr-1 h-4 w-4 animate-spin" />
                ) : null}
                Load more
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
