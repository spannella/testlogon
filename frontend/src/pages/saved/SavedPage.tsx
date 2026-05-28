import { useState } from "react";
import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Bookmark, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { getBookmarks, removeBookmark, type BookmarkItem } from "@/api/endpoints/bookmarks";

export default function SavedPage() {
  const queryClient = useQueryClient();
  const [contentType, setContentType] = useState<string | undefined>(undefined);

  const {
    data,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
    isLoading,
  } = useInfiniteQuery({
    queryKey: ["bookmarks", contentType],
    queryFn: ({ pageParam }) =>
      getBookmarks({
        limit: 24,
        cursor: pageParam as string | undefined,
        content_type: contentType,
      }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor || undefined,
  });

  const removeMutation = useMutation({
    mutationFn: (item: BookmarkItem) => removeBookmark(item.content_type, item.content_id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["bookmarks"] });
      toast.success("Removed from saved");
    },
    onError: () => {
      toast.error("Failed to remove bookmark");
    },
  });

  const allBookmarks = data?.pages.flatMap((p) => p.bookmarks) ?? [];

  return (
    <div className="mx-auto w-full max-w-4xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Saved"
        description="Your bookmarked posts and videos"
      />

      <Tabs
        value={contentType ?? "all"}
        onValueChange={(v) => setContentType(v === "all" ? undefined : v)}
      >
        <TabsList>
          <TabsTrigger value="all">All</TabsTrigger>
          <TabsTrigger value="post">Posts</TabsTrigger>
          <TabsTrigger value="video">Videos</TabsTrigger>
        </TabsList>
      </Tabs>

      {isLoading && (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <Card key={i} className="animate-pulse">
              <CardContent className="h-40 p-4" />
            </Card>
          ))}
        </div>
      )}

      {!isLoading && allBookmarks.length === 0 && (
        <div className="flex flex-col items-center justify-center py-16 text-center">
          <Bookmark className="h-12 w-12 text-muted-foreground mb-4" />
          <h3 className="text-lg font-medium">No saved items yet</h3>
          <p className="text-sm text-muted-foreground mt-1">
            Bookmark posts and videos to see them here.
          </p>
        </div>
      )}

      {!isLoading && allBookmarks.length > 0 && (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {allBookmarks.map((item) => (
            <Card key={`${item.content_type}:${item.content_id}`}>
              <CardContent className="p-4 space-y-3">
                {item.content_preview?.image_url && (
                  <img
                    src={item.content_preview.image_url}
                    alt=""
                    className="w-full h-32 object-cover rounded-md"
                  />
                )}
                <div className="flex items-center gap-2">
                  <Avatar className="h-6 w-6">
                    <AvatarFallback className="text-xs">
                      {(item.content_preview.author_id || "?").charAt(0).toUpperCase()}
                    </AvatarFallback>
                  </Avatar>
                  <span className="text-sm font-medium truncate">
                    {item.content_preview.author_display_name || item.content_preview.author_id}
                  </span>
                </div>
                <p className="text-sm text-muted-foreground line-clamp-3">
                  {item.content_preview.body_snippet || "[No content]"}
                </p>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-muted-foreground">
                    Saved {new Date(item.created_at).toLocaleDateString()}
                  </span>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 text-xs text-destructive hover:text-destructive"
                    onClick={() => removeMutation.mutate(item)}
                    disabled={removeMutation.isPending}
                  >
                    <Trash2 className="h-3 w-3 mr-1" />
                    Remove
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {hasNextPage && (
        <div className="flex justify-center">
          <Button
            variant="outline"
            onClick={() => fetchNextPage()}
            disabled={isFetchingNextPage}
          >
            {isFetchingNextPage ? "Loading..." : "Load more"}
          </Button>
        </div>
      )}
    </div>
  );
}
