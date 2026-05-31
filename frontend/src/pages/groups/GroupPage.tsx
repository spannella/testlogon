import { useState } from "react";
import { useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient, useInfiniteQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { Users, Pin, Globe, Lock, Trash2, Send } from "lucide-react";
import {
  getGroup,
  getGroupFeed,
  joinGroup,
  leaveGroup,
  createGroupPost,
  pinGroupPost,
  unpinGroupPost,
  deleteGroupPost,
} from "@/api/endpoints/groups";
import type { GroupFeedPost } from "@/api/types";
import { useAuthStore } from "@/stores/authStore";

export default function GroupPage() {
  const { groupId } = useParams<{ groupId: string }>();
  const queryClient = useQueryClient();
  const userId = useAuthStore((s) => s.userId);

  const { data: group, isLoading: groupLoading } = useQuery({
    queryKey: ["group", groupId],
    queryFn: () => getGroup(groupId!),
    enabled: !!groupId,
    staleTime: 30_000,
  });

  const {
    data: feedPages,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
  } = useInfiniteQuery({
    queryKey: ["group-feed", groupId],
    queryFn: ({ pageParam }) =>
      getGroupFeed(groupId!, { cursor: pageParam, limit: 20 }),
    getNextPageParam: (lastPage: any) =>
      lastPage.has_more ? lastPage.cursor : undefined,
    enabled: !!groupId,
    staleTime: 30_000,
    initialPageParam: undefined as string | undefined,
  });

  const isMember = group?.my_role != null;
  const isAdminOrMod = group?.my_role === "admin" || group?.my_role === "moderator";

  const joinMut = useMutation({
    mutationFn: () => joinGroup(groupId!),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["group", groupId] }),
  });

  const leaveMut = useMutation({
    mutationFn: () => leaveGroup(groupId!),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["group", groupId] }),
  });

  const allPosts: GroupFeedPost[] =
    feedPages?.pages.flatMap((p: any) => p.posts ?? []) ?? [];

  if (groupLoading) {
    return (
      <div className="flex items-center justify-center min-h-[200px]">
        <p className="text-muted-foreground">Loading group...</p>
      </div>
    );
  }

  if (!group) {
    return (
      <div className="flex items-center justify-center min-h-[200px]">
        <p className="text-muted-foreground">Group not found</p>
      </div>
    );
  }

  return (
    <div className="max-w-3xl mx-auto p-4 space-y-4" data-testid="group-page">
      {/* Group Header */}
      <Card>
        <CardHeader>
          <div className="flex items-start justify-between">
            <div>
              <CardTitle className="text-2xl">{group.name}</CardTitle>
              <p className="text-muted-foreground mt-1">{group.description}</p>
              <div className="flex items-center gap-3 mt-2 text-sm text-muted-foreground">
                <span className="flex items-center gap-1">
                  <Users className="h-4 w-4" />
                  {group.member_count} {group.member_count === 1 ? "member" : "members"}
                </span>
                {group.topic && <Badge variant="secondary">{group.topic}</Badge>}
                <Badge variant="outline">
                  {group.visibility === "public" ? (
                    <><Globe className="h-3 w-3 mr-1" /> Public</>
                  ) : (
                    <><Lock className="h-3 w-3 mr-1" /> Private</>
                  )}
                </Badge>
              </div>
            </div>
            <div>
              {isMember ? (
                <Button variant="outline" onClick={() => leaveMut.mutate()}>
                  Leave Group
                </Button>
              ) : (
                <Button onClick={() => joinMut.mutate()}>
                  {group.visibility === "public" ? "Join Group" : "Request to Join"}
                </Button>
              )}
            </div>
          </div>
          {group.my_role && (
            <Badge variant="secondary" className="mt-2">
              Your role: {group.my_role}
            </Badge>
          )}
        </CardHeader>
      </Card>

      {/* Post Composer (members only) */}
      {isMember && (
        <GroupPostComposer
          groupId={groupId!}
          onPostCreated={() =>
            queryClient.invalidateQueries({ queryKey: ["group-feed", groupId] })
          }
        />
      )}

      {/* Non-member CTA */}
      {!isMember && (
        <Card>
          <CardContent className="py-4">
            <p className="text-center text-muted-foreground">
              Join to see all posts and participate in the group.
            </p>
          </CardContent>
        </Card>
      )}

      {/* Feed */}
      {allPosts.length === 0 ? (
        <Card>
          <CardContent className="py-8">
            <p className="text-center text-muted-foreground">
              No posts yet. Be the first to share!
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {allPosts.map((post) => (
            <GroupPostCard
              key={post.post_id}
              post={post}
              groupId={groupId!}
              isAdminOrMod={isAdminOrMod}
              isAuthor={post.user_id === userId}
              onRefresh={() =>
                queryClient.invalidateQueries({ queryKey: ["group-feed", groupId] })
              }
            />
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
            {isFetchingNextPage ? "Loading..." : "Load More"}
          </Button>
        </div>
      )}
    </div>
  );
}

// ── GroupPostComposer ────────────────────────────────────────────

function GroupPostComposer({
  groupId,
  onPostCreated,
}: {
  groupId: string;
  onPostCreated: () => void;
}) {
  const [text, setText] = useState("");
  const [audience, setAudience] = useState<"public" | "members_only">("public");

  const createMut = useMutation({
    mutationFn: () =>
      createGroupPost(groupId, { text, audience }),
    onSuccess: () => {
      setText("");
      onPostCreated();
    },
  });

  return (
    <Card data-testid="group-post-composer">
      <CardContent className="pt-4 space-y-3">
        <Textarea
          placeholder="Share something with the group..."
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={3}
        />
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Button
              variant={audience === "public" ? "default" : "outline"}
              size="sm"
              onClick={() => setAudience("public")}
            >
              <Globe className="h-3 w-3 mr-1" /> Public
            </Button>
            <Button
              variant={audience === "members_only" ? "default" : "outline"}
              size="sm"
              onClick={() => setAudience("members_only")}
            >
              <Lock className="h-3 w-3 mr-1" /> Members Only
            </Button>
          </div>
          <Button
            onClick={() => createMut.mutate()}
            disabled={!text.trim() || createMut.isPending}
          >
            <Send className="h-4 w-4 mr-1" /> Post
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ── GroupPostCard ─────────────────────────────────────────────────

function GroupPostCard({
  post,
  groupId,
  isAdminOrMod,
  isAuthor,
  onRefresh,
}: {
  post: GroupFeedPost;
  groupId: string;
  isAdminOrMod: boolean;
  isAuthor: boolean;
  onRefresh: () => void;
}) {
  const pinMut = useMutation({
    mutationFn: () =>
      post.pinned
        ? unpinGroupPost(groupId, post.post_id)
        : pinGroupPost(groupId, post.post_id),
    onSuccess: onRefresh,
  });

  const deleteMut = useMutation({
    mutationFn: () => deleteGroupPost(groupId, post.post_id),
    onSuccess: onRefresh,
  });

  return (
    <Card>
      <CardContent className="pt-4">
        <div className="flex items-start justify-between">
          <div className="flex-1">
            {post.pinned && (
              <Badge variant="outline" className="mb-2 text-xs">
                <Pin className="h-3 w-3 mr-1" /> Pinned
              </Badge>
            )}
            {post.audience === "members_only" && (
              <Badge variant="secondary" className="mb-2 ml-1 text-xs">
                Members Only
              </Badge>
            )}
            <p className="text-sm text-muted-foreground mb-1">
              {post.user_display_name || post.user_id}
            </p>
            <p className="whitespace-pre-wrap">{post.text}</p>
            {post.image_url && (
              <img
                src={post.image_url}
                alt="Post image"
                className="mt-2 rounded max-h-64 object-cover"
              />
            )}
            <p className="text-xs text-muted-foreground mt-2">
              {new Date(post.created_at * 1000).toLocaleString()}
            </p>
          </div>
          <div className="flex gap-1">
            {isAdminOrMod && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => pinMut.mutate()}
                title={post.pinned ? "Unpin" : "Pin to top"}
              >
                <Pin className="h-4 w-4" />
              </Button>
            )}
            {(isAuthor || isAdminOrMod) && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => deleteMut.mutate()}
                title="Delete post"
              >
                <Trash2 className="h-4 w-4" />
              </Button>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
