import { useState } from "react";
import { useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  listDelegatedPosts,
  createDelegatedPost,
  editDelegatedPost,
  deleteDelegatedPost,
  listPendingDrafts,
  approveDraft,
  rejectDraft,
  getFeedAnalytics,
  getFeedDelegateAudit,
} from "@/api/endpoints/delegateFeed";
import type { DelegatedPostOut } from "@/api/types";

export default function DelegateFeedPage() {
  const { creatorId } = useParams<{ creatorId: string }>();
  const qc = useQueryClient();
  const [newPostText, setNewPostText] = useState("");
  const [editingPost, setEditingPost] = useState<DelegatedPostOut | null>(null);
  const [editText, setEditText] = useState("");
  const [rejectNote, setRejectNote] = useState("");
  const [rejectingPostId, setRejectingPostId] = useState<string | null>(null);

  const postsQ = useQuery({
    queryKey: ["delegate-feed-posts", creatorId],
    queryFn: () => listDelegatedPosts(creatorId!),
    enabled: !!creatorId,
  });

  const draftsQ = useQuery({
    queryKey: ["delegate-feed-drafts", creatorId],
    queryFn: () => listPendingDrafts(creatorId!),
    enabled: !!creatorId,
  });

  const analyticsQ = useQuery({
    queryKey: ["delegate-feed-analytics", creatorId],
    queryFn: () => getFeedAnalytics(creatorId!),
    enabled: !!creatorId,
  });

  const auditQ = useQuery({
    queryKey: ["delegate-feed-audit", creatorId],
    queryFn: () => getFeedDelegateAudit(creatorId!),
    enabled: !!creatorId,
  });

  const createMut = useMutation({
    mutationFn: () => createDelegatedPost(creatorId!, { text: newPostText }),
    onSuccess: () => {
      setNewPostText("");
      qc.invalidateQueries({ queryKey: ["delegate-feed-posts", creatorId] });
      qc.invalidateQueries({ queryKey: ["delegate-feed-drafts", creatorId] });
    },
  });

  const editMut = useMutation({
    mutationFn: (args: { postId: string; text: string }) =>
      editDelegatedPost(creatorId!, args.postId, { text: args.text }),
    onSuccess: () => {
      setEditingPost(null);
      setEditText("");
      qc.invalidateQueries({ queryKey: ["delegate-feed-posts", creatorId] });
    },
  });

  const deleteMut = useMutation({
    mutationFn: (postId: string) => deleteDelegatedPost(creatorId!, postId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["delegate-feed-posts", creatorId] });
    },
  });

  const approveMut = useMutation({
    mutationFn: (postId: string) => approveDraft(creatorId!, postId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["delegate-feed-drafts", creatorId] });
      qc.invalidateQueries({ queryKey: ["delegate-feed-posts", creatorId] });
    },
  });

  const rejectMut = useMutation({
    mutationFn: (args: { postId: string; note: string }) =>
      rejectDraft(creatorId!, args.postId, { note: args.note }),
    onSuccess: () => {
      setRejectingPostId(null);
      setRejectNote("");
      qc.invalidateQueries({ queryKey: ["delegate-feed-drafts", creatorId] });
    },
  });

  if (!creatorId) {
    return <p className="p-4 text-muted-foreground">No creator selected.</p>;
  }

  const statusBadge = (post: DelegatedPostOut) => {
    if (post.approval_status === "pending") {
      return <Badge variant="outline">Pending Approval</Badge>;
    }
    if (post.approval_status === "rejected") {
      return <Badge variant="destructive">Rejected</Badge>;
    }
    if (post.status === "draft") {
      return <Badge variant="secondary">Draft</Badge>;
    }
    return <Badge>Published</Badge>;
  };

  return (
    <div className="mx-auto max-w-3xl space-y-6 p-4">
      <h1 className="text-2xl font-bold">
        Delegate Feed &mdash; {creatorId}
      </h1>

      <Tabs defaultValue="posts">
        <TabsList>
          <TabsTrigger value="posts">Posts</TabsTrigger>
          <TabsTrigger value="drafts">
            Drafts{" "}
            {draftsQ.data && draftsQ.data.length > 0 && (
              <Badge variant="secondary" className="ml-1">
                {draftsQ.data.length}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="analytics">Analytics</TabsTrigger>
          <TabsTrigger value="audit">Audit</TabsTrigger>
        </TabsList>

        {/* -- Posts tab -- */}
        <TabsContent value="posts" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Create Post</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <Textarea
                placeholder="Write a post on behalf of the creator..."
                value={newPostText}
                onChange={(e) => setNewPostText(e.target.value)}
              />
              <Button
                onClick={() => createMut.mutate()}
                disabled={!newPostText.trim() || createMut.isPending}
              >
                {createMut.isPending ? "Creating..." : "Create Post"}
              </Button>
            </CardContent>
          </Card>

          {postsQ.data?.map((post) => (
            <Card key={post.post_id}>
              <CardContent className="pt-4 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">
                    {post.created_at}
                  </span>
                  {statusBadge(post)}
                </div>
                {editingPost?.post_id === post.post_id ? (
                  <div className="space-y-2">
                    <Textarea
                      value={editText}
                      onChange={(e) => setEditText(e.target.value)}
                    />
                    <div className="flex gap-2">
                      <Button
                        size="sm"
                        onClick={() =>
                          editMut.mutate({
                            postId: post.post_id,
                            text: editText,
                          })
                        }
                        disabled={editMut.isPending}
                      >
                        Save
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => setEditingPost(null)}
                      >
                        Cancel
                      </Button>
                    </div>
                  </div>
                ) : (
                  <p>{post.text}</p>
                )}
                {post.delegate_tag && (
                  <p className="text-xs text-muted-foreground">
                    {post.delegate_tag}
                  </p>
                )}
                {post.posted_by_delegate && (
                  <p className="text-xs text-muted-foreground">
                    Delegate: {post.delegate_display_name || post.posted_by_delegate}
                  </p>
                )}
                <div className="flex gap-2 pt-2">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => {
                      setEditingPost(post);
                      setEditText(post.text);
                    }}
                  >
                    Edit
                  </Button>
                  <Button
                    size="sm"
                    variant="destructive"
                    onClick={() => deleteMut.mutate(post.post_id)}
                    disabled={deleteMut.isPending}
                  >
                    Delete
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
          {postsQ.data?.length === 0 && (
            <p className="text-muted-foreground">No posts yet.</p>
          )}
        </TabsContent>

        {/* -- Drafts tab -- */}
        <TabsContent value="drafts" className="space-y-4">
          {draftsQ.data?.map((draft) => (
            <Card key={draft.post_id}>
              <CardContent className="pt-4 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">
                    By {draft.delegate_display_name || draft.posted_by_delegate}
                  </span>
                  {statusBadge(draft)}
                </div>
                <p>{draft.text}</p>
                {draft.approval_note && (
                  <p className="text-sm text-muted-foreground italic">
                    Note: {draft.approval_note}
                  </p>
                )}
                <div className="flex gap-2 pt-2">
                  <Button
                    size="sm"
                    onClick={() => approveMut.mutate(draft.post_id)}
                    disabled={approveMut.isPending}
                  >
                    Approve
                  </Button>
                  {rejectingPostId === draft.post_id ? (
                    <div className="flex gap-2">
                      <Input
                        placeholder="Rejection reason..."
                        value={rejectNote}
                        onChange={(e) => setRejectNote(e.target.value)}
                      />
                      <Button
                        size="sm"
                        variant="destructive"
                        onClick={() =>
                          rejectMut.mutate({
                            postId: draft.post_id,
                            note: rejectNote,
                          })
                        }
                        disabled={rejectMut.isPending}
                      >
                        Confirm
                      </Button>
                    </div>
                  ) : (
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => setRejectingPostId(draft.post_id)}
                    >
                      Reject
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
          {draftsQ.data?.length === 0 && (
            <p className="text-muted-foreground">No pending drafts.</p>
          )}
        </TabsContent>

        {/* -- Analytics tab -- */}
        <TabsContent value="analytics">
          {analyticsQ.data && (
            <Card>
              <CardHeader>
                <CardTitle>Feed Analytics ({analyticsQ.data.period})</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                  <div>
                    <p className="text-sm text-muted-foreground">Total Posts</p>
                    <p className="text-2xl font-bold">
                      {analyticsQ.data.total_posts}
                    </p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Total Likes</p>
                    <p className="text-2xl font-bold">
                      {analyticsQ.data.total_likes}
                    </p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Comments</p>
                    <p className="text-2xl font-bold">
                      {analyticsQ.data.total_comments}
                    </p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">
                      Delegate Posts
                    </p>
                    <p className="text-2xl font-bold">
                      {analyticsQ.data.delegate_post_count}
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* -- Audit tab -- */}
        <TabsContent value="audit">
          <Card>
            <CardHeader>
              <CardTitle>Delegate Feed Actions</CardTitle>
            </CardHeader>
            <CardContent>
              {auditQ.data && auditQ.data.length > 0 ? (
                <div className="space-y-2">
                  {auditQ.data.map((entry) => (
                    <div
                      key={entry.event_id}
                      className="flex items-center justify-between border-b py-2 text-sm"
                    >
                      <div>
                        <span className="font-medium">{entry.action}</span>
                        <span className="ml-2 text-muted-foreground">
                          by {entry.delegate_id}
                        </span>
                      </div>
                      <span className="text-muted-foreground">
                        {new Date(entry.ts * 1000).toLocaleString()}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-muted-foreground">No audit entries.</p>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
