import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Users, Globe, Settings } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useAuthStore } from "@/stores/authStore";
import {
  getSyndicateProfile,
  updateSyndicateProfile,
} from "@/api/endpoints/syndicateFeed";
import { SyndicateFeed } from "./SyndicateFeed";
import { SyndicatePostComposer } from "./SyndicatePostComposer";
import { SyndicateMemberCard } from "./SyndicateMemberCard";

export default function SyndicateProfilePage() {
  const { syndicateId = "" } = useParams();
  const userId = useAuthStore((s) => s.userId);
  const qc = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [editDescription, setEditDescription] = useState("");
  const [editTags, setEditTags] = useState("");

  const { data: profile, isLoading } = useQuery({
    queryKey: ["syndicate-profile", syndicateId],
    queryFn: () => getSyndicateProfile(syndicateId),
    enabled: !!syndicateId,
  });

  const updateMutation = useMutation({
    mutationFn: () =>
      updateSyndicateProfile(syndicateId, {
        description: editDescription,
        tags: editTags
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["syndicate-profile", syndicateId] });
      setEditing(false);
      toast.success("Profile updated");
    },
    onError: () => toast.error("Failed to update profile"),
  });

  if (isLoading || !profile) {
    return (
      <div className="mx-auto max-w-4xl space-y-4 p-4">
        <Skeleton className="h-40 w-full" />
        <Skeleton className="h-24 w-full" />
      </div>
    );
  }

  const isAdmin = profile.admin_user_id === userId;
  const isMember = profile.is_member;

  return (
    <div className="mx-auto max-w-5xl space-y-4 p-4">
      {/* Header */}
      <Card data-testid="syndicate-profile-header">
        <div className="h-24 rounded-t-lg bg-gradient-to-r from-indigo-500 to-purple-500" />
        <CardContent className="space-y-3 pt-4">
          <div className="flex items-start justify-between">
            <div>
              <h1 className="text-2xl font-bold" data-testid="syndicate-name">
                {profile.name}
              </h1>
              {!editing && (
                <p className="text-muted-foreground" data-testid="syndicate-description">
                  {profile.description}
                </p>
              )}
            </div>
            {isAdmin && !editing && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setEditDescription(profile.description);
                  setEditTags(profile.tags.join(", "));
                  setEditing(true);
                }}
                data-testid="syndicate-edit-profile"
              >
                <Settings className="mr-1 h-4 w-4" /> Edit Profile
              </Button>
            )}
          </div>

          {editing && (
            <div className="space-y-2" data-testid="syndicate-edit-form">
              <Textarea
                value={editDescription}
                maxLength={500}
                onChange={(e) => setEditDescription(e.target.value)}
                placeholder="Description"
                data-testid="syndicate-edit-description"
              />
              <input
                className="w-full rounded border px-3 py-2 text-sm"
                value={editTags}
                onChange={(e) => setEditTags(e.target.value)}
                placeholder="Tags (comma separated)"
                data-testid="syndicate-edit-tags"
              />
              <div className="flex gap-2">
                <Button
                  size="sm"
                  onClick={() => updateMutation.mutate()}
                  disabled={updateMutation.isPending}
                  data-testid="syndicate-edit-save"
                >
                  Save
                </Button>
                <Button size="sm" variant="ghost" onClick={() => setEditing(false)}>
                  Cancel
                </Button>
              </div>
            </div>
          )}

          {profile.tags.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {profile.tags.map((t) => (
                <Badge key={t} variant="secondary">
                  {t}
                </Badge>
              ))}
            </div>
          )}

          <div className="flex items-center gap-4 text-sm text-muted-foreground">
            <span data-testid="syndicate-member-count">{profile.member_count} members</span>
            <span data-testid="syndicate-post-count">{profile.post_count} posts</span>
            {profile.website_url && (
              <a
                href={profile.website_url}
                target="_blank"
                rel="noreferrer"
                className="flex items-center gap-1 hover:underline"
              >
                <Globe className="h-4 w-4" /> Website
              </a>
            )}
          </div>

          <Link to={`/syndicates/${syndicateId}/manage`} className="text-xs text-primary hover:underline">
            Manage syndicate
          </Link>
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <Tabs defaultValue="feed">
            <TabsList>
              <TabsTrigger value="feed" data-testid="syndicate-tab-feed">
                Feed
              </TabsTrigger>
              <TabsTrigger value="members" data-testid="syndicate-tab-members">
                Members
              </TabsTrigger>
            </TabsList>

            <TabsContent value="feed" className="space-y-4">
              {isMember && <SyndicatePostComposer syndicateId={syndicateId} />}
              {!isMember && (
                <Card className="border-dashed" data-testid="syndicate-join-banner">
                  <CardContent className="flex items-center gap-3 pt-4">
                    <Users className="h-5 w-5" />
                    <span>Join this syndicate to see members-only posts and contribute.</span>
                  </CardContent>
                </Card>
              )}
              <SyndicateFeed
                syndicateId={syndicateId}
                syndicateName={profile.name}
                isAdmin={isAdmin}
                currentUserId={userId}
              />
            </TabsContent>

            <TabsContent value="members">
              <div className="grid gap-3 sm:grid-cols-2" data-testid="syndicate-members-grid">
                {profile.members.map((m) => (
                  <SyndicateMemberCard key={m.user_id} member={m} />
                ))}
              </div>
            </TabsContent>
          </Tabs>
        </div>

        {/* Sidebar */}
        <div className="space-y-4">
          <Card data-testid="syndicate-bundle-plans">
            <CardHeader>
              <CardTitle className="text-base">Bundle Plans</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {profile.bundle_plans.length === 0 && (
                <p className="text-sm text-muted-foreground">No bundle plans yet.</p>
              )}
              {profile.bundle_plans.map((plan) => (
                <div key={plan.plan_id} className="rounded border p-3" data-testid="syndicate-bundle-plan">
                  <div className="font-medium">{plan.name}</div>
                  <div className="text-sm text-muted-foreground">
                    ${(plan.price_cents / 100).toFixed(2)}/{plan.interval}
                  </div>
                  <Link to={`/syndicates/${syndicateId}/manage`}>
                    <Button size="sm" className="mt-2 w-full">
                      Subscribe
                    </Button>
                  </Link>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
