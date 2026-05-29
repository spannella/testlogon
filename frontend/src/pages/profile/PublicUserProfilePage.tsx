import { useEffect, useMemo } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Helmet } from "react-helmet-async";
import { Lock, Mail, MessageSquare, UserPlus } from "lucide-react";
import { toast } from "sonner";

import { getPublicProfile, getProfileByIdentifier } from "@/api/endpoints/profile";
import { addContact } from "@/api/endpoints/contacts";
import { findOrCreateDm } from "@/api/endpoints/messaging";
import { ErrorPage } from "@/components/shared/ErrorPage";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useAuthStore } from "@/stores/authStore";
import { FollowButton } from "./FollowButton";
import { FollowersTab } from "./FollowersTab";
import { FollowingTab } from "./FollowingTab";
import { StorefrontVideoGrid } from "./StorefrontVideoGrid";
import { StorefrontPostsFeed } from "./StorefrontPostsFeed";
import { PlanBrowser } from "@/pages/subscriptions/PlanBrowser";

// ─── Helpers ──────────────────────────────────────────────────────

function formatCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

// ─── Component ────────────────────────────────────────────────────

export default function PublicUserProfilePage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const params = useParams<{ identifier: string }>();
  const identifier = useMemo(() => (params.identifier || "").trim(), [params.identifier]);
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const viewerUserId = useAuthStore((s) => s.userId);

  // Primary data source: public profile endpoint (has social data, counts, plan flag)
  const pubQ = useQuery({
    queryKey: ["profile", "public", identifier],
    queryFn: () => getPublicProfile(identifier),
    enabled: Boolean(identifier),
    retry: false,
    staleTime: 300_000,
  });

  // Secondary: detailed profile lookup (for audience, member details, canonical redirect)
  // May fail independently -- we don't gate the page on it.
  const detailQ = useQuery({
    queryKey: ["profile", "lookup", identifier],
    queryFn: () => getProfileByIdentifier(identifier),
    enabled: Boolean(identifier),
    retry: false,
  });

  const contactMut = useMutation({
    mutationFn: async (userSub: string) => addContact({ contact_id: userSub }),
    onSuccess: () => toast.success("Added to contacts"),
    onError: () => toast.error("Unable to add contact right now"),
  });

  const pub = pubQ.data;
  const detail = detailQ.data;

  // Canonical redirect (from public profile or detailed lookup)
  const canonicalIdentifier = pub?.canonical_identifier?.trim() || detail?.canonical_identifier?.trim() || pub?.identifier || identifier;

  useEffect(() => {
    if (!identifier || !canonicalIdentifier) return;
    if (canonicalIdentifier === identifier) return;
    navigate(`/u/${encodeURIComponent(canonicalIdentifier)}`, { replace: true });
  }, [canonicalIdentifier, identifier, navigate]);

  if (!identifier) {
    return <ErrorPage status={404} title="Profile Not Available" description="This profile URL is invalid." />;
  }

  if (pubQ.isLoading) {
    return (
      <div className="mx-auto w-full max-w-2xl p-6">
        <Card>
          <CardHeader>
            <CardTitle>Loading profile...</CardTitle>
            <CardDescription>Fetching the latest profile preview.</CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  if (pubQ.isError) {
    const err = pubQ.error;
    if (err && typeof err === "object" && "status" in err) {
      const status = (err as { status: number }).status;
      if (status === 404) {
        return (
          <ErrorPage
            status={404}
            title="Profile Not Available"
            description="This profile could not be found or is not available for viewing."
          />
        );
      }
      if (status === 429) {
        return (
          <ErrorPage
            status={429}
            title="Too Many Requests"
            description="Too many profile lookups were attempted. Please wait and try again."
          />
        );
      }
    }
    return <ErrorPage status={500} title="Profile Unavailable" description="Unable to load this profile right now." />;
  }

  if (!pub) {
    return <ErrorPage status={500} title="Profile Unavailable" description="Unable to load this profile right now." />;
  }

  // Use detail data for audience/member fields if available
  const p = detail?.profile;
  const isMemberAudience = detail?.audience === "member";
  const isOwnerAudience = detail?.audience === "owner";
  const isOwnProfile = isAuthenticated && viewerUserId === pub.user_id;

  const displayName = pub.display_name?.trim() || pub.identifier;
  const publicFields = {
    title: pub.title?.trim() || "",
    description: pub.description?.trim() || "",
    location: pub.location?.trim() || "",
    profilePhotoUrl: pub.profile_photo_url?.trim() || "",
    coverPhotoUrl: pub.cover_photo_url?.trim() || "",
  };

  // Member fields from the detailed lookup (if available)
  const memberFields = {
    email: p?.displayed_email?.trim() || "",
    phone: p?.displayed_telephone_number?.trim() || "",
    languages: (p?.languages ?? []).filter((l) => Boolean(l?.name?.trim())).map((l) => `${l.name}${l.level ? ` (${l.level})` : ""}`),
  };

  const canUseMemberActions = isAuthenticated && !isOwnProfile;

  async function handleMessage() {
    if (!canUseMemberActions || !pub) return;
    try {
      const convo = await findOrCreateDm(pub.user_id);
      navigate("/messages", { state: { openConversation: convo } });
    } catch {
      toast.error("Unable to start a conversation right now");
    }
  }

  // Social data from the public profile endpoint
  const followerCount = pub.follower_count ?? 0;
  const followingCount = pub.following_count ?? 0;
  const postCount = pub.post_count ?? 0;
  const isFollowing = pub.is_following ?? false;
  const hasPlans = pub.has_subscription_plans ?? false;

  const showVideosTab = isAuthenticated;
  const defaultTab = showVideosTab ? "videos" : "posts";

  // The identifier to use for profile posts endpoint
  const profileIdentifier = pub.identifier || identifier;

  return (
    <div className="mx-auto w-full max-w-3xl space-y-4 p-4 sm:p-6">
      <Helmet>
        <title>{displayName} | Control Panel</title>
        <meta name="description" content={(publicFields.description || `${displayName}'s profile`).slice(0, 200)} />
        <meta property="og:title" content={displayName} />
        <meta property="og:description" content={(publicFields.description || `${displayName}'s profile`).slice(0, 200)} />
        <meta property="og:type" content="profile" />
        {publicFields.profilePhotoUrl && <meta property="og:image" content={publicFields.profilePhotoUrl} />}
        <meta property="og:url" content={`${window.location.origin}/u/${canonicalIdentifier}`} />
        <meta name="twitter:card" content="summary" />
        <meta name="twitter:title" content={displayName} />
        <meta name="twitter:description" content={(publicFields.description || "").slice(0, 200)} />
        {publicFields.profilePhotoUrl && <meta name="twitter:image" content={publicFields.profilePhotoUrl} />}
        <link rel="canonical" href={`${window.location.origin}/u/${canonicalIdentifier}`} />
      </Helmet>
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div className="text-sm text-muted-foreground">Canonical profile URL: /u/{canonicalIdentifier}</div>
        <Button variant="outline" size="sm" onClick={() => navigate(-1)}>Back</Button>
      </div>

      {/* Hero Card */}
      <Card>
        {publicFields.coverPhotoUrl && (
          <div className="h-32 w-full overflow-hidden rounded-t-lg bg-muted sm:h-40">
            <img
              src={publicFields.coverPhotoUrl}
              alt={`${displayName} cover`}
              className="h-full w-full object-cover"
            />
          </div>
        )}
        <CardHeader>
          <div className="flex items-center gap-3">
            {publicFields.profilePhotoUrl ? (
              <img
                src={publicFields.profilePhotoUrl}
                alt={`${displayName} avatar`}
                className="h-12 w-12 rounded-full object-cover"
              />
            ) : (
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-muted text-sm font-semibold text-muted-foreground">
                {displayName.slice(0, 1).toUpperCase()}
              </div>
            )}
            <div className="min-w-0">
              <CardTitle className="truncate">{displayName}</CardTitle>
              <CardDescription>{publicFields.title || "Public profile preview"}</CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          {/* Stats Row */}
          <div className="flex gap-4 text-sm text-muted-foreground" data-testid="stats-row">
            <span><strong>{formatCount(followerCount)}</strong> followers</span>
            <span><strong>{formatCount(followingCount)}</strong> following</span>
            <span><strong>{formatCount(postCount)}</strong> posts</span>
          </div>

          {/* Action buttons */}
          <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap sm:items-center">
            {isAuthenticated && !isOwnProfile && (
              <FollowButton
                userId={pub.user_id}
                isFollowing={isFollowing}
                onToggle={() => {
                  void queryClient.invalidateQueries({ queryKey: ["profile", "public", identifier] });
                }}
              />
            )}
            <Button onClick={handleMessage} className="w-full sm:w-auto" disabled={!canUseMemberActions}>
              {canUseMemberActions ? <MessageSquare className="mr-2 h-4 w-4" /> : <Lock className="mr-2 h-4 w-4" />}
              Message
            </Button>
            <Button
              variant="outline"
              className="w-full sm:w-auto"
              disabled={!canUseMemberActions || contactMut.isPending}
              onClick={() => contactMut.mutate(pub.user_id)}
            >
              {canUseMemberActions ? <UserPlus className="mr-2 h-4 w-4" /> : <Lock className="mr-2 h-4 w-4" />}
              Add contact
            </Button>
            {!isAuthenticated && (
              <Button onClick={() => navigate("/login")} variant="secondary" className="w-full sm:w-auto">
                Sign in to view more
              </Button>
            )}
          </div>

          {isOwnerAudience && (
            <p className="text-xs text-muted-foreground">You are viewing your own profile on a canonical URL. Visit Settings for full owner editing.</p>
          )}
          <p className="text-xs text-muted-foreground">Audience: {detail?.audience || "public"}</p>
        </CardContent>
      </Card>

      {/* Subscription Plans Section */}
      {hasPlans && (
        <section data-testid="subscription-plans-section">
          <h2 className="mb-4 text-lg font-semibold">Subscription Plans</h2>
          <PlanBrowser creatorId={pub.user_id} />
        </section>
      )}

      {/* Tabbed Content */}
      <Tabs defaultValue={defaultTab}>
        <TabsList>
          {showVideosTab && (
            <TabsTrigger value="videos">Videos</TabsTrigger>
          )}
          <TabsTrigger value="posts">Posts</TabsTrigger>
          {isAuthenticated && (
            <TabsTrigger value="followers">Followers</TabsTrigger>
          )}
          {isAuthenticated && (
            <TabsTrigger value="following">Following</TabsTrigger>
          )}
          <TabsTrigger value="about">About</TabsTrigger>
        </TabsList>

        {showVideosTab && (
          <TabsContent value="videos">
            <StorefrontVideoGrid creatorId={pub.user_id} />
          </TabsContent>
        )}

        <TabsContent value="posts">
          <StorefrontPostsFeed identifier={profileIdentifier} />
        </TabsContent>

        {isAuthenticated && (
          <TabsContent value="followers" data-testid="followers-tab-content">
            <FollowersTab userId={pub.user_id} />
          </TabsContent>
        )}

        {isAuthenticated && (
          <TabsContent value="following" data-testid="following-tab-content">
            <FollowingTab userId={pub.user_id} />
          </TabsContent>
        )}

        <TabsContent value="about" data-testid="about-tab-content">
          <div className="space-y-3 rounded-lg border bg-card p-4">
            {publicFields.description && <p className="text-sm leading-relaxed">{publicFields.description}</p>}
            {publicFields.location && <p className="text-sm text-muted-foreground">Location: {publicFields.location}</p>}
            {!publicFields.description && !publicFields.location && (
              <p className="text-sm text-muted-foreground">No public profile details are currently available.</p>
            )}

            {isMemberAudience && (
              <div className="space-y-2 rounded-md border bg-muted/20 p-3" data-testid="member-details">
                <p className="text-sm font-medium">Member details</p>
                {memberFields.email && (
                  <p className="text-sm text-muted-foreground">
                    <Mail className="mr-1 inline h-3.5 w-3.5" />
                    {memberFields.email}
                  </p>
                )}
                {memberFields.phone && <p className="text-sm text-muted-foreground">Phone: {memberFields.phone}</p>}
                {memberFields.languages.length > 0 && (
                  <p className="text-sm text-muted-foreground">Languages: {memberFields.languages.join(", ")}</p>
                )}
                {!memberFields.email && !memberFields.phone && memberFields.languages.length === 0 && (
                  <p className="text-xs text-muted-foreground">No additional member-visible fields are currently set.</p>
                )}
              </div>
            )}

            {!isAuthenticated && (
              <div className="rounded-md border bg-muted/30 p-3" data-testid="signin-upsell">
                <p className="mb-2 text-sm font-medium">Public preview</p>
                <p className="text-xs text-muted-foreground">
                  Sign in to view additional profile details and member-only actions.
                </p>
              </div>
            )}

            {pub?.created_at && (
              <p className="text-xs text-muted-foreground">
                Joined {new Date(pub.created_at * 1000).toLocaleDateString(undefined, { year: "numeric", month: "long" })}
              </p>
            )}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
