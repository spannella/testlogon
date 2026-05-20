import { useEffect, useMemo } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Lock, Mail, MessageSquare, UserPlus } from "lucide-react";
import { toast } from "sonner";

import { getProfileByIdentifier, ProfileLookupError } from "@/api/endpoints/profile";
import { addContact } from "@/api/endpoints/contacts";
import { findOrCreateDm } from "@/api/endpoints/messaging";
import { ErrorPage } from "@/components/shared/ErrorPage";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuthStore } from "@/stores/authStore";

export default function PublicUserProfilePage() {
  const navigate = useNavigate();
  const params = useParams<{ identifier: string }>();
  const identifier = useMemo(() => (params.identifier || "").trim(), [params.identifier]);
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const viewerUserId = useAuthStore((s) => s.userId);

  const q = useQuery({
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

  const data = q.data;
  const canonicalIdentifier = data?.canonical_identifier?.trim() || data?.identifier || "";

  useEffect(() => {
    if (!identifier || !canonicalIdentifier) return;
    if (canonicalIdentifier === identifier) return;
    navigate(`/u/${encodeURIComponent(canonicalIdentifier)}`, { replace: true });
  }, [canonicalIdentifier, identifier, navigate]);

  if (!identifier) {
    return <ErrorPage status={404} title="Profile Not Available" description="This profile URL is invalid." />;
  }

  if (q.isLoading) {
    return (
      <div className="mx-auto w-full max-w-2xl p-6">
        <Card>
          <CardHeader>
            <CardTitle>Loading profile…</CardTitle>
            <CardDescription>Fetching the latest profile preview.</CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  if (q.isError) {
    const err = q.error;
    if (err instanceof ProfileLookupError && err.code === "not_found_or_suppressed") {
      return (
        <ErrorPage
          status={404}
          title="Profile Not Available"
          description="This profile could not be found or is not available for viewing."
        />
      );
    }
    if (err instanceof ProfileLookupError && err.code === "rate_limited") {
      const retryHint = err.retryAfterSeconds && err.retryAfterSeconds > 0
        ? ` Please wait about ${err.retryAfterSeconds} seconds and try again.`
        : " Please wait and try again.";
      return (
        <ErrorPage
          status={429}
          title="Too Many Requests"
          description={`Too many profile lookups were attempted.${retryHint}`}
        />
      );
    }
    return <ErrorPage status={500} title="Profile Unavailable" description="Unable to load this profile right now." />;
  }

  if (!data) {
    return <ErrorPage status={500} title="Profile Unavailable" description="Unable to load this profile right now." />;
  }

  const p = data.profile;
  const isMemberAudience = data.audience === "member";
  const isOwnerAudience = data.audience === "owner";

  // Public-safe fields only.
  const displayName = p.display_name?.trim() || data.identifier;
  const publicFields = {
    title: p.title?.trim() || "",
    description: p.description?.trim() || "",
    location: p.location?.trim() || "",
    profilePhotoUrl: p.profile_photo_url?.trim() || "",
    coverPhotoUrl: p.cover_photo_url?.trim() || "",
  };

  // Member-eligible fields only. Owner-private fields are intentionally not rendered.
  const memberFields = {
    email: p.displayed_email?.trim() || "",
    phone: p.displayed_telephone_number?.trim() || "",
    languages: (p.languages ?? []).filter((l) => Boolean(l?.name?.trim())).map((l) => `${l.name}${l.level ? ` (${l.level})` : ""}`),
  };

  const canUseMemberActions = isAuthenticated && isMemberAudience && viewerUserId !== data.user_sub;

  async function handleMessage() {
    if (!canUseMemberActions) return;
    try {
      const convo = await findOrCreateDm(data.user_sub);
      navigate("/messages", { state: { openConversation: convo } });
    } catch {
      toast.error("Unable to start a conversation right now");
    }
  }

  return (
    <div className="mx-auto w-full max-w-3xl space-y-4 p-4 sm:p-6">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div className="text-sm text-muted-foreground">Canonical profile URL: /u/{canonicalIdentifier}</div>
        <Button variant="outline" size="sm" onClick={() => navigate(-1)}>Back</Button>
      </div>

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

          <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap">
            <Button onClick={handleMessage} className="w-full sm:w-auto" disabled={!canUseMemberActions}>
              {canUseMemberActions ? <MessageSquare className="mr-2 h-4 w-4" /> : <Lock className="mr-2 h-4 w-4" />}
              Message
            </Button>
            <Button
              variant="outline"
              className="w-full sm:w-auto"
              disabled={!canUseMemberActions || contactMut.isPending}
              onClick={() => contactMut.mutate(data.user_sub)}
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
          <p className="text-xs text-muted-foreground">Audience: {data.audience}</p>
        </CardContent>
      </Card>
    </div>
  );
}
