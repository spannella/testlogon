import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  addBroadcastAllowlistEntry,
  createBroadcastInviteToken,
  getBroadcastPrivacy,
  listBroadcastAllowlist,
  listBroadcastInviteTokens,
  removeBroadcastAllowlistEntry,
  revokeBroadcastInviteToken,
  setBroadcastPrivacy,
  type BroadcastVisibility,
} from "@/api/endpoints/broadcastPrivacy";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Globe, Link2, Lock, Trash2 } from "lucide-react";
import { toast } from "sonner";

interface BroadcastPrivacyControlsProps {
  sessionId: string;
}

const VISIBILITIES: { value: BroadcastVisibility; label: string; icon: typeof Globe }[] = [
  { value: "public", label: "Public", icon: Globe },
  { value: "unlisted", label: "Unlisted", icon: Link2 },
  { value: "private", label: "Private", icon: Lock },
];

export function BroadcastPrivacyControls({ sessionId }: BroadcastPrivacyControlsProps) {
  const queryClient = useQueryClient();
  const [newViewer, setNewViewer] = useState("");

  const privacyQuery = useQuery({
    queryKey: ["broadcast-privacy", sessionId],
    queryFn: () => getBroadcastPrivacy(sessionId),
  });

  const visibility = privacyQuery.data?.visibility ?? "public";
  const isPrivate = visibility === "private";

  const allowlistQuery = useQuery({
    queryKey: ["broadcast-allowlist", sessionId],
    queryFn: () => listBroadcastAllowlist(sessionId),
    enabled: isPrivate,
  });

  const tokensQuery = useQuery({
    queryKey: ["broadcast-invite-tokens", sessionId],
    queryFn: () => listBroadcastInviteTokens(sessionId),
    enabled: isPrivate,
  });

  const setVisibilityMut = useMutation({
    mutationFn: (v: BroadcastVisibility) => setBroadcastPrivacy(sessionId, v),
    onSuccess: (res) => {
      queryClient.setQueryData(["broadcast-privacy", sessionId], res);
      toast.success(`Broadcast is now ${res.visibility}`);
    },
    onError: () => toast.error("Failed to update visibility."),
  });

  const addViewerMut = useMutation({
    mutationFn: (viewerId: string) => addBroadcastAllowlistEntry(sessionId, viewerId),
    onSuccess: () => {
      setNewViewer("");
      queryClient.invalidateQueries({ queryKey: ["broadcast-allowlist", sessionId] });
      queryClient.invalidateQueries({ queryKey: ["broadcast-privacy", sessionId] });
      toast.success("Viewer added to allowlist");
    },
    onError: () => toast.error("Failed to add viewer."),
  });

  const removeViewerMut = useMutation({
    mutationFn: (viewerId: string) => removeBroadcastAllowlistEntry(sessionId, viewerId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["broadcast-allowlist", sessionId] });
      queryClient.invalidateQueries({ queryKey: ["broadcast-privacy", sessionId] });
      toast.success("Viewer removed");
    },
    onError: () => toast.error("Failed to remove viewer."),
  });

  const createTokenMut = useMutation({
    mutationFn: () => createBroadcastInviteToken(sessionId, 1),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["broadcast-invite-tokens", sessionId] });
      toast.success("Invite token created");
    },
    onError: () => toast.error("Failed to create token."),
  });

  const revokeTokenMut = useMutation({
    mutationFn: (token: string) => revokeBroadcastInviteToken(sessionId, token),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["broadcast-invite-tokens", sessionId] });
      toast.success("Token revoked");
    },
    onError: () => toast.error("Failed to revoke token."),
  });

  return (
    <Card data-testid="broadcast-privacy-controls">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Lock className="h-4 w-4 text-primary" />
          Privacy &amp; Access
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex gap-2" role="group" aria-label="Visibility">
          {VISIBILITIES.map(({ value, label, icon: Icon }) => (
            <Button
              key={value}
              type="button"
              size="sm"
              variant={visibility === value ? "default" : "outline"}
              disabled={setVisibilityMut.isPending || privacyQuery.isLoading}
              onClick={() => setVisibilityMut.mutate(value)}
              data-testid={`privacy-visibility-${value}`}
            >
              <Icon className="mr-1 h-3.5 w-3.5" />
              {label}
            </Button>
          ))}
        </div>

        {isPrivate && (
          <>
            <div className="space-y-2">
              <p className="text-sm font-medium">Allowed viewers</p>
              <div className="flex gap-2">
                <Input
                  placeholder="viewer user id or email"
                  value={newViewer}
                  onChange={(e) => setNewViewer(e.target.value)}
                  data-testid="privacy-allowlist-input"
                />
                <Button
                  type="button"
                  size="sm"
                  disabled={!newViewer.trim() || addViewerMut.isPending}
                  onClick={() => addViewerMut.mutate(newViewer.trim())}
                  data-testid="privacy-allowlist-add"
                >
                  Add
                </Button>
              </div>
              <ul className="space-y-1" data-testid="privacy-allowlist">
                {(allowlistQuery.data?.entries ?? []).map((entry) => (
                  <li
                    key={entry.viewer_id}
                    className="flex items-center justify-between rounded border px-2 py-1 text-sm"
                  >
                    <span className="truncate">{entry.viewer_id}</span>
                    <Button
                      type="button"
                      size="icon"
                      variant="ghost"
                      onClick={() => removeViewerMut.mutate(entry.viewer_id)}
                      aria-label={`Remove ${entry.viewer_id}`}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </li>
                ))}
                {(allowlistQuery.data?.entries ?? []).length === 0 && (
                  <li className="text-sm text-muted-foreground">No viewers allowlisted yet.</li>
                )}
              </ul>
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <p className="text-sm font-medium">Invite tokens</p>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  disabled={createTokenMut.isPending}
                  onClick={() => createTokenMut.mutate()}
                  data-testid="privacy-token-create"
                >
                  New token
                </Button>
              </div>
              <ul className="space-y-1" data-testid="privacy-tokens">
                {(tokensQuery.data?.tokens ?? []).map((t) => (
                  <li
                    key={t.token}
                    className="flex items-center justify-between rounded border px-2 py-1 text-sm"
                  >
                    <code className="truncate">{t.token}</code>
                    <span className="flex items-center gap-2">
                      <Badge variant="secondary">
                        {t.use_count}/{t.max_uses}
                      </Badge>
                      <Button
                        type="button"
                        size="icon"
                        variant="ghost"
                        onClick={() => revokeTokenMut.mutate(t.token)}
                        aria-label={`Revoke token ${t.token}`}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </span>
                  </li>
                ))}
                {(tokensQuery.data?.tokens ?? []).length === 0 && (
                  <li className="text-sm text-muted-foreground">No invite tokens.</li>
                )}
              </ul>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

export default BroadcastPrivacyControls;
