import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { connectionProfilesApi } from "@/api/endpoints/connectionProfiles";
import type { ConnectionProfile } from "@/api/types";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/components/ui/use-toast";
import ConnectionProfilesDialog from "./ConnectionProfilesDialog";

export default function ConnectionProfilesPage() {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editing, setEditing] = useState<ConnectionProfile | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["connection-profiles"],
    queryFn: () => connectionProfilesApi.list(),
  });

  const quickConnectMut = useMutation({
    mutationFn: (id: string) => connectionProfilesApi.quickConnect(id),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["connection-profiles"] });
      toast({
        title: "Quick connect",
        description: `Connecting to ${res.username ? res.username + "@" : ""}${res.hostname}:${res.port}`,
      });
    },
    onError: () => {
      toast({ title: "Quick connect failed", variant: "destructive" });
    },
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => connectionProfilesApi.delete(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["connection-profiles"] });
      toast({ title: "Profile deleted" });
    },
  });

  const profiles = data?.profiles ?? [];

  return (
    <div className="container mx-auto max-w-4xl py-6 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Connection Profiles</h1>
          <p className="text-sm text-muted-foreground">
            Saved connections for one-click quick connect.
          </p>
        </div>
        <Button
          onClick={() => {
            setEditing(null);
            setDialogOpen(true);
          }}
        >
          New Profile
        </Button>
      </div>

      {isLoading && (
        <p className="text-sm text-muted-foreground">Loading profiles…</p>
      )}

      {!isLoading && profiles.length === 0 && (
        <Card>
          <CardContent className="py-10 text-center text-sm text-muted-foreground">
            No connection profiles yet. Create one to enable quick connect.
          </CardContent>
        </Card>
      )}

      <div className="space-y-3">
        {profiles.map((p) => (
          <Card key={p.profile_id} data-testid="connection-profile-card">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="flex items-center gap-2 text-base">
                {p.label}
                {p.is_favorite && (
                  <Badge variant="secondary" data-testid="favorite-badge">
                    Favorite
                  </Badge>
                )}
                <Badge variant="outline">{p.protocol.toUpperCase()}</Badge>
              </CardTitle>
              <div className="flex items-center gap-2">
                <Button
                  size="sm"
                  onClick={() => quickConnectMut.mutate(p.profile_id)}
                  data-testid="quick-connect-btn"
                >
                  Quick Connect
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => {
                    setEditing(p);
                    setDialogOpen(true);
                  }}
                >
                  Edit
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => deleteMut.mutate(p.profile_id)}
                >
                  Delete
                </Button>
              </div>
            </CardHeader>
            <CardContent className="pb-4 text-sm text-muted-foreground">
              {p.username ? `${p.username}@` : ""}
              {p.hostname || p.instance_id || "—"}:{p.port}
              {p.bastion_path_id ? " · via bastion" : ""}
              {p.last_used_at > 0 ? " · recently used" : ""}
            </CardContent>
          </Card>
        ))}
      </div>

      <ConnectionProfilesDialog
        open={dialogOpen}
        onClose={() => setDialogOpen(false)}
        profile={editing}
      />
    </div>
  );
}
