import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Monitor, Globe, Clock, LogOut } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import { getSessions, revokeSession, revokeOtherSessions } from "@/api/endpoints/auth";

export function Sessions() {
  const queryClient = useQueryClient();
  const [revokeTarget, setRevokeTarget] = useState<string | null>(null);
  const [revokeAllOpen, setRevokeAllOpen] = useState(false);

  const sessionsQuery = useQuery({
    queryKey: ["sessions"],
    queryFn: getSessions,
  });

  const revokeMutation = useMutation({
    mutationFn: (sessionId: string) => revokeSession(sessionId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sessions"] });
      toast.success("Session revoked");
      setRevokeTarget(null);
    },
    onError: () => toast.error("Failed to revoke session"),
  });

  const revokeAllMutation = useMutation({
    mutationFn: revokeOtherSessions,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sessions"] });
      toast.success("All other sessions revoked");
      setRevokeAllOpen(false);
    },
    onError: () => toast.error("Failed to revoke sessions"),
  });

  const sessions = sessionsQuery.data?.sessions ?? [];

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Monitor className="h-5 w-5 text-muted-foreground" />
            <CardTitle className="text-base">Active Sessions</CardTitle>
          </div>
          {sessions.filter((s) => !s.is_current && !s.revoked).length > 0 && (
            <Button
              size="sm"
              variant="destructive"
              onClick={() => setRevokeAllOpen(true)}
            >
              <LogOut className="mr-1 h-3.5 w-3.5" />
              Revoke All Others
            </Button>
          )}
        </div>
        <CardDescription>Manage your active login sessions across devices</CardDescription>
      </CardHeader>
      <CardContent>
        {sessionsQuery.isLoading ? (
          <div className="space-y-2">
            <Skeleton className="h-16 w-full" />
            <Skeleton className="h-16 w-full" />
          </div>
        ) : sessions.length === 0 ? (
          <p className="text-sm text-muted-foreground">No active sessions.</p>
        ) : (
          <ul className="divide-y">
            {sessions.map((s) => (
              <li key={s.session_id} className="flex items-center justify-between gap-4 py-3">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <p className="truncate text-sm font-medium">
                      {parseUserAgent(s.user_agent)}
                    </p>
                    {s.is_current && (
                      <Badge variant="default" className="shrink-0">Current</Badge>
                    )}
                    {s.revoked && (
                      <Badge variant="secondary" className="shrink-0">Revoked</Badge>
                    )}
                  </div>
                  <div className="mt-0.5 flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                    <span className="inline-flex items-center gap-1">
                      <Globe className="h-3 w-3" />
                      {s.ip}
                    </span>
                    <span className="inline-flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      {s.last_seen_at
                        ? `Last seen ${new Date(s.last_seen_at * 1000).toLocaleString()}`
                        : "Not yet seen"}
                    </span>
                  </div>
                </div>
                {!s.is_current && !s.revoked && (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => setRevokeTarget(s.session_id)}
                  >
                    Revoke
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}
      </CardContent>

      <ConfirmDialog
        open={!!revokeTarget}
        onOpenChange={(o) => { if (!o) setRevokeTarget(null); }}
        title="Revoke Session"
        description="This will log out the device associated with this session."
        variant="danger"
        confirmLabel="Revoke"
        onConfirm={() => { if (revokeTarget) revokeMutation.mutate(revokeTarget); }}
        loading={revokeMutation.isPending}
      />

      <ConfirmDialog
        open={revokeAllOpen}
        onOpenChange={setRevokeAllOpen}
        title="Revoke All Other Sessions"
        description="This will log out all other devices. Only your current session will remain active."
        variant="danger"
        confirmLabel="Revoke All"
        onConfirm={() => revokeAllMutation.mutate()}
        loading={revokeAllMutation.isPending}
      />
    </Card>
  );
}

/** Simple user-agent parser for display */
function parseUserAgent(ua: string): string {
  if (!ua) return "Unknown device";
  // Try to extract browser + OS info
  const browserMatch = ua.match(/(Chrome|Firefox|Safari|Edge|Opera|MSIE|Trident)[/\s]?([\d.]+)?/i);
  const osMatch = ua.match(/(Windows|Mac OS X|Linux|Android|iOS|iPhone)[/\s]?([\d._]+)?/i);
  const browser = browserMatch ? browserMatch[1] : null;
  const os = osMatch ? osMatch[1]?.replace("_", ".") : null;
  if (browser && os) return `${browser} on ${os}`;
  if (browser) return browser;
  if (os) return os;
  return ua.length > 60 ? ua.slice(0, 57) + "..." : ua;
}
