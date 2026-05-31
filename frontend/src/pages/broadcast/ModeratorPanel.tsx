import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Shield,
  Ban,
  Megaphone,
  Users,
  ScrollText,
  Loader2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import {
  listModerators,
  listBans,
  getModerationLog,
  registerModerator,
  postAnnouncement,
  unbanViewer,
} from "@/api/endpoints/delegateBroadcast";
import type {
  BroadcastModeratorOut,
  BroadcastBanOut,
  BroadcastModerationLogEntry,
} from "@/api/types";

interface Props {
  creatorId: string;
  sessionId: string;
}

export default function ModeratorPanel({ creatorId, sessionId }: Props) {
  const qc = useQueryClient();
  const [announcementText, setAnnouncementText] = useState("");

  // -- Queries --
  const moderatorsQuery = useQuery({
    queryKey: ["broadcast-moderators", creatorId, sessionId],
    queryFn: () => listModerators(creatorId, sessionId),
    refetchInterval: 15_000,
  });

  const bansQuery = useQuery({
    queryKey: ["broadcast-bans", creatorId, sessionId],
    queryFn: () => listBans(creatorId, sessionId),
  });

  const logQuery = useQuery({
    queryKey: ["broadcast-mod-log", creatorId, sessionId],
    queryFn: () => getModerationLog(creatorId, sessionId, 50),
  });

  // -- Mutations --
  const registerMut = useMutation({
    mutationFn: () => registerModerator(creatorId, sessionId),
    onSuccess: () => {
      toast.success("Registered as moderator");
      qc.invalidateQueries({ queryKey: ["broadcast-moderators", creatorId, sessionId] });
    },
    onError: () => toast.error("Failed to register"),
  });

  const announceMut = useMutation({
    mutationFn: (text: string) =>
      postAnnouncement(creatorId, sessionId, { text }),
    onSuccess: () => {
      toast.success("Announcement posted");
      setAnnouncementText("");
      qc.invalidateQueries({ queryKey: ["broadcast-mod-log", creatorId, sessionId] });
    },
    onError: () => toast.error("Failed to post announcement"),
  });

  const unbanMut = useMutation({
    mutationFn: (userId: string) => unbanViewer(creatorId, sessionId, userId),
    onSuccess: () => {
      toast.success("Viewer unbanned");
      qc.invalidateQueries({ queryKey: ["broadcast-bans", creatorId, sessionId] });
    },
    onError: () => toast.error("Failed to unban"),
  });

  const moderators: BroadcastModeratorOut[] = moderatorsQuery.data ?? [];
  const bans: BroadcastBanOut[] = bansQuery.data ?? [];
  const logs: BroadcastModerationLogEntry[] = logQuery.data ?? [];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield className="h-5 w-5" />
          Moderator Panel
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Register */}
        <div>
          <Button
            size="sm"
            onClick={() => registerMut.mutate()}
            disabled={registerMut.isPending}
          >
            {registerMut.isPending && <Loader2 className="mr-1 h-4 w-4 animate-spin" />}
            Register as Moderator
          </Button>
        </div>

        {/* Announcement */}
        <div className="space-y-2">
          <h4 className="text-sm font-semibold flex items-center gap-1">
            <Megaphone className="h-4 w-4" /> Post Announcement
          </h4>
          <Textarea
            placeholder="Type an announcement..."
            value={announcementText}
            onChange={(e) => setAnnouncementText(e.target.value)}
            maxLength={500}
            rows={2}
          />
          <Button
            size="sm"
            disabled={!announcementText.trim() || announceMut.isPending}
            onClick={() => announceMut.mutate(announcementText.trim())}
          >
            Send Announcement
          </Button>
        </div>

        {/* Active moderators */}
        <div>
          <h4 className="text-sm font-semibold flex items-center gap-1 mb-2">
            <Users className="h-4 w-4" /> Active Moderators ({moderators.length})
          </h4>
          {moderators.length === 0 && (
            <p className="text-xs text-muted-foreground">No moderators active</p>
          )}
          <ul className="space-y-1">
            {moderators.map((m) => (
              <li key={m.delegate_id} className="flex items-center gap-2 text-sm">
                <Badge variant={m.status === "online" ? "default" : "secondary"}>
                  {m.status}
                </Badge>
                <span>{m.display_name || m.delegate_id}</span>
                <span className="text-xs text-muted-foreground">
                  ({m.actions_count} actions)
                </span>
              </li>
            ))}
          </ul>
        </div>

        {/* Banned viewers */}
        <div>
          <h4 className="text-sm font-semibold flex items-center gap-1 mb-2">
            <Ban className="h-4 w-4" /> Banned Viewers ({bans.length})
          </h4>
          {bans.length === 0 && (
            <p className="text-xs text-muted-foreground">No banned viewers</p>
          )}
          <ul className="space-y-1">
            {bans.map((b) => (
              <li key={b.user_id} className="flex items-center gap-2 text-sm">
                <span>{b.user_id}</span>
                {b.reason && (
                  <span className="text-xs text-muted-foreground">({b.reason})</span>
                )}
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => unbanMut.mutate(b.user_id)}
                >
                  Unban
                </Button>
              </li>
            ))}
          </ul>
        </div>

        {/* Moderation log */}
        <div>
          <h4 className="text-sm font-semibold flex items-center gap-1 mb-2">
            <ScrollText className="h-4 w-4" /> Moderation Log
          </h4>
          {logs.length === 0 && (
            <p className="text-xs text-muted-foreground">No moderation actions yet</p>
          )}
          <ul className="space-y-1 max-h-48 overflow-y-auto">
            {logs.map((entry) => (
              <li key={entry.event_id} className="text-xs border-b pb-1">
                <span className="font-medium">
                  {entry.moderator_display_name || entry.moderator_id}
                </span>{" "}
                <Badge variant="outline" className="text-[10px]">
                  {entry.moderation_type}
                </Badge>
                {entry.target_user_id && (
                  <span className="text-muted-foreground">
                    {" "}target: {entry.target_user_id}
                  </span>
                )}
              </li>
            ))}
          </ul>
        </div>
      </CardContent>
    </Card>
  );
}
