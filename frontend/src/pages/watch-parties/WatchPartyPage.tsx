import { useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  getParty,
  listParticipants,
  joinParty,
  leaveParty,
  endParty,
  controlPlayback,
} from "@/api/endpoints/watchParties";
import { Play, Pause, Square, Users, Link2, Copy } from "lucide-react";

export default function WatchPartyPage() {
  const { partyId } = useParams<{ partyId: string }>();
  const qc = useQueryClient();

  const { data: party, isLoading } = useQuery({
    queryKey: ["watch-party", partyId],
    queryFn: () => getParty(partyId!),
    enabled: !!partyId,
    refetchInterval: 5000,
  });

  const { data: participants } = useQuery({
    queryKey: ["watch-party-participants", partyId],
    queryFn: () => listParticipants(partyId!),
    enabled: !!partyId,
    refetchInterval: 5000,
  });

  const joinMut = useMutation({
    mutationFn: () => joinParty(partyId!),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["watch-party", partyId] });
      qc.invalidateQueries({ queryKey: ["watch-party-participants", partyId] });
    },
  });

  const leaveMut = useMutation({
    mutationFn: () => leaveParty(partyId!),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["watch-party", partyId] });
      qc.invalidateQueries({ queryKey: ["watch-party-participants", partyId] });
    },
  });

  const endMut = useMutation({
    mutationFn: () => endParty(partyId!),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["watch-party", partyId] });
    },
  });

  const controlMut = useMutation({
    mutationFn: (data: { action: "play" | "pause" | "seek"; position?: number }) =>
      controlPlayback(partyId!, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["watch-party", partyId] });
    },
  });

  if (isLoading) return <p>Loading...</p>;
  if (!party) return <p>Party not found</p>;

  const inviteLink = `${window.location.origin}/party/${party.invite_code}`;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">{party.title}</h1>
          <p className="text-muted-foreground">{party.video_title}</p>
        </div>
        <Badge variant={party.status === "ended" ? "destructive" : "default"}>
          {party.status}
        </Badge>
      </div>

      {/* Mock video player area */}
      <Card>
        <CardContent className="p-0">
          <div className="bg-black aspect-video flex items-center justify-center rounded-t-lg">
            <p className="text-white text-lg">Video Player - {party.video_title}</p>
          </div>
          {party.status !== "ended" && (
            <div className="flex items-center gap-2 p-4">
              {party.status !== "playing" ? (
                <Button size="sm" onClick={() => controlMut.mutate({ action: "play" })}>
                  <Play className="h-4 w-4 mr-1" /> Play
                </Button>
              ) : (
                <Button size="sm" variant="outline" onClick={() => controlMut.mutate({ action: "pause" })}>
                  <Pause className="h-4 w-4 mr-1" /> Pause
                </Button>
              )}
              <span className="text-sm text-muted-foreground ml-auto">
                Position: {Math.floor(Number(party.position))}s / {party.video_duration_seconds}s
              </span>
            </div>
          )}
        </CardContent>
      </Card>

      <div className="grid gap-4 md:grid-cols-3">
        {/* Invite link */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Link2 className="h-4 w-4" /> Invite Link
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              <code className="text-xs bg-muted px-2 py-1 rounded flex-1 truncate">
                {inviteLink}
              </code>
              <Button
                size="sm"
                variant="outline"
                onClick={() => navigator.clipboard?.writeText(inviteLink)}
              >
                <Copy className="h-3 w-3" />
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Participants */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Users className="h-4 w-4" /> Participants ({party.participant_count})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-1 text-sm">
              {participants?.filter(p => p.status === "active").map((p) => (
                <li key={p.user_sub} className="flex items-center justify-between">
                  <span className="truncate">{p.user_sub}</span>
                  <Badge variant="outline" className="text-xs">{p.role}</Badge>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>

        {/* Actions */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Actions</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {party.status !== "ended" && (
              <>
                <Button size="sm" className="w-full" variant="outline" onClick={() => joinMut.mutate()}>
                  Join Party
                </Button>
                <Button size="sm" className="w-full" variant="outline" onClick={() => leaveMut.mutate()}>
                  Leave Party
                </Button>
                <Button
                  size="sm"
                  className="w-full"
                  variant="destructive"
                  onClick={() => endMut.mutate()}
                >
                  <Square className="h-4 w-4 mr-1" /> End Party
                </Button>
              </>
            )}
            {party.status === "ended" && (
              <p className="text-sm text-muted-foreground text-center">This party has ended.</p>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
