import { useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Video, Play, Trash2, Loader2, X } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

import {
  listSshRecordings,
  deleteSshRecording,
  getSshRecordingPlayback,
} from "@/api/endpoints/sshSessionRecording";
import type { SshRecordingOut, SshRecordingPlaybackOut } from "@/api/types";
import SshRecordingPlayer from "./SshRecordingPlayer";

const RECORDINGS_QUERY_KEY = ["compute", "ssh-recordings"];

function formatDuration(seconds: number): string {
  if (!seconds) return "0s";
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return m > 0 ? `${m}m ${s}s` : `${s}s`;
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatRelative(ts: number): string {
  if (!ts) return "—";
  const diff = Math.floor(Date.now() / 1000) - ts;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export default function SshRecordingsPage() {
  const queryClient = useQueryClient();
  const [hostFilter, setHostFilter] = useState("");
  const [playingId, setPlayingId] = useState<string | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: RECORDINGS_QUERY_KEY,
    queryFn: () => listSshRecordings(),
  });

  const recordings = data?.recordings ?? [];

  const hosts = useMemo(() => {
    const set = new Set<string>();
    recordings.forEach((r) => set.add(r.host_key));
    return Array.from(set).sort();
  }, [recordings]);

  const filtered = useMemo(
    () =>
      hostFilter
        ? recordings.filter((r) => r.host_key === hostFilter)
        : recordings,
    [recordings, hostFilter],
  );

  const { data: playback, isLoading: playbackLoading } =
    useQuery<SshRecordingPlaybackOut>({
      queryKey: [...RECORDINGS_QUERY_KEY, "playback", playingId],
      queryFn: () => getSshRecordingPlayback(playingId as string),
      enabled: !!playingId,
    });

  const deleteMut = useMutation({
    mutationFn: (id: string) => deleteSshRecording(id),
    onSuccess: (_d, id) => {
      toast.success("Recording deleted");
      if (playingId === id) setPlayingId(null);
      queryClient.invalidateQueries({ queryKey: RECORDINGS_QUERY_KEY });
    },
    onError: () => toast.error("Failed to delete recording"),
  });

  const playingRec: SshRecordingOut | undefined = filtered.find(
    (r) => r.recording_id === playingId,
  );

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Video className="h-5 w-5" />
            Session Recordings
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <Input
              data-testid="ssh-recording-host-filter"
              placeholder="Filter by host (e.g. host:22)"
              value={hostFilter}
              onChange={(e) => setHostFilter(e.target.value)}
              list="ssh-recording-hosts"
              className="max-w-xs"
            />
            <datalist id="ssh-recording-hosts">
              {hosts.map((h) => (
                <option key={h} value={h} />
              ))}
            </datalist>
            {hostFilter && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setHostFilter("")}
              >
                <X className="mr-1 h-4 w-4" />
                Clear
              </Button>
            )}
          </div>

          {isLoading ? (
            <div className="flex items-center gap-2 text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
              Loading recordings…
            </div>
          ) : filtered.length === 0 ? (
            <p
              data-testid="ssh-recordings-empty"
              className="text-sm text-muted-foreground"
            >
              No session recordings yet.
            </p>
          ) : (
            <Table data-testid="ssh-recordings-table">
              <TableHeader>
                <TableRow>
                  <TableHead>Host</TableHead>
                  <TableHead>Username</TableHead>
                  <TableHead>Started</TableHead>
                  <TableHead>Duration</TableHead>
                  <TableHead>Size</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((rec) => (
                  <TableRow key={rec.recording_id} data-testid="ssh-recording-row">
                    <TableCell className="font-medium">
                      {rec.host_key}
                      {rec.status === "recording" && (
                        <Badge variant="secondary" className="ml-2">
                          live
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell>{rec.username || "—"}</TableCell>
                    <TableCell>{formatRelative(rec.created_at)}</TableCell>
                    <TableCell>{formatDuration(rec.duration_seconds)}</TableCell>
                    <TableCell>{formatSize(rec.file_size_bytes)}</TableCell>
                    <TableCell className="text-right">
                      <Button
                        size="sm"
                        variant="secondary"
                        className="mr-2"
                        data-testid="ssh-recording-play"
                        onClick={() => setPlayingId(rec.recording_id)}
                      >
                        <Play className="mr-1 h-4 w-4" />
                        Play
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        data-testid="ssh-recording-delete"
                        disabled={deleteMut.isPending}
                        onClick={() => deleteMut.mutate(rec.recording_id)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {playingId && (
        <Card data-testid="ssh-recording-player-card">
          <CardHeader>
            <CardTitle className="flex items-center justify-between text-base">
              <span>
                Playback — {playingRec?.host_key ?? playingId}
              </span>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => setPlayingId(null)}
              >
                <X className="h-4 w-4" />
              </Button>
            </CardTitle>
          </CardHeader>
          <CardContent>
            {playbackLoading || !playback ? (
              <div className="flex items-center gap-2 text-muted-foreground">
                <Loader2 className="h-4 w-4 animate-spin" />
                Loading recording…
              </div>
            ) : (
              <SshRecordingPlayer
                events={playback.events}
                cols={playingRec?.terminal_cols}
                rows={playingRec?.terminal_rows}
                autoPlay
              />
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
