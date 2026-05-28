import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Copy, UserPlus, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  createGuestInvite,
  listGuestInvites,
  revokeGuestInvite,
} from "@/api/endpoints/broadcast-inputs";
import type { BroadcastGuestInvite } from "@/api/types";

interface GuestInviteDialogProps {
  sessionId: string;
}

export default function GuestInviteDialog({ sessionId }: GuestInviteDialogProps) {
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [label, setLabel] = useState("Guest");
  const [joinMode, setJoinMode] = useState<"browser" | "rtmp">("browser");
  const [expiryMinutes, setExpiryMinutes] = useState(60);

  const invitesQuery = useQuery({
    queryKey: ["broadcast", "guest-invites", sessionId],
    queryFn: () => listGuestInvites(sessionId),
    enabled: open,
    refetchInterval: 5000,
  });

  const invites: BroadcastGuestInvite[] = invitesQuery.data?.invites ?? [];

  const createMut = useMutation({
    mutationFn: () =>
      createGuestInvite(sessionId, {
        join_mode: joinMode,
        label,
        expiry_minutes: expiryMinutes,
      }),
    onSuccess: (result) => {
      toast.success(`Invite created: ${result.invite_id}`);
      if (result.stream_key) {
        navigator.clipboard.writeText(result.stream_key);
        toast.info("Stream key copied to clipboard");
      }
      queryClient.invalidateQueries({ queryKey: ["broadcast", "guest-invites", sessionId] });
      queryClient.invalidateQueries({ queryKey: ["broadcast", "inputs", sessionId] });
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed to create invite"),
  });

  const revokeMut = useMutation({
    mutationFn: (inviteId: string) => revokeGuestInvite(sessionId, inviteId),
    onSuccess: () => {
      toast.success("Invite revoked");
      queryClient.invalidateQueries({ queryKey: ["broadcast", "guest-invites", sessionId] });
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : "Failed to revoke invite"),
  });

  const copyUrl = (url: string) => {
    navigator.clipboard.writeText(window.location.origin + url);
    toast.success("Invite URL copied");
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm">
          <UserPlus className="h-4 w-4 mr-1" />
          Invite Guest
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Guest Co-Streaming</DialogTitle>
          <DialogDescription>
            Invite guests to join your broadcast via RTMP or browser.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {/* Create invite form */}
          <div className="space-y-3 rounded-md border p-3">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label htmlFor="guest-label">Guest Name</Label>
                <Input
                  id="guest-label"
                  value={label}
                  onChange={(e) => setLabel(e.target.value)}
                  placeholder="Guest"
                />
              </div>
              <div>
                <Label>Join Mode</Label>
                <Select value={joinMode} onValueChange={(v) => setJoinMode(v as "browser" | "rtmp")}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="browser">Browser (WebRTC)</SelectItem>
                    <SelectItem value="rtmp">RTMP (OBS)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div>
              <Label htmlFor="expiry">Expiry (minutes)</Label>
              <Input
                id="expiry"
                type="number"
                min={5}
                max={1440}
                value={expiryMinutes}
                onChange={(e) => setExpiryMinutes(Number(e.target.value))}
              />
            </div>
            <Button onClick={() => createMut.mutate()} disabled={createMut.isPending} className="w-full">
              <UserPlus className="h-4 w-4 mr-2" />
              Create Invite
            </Button>
          </div>

          {/* Active invites list */}
          {invites.length > 0 && (
            <div className="space-y-2">
              <h4 className="text-sm font-medium">Active Invites</h4>
              {invites.map((inv) => (
                <div
                  key={inv.invite_id}
                  className="flex items-center justify-between rounded-md border p-2 text-sm"
                >
                  <div className="flex items-center gap-2">
                    <Badge
                      variant={
                        inv.status === "accepted"
                          ? "default"
                          : inv.status === "pending"
                            ? "secondary"
                            : "destructive"
                      }
                    >
                      {inv.status}
                    </Badge>
                    <span>{inv.guest_display_name || inv.join_mode}</span>
                  </div>
                  <div className="flex items-center gap-1">
                    {inv.invite_url && inv.status === "pending" && (
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7"
                        onClick={() => copyUrl(inv.invite_url!)}
                      >
                        <Copy className="h-3 w-3" />
                      </Button>
                    )}
                    {inv.status === "pending" && (
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7 text-destructive"
                        onClick={() => revokeMut.mutate(inv.invite_id)}
                      >
                        <X className="h-3 w-3" />
                      </Button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
