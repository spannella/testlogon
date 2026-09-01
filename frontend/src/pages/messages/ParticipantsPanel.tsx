import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Users, X, Shield, User, UserPlus, UserMinus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";
import {
  getConversation,
  addParticipants,
  updateParticipantRole,
  removeParticipant,
} from "@/api/endpoints/messaging";
import type { Participant } from "@/api/types";
import { canManageParticipants, canRemoveParticipant } from "@/lib/conversationActions";
import { useAuthStore } from "@/stores/authStore";
import { UserSearch } from "./UserSearch";

interface ParticipantsPanelProps {
  conversationId: string;
  open: boolean;
  onClose: () => void;
}

export function ParticipantsPanel({
  conversationId,
  open,
  onClose,
}: ParticipantsPanelProps) {
  const queryClient = useQueryClient();
  const [showAddUser, setShowAddUser] = useState(false);
  const viewerUserId = useAuthStore((s) => s.userId);

  const { data: convo } = useQuery({
    queryKey: ["conversation-detail", conversationId],
    queryFn: () => getConversation(conversationId),
    enabled: open,
  });

  const addMut = useMutation({
    mutationFn: (userId: string) =>
      addParticipants(conversationId, { participant_ids: [userId] }),
    onSuccess: () => {
      toast.success("Participant added");
      void queryClient.invalidateQueries({ queryKey: ["conversation-detail", conversationId] });
      void queryClient.invalidateQueries({ queryKey: ["conversations"] });
      setShowAddUser(false);
    },
    onError: () => toast.error("Failed to add participant"),
  });

  const roleMut = useMutation({
    mutationFn: ({ pid, role }: { pid: string; role: "admin" | "member" }) =>
      updateParticipantRole(conversationId, pid, { role }),
    onSuccess: () => {
      toast.success("Role updated");
      void queryClient.invalidateQueries({ queryKey: ["conversation-detail", conversationId] });
    },
    onError: () => toast.error("Failed to update role"),
  });

  const removeMut = useMutation({
    mutationFn: (pid: string) => removeParticipant(conversationId, pid),
    onSuccess: () => {
      toast.success("Participant removed");
      void queryClient.invalidateQueries({ queryKey: ["conversation-detail", conversationId] });
      void queryClient.invalidateQueries({ queryKey: ["conversations"] });
    },
    onError: () => toast.error("Failed to remove participant"),
  });

  if (!open) return null;

  const participants: Participant[] = convo?.participants ?? [];
  // Admin-only controls; guarded by the pure lib against the viewer's role.
  const canManage = canManageParticipants(convo, viewerUserId);

  // Sort admins first
  const sorted = [...participants].sort((a, b) => {
    if (a.role === "admin" && b.role !== "admin") return -1;
    if (a.role !== "admin" && b.role === "admin") return 1;
    return 0;
  });

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-40 bg-black/20"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Panel */}
      <div
        className={cn(
          "fixed right-0 top-0 z-50 flex h-full w-80 flex-col border-l border-border bg-background shadow-lg",
          "animate-in slide-in-from-right duration-200",
        )}
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <div className="flex items-center gap-2">
            <Users className="h-4 w-4" />
            <h3 className="text-sm font-semibold">
              Participants ({participants.length})
            </h3>
          </div>
          <Button variant="ghost" size="icon" className="h-8 w-8" onClick={onClose}>
            <X className="h-4 w-4" />
          </Button>
        </div>

        {/* Add participant (admins only) */}
        {canManage && (
          <div className="border-b border-border p-3">
            {showAddUser ? (
              <UserSearch
                placeholder="Search user to add..."
                onSelect={(user) => addMut.mutate(user.user_id)}
              />
            ) : (
              <Button
                variant="outline"
                size="sm"
                className="w-full"
                onClick={() => setShowAddUser(true)}
              >
                <UserPlus className="mr-1.5 h-4 w-4" />
                Add Participant
              </Button>
            )}
          </div>
        )}

        {/* Participant list */}
        <div className="flex-1 overflow-y-auto">
          {sorted.map((p) => {
            const name = p.display_name ?? p.user_id;
            const initials = name.slice(0, 2).toUpperCase();
            const isAdmin = p.role === "admin";

            return (
              <div
                key={p.user_id}
                className="flex items-center gap-3 border-b border-border/50 px-4 py-2.5"
              >
                <Avatar className="h-8 w-8 shrink-0">
                  <AvatarFallback className="text-xs">{initials}</AvatarFallback>
                </Avatar>

                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium">{name}</p>
                  <p className="truncate text-xs text-muted-foreground">{p.user_id}</p>
                </div>

                {/* Role control -- admins only; otherwise read-only badge */}
                {canManage ? (
                  <Select
                    value={p.role ?? "member"}
                    onValueChange={(value) =>
                      roleMut.mutate({ pid: p.user_id, role: value as "admin" | "member" })
                    }
                  >
                    <SelectTrigger className="h-7 w-24">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="admin">
                        <span className="flex items-center gap-1">
                          <Shield className="h-3 w-3" /> Admin
                        </span>
                      </SelectItem>
                      <SelectItem value="member">
                        <span className="flex items-center gap-1">
                          <User className="h-3 w-3" /> Member
                        </span>
                      </SelectItem>
                    </SelectContent>
                  </Select>
                ) : (
                  isAdmin && (
                    <Badge variant="outline" className="shrink-0 text-[10px]">
                      Admin
                    </Badge>
                  )
                )}

                {/* Remove participant -- admins only, never self */}
                {canRemoveParticipant(convo, viewerUserId, p.user_id) && (
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7 shrink-0 text-destructive hover:text-destructive"
                    aria-label={`Remove ${name}`}
                    disabled={removeMut.isPending}
                    onClick={() => removeMut.mutate(p.user_id)}
                  >
                    <UserMinus className="h-4 w-4" />
                  </Button>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </>
  );
}
