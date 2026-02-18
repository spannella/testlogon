import * as React from "react";
import { useMutation } from "@tanstack/react-query";
import { AlertTriangle, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { useAuthStore } from "@/stores/authStore";
import { useImpersonationStore } from "@/stores/impersonationStore";
import { startImpersonation, stopImpersonation } from "@/api/endpoints/adminImpersonation";
import { ApiError } from "@/api/client";

function accessTokenRole(token: string | null): string | null {
  if (!token || token.split(".").length < 2) return null;
  try {
    const payload = JSON.parse(atob(token.split(".")[1]!));
    return typeof payload?.role === "string" ? payload.role : null;
  } catch {
    return null;
  }
}

function formatExpiry(epoch?: number | null) {
  if (!epoch) return "-";
  return new Date(epoch * 1000).toLocaleString();
}

export default function ImpersonationBanner() {
  const accessToken = useAuthStore((s) => s.accessToken);
  const role = accessTokenRole(accessToken);
  const canImpersonate = role === "admin" || role === "root";

  const imp = useImpersonationStore();
  const active = imp.isActive();

  const [open, setOpen] = React.useState(false);
  const [targetUserSub, setTargetUserSub] = React.useState("");
  const [reason, setReason] = React.useState("");

  const startMut = useMutation({
    mutationFn: () => startImpersonation({ target_user_sub: targetUserSub.trim(), reason: reason.trim() }),
    onSuccess: (resp) => {
      imp.start({
        token: resp.token,
        impersonationId: resp.impersonation_id,
        actorSub: resp.actor_sub,
        effectiveSub: resp.effective_sub,
        expiresAt: resp.expires_at,
      });
      setOpen(false);
      setTargetUserSub("");
      setReason("");
      toast.success(`Now acting as ${resp.effective_sub}`);
    },
    onError: (err) => {
      const msg = err instanceof ApiError ? err.detail : "Failed to start impersonation";
      toast.error(msg);
    },
  });

  const stopMut = useMutation({
    mutationFn: async () => {
      const id = imp.impersonationId;
      if (!id) return { ok: true };
      return stopImpersonation({ impersonation_id: id });
    },
    onSuccess: () => {
      imp.clear();
      toast.success("Impersonation ended");
    },
    onError: (err) => {
      imp.clear();
      const msg = err instanceof ApiError ? err.detail : "Failed to stop impersonation; local context cleared";
      toast.error(msg);
    },
  });

  if (!canImpersonate && !active) return null;

  return (
    <div className="border-b border-amber-300/60 bg-amber-100/80 px-4 py-2 text-amber-950 backdrop-blur-sm dark:border-amber-900/60 dark:bg-amber-900/30 dark:text-amber-100">
      <div className="mx-auto flex w-full max-w-7xl items-center justify-between gap-3">
        <div className="flex min-w-0 items-center gap-2 text-sm">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          {active ? (
            <span className="truncate">
              Acting as <span className="font-semibold">{imp.effectiveSub}</span>
              {imp.actorSub ? <> (actor: {imp.actorSub})</> : null} • expires {formatExpiry(imp.expiresAt)}
            </span>
          ) : (
            <span className="truncate">Admin/root impersonation controls available.</span>
          )}
        </div>

        <div className="flex shrink-0 items-center gap-2">
          {!active && canImpersonate ? (
            <Dialog open={open} onOpenChange={setOpen}>
              <DialogTrigger asChild>
                <Button size="sm" variant="secondary">Start impersonation</Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Start impersonation</DialogTitle>
                  <DialogDescription>
                    Enter target user and reason. Banner will remain visible while acting as another user.
                  </DialogDescription>
                </DialogHeader>
                <div className="space-y-3 py-1">
                  <div className="space-y-1.5">
                    <Label htmlFor="imp-target">Target user_sub</Label>
                    <Input id="imp-target" value={targetUserSub} onChange={(e) => setTargetUserSub(e.target.value)} placeholder="user_123" />
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="imp-reason">Reason</Label>
                    <Input id="imp-reason" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Support ticket / investigation context" />
                  </div>
                </div>
                <DialogFooter>
                  <Button
                    onClick={() => {
                      if (!targetUserSub.trim()) {
                        toast.error("Target user_sub is required");
                        return;
                      }
                      startMut.mutate();
                    }}
                    disabled={startMut.isPending}
                  >
                    {startMut.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                    Begin
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          ) : null}

          {active ? (
            <Button size="sm" variant="destructive" onClick={() => stopMut.mutate()} disabled={stopMut.isPending}>
              {stopMut.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
              Stop impersonation
            </Button>
          ) : null}
        </div>
      </div>
    </div>
  );
}
