import * as React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, ShieldCheck, ShieldOff, XCircle } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import { StatusBadge } from "@/components/shared/StatusBadge";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import {
  getAccountStatus,
  suspendAccount,
  reactivateAccount,
  startAccountClosure,
  finalizeAccountClosure,
} from "@/api/endpoints/account";

function statusVariant(status: string) {
  switch (status) {
    case "active":
      return "success" as const;
    case "suspended":
      return "warning" as const;
    case "closed":
    case "closure_pending":
      return "danger" as const;
    default:
      return "neutral" as const;
  }
}

export function Account() {
  const queryClient = useQueryClient();
  const [suspendOpen, setSuspendOpen] = React.useState(false);
  const [suspendReason, setSuspendReason] = React.useState("");
  const [closureStep, setClosureStep] = React.useState<"idle" | "confirm" | "finalize">("idle");
  const [challengeId, setChallengeId] = React.useState("");

  const statusQuery = useQuery({
    queryKey: ["account-status"],
    queryFn: getAccountStatus,
  });

  const suspendMutation = useMutation({
    mutationFn: () => suspendAccount({ reason: suspendReason || undefined }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["account-status"] });
      setSuspendOpen(false);
      setSuspendReason("");
      toast.success("Account suspended");
    },
    onError: () => {
      toast.error("Failed to suspend account");
    },
  });

  const reactivateMutation = useMutation({
    mutationFn: () => reactivateAccount(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["account-status"] });
      toast.success("Account reactivated");
    },
    onError: () => {
      toast.error("Failed to reactivate account");
    },
  });

  const startClosureMutation = useMutation({
    mutationFn: () => startAccountClosure(),
    onSuccess: (data) => {
      setChallengeId(data.challenge_id);
      setClosureStep("finalize");
    },
    onError: () => {
      toast.error("Failed to start account closure");
      setClosureStep("idle");
    },
  });

  const finalizeClosureMutation = useMutation({
    mutationFn: () => finalizeAccountClosure({ challenge_id: challengeId }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["account-status"] });
      setClosureStep("idle");
      setChallengeId("");
      toast.success("Account closure finalized");
    },
    onError: () => {
      toast.error("Failed to finalize account closure");
    },
  });

  const status = statusQuery.data?.status ?? "unknown";

  if (statusQuery.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-24 w-full rounded-xl" />
        <Skeleton className="h-32 w-full rounded-xl" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Current status */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Account Status</CardTitle>
            <StatusBadge variant={statusVariant(status)} className="capitalize">
              {status.replace("_", " ")}
            </StatusBadge>
          </div>
          {statusQuery.data?.reason && (
            <CardDescription>Reason: {statusQuery.data.reason}</CardDescription>
          )}
          {statusQuery.data?.updated_at && (
            <CardDescription className="text-xs">
              Last updated: {new Date(statusQuery.data.updated_at * 1000).toLocaleString()}
            </CardDescription>
          )}
        </CardHeader>
      </Card>

      {/* Suspend / Reactivate */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            {status === "suspended" ? (
              <ShieldOff className="h-4 w-4 text-warning" />
            ) : (
              <ShieldCheck className="h-4 w-4" />
            )}
            {status === "suspended" ? "Reactivate Account" : "Suspend Account"}
          </CardTitle>
          <CardDescription>
            {status === "suspended"
              ? "Your account is currently suspended. Reactivate to regain full access."
              : "Temporarily suspend your account. You can reactivate later."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {status === "suspended" ? (
            <Button
              onClick={() => reactivateMutation.mutate()}
              disabled={reactivateMutation.isPending}
            >
              {reactivateMutation.isPending ? "Reactivating..." : "Reactivate Account"}
            </Button>
          ) : (
            <Button
              variant="destructive"
              onClick={() => setSuspendOpen(true)}
              disabled={status === "closed" || status === "closure_pending"}
            >
              Suspend Account
            </Button>
          )}
        </CardContent>
      </Card>

      {/* Suspend dialog with reason */}
      <ConfirmDialog
        open={suspendOpen}
        onOpenChange={setSuspendOpen}
        title="Suspend Your Account"
        description="Are you sure you want to suspend your account? You will be able to reactivate later."
        confirmLabel="Suspend"
        variant="danger"
        onConfirm={() => suspendMutation.mutate()}
        loading={suspendMutation.isPending}
      />

      <Separator />

      {/* Account Closure */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-destructive">
            <XCircle className="h-4 w-4" />
            Close Account
          </CardTitle>
          <CardDescription>
            Permanently close your account. This action cannot be easily reversed.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {status === "closed" ? (
            <div className="flex items-center gap-2 rounded-lg border border-destructive/20 bg-destructive/5 px-4 py-3">
              <AlertTriangle className="h-4 w-4 text-destructive" />
              <p className="text-sm text-destructive">
                This account has been closed
                {statusQuery.data?.closed_at
                  ? ` on ${new Date(statusQuery.data.closed_at * 1000).toLocaleDateString()}`
                  : ""}
                .
              </p>
            </div>
          ) : closureStep === "idle" ? (
            <Button
              variant="destructive"
              onClick={() => setClosureStep("confirm")}
              disabled={status === "closure_pending"}
            >
              Begin Account Closure
            </Button>
          ) : closureStep === "confirm" ? (
            <div className="space-y-3">
              <div className="flex items-center gap-2 rounded-lg border border-destructive/20 bg-destructive/5 px-4 py-3">
                <AlertTriangle className="h-4 w-4 text-destructive" />
                <p className="text-sm">
                  This will permanently close your account. All data will be scheduled for deletion.
                </p>
              </div>
              <div className="flex gap-2">
                <Button
                  variant="destructive"
                  onClick={() => startClosureMutation.mutate()}
                  disabled={startClosureMutation.isPending}
                >
                  {startClosureMutation.isPending ? "Processing..." : "Confirm Closure"}
                </Button>
                <Button variant="outline" onClick={() => setClosureStep("idle")}>
                  Cancel
                </Button>
              </div>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="flex items-center gap-2 rounded-lg border border-destructive/20 bg-destructive/5 px-4 py-3">
                <AlertTriangle className="h-4 w-4 text-destructive" />
                <p className="text-sm">
                  A verification challenge has been sent. Enter the challenge ID below to finalize.
                </p>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="challenge-id">Challenge ID</Label>
                <Input
                  id="challenge-id"
                  value={challengeId}
                  onChange={(e) => setChallengeId(e.target.value)}
                  readOnly
                />
              </div>
              <div className="flex gap-2">
                <Button
                  variant="destructive"
                  onClick={() => finalizeClosureMutation.mutate()}
                  disabled={!challengeId || finalizeClosureMutation.isPending}
                >
                  {finalizeClosureMutation.isPending ? "Finalizing..." : "Finalize Closure"}
                </Button>
                <Button
                  variant="outline"
                  onClick={() => {
                    setClosureStep("idle");
                    setChallengeId("");
                  }}
                >
                  Cancel
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
