import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  adminGetFaceComparison,
  adminOverrideFaceComparison,
} from "@/api/endpoints/kycFacialComparison";
import type { FaceComparisonResultValue } from "@/api/types";

interface Props {
  caseId: string;
}

function resultBadge(result: string): "success" | "warning" | "destructive" | "secondary" {
  if (result === "pass") return "success";
  if (result === "review") return "warning";
  if (result === "fail") return "destructive";
  return "secondary";
}

function formatDate(ts: number): string {
  if (!ts) return "--";
  return new Date(ts * 1000).toLocaleString();
}

/**
 * KYC-014 admin side-by-side facial-comparison review. Shows the selfie and ID
 * photo next to each other with the best confidence score, lists all attempts,
 * and lets a root/admin override the result with a reason.
 */
export function KycFacialComparisonReview({ caseId }: Props) {
  const queryClient = useQueryClient();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [decision, setDecision] = useState<"pass" | "fail">("pass");
  const [reason, setReason] = useState("");

  const { data, isLoading } = useQuery({
    queryKey: ["kyc", "admin-face-comparison", caseId],
    queryFn: () => adminGetFaceComparison(caseId),
    staleTime: 5_000,
  });

  const targetComparisonId =
    data?.best_comparison?.comparison_id ?? data?.comparisons?.[0]?.comparison_id ?? null;

  const overrideMutation = useMutation({
    mutationFn: () => {
      if (!targetComparisonId) throw new Error("no_comparison");
      return adminOverrideFaceComparison(caseId, targetComparisonId, { decision, reason });
    },
    onSuccess: () => {
      toast.success("Comparison overridden");
      setDialogOpen(false);
      setReason("");
      queryClient.invalidateQueries({ queryKey: ["kyc", "admin-face-comparison", caseId] });
    },
    onError: () => toast.error("Override failed"),
  });

  function openOverride(d: "pass" | "fail") {
    setDecision(d);
    setReason("");
    setDialogOpen(true);
  }

  if (isLoading) {
    return (
      <Card data-testid="admin-face-comparison">
        <CardHeader>
          <CardTitle className="text-sm font-medium">Face Comparison</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">Loading...</p>
        </CardContent>
      </Card>
    );
  }

  const best = data?.best_comparison;

  return (
    <Card data-testid="admin-face-comparison">
      <CardHeader>
        <CardTitle className="text-sm font-medium">Face Comparison</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Side-by-side images */}
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-1">
            <h4 className="text-xs font-medium text-muted-foreground">Selfie</h4>
            {data?.selfie_url ? (
              <img
                src={data.selfie_url}
                alt="Selfie"
                className="w-full rounded-lg border object-cover"
                data-testid="face-comparison-selfie-img"
              />
            ) : (
              <div className="flex h-32 items-center justify-center rounded-lg border text-xs text-muted-foreground">
                No selfie
              </div>
            )}
          </div>
          <div className="space-y-1">
            <h4 className="text-xs font-medium text-muted-foreground">ID Photo</h4>
            {data?.id_front_url ? (
              <img
                src={data.id_front_url}
                alt="ID front"
                className="w-full rounded-lg border object-cover"
                data-testid="face-comparison-id-img"
              />
            ) : (
              <div className="flex h-32 items-center justify-center rounded-lg border text-xs text-muted-foreground">
                No ID photo
              </div>
            )}
          </div>
        </div>

        {/* Best score */}
        {best ? (
          <div className="text-center" data-testid="face-comparison-best">
            <span className="text-3xl font-bold">{best.confidence_score}</span>
            <span className="ml-2">
              <Badge variant={resultBadge(best.result)}>{best.result}</Badge>
            </span>
            <p className="text-xs text-muted-foreground">
              Best of {data?.total_attempts ?? 0} attempt
              {(data?.total_attempts ?? 0) === 1 ? "" : "s"}
            </p>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">No comparison attempts yet.</p>
        )}

        {/* All attempts */}
        {data && data.comparisons.length > 0 && (
          <div className="space-y-1">
            <h4 className="text-xs font-medium text-muted-foreground">All Attempts</h4>
            <table className="w-full text-sm" data-testid="face-comparison-attempts">
              <thead>
                <tr className="text-left text-xs text-muted-foreground">
                  <th className="py-1">#</th>
                  <th>Score</th>
                  <th>Result</th>
                  <th>Date</th>
                  <th>Override</th>
                </tr>
              </thead>
              <tbody>
                {data.comparisons.map((c) => (
                  <tr key={c.comparison_id} className="border-t">
                    <td className="py-1">{c.attempt_number}</td>
                    <td>{c.confidence_score}</td>
                    <td>
                      <Badge variant={resultBadge(c.result)}>{c.result}</Badge>
                    </td>
                    <td className="text-xs text-muted-foreground">{formatDate(c.created_at)}</td>
                    <td className="text-xs">
                      {c.admin_override
                        ? `${(c.admin_override as { decision: FaceComparisonResultValue }).decision} (override)`
                        : "--"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Decision buttons */}
        {targetComparisonId && (
          <div className="flex justify-end gap-2">
            <Button
              variant="default"
              onClick={() => openOverride("pass")}
              data-testid="override-approve"
            >
              Approve Match
            </Button>
            <Button
              variant="destructive"
              onClick={() => openOverride("fail")}
              data-testid="override-reject"
            >
              Reject Match
            </Button>
          </div>
        )}

        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>
                Override Comparison Result — {decision === "pass" ? "Approve" : "Reject"}
              </DialogTitle>
            </DialogHeader>
            <div className="space-y-3">
              <Label htmlFor="override-reason">Reason</Label>
              <Textarea
                id="override-reason"
                value={reason}
                minLength={5}
                onChange={(e) => setReason(e.target.value)}
                placeholder="Explain the override decision (min 5 characters)"
                data-testid="override-reason"
              />
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setDialogOpen(false)}>
                Cancel
              </Button>
              <Button
                onClick={() => overrideMutation.mutate()}
                disabled={reason.trim().length < 5 || overrideMutation.isPending}
                data-testid="override-confirm"
              >
                Confirm Override
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </CardContent>
    </Card>
  );
}

export default KycFacialComparisonReview;
