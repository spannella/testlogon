import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, XCircle, ShieldAlert, Loader2 } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { compareFace, listFaceComparisons } from "@/api/endpoints/kycFacialComparison";
import type { FaceComparisonResult as FaceComparison } from "@/api/types";

interface Props {
  caseId: string;
}

function resultBadge(result: string): { variant: "success" | "warning" | "destructive"; label: string } {
  if (result === "pass") return { variant: "success", label: "Match Confirmed" };
  if (result === "review") return { variant: "warning", label: "Manual Review Required" };
  return { variant: "destructive", label: "Match Failed" };
}

function scoreColor(score: number): string {
  if (score >= 70) return "text-success";
  if (score >= 50) return "text-warning";
  return "text-destructive";
}

/**
 * KYC-014 user-facing facial-comparison result, shown after selfie upload in the
 * KYC wizard. Lets the user trigger a comparison and view the confidence score,
 * result badge, attempt counter, and anti-spoof details.
 */
export function FaceComparisonResult({ caseId }: Props) {
  const queryClient = useQueryClient();
  const [showAntiSpoof, setShowAntiSpoof] = useState(false);

  const { data: list } = useQuery({
    queryKey: ["kyc", "face-comparisons", caseId],
    queryFn: () => listFaceComparisons(caseId),
    staleTime: 10_000,
  });

  const latest: FaceComparison | undefined = list?.comparisons?.[0];

  const mutation = useMutation({
    mutationFn: () => compareFace(caseId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["kyc", "face-comparisons", caseId] });
    },
  });

  const result = latest;
  const badge = result ? resultBadge(result.result) : null;

  return (
    <Card data-testid="face-comparison-result">
      <CardHeader>
        <CardTitle className="text-sm font-medium">Face Comparison</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {!result && (
          <div className="space-y-2">
            <p className="text-sm text-muted-foreground">
              Compare your selfie against your ID photo.
            </p>
            <Button
              onClick={() => mutation.mutate()}
              disabled={mutation.isPending}
              data-testid="run-face-comparison"
            >
              {mutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Run Face Comparison
            </Button>
          </div>
        )}

        {result && badge && (
          <>
            <div className="flex items-center gap-6">
              <div
                className={`text-4xl font-bold ${scoreColor(result.confidence_score)}`}
                data-testid="face-comparison-score"
              >
                {result.confidence_score}
                <span className="text-base text-muted-foreground">/100</span>
              </div>
              <Badge variant={badge.variant} data-testid="face-comparison-badge">
                {badge.label}
              </Badge>
              <span className="text-sm text-muted-foreground">
                Attempt {result.attempt_number} of {result.max_attempts}
              </span>
            </div>

            {result.result === "fail" && result.remaining_attempts > 0 && (
              <div className="space-y-2">
                <p className="text-sm">
                  Your selfie did not match. You have {result.remaining_attempts} attempt
                  {result.remaining_attempts === 1 ? "" : "s"} left.
                </p>
                <Button
                  variant="outline"
                  onClick={() => mutation.mutate()}
                  disabled={mutation.isPending}
                  data-testid="retry-face-comparison"
                >
                  Run Again
                </Button>
              </div>
            )}

            {result.result === "fail" && result.remaining_attempts === 0 && (
              <p className="text-sm text-destructive" data-testid="face-comparison-exhausted">
                All comparison attempts used. An admin will review manually.
              </p>
            )}

            <div>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setShowAntiSpoof((v) => !v)}
                data-testid="toggle-anti-spoof"
              >
                <ShieldAlert className="mr-2 h-4 w-4" />
                Anti-Spoof Details ({result.anti_spoof.passed_checks}/
                {result.anti_spoof.total_checks})
              </Button>
              {showAntiSpoof && (
                <div className="mt-2 space-y-1" data-testid="anti-spoof-detail">
                  {result.anti_spoof.checks.map((c) => (
                    <div key={c.check} className="flex items-center gap-2 text-sm">
                      {c.passed ? (
                        <CheckCircle2 className="h-4 w-4 text-success" />
                      ) : (
                        <XCircle className="h-4 w-4 text-destructive" />
                      )}
                      <span className="font-medium">{c.check}</span>
                      <span className="text-muted-foreground">{c.detail}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

export default FaceComparisonResult;
