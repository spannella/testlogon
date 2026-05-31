import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { CheckCircle, Circle, Loader2, ShieldCheck } from "lucide-react";
import { toast } from "sonner";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import KycTierBadge from "@/components/shared/KycTierBadge";
import { getMyTier, checkRequirements, evaluateTier } from "@/api/endpoints/kyc-tiers";

const TIER_NAMES: Record<number, string> = {
  0: "Unverified",
  1: "Basic",
  2: "ID Verified",
  3: "Enhanced",
  4: "Institutional",
};

const REQUIREMENT_LABELS: Record<string, string> = {
  email_verified: "Email verified",
  phone_verified: "Phone verified",
  tier_1: "Basic tier achieved",
  kyc_case_approved: "KYC case approved (ID + selfie)",
  tier_2: "ID Verified tier achieved",
  proof_of_address: "Proof of address submitted",
  verification_call: "Verification call completed",
  questionnaire_completed: "Questionnaire completed",
  tier_3: "Enhanced tier achieved",
  business_kyc_approved: "Business KYC approved",
  api_access_approved: "API access approved",
};

export default function KycTierProgress() {
  const queryClient = useQueryClient();

  const tierQuery = useQuery({
    queryKey: ["kyc", "tier", "me"],
    queryFn: getMyTier,
  });

  const currentTier = tierQuery.data?.current_tier ?? 0;
  const nextTier = Math.min(currentTier + 1, 4);

  const requirementsQuery = useQuery({
    queryKey: ["kyc", "tier", "requirements", nextTier],
    queryFn: () => checkRequirements(nextTier),
    enabled: currentTier < 4,
  });

  const evaluateMut = useMutation({
    mutationFn: evaluateTier,
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["kyc", "tier"] });
      if (data.current_tier > currentTier) {
        toast.success(`Upgraded to ${TIER_NAMES[data.current_tier] ?? `Tier ${data.current_tier}`}`);
      } else {
        toast.info("No upgrade available at this time");
      }
    },
    onError: () => {
      toast.error("Evaluation failed");
    },
  });

  if (tierQuery.isLoading) {
    return (
      <div className="flex items-center justify-center p-8">
        <Loader2 className="h-6 w-6 animate-spin" />
      </div>
    );
  }

  const history = tierQuery.data?.history ?? [];
  const requirements = requirementsQuery.data;

  return (
    <div className="max-w-2xl mx-auto space-y-6 p-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5" />
            KYC Verification
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Current Tier */}
          <div className="flex items-center gap-3">
            <span className="text-sm font-medium">Current Tier:</span>
            <KycTierBadge tier={currentTier} />
          </div>

          {/* Next Tier Requirements */}
          {currentTier < 4 && requirements && (
            <div className="space-y-3">
              <h3 className="text-sm font-semibold">
                Requirements for {TIER_NAMES[nextTier] ?? `Tier ${nextTier}`}
              </h3>
              <ul className="space-y-2" data-testid="requirements-checklist">
                {[...requirements.met, ...requirements.unmet].map((req) => {
                  const isMet = requirements.met.includes(req);
                  return (
                    <li key={req} className="flex items-center gap-2 text-sm">
                      {isMet ? (
                        <CheckCircle className="h-4 w-4 text-green-500" data-testid="req-met" />
                      ) : (
                        <Circle className="h-4 w-4 text-muted-foreground" data-testid="req-unmet" />
                      )}
                      <span className={isMet ? "text-green-700 dark:text-green-400" : ""}>
                        {REQUIREMENT_LABELS[req] ?? req}
                      </span>
                    </li>
                  );
                })}
              </ul>
            </div>
          )}

          {currentTier >= 4 && (
            <p className="text-sm text-muted-foreground">
              You have reached the highest verification tier.
            </p>
          )}

          {/* Evaluate Button */}
          {currentTier < 4 && (
            <Button
              onClick={() => evaluateMut.mutate()}
              disabled={evaluateMut.isPending}
              data-testid="evaluate-tier-btn"
            >
              {evaluateMut.isPending ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : null}
              Check Eligibility
            </Button>
          )}
        </CardContent>
      </Card>

      {/* Tier History */}
      {history.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Tier History</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2" data-testid="tier-history">
              {history.map((entry, i) => (
                <li key={i} className="flex items-center justify-between text-sm border-b pb-2 last:border-0">
                  <span>
                    {TIER_NAMES[entry.from_tier] ?? `Tier ${entry.from_tier}`}
                    {" -> "}
                    {TIER_NAMES[entry.to_tier] ?? `Tier ${entry.to_tier}`}
                  </span>
                  <span className="text-muted-foreground text-xs">
                    {entry.reason}
                  </span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
