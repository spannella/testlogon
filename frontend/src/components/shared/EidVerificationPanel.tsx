import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { ShieldCheck, Loader2, AlertTriangle, CheckCircle2 } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Label } from "@/components/ui/label";
import {
  getEidSchemes,
  getEidStatus,
  startEidVerification,
  mockEidVerify,
  completeEidCallback,
} from "@/api/endpoints/kycEidv";
import type { EidVerification } from "@/api/types";

interface EidVerificationPanelProps {
  caseId: string;
  userCountry?: string;
  onVerified?: () => void;
}

/**
 * KYC-022 user-facing eID verification flow: select a scheme, initiate the
 * session, run the (dev) mock provider + callback, then show the result. Acts as
 * an alternative to manual ID-document upload for Tier 2.
 */
export function EidVerificationPanel({ caseId, userCountry, onVerified }: EidVerificationPanelProps) {
  const qc = useQueryClient();
  const [selected, setSelected] = useState<string | null>(null);

  const schemesQuery = useQuery({
    queryKey: ["kyc", "eid", "schemes", userCountry ?? null],
    queryFn: () => getEidSchemes(userCountry),
  });

  const statusQuery = useQuery({
    queryKey: ["kyc", "eid", "status", caseId],
    queryFn: () => getEidStatus(caseId),
    enabled: !!caseId,
  });

  const verifyMut = useMutation({
    mutationFn: async (scheme: string) => {
      const start = await startEidVerification(caseId, scheme);
      // Dev/mock flow: call the mock provider, then complete the callback.
      const assertion = await mockEidVerify(start.session_id);
      await completeEidCallback(start.session_id, assertion.assertion, assertion.signature);
      return getEidStatus(caseId);
    },
    onSuccess: (status) => {
      qc.invalidateQueries({ queryKey: ["kyc", "eid", "status", caseId] });
      qc.invalidateQueries({ queryKey: ["kyc", "case", caseId] });
      qc.invalidateQueries({ queryKey: ["kyc", "readiness", caseId] });
      const v = status.eid_verification;
      if (v?.discrepancies?.some((d) => d.severity === "critical")) {
        toast.warning("eID verified, but a discrepancy was flagged for review.");
      } else {
        toast.success("Identity verified with eID.");
      }
      onVerified?.();
    },
    onError: () => {
      toast.error("eID verification failed. Please try again.");
    },
  });

  const verification = statusQuery.data?.eid_verification ?? null;

  if (verification) {
    return <EidResultCard verification={verification} />;
  }

  const schemes = schemesQuery.data?.schemes ?? [];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <ShieldCheck className="h-5 w-5 text-blue-600" />
          Verify with eID
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-sm text-gray-600">
          Use your government electronic ID instead of uploading documents. A successful
          verification automatically upgrades you to Tier 2.
        </p>
        {schemesQuery.isLoading ? (
          <div className="flex items-center gap-2 text-sm text-gray-500">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading schemes…
          </div>
        ) : (
          <RadioGroup value={selected ?? ""} onValueChange={setSelected}>
            {schemes.map((s) => (
              <div key={s.id} className="flex items-start gap-3 rounded-md border p-3">
                <RadioGroupItem value={s.id} id={`eid-scheme-${s.id}`} className="mt-1" />
                <Label htmlFor={`eid-scheme-${s.id}`} className="flex-1 cursor-pointer">
                  <span className="flex items-center gap-2 font-medium">
                    {s.name}
                    <Badge variant="secondary">{s.assurance_level}</Badge>
                  </span>
                  <span className="block text-xs text-gray-500">{s.description}</span>
                </Label>
              </div>
            ))}
          </RadioGroup>
        )}
        <Button
          disabled={!selected || verifyMut.isPending}
          onClick={() => selected && verifyMut.mutate(selected)}
          className="w-full"
        >
          {verifyMut.isPending ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Verifying…
            </>
          ) : (
            "Verify with eID"
          )}
        </Button>
      </CardContent>
    </Card>
  );
}

/** Displays a completed eID verification result. */
export function EidResultCard({ verification }: { verification: EidVerification }) {
  const hasCritical = verification.discrepancies?.some((d) => d.severity === "critical");
  const fields = verification.verified_fields ?? {};
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          {hasCritical ? (
            <AlertTriangle className="h-5 w-5 text-amber-500" />
          ) : (
            <CheckCircle2 className="h-5 w-5 text-green-600" />
          )}
          eID Verification
          <Badge variant={hasCritical ? "destructive" : "default"}>
            {hasCritical ? "Flagged" : "Verified"}
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <div className="flex flex-wrap gap-2">
          <Badge variant="outline">Scheme: {verification.scheme}</Badge>
          <Badge variant="outline">Assurance: {verification.assurance_level}</Badge>
          {verification.auto_tier_upgrade && <Badge>Tier 2 upgraded</Badge>}
        </div>
        <dl className="grid grid-cols-2 gap-2">
          <Field label="First name" value={fields.first_name} />
          <Field label="Last name" value={fields.last_name} />
          <Field label="Date of birth" value={fields.date_of_birth} />
          <Field label="Nationality" value={fields.nationality} />
          <Field label="Document number" value={fields.document_number} />
        </dl>
        {verification.discrepancies?.length > 0 && (
          <div className="rounded-md border border-amber-200 bg-amber-50 p-2 text-xs text-amber-800">
            <p className="font-medium">Discrepancies detected:</p>
            <ul className="list-inside list-disc">
              {verification.discrepancies.map((d) => (
                <li key={d.field}>
                  {d.field}: profile “{d.profile_value}” vs eID “{d.eid_value}” ({d.severity})
                </li>
              ))}
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function Field({ label, value }: { label: string; value?: string }) {
  if (!value) return null;
  return (
    <>
      <dt className="text-gray-500">{label}</dt>
      <dd className="font-medium">{value}</dd>
    </>
  );
}
