import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  crossReferenceKycCaseAddress,
  getKycCaseAddressVerification,
  listKycCaseAddressAttempts,
  overrideKycCaseAddressDecision,
  validateKycPostalCode,
  verifyKycCaseAddress,
} from "@/api/endpoints/kycAddressVerification";
import type {
  AddressInput,
  AddressVerificationDecision,
  AddressVerificationOut,
} from "@/api/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
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

const EMPTY_ADDRESS: AddressInput = {
  line_1: "",
  line_2: "",
  city: "",
  state: "",
  postal_code: "",
  country: "US",
};

function statusVariant(status: string): "default" | "secondary" | "destructive" {
  if (status === "verified") return "default";
  if (status === "partial_match" || status === "pending") return "secondary";
  return "destructive";
}

function decisionVariant(
  decision: string,
): "default" | "secondary" | "destructive" {
  if (decision === "verified") return "default";
  if (decision === "needs_review") return "secondary";
  return "destructive";
}

export function AddressVerificationBadge({
  status,
  confidence,
}: {
  status: string;
  confidence?: number;
}) {
  return (
    <Badge variant={statusVariant(status)} data-testid="address-verification-badge">
      {status.replace(/_/g, " ")}
      {typeof confidence === "number" ? ` · ${Math.round(confidence * 100)}%` : ""}
    </Badge>
  );
}

function AddressFields({
  address,
  onChange,
  prefix,
}: {
  address: AddressInput;
  onChange: (next: AddressInput) => void;
  prefix: string;
}) {
  const set = (k: keyof AddressInput, v: string) =>
    onChange({ ...address, [k]: v });
  return (
    <div className="grid grid-cols-2 gap-2">
      <Input
        placeholder="Street line 1"
        value={address.line_1}
        onChange={(e) => set("line_1", e.target.value)}
        data-testid={`${prefix}-line1`}
      />
      <Input
        placeholder="Line 2"
        value={address.line_2 ?? ""}
        onChange={(e) => set("line_2", e.target.value)}
        data-testid={`${prefix}-line2`}
      />
      <Input
        placeholder="City"
        value={address.city}
        onChange={(e) => set("city", e.target.value)}
        data-testid={`${prefix}-city`}
      />
      <Input
        placeholder="State"
        value={address.state ?? ""}
        onChange={(e) => set("state", e.target.value)}
        data-testid={`${prefix}-state`}
      />
      <Input
        placeholder="Postal code"
        value={address.postal_code}
        onChange={(e) => set("postal_code", e.target.value)}
        data-testid={`${prefix}-postal`}
      />
      <Input
        placeholder="Country (ISO-2)"
        value={address.country}
        maxLength={2}
        onChange={(e) => set("country", e.target.value.toUpperCase())}
        data-testid={`${prefix}-country`}
      />
    </div>
  );
}

function VerificationResultCard({
  result,
}: {
  result: AddressVerificationOut | undefined;
}) {
  if (!result) return null;
  return (
    <div className="space-y-2" data-testid="address-verification-result">
      <div className="flex items-center gap-2">
        <AddressVerificationBadge
          status={result.status}
          confidence={result.confidence_score}
        />
        <Badge variant={decisionVariant(result.decision)}>{result.decision}</Badge>
        {result.country_format_valid ? (
          <span className="text-xs text-muted-foreground">postal format ok</span>
        ) : (
          <span className="text-xs text-destructive">postal format invalid</span>
        )}
      </div>
      {result.standardized_address && (
        <div className="text-sm">
          <span className="font-medium">Standardized: </span>
          {result.standardized_address.line_1}, {result.standardized_address.city}{" "}
          {result.standardized_address.state}{" "}
          {result.standardized_address.postal_code}{" "}
          {result.standardized_address.country}
        </div>
      )}
      {result.geocoding && (
        <div className="text-xs text-muted-foreground" data-testid="geocoding">
          lat {result.geocoding.lat}, lng {result.geocoding.lng}
        </div>
      )}
      {result.discrepancies.length > 0 && (
        <ul className="list-disc pl-5 text-xs text-destructive">
          {result.discrepancies.map((d) => (
            <li key={d}>{d}</li>
          ))}
        </ul>
      )}
      {result.cross_reference && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">
              Document cross-reference · match{" "}
              {Math.round(result.cross_reference.match_score * 100)}%
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Field</TableHead>
                  <TableHead>Profile</TableHead>
                  <TableHead>Document</TableHead>
                  <TableHead>Match</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {result.cross_reference.field_comparisons.map((fc) => (
                  <TableRow key={fc.field}>
                    <TableCell>{fc.field}</TableCell>
                    <TableCell>{fc.profile}</TableCell>
                    <TableCell>{fc.document}</TableCell>
                    <TableCell>{fc.match ? "✓" : "✗"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

export default function KycAddressVerificationPanel({
  caseId: caseIdProp,
}: {
  caseId?: string;
}) {
  const queryClient = useQueryClient();
  const [caseId, setCaseId] = useState(caseIdProp ?? "");
  const [address, setAddress] = useState<AddressInput>(EMPTY_ADDRESS);
  const [docAddress, setDocAddress] = useState<AddressInput>(EMPTY_ADDRESS);
  const [postalCheck, setPostalCheck] = useState<string>("");

  const verificationQuery = useQuery({
    queryKey: ["kyc-address-verification", caseId],
    queryFn: () => getKycCaseAddressVerification(caseId),
    enabled: !!caseId,
  });

  const attemptsQuery = useQuery({
    queryKey: ["kyc-address-verification-attempts", caseId],
    queryFn: () => listKycCaseAddressAttempts(caseId),
    enabled: !!caseId,
  });

  const invalidate = () => {
    queryClient.invalidateQueries({
      queryKey: ["kyc-address-verification", caseId],
    });
    queryClient.invalidateQueries({
      queryKey: ["kyc-address-verification-attempts", caseId],
    });
  };

  const verifyMut = useMutation({
    mutationFn: () => verifyKycCaseAddress(caseId, address),
    onSuccess: invalidate,
  });

  const crossRefMut = useMutation({
    mutationFn: () => crossReferenceKycCaseAddress(caseId, docAddress),
    onSuccess: invalidate,
  });

  const overrideMut = useMutation({
    mutationFn: (decision: AddressVerificationDecision) =>
      overrideKycCaseAddressDecision(caseId, decision),
    onSuccess: invalidate,
  });

  const postalMut = useMutation({
    mutationFn: () => validateKycPostalCode(postalCheck, address.country),
  });

  const result = verificationQuery.data?.verification;

  return (
    <Card data-testid="kyc-address-verification-panel">
      <CardHeader>
        <CardTitle>Address Verification (KYC-018)</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <Input
          placeholder="KYC case id"
          value={caseId}
          onChange={(e) => setCaseId(e.target.value)}
          data-testid="case-id-input"
        />

        <div className="space-y-2">
          <div className="text-sm font-medium">Profile address</div>
          <AddressFields address={address} onChange={setAddress} prefix="addr" />
          <Button
            onClick={() => verifyMut.mutate()}
            disabled={!caseId || verifyMut.isPending}
            data-testid="verify-btn"
          >
            Verify address
          </Button>
        </div>

        <VerificationResultCard result={result} />

        <div className="space-y-2">
          <div className="text-sm font-medium">
            Document cross-reference (admin)
          </div>
          <AddressFields
            address={docAddress}
            onChange={setDocAddress}
            prefix="doc"
          />
          <Button
            variant="secondary"
            onClick={() => crossRefMut.mutate()}
            disabled={!caseId || crossRefMut.isPending}
            data-testid="cross-reference-btn"
          >
            Cross-reference document
          </Button>
        </div>

        <div className="flex items-center gap-2">
          <Input
            placeholder="Postal code to validate"
            value={postalCheck}
            onChange={(e) => setPostalCheck(e.target.value)}
            data-testid="postal-input"
          />
          <Button
            variant="outline"
            onClick={() => postalMut.mutate()}
            data-testid="validate-postal-btn"
          >
            Validate
          </Button>
          {postalMut.data && (
            <span
              className="text-xs"
              data-testid="postal-result"
            >
              {postalMut.data.valid ? "valid" : postalMut.data.format_hint}
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          <span className="text-sm font-medium">Override decision:</span>
          {(["verified", "needs_review", "failed"] as const).map((d) => (
            <Button
              key={d}
              size="sm"
              variant="outline"
              onClick={() => overrideMut.mutate(d)}
              disabled={!caseId || overrideMut.isPending}
              data-testid={`override-${d}`}
            >
              {d}
            </Button>
          ))}
        </div>

        {attemptsQuery.data && attemptsQuery.data.attempts.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Attempt history</CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Status</TableHead>
                    <TableHead>Decision</TableHead>
                    <TableHead>Confidence</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {attemptsQuery.data.attempts.map((a) => (
                    <TableRow key={a.verification_id ?? a.created_at}>
                      <TableCell>
                        <AddressVerificationBadge status={a.status} />
                      </TableCell>
                      <TableCell>{a.decision}</TableCell>
                      <TableCell>
                        {Math.round(a.confidence_score * 100)}%
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        )}
      </CardContent>
    </Card>
  );
}
