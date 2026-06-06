import { useQuery } from "@tanstack/react-query";

import { adminListKycResidencyForCase } from "@/api/endpoints/kycResidency";
import { VerificationStateBadge } from "@/components/shared/VerificationStateBadge";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type {
  KycResidencyAddressMatch,
  KycResidencyDocumentOut,
} from "@/api/types";

const ADDRESS_FIELDS = ["line1", "city", "state", "postal_code", "country"] as const;

function MatchBadge({ status }: { status: string | undefined | null }) {
  if (!status) return <span className="text-muted-foreground">—</span>;
  const variant =
    status === "match"
      ? "default"
      : status === "partial"
        ? "secondary"
        : status === "mismatch"
          ? "destructive"
          : "outline";
  return <Badge variant={variant}>{status}</Badge>;
}

function AddressComparisonTable({
  match,
  extracted,
}: {
  match: KycResidencyAddressMatch;
  extracted: Record<string, string>;
}) {
  const profileAddress = match.profile_address ?? {};
  const fieldMatches = match.field_matches ?? {};

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <span className="text-sm font-medium">Overall address match:</span>
        <MatchBadge status={match.status} />
      </div>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b">
              <th className="py-1 pr-4 text-left font-medium text-muted-foreground">Field</th>
              <th className="py-1 pr-4 text-left font-medium text-muted-foreground">Profile</th>
              <th className="py-1 pr-4 text-left font-medium text-muted-foreground">Document</th>
              <th className="py-1 text-left font-medium text-muted-foreground">Match</th>
            </tr>
          </thead>
          <tbody>
            {ADDRESS_FIELDS.map((field) => (
              <tr key={field} className="border-b last:border-0">
                <td className="py-1.5 pr-4 capitalize text-muted-foreground">
                  {field.replace("_", " ")}
                </td>
                <td className="py-1.5 pr-4" data-testid={`profile-${field}`}>
                  {profileAddress[field] ?? <span className="text-muted-foreground">—</span>}
                </td>
                <td className="py-1.5 pr-4" data-testid={`extracted-${field}`}>
                  {extracted[field] ?? <span className="text-muted-foreground">—</span>}
                </td>
                <td className="py-1.5" data-testid={`match-${field}`}>
                  <MatchBadge status={fieldMatches[field]} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ResidencyDocumentCard({ doc }: { doc: KycResidencyDocumentOut }) {
  const extracted = (doc.extracted_address as Record<string, string>) ?? {};
  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between gap-2">
          <CardTitle className="text-sm font-medium capitalize">
            {doc.document_type.replace(/_/g, " ")}
            {doc.issuing_entity ? ` — ${doc.issuing_entity}` : ""}
          </CardTitle>
          <div className="flex items-center gap-2">
            {doc.document_date && (
              <span className="text-xs text-muted-foreground">{doc.document_date}</span>
            )}
            <span data-testid="residency-doc-status">
              <VerificationStateBadge state={doc.status} />
            </span>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {doc.address_match ? (
          <AddressComparisonTable match={doc.address_match} extracted={extracted} />
        ) : (
          <p className="text-sm text-muted-foreground">
            Address extraction not yet run for this document.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

interface ResidencyVerificationTabProps {
  caseId: string;
}

export function ResidencyVerificationTab({ caseId }: ResidencyVerificationTabProps) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["kyc-residency-case", caseId],
    queryFn: () => adminListKycResidencyForCase(caseId),
    enabled: !!caseId,
  });

  if (isLoading) {
    return (
      <p className="py-4 text-sm text-muted-foreground">Loading residency documents...</p>
    );
  }

  if (isError) {
    return (
      <p className="py-4 text-sm text-destructive">Failed to load residency documents.</p>
    );
  }

  const docs: KycResidencyDocumentOut[] = data?.documents ?? [];

  if (docs.length === 0) {
    return (
      <Card>
        <CardContent className="py-8 text-center text-sm text-muted-foreground">
          No residency documents attached to this case.
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4" data-testid="residency-verification-tab">
      {docs.map((doc) => (
        <ResidencyDocumentCard key={doc.document_id} doc={doc} />
      ))}
    </div>
  );
}
