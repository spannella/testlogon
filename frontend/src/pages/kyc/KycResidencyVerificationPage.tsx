import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  extractKycResidencyDocument,
  listMyKycResidencyDocuments,
  uploadKycResidencyDocument,
} from "@/api/endpoints/kycResidency";
import type {
  KycResidencyDocumentOut,
  KycResidencyDocumentType,
  KycResidencyMatchStatus,
} from "@/api/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";

const DOC_TYPE_LABELS: Record<KycResidencyDocumentType, string> = {
  utility_bill: "Utility Bill",
  bank_statement: "Bank Statement",
  government_letter: "Government Letter",
  tax_document: "Tax Document",
  lease_agreement: "Lease Agreement",
};

const STATUS_VARIANTS: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
  pending: "secondary",
  verified: "default",
  rejected: "destructive",
  expired: "outline",
};

const MATCH_VARIANTS: Record<KycResidencyMatchStatus, "default" | "secondary" | "destructive" | "outline"> = {
  match: "default",
  partial: "secondary",
  mismatch: "destructive",
  not_available: "outline",
};

const FIELD_LABELS: Record<string, string> = {
  line1: "Street",
  city: "City",
  state: "State",
  postal_code: "Postal code",
  country: "Country",
};

function ResidencyDocRow({
  doc,
  onReExtract,
  reExtracting,
}: {
  doc: KycResidencyDocumentOut;
  onReExtract: (id: string) => void;
  reExtracting: boolean;
}) {
  const match = doc.address_match;
  return (
    <div className="space-y-3 rounded-md border p-3">
      <div className="flex items-center justify-between gap-2">
        <div className="space-y-1">
          <div className="font-medium">{DOC_TYPE_LABELS[doc.document_type]}</div>
          <div className="text-xs text-muted-foreground">
            {doc.issuing_entity} &middot; {doc.document_date} &middot; {doc.file_name}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant={STATUS_VARIANTS[doc.status] ?? "outline"}>{doc.status}</Badge>
          <Badge variant={doc.recency_valid ? "default" : "destructive"}>
            {doc.recency_valid ? `Within window (${doc.recency_days}d)` : `Too old (${doc.recency_days}d)`}
          </Badge>
        </div>
      </div>

      {match && (
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-sm">
            <span className="text-muted-foreground">Address match:</span>
            <Badge variant={MATCH_VARIANTS[match.status]}>{match.status}</Badge>
          </div>
          {match.status !== "not_available" && (
            <div className="flex flex-wrap gap-2">
              {Object.entries(match.field_matches).map(([field, status]) => (
                <Badge key={field} variant={MATCH_VARIANTS[status]}>
                  {FIELD_LABELS[field] ?? field}: {status}
                </Badge>
              ))}
            </div>
          )}
        </div>
      )}

      <div>
        <Button
          size="sm"
          variant="outline"
          disabled={reExtracting}
          onClick={() => onReExtract(doc.document_id)}
        >
          Re-run verification
        </Button>
      </div>
    </div>
  );
}

export function KycResidencyVerificationPage() {
  const queryClient = useQueryClient();
  const [documentType, setDocumentType] = useState<KycResidencyDocumentType>("utility_bill");
  const [issuingEntity, setIssuingEntity] = useState("");
  const [documentDate, setDocumentDate] = useState("");
  const [fileName, setFileName] = useState("");

  const documentsQuery = useQuery({
    queryKey: ["kyc", "residency", "mine"],
    queryFn: () => listMyKycResidencyDocuments(),
  });

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ["kyc", "residency", "mine"] });

  const uploadMutation = useMutation({
    mutationFn: () =>
      uploadKycResidencyDocument({
        document_type: documentType,
        issuing_entity: issuingEntity,
        document_date: documentDate,
        file_name: fileName,
      }),
    onSuccess: () => {
      setIssuingEntity("");
      setDocumentDate("");
      setFileName("");
      invalidate();
    },
  });

  const extractMutation = useMutation({
    mutationFn: (id: string) => extractKycResidencyDocument(id),
    onSuccess: invalidate,
  });

  const documents = documentsQuery.data?.documents ?? [];
  const canSubmit = Boolean(issuingEntity && documentDate && fileName) && !uploadMutation.isPending;

  return (
    <div className="mx-auto max-w-3xl space-y-6 p-4">
      <div>
        <h1 className="text-2xl font-semibold">Proof of Residency</h1>
        <p className="text-sm text-muted-foreground">
          Upload a recent utility bill, bank statement, lease, or government letter. We check the
          document is recent and that its address matches your profile.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Upload a residency document</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="res-doc-type">Document type</Label>
            <select
              id="res-doc-type"
              className="w-full rounded-md border bg-background p-2 text-sm"
              value={documentType}
              onChange={(e) => setDocumentType(e.target.value as KycResidencyDocumentType)}
            >
              {Object.entries(DOC_TYPE_LABELS).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </div>
          <div className="space-y-2">
            <Label htmlFor="res-issuer">Issuing entity</Label>
            <Input
              id="res-issuer"
              value={issuingEntity}
              onChange={(e) => setIssuingEntity(e.target.value)}
              placeholder="Pacific Gas & Electric"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="res-date">Document date</Label>
            <Input
              id="res-date"
              type="date"
              value={documentDate}
              onChange={(e) => setDocumentDate(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="res-file">File name</Label>
            <Input
              id="res-file"
              value={fileName}
              onChange={(e) => setFileName(e.target.value)}
              placeholder="utility_bill.pdf"
            />
          </div>
          <Button onClick={() => uploadMutation.mutate()} disabled={!canSubmit}>
            {uploadMutation.isPending ? "Uploading…" : "Upload & verify"}
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Your residency documents</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {documentsQuery.isLoading && <p className="text-sm">Loading…</p>}
          {!documentsQuery.isLoading && documents.length === 0 && (
            <p className="text-sm text-muted-foreground">No residency documents uploaded yet.</p>
          )}
          {documents.map((doc) => (
            <ResidencyDocRow
              key={doc.document_id}
              doc={doc}
              reExtracting={extractMutation.isPending}
              onReExtract={(id) => extractMutation.mutate(id)}
            />
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

export default KycResidencyVerificationPage;
