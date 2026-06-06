import { useQuery } from "@tanstack/react-query";

import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { listKycDocumentsForCase } from "@/api/endpoints/kycDocuments";
import type {
  KycDocumentConfidence,
  KycDocumentFieldMatch,
  KycDocumentMatchStatus,
  KycDocumentOut,
} from "@/api/types";

// ─── Badge helpers ──────────────────────────────────────────────────────────

function matchVariant(
  status: KycDocumentMatchStatus,
): "default" | "secondary" | "destructive" | "outline" {
  if (status === "match") return "default";
  if (status === "partial") return "secondary";
  if (status === "mismatch") return "destructive";
  return "outline";
}

function confidenceVariant(
  confidence: KycDocumentConfidence,
): "default" | "secondary" | "destructive" | "outline" {
  if (confidence === "high") return "default";
  if (confidence === "low" || confidence === "failed") return "destructive";
  return "secondary";
}

// ─── Per-document card ──────────────────────────────────────────────────────

function DocumentExtractCard({ doc }: { doc: KycDocumentOut }) {
  const fields = doc.extracted_fields ?? {};
  const matches: Record<string, KycDocumentFieldMatch> = doc.match_results ?? {};
  const fieldEntries = Object.entries(fields);

  return (
    <Card data-testid={`extraction-card-${doc.document_id}`}>
      <CardHeader>
        <CardTitle className="flex items-center justify-between gap-2 text-sm font-medium">
          <span className="capitalize">{doc.document_type}</span>
          {doc.overall_confidence && (
            <Badge
              variant={confidenceVariant(doc.overall_confidence)}
              data-testid="doc-confidence"
            >
              {doc.overall_confidence} confidence
            </Badge>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {fieldEntries.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            {doc.status === "pending"
              ? "Extraction not yet run."
              : "No fields extracted."}
          </p>
        ) : (
          <Table data-testid={`extraction-fields-${doc.document_id}`}>
            <TableHeader>
              <TableRow>
                <TableHead className="w-1/3">Field</TableHead>
                <TableHead>Value</TableHead>
                <TableHead className="text-right">Match</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {fieldEntries.map(([key, value]) => {
                const m = matches[key];
                return (
                  <TableRow key={key}>
                    <TableCell className="font-medium text-muted-foreground">
                      {key}
                    </TableCell>
                    <TableCell className="break-all">{value}</TableCell>
                    <TableCell className="text-right">
                      {m ? (
                        <Badge
                          variant={matchVariant(m.status)}
                          data-testid={`match-${key}`}
                        >
                          {m.status}
                        </Badge>
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Panel ──────────────────────────────────────────────────────────────────

/**
 * Per-document OCR extraction results for a KYC case: extracted fields,
 * per-field match status, and overall confidence. Fetches all documents for the
 * case via the admin by-status endpoint scoped with `case_id` (GAP-0247 /
 * GAP-0248).
 */
export function ExtractionResultsPanel({ caseId }: { caseId: string }) {
  const query = useQuery({
    queryKey: ["kyc-case-documents", caseId],
    queryFn: () => listKycDocumentsForCase(caseId),
    enabled: !!caseId,
  });

  if (query.isLoading) {
    return (
      <p
        className="text-sm text-muted-foreground"
        data-testid="extraction-loading"
      >
        Loading document extraction results...
      </p>
    );
  }

  if (query.isError) {
    return (
      <p className="text-sm text-destructive" data-testid="extraction-error">
        Failed to load document extraction results.
      </p>
    );
  }

  const docs = query.data?.documents ?? [];

  if (docs.length === 0) {
    return (
      <p
        className="text-sm text-muted-foreground"
        data-testid="extraction-empty"
      >
        No documents associated with this case.
      </p>
    );
  }

  return (
    <div className="space-y-4" data-testid="extraction-results-panel">
      {docs.map((doc) => (
        <DocumentExtractCard key={doc.document_id} doc={doc} />
      ))}
    </div>
  );
}
