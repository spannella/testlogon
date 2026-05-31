import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { ShieldCheck, Loader2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  listKycDocumentsByStatus,
  reviewKycDocument,
} from "@/api/endpoints/kycDocuments";
import type {
  KycDocumentMatchStatus,
  KycDocumentOut,
  KycDocumentStatus,
} from "@/api/types";

const STATUSES: KycDocumentStatus[] = [
  "pending",
  "extracted",
  "failed",
  "approved",
  "rejected",
];

function matchVariant(s: KycDocumentMatchStatus) {
  if (s === "match") return "default" as const;
  if (s === "partial") return "secondary" as const;
  if (s === "mismatch") return "destructive" as const;
  return "outline" as const;
}

function MatchBadges({ doc }: { doc: KycDocumentOut }) {
  const results = doc.match_results ?? {};
  const entries = Object.entries(results);
  if (entries.length === 0) {
    return <span className="text-xs text-muted-foreground">—</span>;
  }
  return (
    <div className="flex flex-wrap gap-1">
      {entries.map(([field, m]) => (
        <Badge
          key={field}
          variant={matchVariant(m.status)}
          data-testid={`kyc-match-${field}`}
        >
          {field}: {m.status}
        </Badge>
      ))}
    </div>
  );
}

function ReviewRow({ doc }: { doc: KycDocumentOut }) {
  const queryClient = useQueryClient();
  const review = useMutation({
    mutationFn: (decision: "approve" | "reject") =>
      reviewKycDocument(doc.document_id, { decision }),
    onSuccess: (_d, decision) => {
      toast.success(`Document ${decision === "approve" ? "approved" : "rejected"}`);
      queryClient.invalidateQueries({ queryKey: ["kyc-documents", "by-status"] });
    },
    onError: () => toast.error("Review failed"),
  });

  const reviewable = doc.status === "extracted" || doc.status === "failed";

  return (
    <TableRow data-testid="kyc-review-row" data-document-id={doc.document_id}>
      <TableCell className="font-mono text-xs">{doc.document_id}</TableCell>
      <TableCell>{doc.document_type}</TableCell>
      <TableCell>
        <Badge variant="outline">{doc.overall_confidence ?? "—"}</Badge>
      </TableCell>
      <TableCell>
        <MatchBadges doc={doc} />
      </TableCell>
      <TableCell>
        <div className="flex gap-2">
          <Button
            size="sm"
            disabled={!reviewable || review.isPending}
            onClick={() => review.mutate("approve")}
            data-testid="kyc-review-approve"
          >
            Approve
          </Button>
          <Button
            size="sm"
            variant="destructive"
            disabled={!reviewable || review.isPending}
            onClick={() => review.mutate("reject")}
            data-testid="kyc-review-reject"
          >
            Reject
          </Button>
        </div>
      </TableCell>
    </TableRow>
  );
}

export default function KycDocumentReviewQueuePage() {
  const [status, setStatus] = useState<KycDocumentStatus>("extracted");

  const { data, isLoading } = useQuery({
    queryKey: ["kyc-documents", "by-status", status],
    queryFn: () => listKycDocumentsByStatus(status),
  });

  const documents = data?.documents ?? [];

  return (
    <div className="mx-auto max-w-5xl space-y-6 p-4">
      <div className="flex items-center gap-2">
        <ShieldCheck className="h-6 w-6" />
        <h1 className="text-2xl font-semibold">KYC Document Review</h1>
      </div>

      <Tabs value={status} onValueChange={(v) => setStatus(v as KycDocumentStatus)}>
        <TabsList>
          {STATUSES.map((s) => (
            <TabsTrigger key={s} value={s} data-testid={`kyc-status-tab-${s}`}>
              {s}
            </TabsTrigger>
          ))}
        </TabsList>
      </Tabs>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg capitalize">{status} documents</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" /> Loading...
            </div>
          ) : documents.length === 0 ? (
            <p className="text-sm text-muted-foreground" data-testid="kyc-review-empty">
              No documents in this status.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Document ID</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Confidence</TableHead>
                  <TableHead>Match results</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {documents.map((doc) => (
                  <ReviewRow key={doc.document_id} doc={doc} />
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
