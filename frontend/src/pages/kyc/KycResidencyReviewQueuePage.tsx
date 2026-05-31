import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  listKycResidencyByStatus,
  reviewKycResidencyDocument,
} from "@/api/endpoints/kycResidency";
import type {
  KycResidencyDocumentOut,
  KycResidencyMatchStatus,
  KycResidencyStatus,
} from "@/api/types";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

const STATUS_TABS: KycResidencyStatus[] = ["pending", "verified", "rejected", "expired"];

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

const ADDR_FIELDS: Array<keyof AddressLike> = [
  "line1",
  "line2",
  "city",
  "state",
  "postal_code",
  "country",
];

type AddressLike = {
  line1?: string;
  line2?: string;
  city?: string;
  state?: string;
  postal_code?: string;
  country?: string;
};

function AddressCard({ title, source, address }: { title: string; source: string; address: AddressLike }) {
  return (
    <div className="rounded-md border p-3 text-sm">
      <div className="mb-2 font-medium">{title}</div>
      <dl className="space-y-1">
        {ADDR_FIELDS.map((f) => (
          <div key={f} className="flex justify-between gap-2">
            <dt className="text-muted-foreground">{f}</dt>
            <dd className="text-right">{(address?.[f] as string) ?? "—"}</dd>
          </div>
        ))}
      </dl>
      <div className="mt-2 text-xs text-muted-foreground">{source}</div>
    </div>
  );
}

function ReviewPanel({ doc, onReviewed }: { doc: KycResidencyDocumentOut; onReviewed: () => void }) {
  const reviewMutation = useMutation({
    mutationFn: (decision: "approve" | "reject") =>
      reviewKycResidencyDocument(doc.document_id, { decision }),
    onSuccess: onReviewed,
  });
  const match = doc.address_match;
  return (
    <div className="space-y-3 rounded-md border p-4">
      <div className="flex items-center justify-between gap-2">
        <div>
          <div className="font-medium">{doc.document_type}</div>
          <div className="text-xs text-muted-foreground">
            {doc.issuing_entity} &middot; {doc.document_date} &middot; {doc.file_name}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant={STATUS_VARIANTS[doc.status] ?? "outline"}>{doc.status}</Badge>
          <Badge variant={doc.recency_valid ? "default" : "destructive"}>
            {doc.recency_valid ? "recent" : "expired"} ({doc.recency_days}d)
          </Badge>
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        <AddressCard
          title="Document address"
          source="Extracted from document"
          address={(doc.extracted_address ?? {}) as AddressLike}
        />
        <AddressCard
          title="Profile address"
          source="User profile"
          address={(match?.profile_address ?? {}) as AddressLike}
        />
      </div>

      {match && (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm text-muted-foreground">Overall:</span>
          <Badge variant={MATCH_VARIANTS[match.status]}>{match.status}</Badge>
          {Object.entries(match.field_matches).map(([field, status]) => (
            <Badge key={field} variant={MATCH_VARIANTS[status]}>
              {field}: {status}
            </Badge>
          ))}
        </div>
      )}

      <div className="flex gap-2">
        <Button
          size="sm"
          disabled={reviewMutation.isPending}
          onClick={() => reviewMutation.mutate("approve")}
        >
          Approve
        </Button>
        <Button
          size="sm"
          variant="destructive"
          disabled={reviewMutation.isPending}
          onClick={() => reviewMutation.mutate("reject")}
        >
          Reject
        </Button>
      </div>
    </div>
  );
}

export function KycResidencyReviewQueuePage() {
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<KycResidencyStatus>("pending");

  const queueQuery = useQuery({
    queryKey: ["kyc", "residency", "by-status", status],
    queryFn: () => listKycResidencyByStatus(status),
  });

  const documents = queueQuery.data?.documents ?? [];

  return (
    <div className="mx-auto max-w-4xl space-y-6 p-4">
      <div>
        <h1 className="text-2xl font-semibold">Residency Review Queue</h1>
        <p className="text-sm text-muted-foreground">
          Review proof-of-residency documents and compare the extracted address against the user
          profile.
        </p>
      </div>

      <div className="flex flex-wrap gap-2">
        {STATUS_TABS.map((s) => (
          <Button
            key={s}
            size="sm"
            variant={s === status ? "default" : "outline"}
            onClick={() => setStatus(s)}
          >
            {s}
          </Button>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{status} documents</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {queueQuery.isLoading && <p className="text-sm">Loading…</p>}
          {!queueQuery.isLoading && documents.length === 0 && (
            <p className="text-sm text-muted-foreground">No documents in this queue.</p>
          )}
          {documents.map((doc) => (
            <ReviewPanel
              key={doc.document_id}
              doc={doc}
              onReviewed={() =>
                queryClient.invalidateQueries({ queryKey: ["kyc", "residency", "by-status"] })
              }
            />
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

export default KycResidencyReviewQueuePage;
