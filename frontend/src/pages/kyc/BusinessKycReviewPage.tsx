import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

import {
  adminApproveKybCase,
  adminGetKybCase,
  adminKybQueue,
  adminRejectKybCase,
  adminScreenKybCase,
} from "@/api/endpoints/kycBusiness";
import type { KybScreeningEnvelope } from "@/api/types";

export default function BusinessKycReviewPage() {
  const queryClient = useQueryClient();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [screening, setScreening] = useState<KybScreeningEnvelope | null>(null);

  const queueQuery = useQuery({
    queryKey: ["kyb-admin", "queue"],
    queryFn: () => adminKybQueue(),
  });

  const caseQuery = useQuery({
    queryKey: ["kyb-admin", "case", selectedId],
    queryFn: () => adminGetKybCase(selectedId as string),
    enabled: !!selectedId,
  });

  const refresh = () => queryClient.invalidateQueries({ queryKey: ["kyb-admin"] });

  const screenMut = useMutation({
    mutationFn: () => adminScreenKybCase(selectedId as string),
    onSuccess: (res) => {
      setScreening(res);
      toast.success(res.any_hit ? "Sanctions hit found" : "All clear");
    },
  });

  const approveMut = useMutation({
    mutationFn: () =>
      adminApproveKybCase(selectedId as string, {
        expected_version: caseQuery.data?.case.version ?? 1,
        note: "Approved via review queue",
      }),
    onSuccess: () => {
      toast.success("Approved — owner upgraded to Tier 4");
      refresh();
    },
    onError: () => toast.error("Approve failed"),
  });

  const rejectMut = useMutation({
    mutationFn: () =>
      adminRejectKybCase(selectedId as string, {
        expected_version: caseQuery.data?.case.version ?? 1,
        note: "Rejected via review queue",
      }),
    onSuccess: () => {
      toast.success("Rejected");
      refresh();
    },
    onError: () => toast.error("Reject failed"),
  });

  const activeCase = caseQuery.data?.case;

  return (
    <div className="container mx-auto max-w-4xl space-y-6 py-6">
      <h1 className="text-2xl font-semibold">Business KYC Review Queue</h1>

      <Card>
        <CardHeader>
          <CardTitle>Pending business cases</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {(queueQuery.data?.cases ?? []).map((c) => (
            <button
              key={c.kyb_case_id}
              onClick={() => {
                setSelectedId(c.kyb_case_id);
                setScreening(null);
              }}
              className="flex w-full items-center justify-between rounded border p-2 text-left hover:bg-accent"
            >
              <span>{c.company.legal_name}</span>
              <Badge>{c.status}</Badge>
            </button>
          ))}
          {(queueQuery.data?.cases ?? []).length === 0 && (
            <p className="text-sm text-muted-foreground">Queue is empty.</p>
          )}
        </CardContent>
      </Card>

      {activeCase && (
        <Card>
          <CardHeader>
            <CardTitle>
              {activeCase.company.legal_name} — <Badge>{activeCase.status}</Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <p>Registration: {activeCase.company.registration_number}</p>
            <p>Jurisdiction: {activeCase.company.jurisdiction}</p>
            <p>UBOs: {activeCase.ubo_summary.total_ubos}</p>
            <p>Documents: {activeCase.document_count}</p>
            <div className="flex gap-2">
              <Button variant="secondary" onClick={() => screenMut.mutate()}>
                Run sanctions screening
              </Button>
              <Button onClick={() => approveMut.mutate()} disabled={approveMut.isPending}>
                Approve
              </Button>
              <Button
                variant="destructive"
                onClick={() => rejectMut.mutate()}
                disabled={rejectMut.isPending}
              >
                Reject
              </Button>
            </div>
            {screening && (
              <div className="rounded border p-2">
                <p className="font-semibold">
                  Screening: {screening.any_hit ? "HIT" : "clear"}
                </p>
                {screening.screened.map((s, i) => (
                  <p key={i} className="text-xs">
                    {s.subject}: {s.name}
                  </p>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
