import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import {
  checkContentCompliance,
  getContentCompliance,
  listContentFlags,
  listContentLicenseRefs,
} from "@/api/endpoints/licenseCompliance";
import { ComplianceBadge } from "@/components/shared/ComplianceBadge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

interface Props {
  contentId: string | null;
  open: boolean;
  onOpenChange: (v: boolean) => void;
}

function fmtDate(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

export function LicenseComplianceDetailDialog({
  contentId,
  open,
  onOpenChange,
}: Props) {
  const queryClient = useQueryClient();
  const enabled = !!contentId && open;

  const statusQuery = useQuery({
    queryKey: ["compliance", "status", contentId],
    queryFn: () => getContentCompliance(contentId!),
    enabled,
  });
  const refsQuery = useQuery({
    queryKey: ["compliance", "refs", contentId],
    queryFn: () => listContentLicenseRefs(contentId!),
    enabled,
  });
  const flagsQuery = useQuery({
    queryKey: ["compliance", "flags", contentId],
    queryFn: () => listContentFlags(contentId!),
    enabled,
  });

  const checkMut = useMutation({
    mutationFn: async () => checkContentCompliance(contentId!),
    onSuccess: () => {
      toast.success("Compliance re-checked");
      queryClient.invalidateQueries({ queryKey: ["compliance"] });
    },
    onError: (e: Error) => toast.error(e.message || "Check failed"),
  });

  const status = statusQuery.data;
  const refs = refsQuery.data?.items ?? [];
  const flags = flagsQuery.data?.items ?? [];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Compliance Detail</DialogTitle>
          <DialogDescription>{contentId}</DialogDescription>
        </DialogHeader>

        <div className="space-y-5">
          <div className="flex items-center gap-3">
            <span className="text-sm text-muted-foreground">Status:</span>
            {status ? (
              <ComplianceBadge status={status.compliance_status} />
            ) : (
              <span className="text-sm">No record yet</span>
            )}
            <Button
              size="sm"
              variant="outline"
              className="ml-auto"
              onClick={() => checkMut.mutate()}
              disabled={checkMut.isPending}
            >
              {checkMut.isPending ? "Checking…" : "Check Now"}
            </Button>
          </div>

          <section>
            <h4 className="mb-2 text-sm font-semibold">License References</h4>
            {refs.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No license references on this content.
              </p>
            ) : (
              <ul className="space-y-2">
                {refs.map((r) => (
                  <li
                    key={r.license_id}
                    className="flex items-center justify-between rounded border p-2 text-sm"
                  >
                    <div>
                      <div className="font-mono text-xs">{r.license_id}</div>
                      <div className="text-muted-foreground">
                        {r.license_type} · expires {fmtDate(r.expires_at)}
                      </div>
                    </div>
                    <ComplianceBadge status={r.license_status} />
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section>
            <h4 className="mb-2 text-sm font-semibold">Issues</h4>
            {status && status.issues.length > 0 ? (
              <ul className="list-disc space-y-1 pl-5 text-sm">
                {status.issues.map((iss, i) => (
                  <li key={i}>
                    {String((iss as Record<string, unknown>).type ?? "issue")}
                    {" — "}
                    {String((iss as Record<string, unknown>).detail ?? "")}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted-foreground">No issues.</p>
            )}
          </section>

          <section>
            <h4 className="mb-2 text-sm font-semibold">Flags</h4>
            {flags.length === 0 ? (
              <p className="text-sm text-muted-foreground">No flags.</p>
            ) : (
              <ul className="space-y-2">
                {flags.map((f) => (
                  <li key={f.flag_id} className="rounded border p-2 text-sm">
                    <div className="flex items-center justify-between">
                      <span className="font-medium">
                        {f.reason.replace(/_/g, " ")}
                      </span>
                      <ComplianceBadge status={f.status} />
                    </div>
                    {f.evidence && (
                      <p className="mt-1 text-muted-foreground">{f.evidence}</p>
                    )}
                    {f.resolution_notes && (
                      <p className="mt-1 text-xs italic">
                        Resolution: {f.resolution_notes}
                      </p>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export default LicenseComplianceDetailDialog;
