import { useQuery, useMutation } from "@tanstack/react-query";
import { toast } from "sonner";

import {
  downloadLicenseAgreement,
  getLicenseAgreement,
  listLicenseAgreementContent,
  unlinkLicenseAgreementContent,
} from "@/api/endpoints/licenseAgreements";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

interface Props {
  licenseId: string | null;
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onChanged: () => void;
}

function fmt(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString();
}

export function AgreementDetailDialog({
  licenseId,
  open,
  onOpenChange,
  onChanged,
}: Props) {
  const detailQuery = useQuery({
    queryKey: ["license-agreement", licenseId],
    queryFn: () => getLicenseAgreement(licenseId as string),
    enabled: !!licenseId && open,
  });

  const contentQuery = useQuery({
    queryKey: ["license-agreement-content", licenseId],
    queryFn: () => listLicenseAgreementContent(licenseId as string),
    enabled: !!licenseId && open,
  });

  const downloadMut = useMutation({
    mutationFn: async () => downloadLicenseAgreement(licenseId as string),
    onSuccess: (res) => {
      window.open(res.download_url, "_blank");
    },
    onError: (e: Error) => toast.error(e.message || "Download failed"),
  });

  const unlinkMut = useMutation({
    mutationFn: async (contentId: string) =>
      unlinkLicenseAgreementContent(licenseId as string, contentId),
    onSuccess: () => {
      toast.success("Content unlinked");
      contentQuery.refetch();
      onChanged();
    },
    onError: (e: Error) => toast.error(e.message || "Unlink failed"),
  });

  const a = detailQuery.data;
  const items = contentQuery.data?.items ?? [];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{a?.title ?? "Agreement"}</DialogTitle>
        </DialogHeader>
        {a ? (
          <div className="space-y-3 text-sm">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="secondary">{a.status}</Badge>
              <Badge variant="outline">{a.license_type.replace(/_/g, " ")}</Badge>
              <span className="text-muted-foreground">v{a.version}</span>
            </div>
            <dl className="grid grid-cols-2 gap-2">
              <dt className="text-muted-foreground">Licensor</dt>
              <dd>{a.licensor_name || "—"}</dd>
              <dt className="text-muted-foreground">Territory</dt>
              <dd>{a.territory}</dd>
              <dt className="text-muted-foreground">Expires</dt>
              <dd>{fmt(a.expires_at)}</dd>
              <dt className="text-muted-foreground">File</dt>
              <dd>{a.file_name}</dd>
            </dl>
            {a.notes && <p className="text-muted-foreground">{a.notes}</p>}
            {a.rejection_reason && (
              <p className="text-destructive">
                Rejected: {a.rejection_reason}
              </p>
            )}
            <Button
              size="sm"
              variant="outline"
              onClick={() => downloadMut.mutate()}
              disabled={downloadMut.isPending}
            >
              Download document
            </Button>
            <div>
              <h4 className="mb-1 font-medium">Linked content</h4>
              {items.length === 0 ? (
                <p className="text-muted-foreground">No linked content.</p>
              ) : (
                <ul className="space-y-1">
                  {items.map((c) => (
                    <li
                      key={c.content_id}
                      className="flex items-center justify-between gap-2"
                    >
                      <span>
                        <Badge variant="outline">{c.content_type}</Badge>{" "}
                        {c.content_id}
                      </span>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => unlinkMut.mutate(c.content_id)}
                        disabled={unlinkMut.isPending}
                      >
                        Unlink
                      </Button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">Loading…</p>
        )}
      </DialogContent>
    </Dialog>
  );
}
