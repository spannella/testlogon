import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Gavel,
  Lock,
  Unlock,
  Download,
  Loader2,
  FileLock2,
  ShieldAlert,
} from "lucide-react";
import { toast } from "sonner";
import {
  listLegalHolds,
  placeLegalHold,
  releaseLegalHold,
  listLegalExports,
  createLegalExport,
  generateLegalExport,
  getLegalExportDownloadUrl,
} from "@/api/endpoints/legal";
import type { LegalHold, LegalExport } from "@/api/types";

const DATA_TYPES = ["profile", "addresses", "billing", "alerts", "audit_trail"];

function fmtDate(ts?: number | null) {
  if (!ts) return "--";
  return new Date(ts * 1000).toLocaleString();
}

function fmtSize(bytes?: number) {
  if (!bytes) return "--";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function errMsg(err: unknown, fallback: string): string {
  const e = err as { status?: number; detail?: string };
  if (e?.status === 403)
    return "Legal role or root access is required for this action.";
  if (e?.status === 404)
    return "Legal export is not enabled on this server.";
  return e?.detail || fallback;
}

function HoldStatus({ status }: { status: string }) {
  return (
    <Badge variant={status === "active" ? "destructive" : "outline"}>
      {status === "active" ? "Active" : status}
    </Badge>
  );
}

function ExportStatus({ status }: { status: string }) {
  const variant =
    status === "completed"
      ? "default"
      : status === "failed"
        ? "destructive"
        : "secondary";
  return <Badge variant={variant}>{status}</Badge>;
}

export default function LegalHoldPage() {
  const queryClient = useQueryClient();

  // ─── Place-hold form state ───
  const [holdDialogOpen, setHoldDialogOpen] = useState(false);
  const [holdUserSub, setHoldUserSub] = useState("");
  const [holdReason, setHoldReason] = useState("");
  const [holdMatterRef, setHoldMatterRef] = useState("");
  const [holdCaseId, setHoldCaseId] = useState("");

  // ─── Create-export form state ───
  const [exportDialogOpen, setExportDialogOpen] = useState(false);
  const [matterRef, setMatterRef] = useState("");
  const [authority, setAuthority] = useState("");
  const [legalBasis, setLegalBasis] = useState("");
  const [targets, setTargets] = useState("");
  const [reason, setReason] = useState("");
  const [selectedTypes, setSelectedTypes] = useState<string[]>([...DATA_TYPES]);

  const holdsQ = useQuery({
    queryKey: ["legal", "holds"],
    queryFn: listLegalHolds,
    refetchInterval: 15_000,
  });

  const exportsQ = useQuery({
    queryKey: ["legal", "exports"],
    queryFn: listLegalExports,
    refetchInterval: 15_000,
  });

  const placeMut = useMutation({
    mutationFn: () =>
      placeLegalHold({
        user_sub: holdUserSub.trim(),
        reason: holdReason.trim(),
        matter_ref: holdMatterRef.trim() || undefined,
        case_id: holdCaseId.trim() || undefined,
      }),
    onSuccess: () => {
      toast.success("Legal hold placed");
      setHoldDialogOpen(false);
      setHoldUserSub("");
      setHoldReason("");
      setHoldMatterRef("");
      setHoldCaseId("");
      queryClient.invalidateQueries({ queryKey: ["legal", "holds"] });
    },
    onError: (err) => toast.error(errMsg(err, "Failed to place hold")),
  });

  const releaseMut = useMutation({
    mutationFn: (holdId: string) => releaseLegalHold(holdId),
    onSuccess: () => {
      toast.success("Legal hold released");
      queryClient.invalidateQueries({ queryKey: ["legal", "holds"] });
    },
    onError: (err) => toast.error(errMsg(err, "Failed to release hold")),
  });

  const createExportMut = useMutation({
    mutationFn: () =>
      createLegalExport({
        matter_ref: matterRef.trim(),
        requesting_authority: authority.trim(),
        legal_basis: legalBasis.trim(),
        target_user_subs: targets
          .split(/[\s,]+/)
          .map((s) => s.trim())
          .filter(Boolean),
        data_types: selectedTypes.length ? selectedTypes : undefined,
        reason: reason.trim() || undefined,
      }),
    onSuccess: () => {
      toast.success("Legal export intake created");
      setExportDialogOpen(false);
      setMatterRef("");
      setAuthority("");
      setLegalBasis("");
      setTargets("");
      setReason("");
      setSelectedTypes([...DATA_TYPES]);
      queryClient.invalidateQueries({ queryKey: ["legal", "exports"] });
    },
    onError: (err) => toast.error(errMsg(err, "Failed to create export")),
  });

  const generateMut = useMutation({
    mutationFn: (id: string) => generateLegalExport(id),
    onSuccess: () => {
      toast.success("Sealed package generated");
      queryClient.invalidateQueries({ queryKey: ["legal", "exports"] });
    },
    onError: (err) => toast.error(errMsg(err, "Failed to generate package")),
  });

  const toggleType = (t: string) =>
    setSelectedTypes((prev) =>
      prev.includes(t) ? prev.filter((x) => x !== t) : [...prev, t],
    );

  const holds = holdsQ.data ?? [];
  const exports = exportsQ.data ?? [];

  const forbidden =
    (holdsQ.error as { status?: number })?.status === 403 ||
    (exportsQ.error as { status?: number })?.status === 403;
  const notEnabled =
    (holdsQ.error as { status?: number })?.status === 404 ||
    (exportsQ.error as { status?: number })?.status === 404;

  return (
    <div className="mx-auto max-w-5xl space-y-6 p-4 md:p-8">
      <div>
        <h1 className="flex items-center gap-2 text-2xl font-bold">
          <Gavel className="h-6 w-6" />
          Legal Holds & Exports
        </h1>
        <p className="text-muted-foreground">
          Place or release litigation holds and create chain-of-custody
          law-enforcement / subpoena exports. ROOT or legal-role access only.
        </p>
      </div>

      {forbidden && (
        <Card className="border-destructive/50">
          <CardContent className="flex items-center gap-2 py-4 text-destructive">
            <ShieldAlert className="h-5 w-5" />
            You do not have legal/root access to this area.
          </CardContent>
        </Card>
      )}

      {notEnabled && (
        <Card className="border-amber-500/50">
          <CardContent className="flex items-center gap-2 py-4 text-amber-600">
            <ShieldAlert className="h-5 w-5" />
            The legal-export feature is disabled on this server
            (LEGAL_EXPORT_ENABLED). Actions will return 404 until it is enabled.
          </CardContent>
        </Card>
      )}

      {/* ─── Legal holds ─────────────────────────────────────── */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Lock className="h-5 w-5" />
              Active Legal Holds
            </CardTitle>
            <CardDescription>
              A hold suspends deletion / retention for the held user until released.
            </CardDescription>
          </div>
          <Button onClick={() => setHoldDialogOpen(true)} size="sm">
            Place Hold
          </Button>
        </CardHeader>
        <CardContent>
          {holdsQ.isLoading ? (
            <div className="flex justify-center py-6">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : holds.length === 0 ? (
            <p className="py-4 text-center text-muted-foreground">
              No active legal holds.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left">
                    <th className="pb-2 pr-4 font-medium">User</th>
                    <th className="pb-2 pr-4 font-medium">Matter</th>
                    <th className="pb-2 pr-4 font-medium">Reason</th>
                    <th className="pb-2 pr-4 font-medium">Status</th>
                    <th className="pb-2 pr-4 font-medium">Placed</th>
                    <th className="pb-2 font-medium" />
                  </tr>
                </thead>
                <tbody>
                  {holds.map((h: LegalHold) => (
                    <tr key={h.hold_id} className="border-b last:border-0">
                      <td className="py-2 pr-4 font-mono text-xs">{h.user_sub}</td>
                      <td className="py-2 pr-4">{h.matter_ref || "--"}</td>
                      <td className="py-2 pr-4">{h.reason || "--"}</td>
                      <td className="py-2 pr-4">
                        <HoldStatus status={h.status} />
                      </td>
                      <td className="py-2 pr-4 text-muted-foreground">
                        {fmtDate(h.created_at)}
                      </td>
                      <td className="py-2">
                        {h.status === "active" && (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => releaseMut.mutate(h.hold_id)}
                            disabled={releaseMut.isPending}
                          >
                            <Unlock className="mr-1 h-3.5 w-3.5" />
                            Release
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* ─── Legal exports ───────────────────────────────────── */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <FileLock2 className="h-5 w-5" />
              Law-Enforcement Exports
            </CardTitle>
            <CardDescription>
              Scoped, sealed, HMAC-signed chain-of-custody packages. Create an
              intake, then generate the sealed package and download it.
            </CardDescription>
          </div>
          <Button onClick={() => setExportDialogOpen(true)} size="sm">
            New Export
          </Button>
        </CardHeader>
        <CardContent>
          {exportsQ.isLoading ? (
            <div className="flex justify-center py-6">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : exports.length === 0 ? (
            <p className="py-4 text-center text-muted-foreground">
              No legal exports yet.
            </p>
          ) : (
            <div className="space-y-3">
              {exports.map((ex: LegalExport) => (
                <div
                  key={ex.legal_export_id}
                  className="rounded-md border p-3 text-sm"
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="font-medium">{ex.matter_ref}</span>
                      <ExportStatus status={ex.status} />
                      {ex.sealed && (
                        <Badge variant="outline" className="gap-1">
                          <Lock className="h-3 w-3" /> Sealed
                        </Badge>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      {ex.status === "intake" && (
                        <Button
                          size="sm"
                          onClick={() => generateMut.mutate(ex.legal_export_id)}
                          disabled={generateMut.isPending}
                        >
                          {generateMut.isPending ? (
                            <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />
                          ) : null}
                          Generate
                        </Button>
                      )}
                      {ex.status === "completed" && (
                        <a
                          href={getLegalExportDownloadUrl(ex.legal_export_id)}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          <Button variant="outline" size="sm">
                            <Download className="mr-1 h-3.5 w-3.5" />
                            Download ({fmtSize(ex.size_bytes)})
                          </Button>
                        </a>
                      )}
                    </div>
                  </div>
                  <div className="mt-2 grid grid-cols-1 gap-x-6 gap-y-1 text-xs text-muted-foreground sm:grid-cols-2">
                    <span>Authority: {ex.requesting_authority}</span>
                    <span>Legal basis: {ex.legal_basis}</span>
                    <span>
                      Targets: {(ex.target_user_subs ?? []).join(", ") || "--"}
                    </span>
                    <span>Data types: {(ex.data_types ?? []).join(", ")}</span>
                    <span>Created: {fmtDate(ex.created_at)}</span>
                    {ex.expires_at ? (
                      <span>Expires: {fmtDate(ex.expires_at)}</span>
                    ) : null}
                    {ex.package_sha256 ? (
                      <span className="break-all sm:col-span-2">
                        SHA-256: <span className="font-mono">{ex.package_sha256}</span>
                      </span>
                    ) : null}
                    {ex.error_message ? (
                      <span className="text-destructive sm:col-span-2">
                        Error: {ex.error_message}
                      </span>
                    ) : null}
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* ─── Place-hold dialog ───────────────────────────────── */}
      <Dialog open={holdDialogOpen} onOpenChange={setHoldDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Place Legal Hold</DialogTitle>
            <DialogDescription>
              Suspends deletion and retention expiry for the target user until
              the hold is released.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <div>
              <Label htmlFor="hold-user">Target user_sub *</Label>
              <Input
                id="hold-user"
                value={holdUserSub}
                onChange={(e) => setHoldUserSub(e.target.value)}
                placeholder="user_sub or email"
              />
            </div>
            <div>
              <Label htmlFor="hold-reason">Reason *</Label>
              <Textarea
                id="hold-reason"
                value={holdReason}
                onChange={(e) => setHoldReason(e.target.value)}
                rows={2}
                placeholder="Litigation / preservation reason"
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label htmlFor="hold-matter">Matter ref</Label>
                <Input
                  id="hold-matter"
                  value={holdMatterRef}
                  onChange={(e) => setHoldMatterRef(e.target.value)}
                />
              </div>
              <div>
                <Label htmlFor="hold-case">Case ID</Label>
                <Input
                  id="hold-case"
                  value={holdCaseId}
                  onChange={(e) => setHoldCaseId(e.target.value)}
                />
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setHoldDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => placeMut.mutate()}
              disabled={
                placeMut.isPending || !holdUserSub.trim() || !holdReason.trim()
              }
            >
              {placeMut.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : null}
              Place Hold
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ─── Create-export dialog ────────────────────────────── */}
      <Dialog open={exportDialogOpen} onOpenChange={setExportDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New Legal Export</DialogTitle>
            <DialogDescription>
              Records chain-of-custody intake. Matter ref, requesting authority,
              legal basis and at least one target are required.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <div>
              <Label htmlFor="ex-matter">Matter ref *</Label>
              <Input
                id="ex-matter"
                value={matterRef}
                onChange={(e) => setMatterRef(e.target.value)}
                placeholder="Subpoena / warrant number"
              />
            </div>
            <div>
              <Label htmlFor="ex-authority">Requesting authority *</Label>
              <Input
                id="ex-authority"
                value={authority}
                onChange={(e) => setAuthority(e.target.value)}
                placeholder="e.g. FBI, court name"
              />
            </div>
            <div>
              <Label htmlFor="ex-basis">Legal basis *</Label>
              <Input
                id="ex-basis"
                value={legalBasis}
                onChange={(e) => setLegalBasis(e.target.value)}
                placeholder="e.g. subpoena, search warrant"
              />
            </div>
            <div>
              <Label htmlFor="ex-targets">Target user_subs * (comma/space separated)</Label>
              <Textarea
                id="ex-targets"
                value={targets}
                onChange={(e) => setTargets(e.target.value)}
                rows={2}
              />
            </div>
            <div>
              <Label htmlFor="ex-reason">Reason (optional)</Label>
              <Input
                id="ex-reason"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
              />
            </div>
            <div>
              <p className="mb-1 text-sm font-medium">Data types</p>
              <div className="flex flex-wrap gap-3">
                {DATA_TYPES.map((t) => (
                  <label key={t} className="flex items-center gap-1.5 text-sm">
                    <input
                      type="checkbox"
                      checked={selectedTypes.includes(t)}
                      onChange={() => toggleType(t)}
                    />
                    {t}
                  </label>
                ))}
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setExportDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => createExportMut.mutate()}
              disabled={
                createExportMut.isPending ||
                !matterRef.trim() ||
                !authority.trim() ||
                !legalBasis.trim() ||
                !targets.trim()
              }
            >
              {createExportMut.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : null}
              Create Intake
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
